"""Read-only, secret-safe repository context snapshot generator.

Usage (from repository root):
    python scripts/project_context.py --markdown > PROJECT_CONTEXT_SNAPSHOT.md
    python scripts/project_context.py --json > project_context_snapshot.json

The script reads filenames/metadata and selected text manifests only. It never
imports or executes project code, writes repository files, or emits secret file
contents. Review generated output before sharing it. It does not overwrite
PROJECT_CONTEXT.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "node_modules", ".next", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "target", ".bin",
    "dist", "build", "coverage",
}
SECRET_NAMES = {
    ".env", ".env.local", ".env.production", "id_rsa", "id_ed25519",
    "credentials", "secrets.json", "token.json",
}
SECRET_PARTS = ("secret", "credential", "private_key", "apikey", "api_key", "token")
IMPORTANT_FILES = [
    "PROJECT_CONTEXT.md", "AGENTS.md", "README.md", "pyproject.toml",
    "MASTER_PROJECT_CONTEXT/README.md",
    "MASTER_PROJECT_CONTEXT/.context/canonical_context.md",
    "MASTER_PROJECT_CONTEXT/.context/project_state.md",
    "MASTER_PROJECT_CONTEXT/.context/handoff.md",
    "MASTER_PROJECT_CONTEXT/.context/architecture_reference.md",
    "MASTER_PROJECT_CONTEXT/.context/adrs.md",
    "MASTER_PROJECT_CONTEXT/.context/execution_map.md",
    "requirements.txt", "requirements-dev.txt", "frontend/package.json",
    "frontend/package-lock.json", "backend/shared/requirements.txt",
    "backend/shared/crypto/profile.json",
    "backend/verification_service/requirements.txt",
    "backend/verification_service/crypto_runtime/package.json",
    "backend/verification_service/crypto_runtime/package-lock.json",
    "docker-compose.yml", "backend/verification_service/app/core/verifier.py",
    "backend/verification_service/app/core/legacy_acir.py",
    "backend/verification_service/tests/test_b1_live_crypto.py",
    "archive/proofs/temp/manifest.json", "archive/proofs/temp/profile.json",
    "archive/proofs/temp/chunk_0_segment_0.proof",
    "archive/proofs/temp/segment_init_32.vk",
]
IMPORTANT_SCRIPTS = [
    "scripts/verify_archive.py", "scripts/run_negative_tests.py",
    "scripts/run_c32_negative_tests.py", "scripts/smoke_test_c32.py",
    "scripts/generate_c32_circuits.py", "scripts/execute_stage21.py",
    "scripts/generate_crypto_vectors.py", "scripts/generate_inventory.py",
]


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def is_secret_path(path: Path) -> bool:
    parts = [part.lower() for part in path.parts]
    name = path.name.lower()
    return name in SECRET_NAMES or any(part == ".env" or part.startswith(".env.") for part in parts) or any(
        marker in name for marker in SECRET_PARTS
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    return result.stdout.rstrip("\r\n")


def ignored_paths(paths: list[str]) -> set[str]:
    """Ask Git once which inventory paths are ignored, without reading file contents."""
    if not paths:
        return set()
    try:
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--stdin"],
            cwd=ROOT, input="\n".join(paths) + "\n", capture_output=True,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return {line.replace("\\", "/") for line in result.stdout.splitlines()}


def tree_and_files() -> tuple[list[str], list[dict[str, Any]]]:
    directories: list[str] = []
    files: list[dict[str, Any]] = []
    for current, dirnames, filenames in os.walk(ROOT):
        current_path = Path(current)
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in EXCLUDED_DIRS and not is_secret_path(current_path / name)
        )
        if current_path != ROOT:
            directories.append(rel(current_path))
        for filename in sorted(filenames):
            path = current_path / filename
            relative = rel(path)
            if is_secret_path(path):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            files.append({"path": relative, "size_bytes": size})
    ignored = ignored_paths([item["path"] for item in files])
    visible_files = [item for item in files if item["path"] not in ignored]
    # A directory is retained when it has visible descendants. Empty
    # directories are not represented by Git and are not useful inventory.
    visible_dirs = [directory for directory in directories if any(
        item["path"].startswith(directory + "/") for item in visible_files
    )]
    return sorted(visible_dirs), sorted(visible_files, key=lambda item: item["path"])


def artifact_records() -> list[dict[str, Any]]:
    archive_dir = ROOT / "archive" if (ROOT / "archive").exists() else ROOT / "archives"
    roots = [archive_dir, ROOT / "backend" / "shared" / "crypto"]
    records = []
    for base in roots:
        if not base.exists():
            continue
        for current, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(name for name in dirnames if name not in EXCLUDED_DIRS)
            for filename in sorted(filenames):
                path = Path(current) / filename
                lower = filename.lower()
                if is_secret_path(path) or not (
                    lower.endswith((".proof", ".vk"))
                    or lower in {"profile.json", "manifest.json"}
                ):
                    continue
                try:
                    records.append({"path": rel(path), "size_bytes": path.stat().st_size, "sha256": sha256(path)})
                except OSError:
                    continue
    return sorted(records, key=lambda item: item["path"])


def package_versions() -> dict[str, Any]:
    result: dict[str, Any] = {"python": {}, "node": {}, "noir": {}}
    pyproject = ROOT / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8", errors="replace")
        result["python"]["project_file"] = "pyproject.toml"
        result["python"]["pytest_config_present"] = "[tool.pytest.ini_options]" in text
    for name in ("requirements.txt", "requirements-dev.txt", "backend/shared/requirements.txt"):
        path = ROOT / name
        if path.is_file():
            result["python"].setdefault("requirements_files", []).append(name)
    docker_python = {}
    for name in ("backend/shared/Dockerfile", "backend/verification_service/Dockerfile", "backend/zkp_service/Dockerfile"):
        path = ROOT / name
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"(?im)^\s*FROM\s+python:([\w.-]+)", text)
            if match:
                docker_python[name] = match.group(1)
    result["python"]["docker_base_images"] = docker_python
    package = ROOT / "frontend/package.json"
    if package.is_file():
        data = json.loads(package.read_text(encoding="utf-8"))
        result["node"]["frontend"] = {"name": data.get("name"), "dependencies": {
            key: data.get("dependencies", {}).get(key)
            for key in ("next", "react", "react-dom")
        }, "scripts": sorted(data.get("scripts", {}).keys())}
    crypto_package = ROOT / "backend/verification_service/crypto_runtime/package.json"
    if crypto_package.is_file():
        data = json.loads(crypto_package.read_text(encoding="utf-8"))
        result["node"]["crypto_runtime"] = {"dependencies": data.get("dependencies", {})}
    profile = ROOT / "backend/shared/crypto/profile.json"
    if profile.is_file():
        data = json.loads(profile.read_text(encoding="utf-8"))
        result["noir"]["profile_versions"] = {
            key: value.get("nargo_version") for key, value in data.get("profiles", {}).items()
        }
    return result


def build_snapshot() -> dict[str, Any]:
    directories, all_files = tree_and_files()
    file_map = {item["path"]: item for item in all_files}
    important = []
    for name in IMPORTANT_FILES:
        path = ROOT / name
        if path.is_file() and not is_secret_path(path):
            item = {"path": name, "size_bytes": path.stat().st_size}
            if name.endswith((".proof", ".vk")) or name.endswith("profile.json"):
                item["sha256"] = sha256(path)
            important.append(item)
    status = git("status", "--short", "--branch")
    return {
        "schema_version": 1,
        "repository_root_name": ROOT.name,
        "git": {
            "branch": git("branch", "--show-current"),
            "commit": git("rev-parse", "HEAD"),
            "status_short": status,
        },
        "versions_and_tooling": package_versions(),
        "test_framework_evidence": {
            "pytest_config": (ROOT / "pyproject.toml").is_file(),
            "b1_live_test": "backend/verification_service/tests/test_b1_live_crypto.py" in file_map,
            "frontend_test_script": "frontend/package.json" in file_map,
        },
        "directory_tree": directories,
        "file_inventory": all_files,
        "important_files": important,
        "important_scripts": [name for name in IMPORTANT_SCRIPTS if (ROOT / name).is_file()],
        "security_artifacts": artifact_records(),
        "context_documents": [name for name in (".context/canonical_context.md", ".context/project_state.md", ".context/handoff.md", ".context/architecture_reference.md", ".context/adrs.md", ".context/execution_map.md", "AGENTS.md") if (ROOT / name).is_file()],
        "secret_handling": "Secret paths are omitted; file contents are never emitted. Excluded build/cache directories are not inventoried.",
        "notes": [
            "Generated read-only snapshot; not authoritative project status.",
            "Git status output may contain user-chosen filenames; review before sharing.",
            "No project code was imported or executed.",
        ],
    }


def markdown(snapshot: dict[str, Any]) -> str:
    git_info = snapshot["git"]
    lines = [
        "# Repository Context Snapshot", "",
        "Generated by `scripts/project_context.py`; read-only inventory, not an authoritative status decision.", "",
        "## Git", "",
        f"- Branch: `{git_info['branch'] or 'UNKNOWN'}`",
        f"- Commit: `{git_info['commit'] or 'UNKNOWN'}`", "",
        "```text", git_info["status_short"] or "(status unavailable)", "```", "",
        "## Tooling Evidence", "", "```json",
        json.dumps(snapshot["versions_and_tooling"], indent=2, sort_keys=True), "```", "",
        "## Important Files", "", "| Path | Bytes | SHA-256 (selected artifacts) |", "|---|---:|---|",
    ]
    for item in snapshot["important_files"]:
        lines.append(f"| `{item['path']}` | {item['size_bytes']} | `{item.get('sha256', '')}` |")
    lines.extend(["", "## Important Scripts", ""])
    lines.extend(f"- `{name}`" for name in snapshot["important_scripts"])
    lines.extend(["", "## Security Artifact Inventory", "", "| Path | Bytes | SHA-256 |", "|---|---:|---|"])
    for item in snapshot["security_artifacts"]:
        lines.append(f"| `{item['path']}` | {item['size_bytes']} | `{item['sha256']}` |")
    lines.extend(["", "## Directory Tree", "", *[f"- `{path}/`" for path in snapshot["directory_tree"]]])
    lines.extend(["", "## File Inventory", "", "| Path | Bytes |", "|---|---:|"])
    lines.extend(f"| `{item['path']}` | {item['size_bytes']} |" for item in snapshot["file_inventory"])
    lines.extend(["", "## Secret Handling", "", snapshot["secret_handling"], ""])
    lines.extend(f"- {note}" for note in snapshot["notes"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--json", action="store_true", help="emit deterministic JSON")
    output.add_argument("--markdown", action="store_true", help="emit Markdown inventory")
    args = parser.parse_args()
    snapshot = build_snapshot()
    if args.json:
        print(json.dumps(snapshot, indent=2, sort_keys=True))
    else:
        print(markdown(snapshot), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
package_source_zip.py - Source ZIP Packaging Script with Strict Master Archive Exclusion

Packages the repository source code while strictly and automatically excluding
the root-level `master_archive/` directory, private credentials, and build caches,
while retaining `archive/` and all required source, test, migration, and config assets.
"""

import argparse
import os
import sys
import zipfile
from pathlib import Path


# Explicit directory names to exclude when encountered at specific or general levels
EXCLUDED_ROOT_DIRS = {
    "master_archive",     # Root-level non-essential archive (strictly excluded)
    ".git",               # Version control
    ".venv",              # Python virtual environment
    "venv",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "dist",               # Build outputs / packaging destination
    "scratch",            # Ephemeral scratch directory (strictly excluded)
}

EXCLUDED_DIR_NAMES = {
    "__pycache__",
    "node_modules",
    ".next",
    ".cache",
    "target",             # Nargo build cache
}

EXCLUDED_FILE_PATTERNS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".log",
}

# Sensitive / credential files that must NEVER be packaged
EXCLUDED_EXACT_FILES = {
    ".env",
    "db.txt",
    "d9_credentials.json",
    "compose_logs.txt",
    "verification_logs.txt",
}

EXCLUDED_EXTENSIONS = {
    ".pem",
    ".key",
    ".pfx",
    ".p12",
}


def should_exclude(rel_path: Path, root_path: Path, output_zip_path: Path) -> tuple[bool, str]:
    """
    Evaluates whether a relative path should be excluded from the source ZIP.
    Returns (True, reason) or (False, "").
    """
    parts = rel_path.parts
    if not parts:
        return True, "empty_path"

    # 1. Output zip file itself
    full_path = root_path / rel_path
    try:
        if full_path.resolve() == output_zip_path.resolve():
            return True, "output_zip_itself"
    except Exception:
        pass

    # 2. Root-level excluded directories (specifically master_archive)
    if parts[0] in EXCLUDED_ROOT_DIRS:
        return True, f"excluded_root_dir:{parts[0]}"

    # 3. Intermediate excluded directories (caches, node_modules)
    for part in parts[:-1]:
        if part in EXCLUDED_DIR_NAMES:
            return True, f"excluded_dir_name:{part}"

    # If it's a directory, check its name
    if full_path.is_dir():
        if parts[-1] in EXCLUDED_DIR_NAMES:
            return True, f"excluded_dir_name:{parts[-1]}"
        return False, ""

    # 4. Excluded sensitive files
    filename = parts[-1]
    if filename in EXCLUDED_EXACT_FILES:
        return True, f"sensitive_file:{filename}"

    if filename.startswith(".env") and not filename.endswith(".example"):
        return True, f"env_file:{filename}"

    # 5. Excluded file extensions (keys, certs, compiled bytecode)
    ext = full_path.suffix.lower()
    if ext in EXCLUDED_EXTENSIONS:
        return True, f"sensitive_extension:{ext}"

    if ext in EXCLUDED_FILE_PATTERNS:
        return True, f"cache_extension:{ext}"

    return False, ""


def package_source_zip(root_dir: str | Path, output_path: str | Path, verbose: bool = False) -> Path:
    """
    Packages the project root into a zip file with explicit exclusion rules.
    """
    root_path = Path(root_dir).resolve()
    output_zip_path = Path(output_path).resolve()

    if not root_path.is_dir():
        raise ValueError(f"Root path does not exist or is not a directory: {root_path}")

    # Ensure output parent directory exists
    output_zip_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Packaging source from: {root_path}")
    print(f"[*] Target ZIP output:     {output_zip_path}")
    print(f"[*] Verifying master_archive/ is present on disk before packaging...")
    local_master_archive = root_path / "master_archive"
    if not local_master_archive.is_dir():
        print(f"[!] Warning: local master_archive/ not found at {local_master_archive}")
    else:
        print(f"[+] Confirmed: local master_archive/ exists on disk ({sum(1 for _ in local_master_archive.rglob('*'))} items).")

    temp_zip_path = output_zip_path.with_suffix(".tmp.zip")
    if temp_zip_path.exists():
        temp_zip_path.unlink()

    included_count = 0
    excluded_count = 0

    with zipfile.ZipFile(temp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for current_root, dirs, files in os.walk(root_path):
            current_path = Path(current_root)
            rel_dir = current_path.relative_to(root_path)

            # Filter dirs in-place to avoid descending into excluded trees
            dirs_to_remove = []
            for d in dirs:
                rel_d = rel_dir / d if rel_dir != Path(".") else Path(d)
                excluded, reason = should_exclude(rel_d, root_path, output_zip_path)
                if excluded:
                    dirs_to_remove.append(d)
                    if verbose:
                        print(f"[-] Excluding directory: {rel_d} ({reason})")
            for d in dirs_to_remove:
                dirs.remove(d)

            for f in sorted(files):
                rel_file = rel_dir / f if rel_dir != Path(".") else Path(f)
                excluded, reason = should_exclude(rel_file, root_path, output_zip_path)
                if excluded:
                    excluded_count += 1
                    if verbose:
                        print(f"[-] Excluding file: {rel_file} ({reason})")
                    continue

                full_file = current_path / f
                # Normalized posix zip entry name
                arcname = rel_file.as_posix()
                zf.write(full_file, arcname=arcname)
                included_count += 1

    # Atomic move to final destination
    if output_zip_path.exists():
        output_zip_path.unlink()
    temp_zip_path.rename(output_zip_path)

    print(f"[+] Successfully created source ZIP: {output_zip_path}")
    print(f"[+] Total files included: {included_count}")
    print(f"[+] Total files excluded: {excluded_count}")

    # Validate output zip contents
    validate_zip_contents(output_zip_path, root_path)
    return output_zip_path


def validate_zip_contents(zip_path: Path, root_path: Path) -> bool:
    """
    Validates that:
    1. root master_archive/ is 100% absent.
    2. root archive/ is present with assets.
    3. Required source, migrations, tests, and configs are present.
    4. Prohibited secrets (.env, keys) are absent.
    5. Local master_archive/ remains intact on disk.
    """
    print("\n[*] Validating package contents...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()

    # Check 1: master_archive exclusion
    master_archive_entries = [name for name in namelist if name == "master_archive" or name.startswith("master_archive/")]
    if master_archive_entries:
        raise AssertionError(f"Validation FAILED: master_archive found in ZIP! Entries: {master_archive_entries[:5]}")
    print("[+] PASS: root-level master_archive/ is completely absent from ZIP.")

    # Check 2: archive inclusion
    archive_entries = [name for name in namelist if name.startswith("archive/")]
    if not archive_entries:
        raise AssertionError("Validation FAILED: root-level archive/ is missing from ZIP!")
    print(f"[+] PASS: root-level archive/ is present ({len(archive_entries)} files included).")

    # Check 3: Essential required files
    required_checks = [
        "backend/alembic/versions/001_initial_schema.py",
        "backend/alembic/versions/012_vulnerability_ingestion_provenance.py",
        "backend/alembic/versions/013_add_vuln_lifecycle.py",
        "backend/alembic/versions/014_application_tenant_isolation.py",
        "backend/alembic/versions/015_auth_lifecycle_and_revocation.py",
        "backend/alembic/versions/016_add_snapshot_ttl_expires_at.py",
        "backend/shared/crypto/smt.py",
        "backend/verification_service/app/core/verifier.py",
        "backend/zkp_service/app/services/prover_service.py",
        "backend/zkp_service/tests/test_log4shell_scenario.py",
        "scripts/bb_launcher.c",
        "scripts/setup_crypto_runtime.ps1",
        "MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md",
        "MASTER_PROJECT_CONTEXT/project_context/ARCHITECTURE.md",
        "MASTER_PROJECT_CONTEXT/project_context/STUDENT_RUNBOOK.md",
        "MASTER_PROJECT_CONTEXT/project_context/DEMONSTRATIONS_AND_VIVA.md",
        "MASTER_PROJECT_CONTEXT/project_context/VIVA_PRESENTATION_SLIDES.md",
        "MASTER_PROJECT_CONTEXT/project_context/SECURITY_VALIDATION_REPORT.md",
        "docker-compose.yml",
        "README.md",
    ]
    for req in required_checks:
        if req not in namelist:
            raise AssertionError(f"Validation FAILED: Essential file missing from ZIP: {req}")
    print(f"[+] PASS: All essential application sources, migrations 001-016, and Stage E/F deliverables are present.")

    # Check 4: Secrets exclusion
    for name in namelist:
        filename = Path(name).name
        if filename == ".env" or (filename.startswith(".env.") and not filename.endswith(".example")):
            raise AssertionError(f"Validation FAILED: Secret file found in ZIP: {name}")
        if Path(name).suffix.lower() in {".pem", ".key"}:
            raise AssertionError(f"Validation FAILED: Private key file found in ZIP: {name}")
    print("[+] PASS: Zero private keys or active .env files included in ZIP.")

    # Check 5: Local master_archive still exists on disk
    local_master_archive = root_path / "master_archive"
    if not local_master_archive.is_dir():
        raise AssertionError("Validation FAILED: Local master_archive/ was modified or deleted on disk!")
    print(f"[+] PASS: Local master_archive/ directory remains intact and untouched on disk.")

    print("\n[+] ALL PACKAGING VALIDATION CRITERIA PASSED.")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Package source code with master_archive exclusion.")
    parser.add_argument("--root", default=".", help="Project root directory (default: current directory)")
    parser.add_argument("--output", default="dist/zkp-sbom-source.zip", help="Destination ZIP path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose exclusion output")
    args = parser.parse_args()

    try:
        package_source_zip(args.root, args.output, verbose=args.verbose)
    except Exception as e:
        print(f"[-] Packaging Error: {e}", file=sys.stderr)
        sys.exit(1)

"""
Noir Compatibility Test Runner — Stage 4.7 Hardened.

This script executes Python ↔ Noir interoperability verification by:
1. Reading authoritative fixed vectors from crypto_vectors.json
2. Generating ephemeral Noir test source (NEVER overwriting production source)
3. Executing each test via nargo
4. Comparing nargo output against Python-computed expectations
5. Returning non-zero exit code on ANY failure

CRITICAL RULES (Stage 4.7):
  - NEVER overwrite production `scripts/noir_compatibility/src/main.nr`
  - NEVER use hardcoded machine-specific paths
  - Exit non-zero on compilation failure, assertion failure, or vector mismatch
  - All expectations are computed from the authoritative fixture file

TOOLCHAIN DEPENDENCY:
  - Requires `nargo` (Noir compiler) in PATH, NARGO_PATH env var,
    or common installation paths.
  - If nargo is not available, reports BLOCKED (not a test failure).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------
# Nargo discovery
# ---------------------------------------------------------------

def find_nargo() -> Optional[str]:
    """Discover nargo binary via PATH, env var, or common locations."""
    # 1. NARGO_PATH environment variable
    env_path = os.environ.get("NARGO_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2. PATH lookup
    which = shutil.which("nargo")
    if which:
        return which

    # 3. Common installation paths
    common_paths = [
        os.path.expanduser("~/.nargo/bin/nargo"),
        os.path.expanduser("~/.cargo/bin/nargo"),
        "/usr/local/bin/nargo",
    ]
    for p in common_paths:
        if os.path.isfile(p):
            return p

    # 4. WSL fallback (Windows only)
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["wsl", "which", "nargo"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return f"wsl:{result.stdout.strip()}"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return None


# ---------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------

def run_tests() -> int:
    """Run Noir compatibility tests. Returns exit code (0=pass, 1=fail, 2=blocked)."""
    project_root = Path(__file__).resolve().parent.parent
    vectors_path = project_root / "backend" / "shared" / "tests" / "vectors" / "crypto_vectors.json"
    noir_project = project_root / "scripts" / "noir_compatibility"

    # Verify vectors exist
    if not vectors_path.exists():
        print(f"ERROR: Vectors file not found: {vectors_path}", file=sys.stderr)
        return 1

    # Discover nargo
    nargo = find_nargo()
    if nargo is None:
        print("=" * 60)
        print("NOIR COMPATIBILITY TESTS: BLOCKED")
        print("=" * 60)
        print("nargo not found. Searched:")
        print("  - NARGO_PATH environment variable")
        print("  - System PATH")
        print("  - ~/.nargo/bin/nargo")
        print("  - ~/.cargo/bin/nargo")
        print("  - /usr/local/bin/nargo")
        if sys.platform == "win32":
            print("  - WSL nargo")
        print("\nInstall nargo to run Noir compatibility tests.")
        print("STATUS: BLOCKED (not a test failure)")
        return 2

    print(f"Using nargo: {nargo}")

    # Load vectors
    with open(vectors_path, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    # Compute Python expectations from crypto library
    sys.path.insert(0, str(project_root / "backend"))
    from shared.crypto.poseidon_bn254 import poseidon_hash
    from shared.crypto.component_hash import sponge, hash_component, MAX_COMPONENT_FIELDS
    from shared.crypto.field_encoding import encode_bytes_to_fields

    def hex_fmt(val: int) -> str:
        return f"0x{val:064x}"

    # Build expectations dict
    expectations = {}

    # Primitive tests
    expectations["test_primitives"] = [
        hex_fmt(poseidon_hash([0])),
        hex_fmt(poseidon_hash([1])),
        hex_fmt(poseidon_hash([1, 2])),
        hex_fmt(poseidon_hash([1, 2, 3])),
        hex_fmt(poseidon_hash([1, 2, 3, 4])),
        hex_fmt(sponge([0] * 216)),
    ]

    # Component hash vectors
    for i, case in enumerate(vectors.get("component_hash", [])):
        desc = case["description"].replace(" ", "_").replace("-", "_").replace("+", "_")
        name = f"test_component_hash_{i}_{desc}"
        expectations[name] = [hex_fmt(int(case["hash"], 16))]

    # Merkle vectors
    for i, case in enumerate(vectors.get("merkle", [])):
        desc = (case["description"]
                .replace(" ", "_").replace("-", "_")
                .replace("(", "").replace(")", "").replace(",", "_"))
        name = f"test_merkle_{i}_{desc}"
        expectations[name] = [hex_fmt(int(case["root"], 16))]

    # Parse test function names from production Noir source
    main_nr_path = noir_project / "src" / "main.nr"
    if not main_nr_path.exists():
        print(f"ERROR: Noir source not found: {main_nr_path}", file=sys.stderr)
        return 1

    with open(main_nr_path, "r", encoding="utf-8") as f:
        content = f.read()

    tests = re.findall(r'fn (test_[a-zA-Z0-9_]+)\(\)', content)
    if not tests:
        print("WARNING: No test functions found in main.nr")
        return 1

    # Run each test
    report: List[str] = []
    passed = 0
    failed = 0

    # Build nargo command
    def build_nargo_cmd(test_name: str) -> List[str]:
        if nargo.startswith("wsl:"):
            nargo_path = nargo[4:]
            return ["wsl", nargo_path, "test", "--exact", test_name, "--show-output"]
        return [nargo, "test", "--exact", test_name, "--show-output"]

    for t in tests:
        print(f"Running {t}...", flush=True)

        cmd = build_nargo_cmd(t)
        try:
            from shared.crypto.config import get_crypto_profile
            timeout_seconds = get_crypto_profile().proof_timeout_seconds
        except Exception:
            timeout_seconds = 120

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                cwd=str(noir_project),
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            report.append(f"### {t}\n* TIMEOUT after {timeout_seconds} seconds")
            failed += 1
            continue


        output = res.stdout.decode("utf-8", errors="replace")
        actual_vals = re.findall(r'(0x[0-9a-fA-F]{64})', output)
        expected_vals = expectations.get(t, [])

        match = True
        if len(actual_vals) != len(expected_vals):
            match = False
            report.append(
                f"### {t}\n* MISMATCH: Expected {len(expected_vals)} outputs, "
                f"got {len(actual_vals)}"
            )
        else:
            lines = [f"### {t}"]
            for idx, (exp, act) in enumerate(zip(expected_vals, actual_vals)):
                status = "MATCH" if exp.lower() == act.lower() else "MISMATCH"
                lines.append(f"- Output {idx}: Python={exp} | Noir={act} | {status}")
                if exp.lower() != act.lower():
                    match = False
            report.append("\n".join(lines))

        if match and res.returncode == 0:
            passed += 1
        else:
            failed += 1
            if res.returncode != 0:
                stderr_text = res.stderr.decode("utf-8", errors="replace").strip()
                report.append(f"  * Execution failed: return code {res.returncode}")
                if stderr_text:
                    # Truncate long stderr for readability
                    report.append(f"  * STDERR: {stderr_text[:500]}")

    # Report
    print("\n\n" + "=" * 60)
    print("STAGE 4.7 — NOIR COMPATIBILITY REPORT")
    print("=" * 60 + "\n")
    print(f"**Total Tests**: {len(tests)}")
    print(f"**Passed**: {passed}")
    print(f"**Failed**: {failed}")
    print(f"\n## Parity Details\n")
    print("\n\n".join(report))

    # Non-zero exit code on ANY failure
    if failed > 0:
        print(f"\nEXIT CODE: 1 ({failed} test(s) failed)")
        return 1

    print("\nEXIT CODE: 0 (all tests passed)")
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())

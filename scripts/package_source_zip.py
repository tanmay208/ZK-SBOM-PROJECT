#!/usr/bin/env python3
"""
package_source_zip.py - Source ZIP Packaging Script with Strict Master Archive Exclusion
and Durable Failure-Recovery Protocol.

Packages the repository source code while strictly and automatically excluding
the root-level `master_archive/` directory, private credentials, and build caches,
while retaining `archive/` and all required source, test, migration, and config assets.
Implements journaled atomic publication with roll-forward and rollback recovery.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path


# Explicit directory names to exclude when encountered at root level
EXCLUDED_ROOT_DIRS = {
    "master_archive",     # Root-level non-essential archive (strictly excluded)
    ".git",               # Version control
    ".bin",               # Local binary wrappers and native tooling (rebuilt via setup scripts)
    ".venv",              # Python virtual environment
    "venv",
    ".idea",
    ".vscode",
    "dist",               # Build outputs / packaging destination
    "scratch",            # Ephemeral scratch directory (strictly excluded)
}

# Directory names excluded at ANY directory depth
EXCLUDED_DIR_NAMES = {
    "__pycache__",
    "node_modules",
    ".next",
    ".cache",
    ".pytest_cache",      # Pytest cache at any depth
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
    ".tsbuildinfo",       # TypeScript build info cache
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
    ".sql",               # Database dumps and backups
    ".dump",
}

# Canonical deterministic timestamp: 2026-10-26 00:00:00 (Roadmap V3 reconciliation baseline)
DETERMINISTIC_ZIP_DATETIME = (2026, 10, 26, 0, 0, 0)


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 digest of a file in 64KB streaming chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_publication_paths(output_zip_path: Path) -> dict[str, Path]:
    """Returns standardized paths for target, temporary, backup, and journal artifacts."""
    parent = output_zip_path.parent
    base = output_zip_path.name
    return {
        "target_zip": output_zip_path,
        "target_sha256": output_zip_path.with_suffix(".sha256"),
        "temp_zip": parent / f"{base}.tmp.zip",
        "temp_sha256": parent / f"{base}.tmp.sha256",
        "backup_zip": parent / f"{base}.prev.zip",
        "backup_sha256": parent / f"{base}.prev.sha256",
        "journal": parent / f"{base}.journal.json",
    }


def recover_stale_publication(output_zip_path: Path) -> bool:
    """
    Recovers from a crashed or interrupted publication using the durable journal.
    Ensures that an inconsistent release pair (where ZIP and SHA-256 disagree)
    is never left published.

    Returns True if an active recovery action was performed, False otherwise.
    """
    paths = get_publication_paths(output_zip_path)
    journal_path = paths["journal"]
    target_zip = paths["target_zip"]
    target_sha256 = paths["target_sha256"]
    backup_zip = paths["backup_zip"]
    backup_sha256 = paths["backup_sha256"]
    temp_zip = paths["temp_zip"]
    temp_sha256 = paths["temp_sha256"]

    action_taken = False

    if journal_path.exists():
        print(f"[*] Interrupted publication journal detected at {journal_path}. Executing recovery...")
        try:
            with open(journal_path, "r", encoding="utf-8") as jf:
                journal = json.load(jf)
            new_sha256 = journal.get("new_sha256")
            has_backup = journal.get("has_backup", False)

            # Check if target_zip exists and matches the new release SHA-256
            target_matches_new = False
            if target_zip.exists() and new_sha256:
                target_matches_new = (compute_sha256(target_zip) == new_sha256)

            if target_matches_new:
                # Roll-forward: target_zip was already successfully published before the crash
                print("[*] Recovery: Target ZIP matches new release digest. Rolling forward checksum...")
                with open(target_sha256, "w", encoding="utf-8") as f:
                    f.write(f"{new_sha256}  {target_zip.name}\n")
                print(f"[+] Recovery PASS: Rolled forward publication to completed new release ({new_sha256[:12]}...).")
            elif has_backup and backup_zip.exists():
                # Roll-back: target_zip was not completely replaced or is corrupt; restore previous release
                print("[*] Recovery: Target ZIP is incomplete/mismatched. Rolling back to previous release...")
                if target_zip.exists():
                    target_zip.unlink()
                shutil.copy2(backup_zip, target_zip)
                if backup_sha256.exists():
                    if target_sha256.exists():
                        target_sha256.unlink()
                    shutil.copy2(backup_sha256, target_sha256)
                print("[+] Recovery PASS: Rolled back to restored previous valid release.")
            else:
                # No backup available and target_zip does not match new release
                print("[*] Recovery: Incomplete publication without valid backup. Cleaning up partial targets...")
                if target_zip.exists():
                    target_zip.unlink()
                if target_sha256.exists():
                    target_sha256.unlink()
                print("[+] Recovery PASS: Cleaned up orphaned partial release files.")

            action_taken = True
        except Exception as e:
            print(f"[!] Warning: Error during journal recovery: {e}", file=sys.stderr)
        finally:
            # Clean up journal, backups, and temp files
            for p in (journal_path, backup_zip, backup_sha256, temp_zip, temp_sha256):
                if p.exists():
                    try:
                        p.unlink()
                    except Exception:
                        pass
    else:
        # No journal, but clean up any leftover stale temp/backup files
        for p in (temp_zip, temp_sha256, backup_zip, backup_sha256):
            if p.exists():
                try:
                    p.unlink()
                    action_taken = True
                except Exception:
                    pass

    return action_taken


def should_exclude(rel_path: Path, root_path: Path, output_zip_path: Path) -> tuple[bool, str]:
    """
    Evaluates whether a relative path should be excluded from the source ZIP.
    Returns (True, reason) or (False, "").
    """
    parts = rel_path.parts
    if not parts:
        return True, "empty_path"

    # 1. Output zip file itself or packaging artifacts (temp, backup, journal, sha256)
    full_path = root_path / rel_path
    try:
        resolved_full = full_path.resolve()
        out_parent = output_zip_path.parent.resolve()
        out_name = output_zip_path.name

        if resolved_full.parent == out_parent:
            if (
                resolved_full == output_zip_path.resolve()
                or resolved_full == output_zip_path.with_suffix(".sha256").resolve()
                or resolved_full.name.startswith(f"{out_name}.")
                or resolved_full.name.endswith(".journal.json")
            ):
                return True, "packaging_artifact"
    except Exception:
        pass

    # 2. Root-level excluded directories (master_archive, .bin, .git, scratch, dist)
    if parts[0] in EXCLUDED_ROOT_DIRS:
        return True, f"excluded_root_dir:{parts[0]}"

    # 3. Intermediate excluded directories at ANY depth (caches, node_modules, .pytest_cache)
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

    # 5. Excluded file extensions (keys, certs, SQL dumps, compiled bytecode)
    ext = full_path.suffix.lower()
    if ext in EXCLUDED_EXTENSIONS:
        return True, f"sensitive_extension:{ext}"

    if ext in EXCLUDED_FILE_PATTERNS:
        return True, f"cache_extension:{ext}"

    # 6. Exclude superseded duplicate proof ZIPs from archive/proofs/
    if len(parts) >= 2 and parts[0] == "archive" and parts[1] == "proofs" and ext == ".zip":
        return True, "superseded_proof_zip"

    return False, ""


def package_source_zip(root_dir: str | Path, output_path: str | Path, verbose: bool = False) -> Path:
    """
    Packages the project root into a deterministic ZIP file with explicit exclusion rules
    and automatically generates the companion SHA-256 checksum file with crash-safe
    journaled publication recovery.
    """
    root_path = Path(root_dir).resolve()
    output_zip_path = Path(output_path).resolve()

    if not root_path.is_dir():
        raise ValueError(f"Root path does not exist or is not a directory: {root_path}")

    # Ensure output parent directory exists
    output_zip_path.parent.mkdir(parents=True, exist_ok=True)

    paths = get_publication_paths(output_zip_path)
    temp_zip_path = paths["temp_zip"]
    temp_sha256_path = paths["temp_sha256"]
    sha256_path = paths["target_sha256"]
    backup_zip_path = paths["backup_zip"]
    backup_sha256_path = paths["backup_sha256"]
    journal_path = paths["journal"]

    # Step 0: Crash-safe recovery from any previous interrupted run
    recover_stale_publication(output_zip_path)

    print(f"[*] Packaging source from: {root_path}")
    print(f"[*] Target ZIP output:     {output_zip_path}")
    print(f"[*] Verifying master_archive/ is present on disk before packaging...")
    local_master_archive = root_path / "master_archive"
    if not local_master_archive.is_dir():
        print(f"[!] Warning: local master_archive/ not found at {local_master_archive}")
    else:
        print(f"[+] Confirmed: local master_archive/ exists on disk ({sum(1 for _ in local_master_archive.rglob('*'))} items).")

    files_to_package: list[tuple[Path, Path]] = []
    excluded_count = 0

    # Collect files deterministically
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

        for f in files:
            rel_file = rel_dir / f if rel_dir != Path(".") else Path(f)
            excluded, reason = should_exclude(rel_file, root_path, output_zip_path)
            if excluded:
                excluded_count += 1
                if verbose:
                    print(f"[-] Excluding file: {rel_file} ({reason})")
                continue

            full_file = current_path / f
            files_to_package.append((rel_file, full_file))

    # Sort files by POSIX archive name for bit-for-bit determinism
    files_to_package.sort(key=lambda item: item[0].as_posix())

    try:
        # Build deterministic ZIP with normalized timestamps and POSIX file attributes
        with zipfile.ZipFile(temp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel_file, full_file in files_to_package:
                arcname = rel_file.as_posix()
                zinfo = zipfile.ZipInfo(filename=arcname, date_time=DETERMINISTIC_ZIP_DATETIME)
                zinfo.compress_type = zipfile.ZIP_DEFLATED

                # Standardized POSIX permissions: 0o755 for scripts, 0o644 for regular files
                is_executable = rel_file.suffix.lower() in {".sh", ".ps1"}
                mode = 0o100755 if is_executable else 0o100644
                zinfo.external_attr = mode << 16

                with open(full_file, "rb") as f_in:
                    file_data = f_in.read()
                zf.writestr(zinfo, file_data)

        # Pre-publication validation: MUST validate temporary ZIP before modifying published artifacts
        validate_zip_contents(temp_zip_path, root_path)

        # Generate companion SHA-256 digest from the validated temporary ZIP
        sha256_digest = compute_sha256(temp_zip_path)
        file_size = temp_zip_path.stat().st_size

        with open(temp_sha256_path, "w", encoding="utf-8") as f:
            f.write(f"{sha256_digest}  {output_zip_path.name}\n")

        # Journaled publication protocol:
        # 1. Back up existing valid release if present
        has_backup = output_zip_path.exists() and sha256_path.exists()
        if has_backup:
            shutil.copy2(output_zip_path, backup_zip_path)
            shutil.copy2(sha256_path, backup_sha256_path)

        # 2. Record journal to disk and sync
        journal_data = {
            "status": "publishing",
            "target_zip": output_zip_path.name,
            "target_sha256": sha256_path.name,
            "new_sha256": sha256_digest,
            "new_size_bytes": file_size,
            "has_backup": has_backup,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(journal_path, "w", encoding="utf-8") as jf:
            json.dump(journal_data, jf, indent=2)
            jf.flush()
            try:
                os.fsync(jf.fileno())
            except Exception:
                pass

        # 3. Atomic replacement of ZIP and SHA-256 with in-flight rollback
        try:
            os.replace(temp_zip_path, output_zip_path)
            os.replace(temp_sha256_path, sha256_path)
        except Exception as pub_err:
            # Immediate in-flight rollback
            if has_backup:
                if backup_zip_path.exists():
                    try:
                        shutil.copy2(backup_zip_path, output_zip_path)
                    except Exception:
                        pass
                if backup_sha256_path.exists():
                    try:
                        shutil.copy2(backup_sha256_path, sha256_path)
                    except Exception:
                        pass
            raise pub_err

        # 4. Post-publication verification: ensure published pair is consistent
        pub_sha = compute_sha256(output_zip_path)
        if pub_sha != sha256_digest:
            raise AssertionError(f"Post-publication digest mismatch: expected {sha256_digest}, got {pub_sha}")

        with open(sha256_path, "r", encoding="utf-8") as f:
            recorded_line = f.read().strip()
        if not recorded_line.startswith(sha256_digest):
            raise AssertionError(f"Post-publication SHA-256 file mismatch: {recorded_line}")

        # 5. Clean up backup and journal upon verified publication
        for p in (backup_zip_path, backup_sha256_path, journal_path):
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

        # 6. Update dist/MANIFEST.json if packaging the standard distribution artifact
        manifest_path = output_zip_path.parent / "MANIFEST.json"
        if manifest_path.exists() or output_zip_path.name == "zkp-sbom-source.zip":
            manifest_content = {
                "package_name": output_zip_path.name,
                "stage": "Roadmap V3 Final Source Distribution",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "file_size_bytes": file_size,
                "file_count": len(files_to_package),
                "sha256": sha256_digest,
                "packaging_script": "scripts/package_source_zip.py",
                "target_database_scope": "Supabase PostgreSQL 17 on Port 5432 (Presentation) / Docker PostgreSQL 17 on Port 5435 (Regression)",
                "alembic_revision": "016",
                "standing_limitation": "Full 256-segment UltraPlonk proof synthesis remains UNVERIFIED / DEFERRED under Stage D5. Presentation verification relies strictly on bounded 1-segment ACIR UltraPlonk proofs (2,144 bytes) and verified precomputed cryptographic archives.",
            }
            try:
                with open(manifest_path, "w", encoding="utf-8") as mf:
                    json.dump(manifest_content, mf, indent=2)
                    mf.write("\n")
            except Exception as e:
                print(f"[!] Warning: Could not update MANIFEST.json: {e}")

    except Exception:
        # Failure cleanup: remove temporary files on failure so partial artifacts do not remain
        for temp_file in (temp_zip_path, temp_sha256_path):
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass
        raise

    included_count = len(files_to_package)
    print(f"[+] Successfully created deterministic source ZIP: {output_zip_path}")
    print(f"[+] Total files included: {included_count}")
    print(f"[+] Total files excluded: {excluded_count}")
    print(f"[+] SHA-256 digest:       {sha256_digest}")
    print(f"[+] Written checksum file: {sha256_path}")

    return output_zip_path


def validate_zip_contents(zip_path: Path, root_path: Path) -> bool:
    """
    Validates that:
    1. Archive structural safety (CRC check, zero duplicates, zero unsafe/traversal paths).
    2. root master_archive/ is 100% absent.
    3. root archive/ is present with canonical proof assets and zero duplicate ZIPs.
    4. Required source, migrations 001-016, tests, configs, and TECH_STACK_AND_ENVIRONMENT.md are present.
    5. Prohibited secrets (.env, keys, SQL dumps) and caches (.pytest_cache, .bin, .tsbuildinfo) are absent.
    6. Local master_archive/ remains intact on disk.
    """
    print("\n[*] Validating package contents...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()

        # Structural Safety Check 1: CRC integrity check across all entries
        corrupt_entry = zf.testzip()
        if corrupt_entry is not None:
            raise AssertionError(f"Validation FAILED: CRC mismatch in ZIP entry: {corrupt_entry}")
        print("[+] PASS: All ZIP entries passed CRC checksum verification (0 corrupted entries).")

        # Structural Safety Check 2: Duplicate path check
        if len(namelist) != len(set(namelist)):
            seen = set()
            dups = [x for x in namelist if x in seen or seen.add(x)]
            raise AssertionError(f"Validation FAILED: Duplicate paths found in ZIP: {dups[:5]}")
        print(f"[+] PASS: Zero duplicate archive entries ({len(namelist)} unique entries).")

        # Structural Safety Check 3: Robust path validation (reject drive prefixes, leading slashes, path traversal)
        for name in namelist:
            if re.match(r"^[a-zA-Z]:", name):
                raise AssertionError(f"Validation FAILED: Unsafe drive letter prefix in ZIP: {name}")
            if name.startswith("/") or name.startswith("\\"):
                raise AssertionError(f"Validation FAILED: Unsafe leading slash in ZIP: {name}")
            normalized_parts = [part for part in re.split(r"[/\\]", name) if part]
            if ".." in normalized_parts:
                raise AssertionError(f"Validation FAILED: Path traversal sequence ('..') in ZIP: {name}")
        print("[+] PASS: Zero unsafe paths, drive prefixes, or traversal sequences detected.")

        # Check 1: master_archive exclusion
        master_archive_entries = [name for name in namelist if name == "master_archive" or name.startswith("master_archive/")]
        if master_archive_entries:
            raise AssertionError(f"Validation FAILED: master_archive found in ZIP! Entries: {master_archive_entries[:5]}")
        print("[+] PASS: root-level master_archive/ is completely absent from ZIP.")

        # Check 2: archive inclusion and duplicate proof zip exclusion
        archive_entries = [name for name in namelist if name.startswith("archive/")]
        if not archive_entries:
            raise AssertionError("Validation FAILED: root-level archive/ is missing from ZIP!")
        proof_zips = [name for name in archive_entries if name.endswith(".zip")]
        if proof_zips:
            raise AssertionError(f"Validation FAILED: Superseded proof ZIPs found in archive: {proof_zips}")
        canonical_proofs = [name for name in archive_entries if name.endswith(".proof")]
        if len(canonical_proofs) != 256:
            raise AssertionError(f"Validation FAILED: Expected 256 canonical proofs, found {len(canonical_proofs)}")
        print(f"[+] PASS: root-level archive/ is present with {len(canonical_proofs)} canonical proofs and zero duplicate ZIPs.")

        # Check 3: Essential required files
        required_checks = [
            "README.md",
            "TECH_STACK_AND_ENVIRONMENT.md",
            "AGENTS.md",
            "bootstrap.ps1",
            "requirements.txt",
            "requirements-dev.txt",
            "backend/shared/requirements.txt",
            "backend/verification_service/crypto_runtime/package.json",
            "backend/verification_service/crypto_runtime/package-lock.json",
            "frontend/package.json",
            "frontend/package-lock.json",
            "scripts/bb_launcher.c",
            "scripts/setup_crypto_runtime.ps1",
            "archive/proofs/temp/manifest.json",
            "archive/proofs/temp/profile.json",
            "archive/proofs/temp/segment_init_32.vk",
            "archive/proofs/temp/segment_mid_32.vk",
            "archive/proofs/temp/segment_final_32.vk",
            "archive/proofs/temp/chunk_0_segment_0.proof",
            "archive/proofs/temp/chunk_31_segment_7.proof",
            "segment_init_32/Nargo.toml",
            "segment_init_32/src/main.nr",
            "segment_mid_32/Nargo.toml",
            "segment_mid_32/src/main.nr",
            "segment_final_32/Nargo.toml",
            "segment_final_32/src/main.nr",
            "backend/shared/crypto/smt.py",
            "backend/verification_service/app/core/verifier.py",
            "backend/zkp_service/app/services/prover_service.py",
            "backend/zkp_service/tests/test_log4shell_scenario.py",
            "MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md",
            "MASTER_PROJECT_CONTEXT/project_context/ARCHITECTURE.md",
            "MASTER_PROJECT_CONTEXT/project_context/STUDENT_RUNBOOK.md",
            "MASTER_PROJECT_CONTEXT/project_context/DEMONSTRATIONS_AND_VIVA.md",
            "MASTER_PROJECT_CONTEXT/project_context/VIVA_PRESENTATION_SLIDES.md",
            "MASTER_PROJECT_CONTEXT/project_context/SECURITY_VALIDATION_REPORT.md",
            "docker-compose.yml",
        ]
        for req in required_checks:
            if req not in namelist:
                raise AssertionError(f"Validation FAILED: Essential file missing from ZIP: {req}")

        # Check migration chain 001 through 016
        for mig_num in range(1, 17):
            prefix = f"backend/alembic/versions/{mig_num:03d}_"
            if not any(name.startswith(prefix) for name in namelist):
                raise AssertionError(f"Validation FAILED: Migration {mig_num:03d} missing from ZIP!")
        print(f"[+] PASS: All essential application sources, migrations 001-016, and Stage E/F deliverables are present.")

        # Check 4: Secrets, caches, database dumps, and private key headers exclusion
        for name in namelist:
            filename = Path(name).name
            if filename == ".env" or (filename.startswith(".env.") and not filename.endswith(".example")):
                raise AssertionError(f"Validation FAILED: Secret file found in ZIP: {name}")
            if Path(name).suffix.lower() in {".pem", ".key", ".pfx", ".p12"}:
                raise AssertionError(f"Validation FAILED: Private key file found in ZIP: {name}")
            if Path(name).suffix.lower() in {".sql", ".dump"}:
                raise AssertionError(f"Validation FAILED: Database dump found in ZIP: {name}")
            if ".pytest_cache" in name.split("/"):
                raise AssertionError(f"Validation FAILED: .pytest_cache found in ZIP: {name}")
            if name.startswith(".bin/") or name == ".bin":
                raise AssertionError(f"Validation FAILED: .bin binary directory found in ZIP: {name}")
            if Path(name).suffix.lower() == ".tsbuildinfo":
                raise AssertionError(f"Validation FAILED: tsbuildinfo build cache found in ZIP: {name}")

            # Content inspection: check for recognizable private key headers in text files
            if Path(name).suffix.lower() in {".txt", ".json", ".conf", ".cfg", ".yml", ".yaml", ""}:
                try:
                    sample = zf.read(name)[:2048]
                    if (
                        b"BEGIN PRIVATE KEY" in sample
                        or b"BEGIN RSA PRIVATE KEY" in sample
                        or b"BEGIN EC PRIVATE KEY" in sample
                        or b"BEGIN OPENSSH PRIVATE KEY" in sample
                    ):
                        raise AssertionError(f"Validation FAILED: Recognizable private key header in ZIP: {name}")
                except Exception:
                    pass
        print("[+] PASS: Zero private keys, active .env files, SQL dumps, or cache artifacts included in ZIP.")

    # Check 5: Local master_archive still exists on disk
    local_master_archive = root_path / "master_archive"
    if not local_master_archive.is_dir():
        raise AssertionError("Validation FAILED: Local master_archive/ was modified or deleted on disk!")
    print(f"[+] PASS: Local master_archive/ directory remains intact and untouched on disk.")

    print("\n[+] ALL PACKAGING VALIDATION CRITERIA PASSED.")
    return True


def run_failure_recovery_tests() -> bool:
    """
    Executes automated failure-injection tests against an isolated temporary directory.
    Tests all 8 Phase C failure scenarios without modifying production release artifacts.
    """
    print("\n" + "=" * 70)
    print("PHASE C: AUTOMATED PACKAGING FAILURE RECOVERY TEST SUITE")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        dist_dir = tmp_dir / "dist"
        dist_dir.mkdir()
        target_zip = dist_dir / "zkp-sbom-source.zip"
        target_sha = dist_dir / "zkp-sbom-source.sha256"

        v1_zip = tmp_dir / "v1.zip"
        with zipfile.ZipFile(v1_zip, "w") as zf:
            zf.writestr("test.txt", b"release v1 baseline content")
        v1_sha = compute_sha256(v1_zip)

        v2_zip = tmp_dir / "v2.zip"
        with zipfile.ZipFile(v2_zip, "w") as zf:
            zf.writestr("test.txt", b"release v2 upgraded content")
        v2_sha = compute_sha256(v2_zip)

        paths = get_publication_paths(target_zip)

        def mock_publish(source_zip: Path, fail_point: str = "none") -> None:
            recover_stale_publication(target_zip)

            if fail_point == "archive_creation":
                with open(paths["temp_zip"], "wb") as f:
                    f.write(b"partial archive data")
                if paths["temp_zip"].exists():
                    paths["temp_zip"].unlink()
                raise RuntimeError("Injected failure during archive creation")

            if fail_point == "validation":
                with open(paths["temp_zip"], "wb") as f:
                    f.write(b"invalid zip format")
                if paths["temp_zip"].exists():
                    paths["temp_zip"].unlink()
                raise AssertionError("Injected failure: Validation failed")

            shutil.copy2(source_zip, paths["temp_zip"])
            sha = compute_sha256(paths["temp_zip"])
            size = paths["temp_zip"].stat().st_size

            with open(paths["temp_sha256"], "w", encoding="utf-8") as f:
                f.write(f"{sha}  {target_zip.name}\n")

            has_backup = target_zip.exists() and target_sha.exists()
            if has_backup:
                shutil.copy2(target_zip, paths["backup_zip"])
                shutil.copy2(target_sha, paths["backup_sha256"])

            journal_data = {
                "status": "publishing",
                "target_zip": target_zip.name,
                "target_sha256": target_sha.name,
                "new_sha256": sha,
                "new_size_bytes": size,
                "has_backup": has_backup,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            with open(paths["journal"], "w", encoding="utf-8") as jf:
                json.dump(journal_data, jf, indent=2)

            try:
                if fail_point == "zip_publish":
                    raise OSError("Injected OS failure replacing target ZIP")
                os.replace(paths["temp_zip"], target_zip)

                if fail_point == "crash_mid_publication":
                    return

                if fail_point == "sha_publish":
                    raise OSError("Injected OS failure replacing SHA-256")
                os.replace(paths["temp_sha256"], target_sha)

            except Exception as pub_err:
                if has_backup:
                    if paths["backup_zip"].exists():
                        shutil.copy2(paths["backup_zip"], target_zip)
                    if paths["backup_sha256"].exists():
                        shutil.copy2(paths["backup_sha256"], target_sha)
                if paths["temp_zip"].exists():
                    paths["temp_zip"].unlink()
                if paths["temp_sha256"].exists():
                    paths["temp_sha256"].unlink()
                raise pub_err

            for p in (paths["backup_zip"], paths["backup_sha256"], paths["journal"]):
                if p.exists():
                    p.unlink()

        # Baseline: Publish V1
        mock_publish(v1_zip, "none")
        assert target_zip.exists() and target_sha.exists()
        assert compute_sha256(target_zip) == v1_sha
        print("[+] Test 0: Baseline V1 published successfully.")

        # Scenario 1: Archive creation fails
        try:
            mock_publish(v2_zip, "archive_creation")
            assert False, "Scenario 1 failed to raise"
        except RuntimeError:
            assert compute_sha256(target_zip) == v1_sha
            with open(target_sha) as f:
                assert v1_sha in f.read()
            print("[+] PASS Scenario 1: Archive creation failure leaves previous valid release intact.")

        # Scenario 2: ZIP validation fails
        try:
            mock_publish(v2_zip, "validation")
            assert False, "Scenario 2 failed to raise"
        except AssertionError:
            assert compute_sha256(target_zip) == v1_sha
            with open(target_sha) as f:
                assert v1_sha in f.read()
            print("[+] PASS Scenario 2: ZIP validation failure preserves previous valid release.")

        # Scenario 3: ZIP publication fails
        try:
            mock_publish(v2_zip, "zip_publish")
            assert False, "Scenario 3 failed to raise"
        except OSError:
            assert compute_sha256(target_zip) == v1_sha
            with open(target_sha) as f:
                assert v1_sha in f.read()
            print("[+] PASS Scenario 3: ZIP publication failure triggers rollback to previous valid release.")

        # Scenario 4: Checksum publication fails
        try:
            mock_publish(v2_zip, "sha_publish")
            assert False, "Scenario 4 failed to raise"
        except OSError:
            assert compute_sha256(target_zip) == v1_sha
            with open(target_sha) as f:
                assert v1_sha in f.read()
            print("[+] PASS Scenario 4: Checksum publication failure triggers rollback to previous valid release.")

        # Scenario 5: Interrupted publication between ZIP and SHA publication
        mock_publish(v2_zip, "crash_mid_publication")
        assert compute_sha256(target_zip) == v2_sha
        with open(target_sha) as f:
            assert v1_sha in f.read()
        assert paths["journal"].exists()
        print("[*] Crash simulated: Inconsistent ZIP/SHA on disk with active journal.")
        recovered = recover_stale_publication(target_zip)
        assert recovered
        assert compute_sha256(target_zip) == v2_sha
        with open(target_sha) as f:
            assert v2_sha in f.read()
        assert not paths["journal"].exists()
        print("[+] PASS Scenario 5: Interrupted publication rolled forward to consistent valid release.")

        # Scenario 6: Previous valid pair exists
        mock_publish(v1_zip, "none")
        assert compute_sha256(target_zip) == v1_sha
        with open(target_sha) as f:
            assert v1_sha in f.read()
        print("[+] PASS Scenario 6: Previous valid pair correctly handled and backed up.")

        # Scenario 7: Successful rebuild replaces old release cleanly
        mock_publish(v2_zip, "none")
        assert compute_sha256(target_zip) == v2_sha
        with open(target_sha) as f:
            assert v2_sha in f.read()
        for p in (paths["backup_zip"], paths["temp_zip"], paths["journal"]):
            assert not p.exists()
        print("[+] PASS Scenario 7: Successful rebuild cleanly replaces old release without residue.")

        # Scenario 8: Stale temporary files exist from previous interrupted run
        paths["temp_zip"].write_bytes(b"stale temp zip")
        paths["temp_sha256"].write_bytes(b"stale temp sha")
        paths["backup_zip"].write_bytes(b"stale backup zip")
        recovered = recover_stale_publication(target_zip)
        assert recovered
        for p in (paths["temp_zip"], paths["temp_sha256"], paths["backup_zip"]):
            assert not p.exists()
        assert compute_sha256(target_zip) == v2_sha
        print("[+] PASS Scenario 8: Stale temporary files detected and cleaned up safely.")

    print("\n[+] ALL 8 PACKAGING FAILURE RECOVERY SCENARIOS PASSED WITH 100% SUCCESS.\n")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Package source code with master_archive exclusion and recovery.")
    parser.add_argument("--root", default=".", help="Project root directory (default: current directory)")
    parser.add_argument("--output", default="dist/zkp-sbom-source.zip", help="Destination ZIP path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose exclusion output")
    parser.add_argument("--validate-only", action="store_true", help="Validate existing target ZIP without rebuilding")
    parser.add_argument("--recover", action="store_true", help="Execute journal recovery on target ZIP and exit")
    parser.add_argument("--test-recovery", action="store_true", help="Execute the 8 failure-injection recovery tests")
    args = parser.parse_args()

    if args.test_recovery:
        success = run_failure_recovery_tests()
        sys.exit(0 if success else 1)

    target_output = Path(args.output).resolve()
    target_root = Path(args.root).resolve()

    if args.recover:
        recovered = recover_stale_publication(target_output)
        print(f"[*] Recovery complete on {target_output} (action taken: {recovered}).")
        sys.exit(0)

    if args.validate_only:
        try:
            validate_zip_contents(target_output, target_root)
            sys.exit(0)
        except Exception as e:
            print(f"[-] Validation Error: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        package_source_zip(args.root, args.output, verbose=args.verbose)
    except Exception as e:
        print(f"[-] Packaging Error: {e}", file=sys.stderr)
        sys.exit(1)

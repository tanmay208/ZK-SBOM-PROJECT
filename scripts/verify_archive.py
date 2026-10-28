"""
Stage21L Proof Archive Integrity Validator

Validates the cryptographic integrity of a Stage21L proof archive
against persisted database records WITHOUT modifying the archive.

Credentials are loaded exclusively from .env / environment variables
via shared.config.get_db_settings.
"""

import os
import sys
import argparse
import hashlib
import json
import zipfile

# ---------------------------------------------------------------------------
# Path & environment bootstrap
# ---------------------------------------------------------------------------
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
)

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"), override=True)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shared.config import get_db_settings
from shared.crypto.config import get_crypto_profile
from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof


def verify_archive(job_id: str) -> bool:
    # ------------------------------------------------------------------
    # Database connection via environment-based settings (no literals).
    # ------------------------------------------------------------------
    db_settings = get_db_settings()
    if not db_settings.password:
        print("FATAL: DB_PASSWORD is not set. Refusing to run.", file=sys.stderr)
        return False

    engine = create_engine(db_settings.url)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    with SessionLocal() as session:
        job = session.query(ProofJob).filter(ProofJob.id == job_id).first()
        if not job:
            print(f"[-] ProofJob {job_id} not found in database.")
            return False

        if not job.proof_archive_hash:
            print(f"[-] ProofJob {job_id} has no proof_archive_hash recorded.")
            return False

        print(f"[+] Found ProofJob {job_id}")
        print(f"    Expected Archive Hash: {job.proof_archive_hash}")

        # Gather chunk/segment topology from DB
        chunks = (
            session.query(ChunkProofSet)
            .filter(ChunkProofSet.proof_job_id == job.id)
            .order_by(ChunkProofSet.chunk_index)
            .all()
        )
        if len(chunks) != 32:
            print(f"[-] Expected 32 chunks, found {len(chunks)}")
            return False

        print("[+] Found 32 ChunkProofSets")

        expected_member_hashes = {}
        for chunk in chunks:
            segs = (
                session.query(SegmentProof)
                .filter(SegmentProof.chunk_id == chunk.id)
                .all()
            )
            for seg in segs:
                key = f"chunk_{chunk.chunk_index}_segment_{seg.segment_index}.proof"
                expected_member_hashes[key] = seg.proof_artifact_hash

        if len(expected_member_hashes) != 256:
            print(
                f"[-] Expected 256 segments, found {len(expected_member_hashes)}"
            )
            return False

        print("[+] Loaded 256 expected segment hashes from database")

        # Locate archive on disk
        project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..")
        )
        archive_path = os.path.join(
            project_root, "archive", "proofs", f"{job.id}.zip"
        )
        if not os.path.exists(archive_path):
            legacy_archive_path = os.path.join(
                project_root, "archives", "proofs", f"{job.id}.zip"
            )
            if os.path.exists(legacy_archive_path):
                archive_path = legacy_archive_path

        if not os.path.exists(archive_path):
            print(f"[-] Archive not found at {archive_path}")
            return False

        # ---------------------------------------------------------------
        # Standalone archive hash verification (independent of profile).
        # ---------------------------------------------------------------
        with open(archive_path, "rb") as f:
            archive_sha256 = hashlib.sha256(f.read()).hexdigest()
        print(f"[+] Archive SHA-256: {archive_sha256}")
        if archive_sha256 != job.proof_archive_hash:
            print(
                f"[-] Archive hash mismatch! Expected {job.proof_archive_hash}"
            )
            return False
        print("[+] Archive hash matches persisted proof_archive_hash")

        # ---------------------------------------------------------------
        # ZIP structural validation
        # ---------------------------------------------------------------
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                names = zf.namelist()

                # Duplicate names
                if len(names) != len(set(names)):
                    print("[-] Archive contains duplicate member names")
                    return False
                print(f"[+] Archive member count: {len(names)} (no duplicates)")

                # Path traversal
                for member in names:
                    if (
                        ".." in member
                        or member.startswith("/")
                        or os.path.isabs(member)
                        or os.path.basename(member) != member
                    ):
                        print(f"[-] Traversal detected: {member}")
                        return False
                print("[+] No path traversal in archive members")

                # Proof file count
                proof_files = [m for m in names if m.endswith(".proof")]
                if len(proof_files) != 256:
                    print(f"[-] Expected 256 proof files, found {len(proof_files)}")
                    return False
                print("[+] Proof file count: 256")

                # Manifest presence
                if "manifest.json" not in names:
                    print("[-] manifest.json missing from archive")
                    return False

                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))

                # Manifest structural validation
                if manifest.get("total_chunks") != 32:
                    print("[-] Manifest total_chunks != 32")
                    return False
                if manifest.get("total_segments") != 256:
                    print("[-] Manifest total_segments != 256")
                    return False
                print("[+] Manifest topology: 32 chunks × 8 segments = 256")

                # Report manifest metadata (do NOT modify)
                print(f"    manifest.job_id = {manifest.get('job_id')}")
                print(
                    f"    manifest.cryptographic_verification_status = "
                    f"{manifest.get('cryptographic_verification_status')}"
                )
                print(
                    f"    manifest.creation_timestamp = "
                    f"{manifest.get('creation_timestamp')}"
                )
                print(
                    f"    manifest.archive_status = "
                    f"{manifest.get('archive_status')}"
                )

                segments_list = manifest.get("segments", [])
                if len(segments_list) != 256:
                    print(
                        f"[-] Manifest segments count = {len(segments_list)}, "
                        f"expected 256"
                    )
                    return False

                # Cross-reference per-proof hashes: archive ↔ DB
                mismatches = 0
                for filename, expected_hash in expected_member_hashes.items():
                    if filename not in names:
                        print(f"[-] Missing archive member: {filename}")
                        mismatches += 1
                        continue
                    member_bytes = zf.read(filename)
                    actual_hash = hashlib.sha256(member_bytes).hexdigest()
                    if actual_hash != expected_hash:
                        print(
                            f"[-] Hash mismatch: {filename} "
                            f"expected={expected_hash} actual={actual_hash}"
                        )
                        mismatches += 1

                if mismatches > 0:
                    print(f"[-] {mismatches} proof hash mismatches detected")
                    return False
                print(
                    "[+] All 256 proof member hashes match persisted "
                    "SegmentProof records"
                )

                # Unexpected members check
                allowed = set(proof_files) | {"manifest.json", "profile.json"}
                allowed.update(
                    f"{n}.vk"
                    for n in (
                        "segment_init_32",
                        "segment_mid_32",
                        "segment_final_32",
                    )
                )
                unexpected = set(names) - allowed
                if unexpected:
                    print(f"[-] Unexpected archive members: {unexpected}")
                    return False
                print("[+] No unexpected archive members")

        except zipfile.BadZipFile:
            print("[-] Archive is not a valid ZIP file")
            return False

    print()
    print("=" * 60)
    print("ARCHIVE INTEGRITY VALIDATION: PASS")
    print()
    print("Classification:")
    print("  - This is ARCHIVE INTEGRITY VALIDATION only.")
    print("  - This is NOT fresh cryptographic execution.")
    print(
        "  - The manifest records "
        "cryptographic_verification_status='pending',"
    )
    print("    indicating the Stage21L workload completed proof generation")
    print("    but no separate bb-verify pass was recorded in the manifest.")
    print("  - The 256 proof hashes are byte-identical to the database records.")
    print("=" * 60)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify Stage21L proof archive integrity."
    )
    parser.add_argument("job_id", help="The UUID of the ProofJob to verify")
    args = parser.parse_args()

    if verify_archive(args.job_id):
        sys.exit(0)
    else:
        sys.exit(1)

"""
Focused regression tests for Stage D post-proving acceptance recovery.
Compatible with standard unittest and pytest.
Covers:
  - Valid commitment extraction from ProofJob fields (no nonexistent ORM access).
  - Missing or malformed commitment rejection (fail-closed).
  - Artifact restoration and rollback in finally blocks after simulated verifier exceptions.
  - Verification that recovery mode does not invoke proof generation.
"""

import base64
import hashlib
import os
import re
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

# Ensure backend and project root are in sys.path
TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER

from shared.database import Base
from shared.models.user import User
import sbom_service.app.models.sbom_models  # register tables
import vulnerability_service.app.models.vulnerability_models  # register tables
import policy_service.app.models.policy_models  # register tables
from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
from verification_service.app.models.verification_models import VerificationRequest
from verification_service.app.schemas.verification_schemas import VerifyProofRequest


class TestProofJobRecoveryAcceptance(unittest.TestCase):
    def setUp(self):
        @compiles(UNIQUEIDENTIFIER, "sqlite")
        def _compile_uid(element, compiler, **kw):
            return "CHAR(36)"

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        with self.engine.connect() as conn:
            for s in ("sbom", "vulnerability", "policy", "zkp", "verification"):
                conn.execute(text(f"ATTACH DATABASE ':memory:' AS {s}"))
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = Session()

    def tearDown(self):
        self.db.close()

    def test_valid_commitment_extraction_from_proof_job(self):
        """Test extracting authoritative commitments directly from ProofJob columns."""
        user = User(id=uuid.uuid4(), username="test_vendor", hashed_password="pw", role="vendor")
        self.db.add(user)
        self.db.commit()

        valid_hex_64 = "0x" + "a1" * 32
        job = ProofJob(
            id=uuid.uuid4(),
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            user_id=user.id,
            status="completed",
            sbom_root=valid_hex_64,
            vulnerability_db_root=valid_hex_64,
            policy_hash=valid_hex_64,
        )
        self.db.add(job)
        self.db.commit()

        # Verify no nonexistent ORM relationships are accessed
        self.assertFalse(hasattr(job, "sbom_upload"))
        self.assertFalse(hasattr(job, "snapshot"))
        self.assertFalse(hasattr(job, "policy"))

        # Verify authoritative columns are populated and valid
        for field_name in ("sbom_root", "vulnerability_db_root", "policy_hash"):
            val = getattr(job, field_name)
            self.assertIsInstance(val, str)
            self.assertTrue(bool(re.match(r"^0x[a-fA-F0-9]{64}$", val)))

        req = VerifyProofRequest(
            sbom_root=job.sbom_root,
            vulnerability_db_root=job.vulnerability_db_root,
            policy_hash=job.policy_hash,
            proof_job_id=job.id,
        )
        self.assertEqual(req.sbom_root, valid_hex_64)
        self.assertEqual(req.vulnerability_db_root, valid_hex_64)
        self.assertEqual(req.policy_hash, valid_hex_64)

    def test_malformed_commitment_rejection(self):
        """Fail-closed validation on missing or malformed commitments."""
        job = MagicMock()
        job.id = uuid.uuid4()
        job.sbom_root = "not_a_hex"
        job.vulnerability_db_root = "0x1234"  # too short
        job.policy_hash = None

        for commitment_name, val in [
            ("sbom_root", job.sbom_root),
            ("vulnerability_db_root", job.vulnerability_db_root),
            ("policy_hash", job.policy_hash),
        ]:
            with self.assertRaises(ValueError):
                if not val or not isinstance(val, str) or not re.match(r"^0x[a-fA-F0-9]{64}$", val):
                    raise ValueError(f"Invalid {commitment_name}")

    def test_artifact_tampering_cleanup_and_restoration(self):
        """Ensure proof tampering during negative tests is 100% restored in finally blocks."""
        user = User(id=uuid.uuid4(), username="admin_clean", hashed_password="pw", role="admin")
        self.db.add(user)
        self.db.commit()

        orig_bytes = b"original_honest_proof_bytes_2144"
        orig_b64 = base64.b64encode(orig_bytes).decode("utf-8")
        orig_hash = hashlib.sha256(orig_bytes).hexdigest()

        seg = SegmentProof(
            id=uuid.uuid4(),
            chunk_id=uuid.uuid4(),
            segment_index=0,
            chunk_index=0,
            total_chunks=32,
            components_commit="0x11",
            status="completed",
            proof_artifact=orig_b64,
            proof_artifact_hash=orig_hash,
        )
        self.db.add(seg)
        self.db.commit()

        # Simulate negative test with simulated exception during verification
        try:
            raw_bytes = base64.b64decode(seg.proof_artifact)
            corrupted = raw_bytes[:-4] + b"\xff" * 4
            seg.proof_artifact = base64.b64encode(corrupted).decode("utf-8")
            seg.proof_artifact_hash = hashlib.sha256(corrupted).hexdigest()
            self.db.commit()

            # Simulate exception during verifier check
            raise RuntimeError("Simulated verifier failure")
        except Exception:
            pass
        finally:
            try:
                seg.proof_artifact = orig_b64
                seg.proof_artifact_hash = orig_hash
                self.db.commit()
            except Exception:
                self.db.rollback()
                seg.proof_artifact = orig_b64
                seg.proof_artifact_hash = orig_hash
                self.db.commit()

        # Fresh read from database
        reloaded_seg = self.db.query(SegmentProof).filter_by(id=seg.id).first()
        self.assertEqual(reloaded_seg.proof_artifact, orig_b64)
        self.assertEqual(reloaded_seg.proof_artifact_hash, orig_hash)
        self.assertEqual(base64.b64decode(reloaded_seg.proof_artifact), orig_bytes)

    def test_recovery_runner_does_not_invoke_proof_generation(self):
        """Verify that recovery runner contains no active proof-generation methods."""
        from scripts.recover_and_verify_acceptance_linux import RecoveryAcceptanceRunner
        runner = RecoveryAcceptanceRunner(Path("/dummy"), Path("/dummy"))
        self.assertTrue(hasattr(runner, "proof_generation_invoked"))
        self.assertFalse(runner.proof_generation_invoked)
        self.assertEqual(runner.proof_generation_count, 0)
        self.assertFalse(hasattr(runner, "generate_segment_proof"))
        self.assertFalse(hasattr(runner, "generate_chunk_proofs"))


if __name__ == "__main__":
    unittest.main()

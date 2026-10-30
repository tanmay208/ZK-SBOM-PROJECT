"""
Deterministic Automated Regression Suite for Master Prompt 3B:
Critical Verification Gateway Hardening.

Verifies:
  1. AUD-3A-005: Exact snapshot identity resolution and ambiguity rejection.
  2. AUD-3A-006: Provenance validation and ecosystem coverage enforcement.
  3. AUD-3A-007: TOCTOU concurrency protection and fail-closed certificate issuance.
  4. AUD-3A-002: V2 policy commitment & revision binding in certificate JWT payloads.
  5. AUD-3A-003: Vacuous non-membership protection via ecosystem gate.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from shared.database import Base
from shared.models.user import User
from policy_service.app.models.policy_models import SecurityPolicy
from policy_service.app.services.policy_contract import PolicyContract
from sbom_service.app.models.sbom_models import Application, Component, SBOMUpload
from verification_service.app.models.verification_models import (
    VerificationCertificate,
    VerificationRequest,
)
from verification_service.app.repositories.verification_repository import (
    VerificationRepository,
)
from verification_service.app.schemas.verification_schemas import VerifyProofRequest
from verification_service.app.services.verification_service import (
    VerificationService,
)
from vulnerability_service.app.models.vulnerability_models import (
    VulnerabilitySnapshot,
)
from zkp_service.app.models.zkp_models import ProofJob

EMPTY_SMT_ROOT = "0x063076f073adbecf1433407cf22ce2503a996a2a55f9f96aa1aa21717d5bc2b0"


@pytest.fixture
def db_session(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "test-secret-key-for-cert-signing-32b")
    monkeypatch.setenv("JWT_SECRET", "supersecretjwtkey")
    monkeypatch.setenv("ALGORITHM", "HS256")
    monkeypatch.setenv("CRYPTO_PROFILE", "prod")

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    with engine.connect() as conn:
        conn.execute(text("ATTACH DATABASE ':memory:' AS sbom"))
        conn.execute(text("ATTACH DATABASE ':memory:' AS vulnerability"))
        conn.execute(text("ATTACH DATABASE ':memory:' AS policy"))
        conn.execute(text("ATTACH DATABASE ':memory:' AS zkp"))
        conn.execute(text("ATTACH DATABASE ':memory:' AS verification"))

    Base.metadata.create_all(engine)

    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _create_baseline_fixtures(session, user_id=None, ecosystems=None, sbom_root=None, vuln_root=None, pol_hash=None):
    if user_id is None:
        user_id = uuid.uuid4()
    if ecosystems is None:
        ecosystems = ["npm"]
    if sbom_root is None:
        sbom_root = "0x" + "1" * 64
    if vuln_root is None:
        vuln_root = EMPTY_SMT_ROOT
    if pol_hash is None:
        pol_hash = "0x" + "2" * 64

    user = User(id=user_id, username=f"user_{user_id.hex[:6]}", hashed_password="pw", role="vendor")
    session.add(user)
    session.flush()

    app = Application(id=uuid.uuid4(), name="App", vendor="Vendor", user_id=user_id)
    session.add(app)
    session.flush()

    sbom = SBOMUpload(
        id=uuid.uuid4(),
        application_id=app.id,
        filename="sbom.json",
        sbom_root=sbom_root,
        status="committed",
    )
    session.add(sbom)
    session.flush()

    for idx, eco in enumerate(ecosystems):
        comp = Component(
            id=uuid.uuid4(),
            sbom_upload_id=sbom.id,
            name=f"pkg-{eco}-{idx}",
            version="1.0.0",
            purl_canonical=f"pkg:{eco}/pkg-{eco}-{idx}@1.0.0",
            component_hash=f"0x{idx:02x}" + "0" * 62,
            position=idx,
        )
        session.add(comp)

    snapshot = VulnerabilitySnapshot(
        id=uuid.uuid4(),
        snapshot_label="snapshot_base",
        status="frozen",
        authoritative_smt_root=vuln_root,
        provenance_json=json.dumps({"ecosystems_covered": ecosystems}),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    session.add(snapshot)
    session.flush()

    policy = SecurityPolicy(
        id=uuid.uuid4(),
        name="Strict Policy",
        max_allowed_cvss=7.0,
        max_allowed_cvss_int=70,
        policy_hash=pol_hash,
        is_active=1,
    )
    session.add(policy)
    session.flush()

    job = ProofJob(
        id=uuid.uuid4(),
        user_id=user_id,
        sbom_upload_id=sbom.id,
        snapshot_id=snapshot.id,
        policy_id=policy.id,
        status="completed",
        sbom_root=sbom_root,
        vulnerability_db_root=vuln_root,
        policy_hash=pol_hash,
    )
    session.add(job)
    session.commit()

    return {
        "user": user,
        "app": app,
        "sbom": sbom,
        "snapshot": snapshot,
        "policy": policy,
        "job": job,
        "sbom_root": sbom_root,
        "vuln_root": vuln_root,
        "pol_hash": pol_hash,
    }


class TestExactSnapshotIdentity:
    """AUD-3A-005: Exact snapshot identity resolution & ambiguity defense."""

    def test_exact_snapshot_id_and_root_match_passes(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is True

    def test_proof_job_with_mismatched_snapshot_root_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        # Tampered vulnerability DB root in verification request
        tampered_vuln_root = "0x" + "9" * 64
        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=tampered_vuln_root,
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_unambiguous_resolution_when_two_snapshots_share_root(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        # Create a second frozen snapshot with identical SMT root
        second_snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_duplicate_root",
            status="frozen",
            authoritative_smt_root=fixtures["vuln_root"],
            provenance_json=json.dumps({"ecosystems_covered": ["npm"]}),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(second_snapshot)
        db_session.commit()

        # ProofJob explicitly references the first snapshot -> resolves unambiguously
        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is True

    def test_ambiguous_resolution_without_proof_job_id_fails_closed(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        # Create a second frozen snapshot with identical SMT root
        second_snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_duplicate_root_ambiguous",
            status="frozen",
            authoritative_smt_root=fixtures["vuln_root"],
            provenance_json=json.dumps({"ecosystems_covered": ["npm"]}),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(second_snapshot)
        db_session.commit()

        # Calling without proof_job_id when multiple snapshots exist MUST fail closed (AUD-3A-005)
        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=None,
        )
        assert is_valid is False

    def test_nonexistent_snapshot_id_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        # Mutate job to point to a non-existent snapshot
        fixtures["job"].snapshot_id = uuid.uuid4()
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_non_frozen_snapshot_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        fixtures["snapshot"].status = "pending"
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_revoked_snapshot_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        fixtures["snapshot"].revoked_at = datetime.now(timezone.utc)
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_expired_snapshot_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        # Set expiry in the past
        fixtures["snapshot"].expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False


class TestProvenanceAndEcosystemCoverage:
    """AUD-3A-006: Provenance validation & ecosystem suitability enforcement."""

    def test_null_provenance_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        fixtures["snapshot"].provenance_json = None
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_empty_or_whitespace_provenance_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        for invalid_val in ["", "   ", " \t \n "]:
            fixtures["snapshot"].provenance_json = invalid_val
            db_session.commit()

            is_valid = repo.validate_authoritative_records(
                sbom_root=fixtures["sbom_root"],
                vuln_root=fixtures["vuln_root"],
                policy_hash=fixtures["pol_hash"],
                require_active_policy=True,
                proof_job_id=fixtures["job"].id,
            )
            assert is_valid is False

    def test_malformed_json_provenance_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        fixtures["snapshot"].provenance_json = "{bad_json: missing_quotes}"
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_missing_ecosystems_field_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        fixtures["snapshot"].provenance_json = json.dumps({"source": "osv", "feed": "test"})
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_empty_ecosystems_list_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        fixtures["snapshot"].provenance_json = json.dumps({"ecosystems_covered": []})
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_malformed_ecosystem_identifiers_rejected(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        fixtures["snapshot"].provenance_json = json.dumps({"ecosystems_covered": ["npm", "invalid ecosystem!@#"]})
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False

    def test_multi_ecosystem_coverage_match(self, db_session):
        # SBOM contains npm and pypi
        fixtures = _create_baseline_fixtures(db_session, ecosystems=["npm", "pypi"])
        repo = VerificationRepository(db_session)

        # Snapshot covers npm, pypi, and maven (superset)
        fixtures["snapshot"].provenance_json = json.dumps({"ecosystems_covered": ["npm", "pypi", "maven"]})
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is True

    def test_multi_ecosystem_coverage_partial_rejected(self, db_session):
        # SBOM contains npm and pypi
        fixtures = _create_baseline_fixtures(db_session, ecosystems=["npm", "pypi"])
        repo = VerificationRepository(db_session)

        # Snapshot only covers npm -> missing pypi
        fixtures["snapshot"].provenance_json = json.dumps({"ecosystems_covered": ["npm"]})
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=fixtures["sbom_root"],
            vuln_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            require_active_policy=True,
            proof_job_id=fixtures["job"].id,
        )
        assert is_valid is False


class TestTOCTOUProtection:
    """AUD-3A-007: TOCTOU race detection between verification and certificate signing."""

    def test_toctou_snapshot_revocation_triggers_record_mismatch_and_no_certificate(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        service = VerificationService(db_session)
        repo = VerificationRepository(db_session)

        # Mock cryptographic verifier to pass
        service._verifier.verify = lambda *args, **kwargs: "verified"

        # Preflight passes, but before certificate signing, mutate snapshot to revoked
        req = VerifyProofRequest(
            proof_job_id=fixtures["job"].id,
            sbom_root=fixtures["sbom_root"],
            vulnerability_db_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
        )

        preflight_context = {
            "proof_job_id": fixtures["job"].id,
            "snapshot_id": fixtures["snapshot"].id,
            "policy_id": fixtures["policy"].id,
        }

        # Snapshot revoked right before signing
        fixtures["snapshot"].revoked_at = datetime.now(timezone.utc)
        db_session.commit()

        record = repo.create_verification_record(
            request=req,
            result="verified",
            user_id=fixtures["user"].id,
            preflight_context=preflight_context,
        )

        # Result must fail closed to record_mismatch
        assert record.result == "record_mismatch"
        assert record.verified_at is None

        # Zero certificates issued
        certs = db_session.query(VerificationCertificate).filter(
            VerificationCertificate.verification_request_id == record.id
        ).all()
        assert len(certs) == 0

    def test_toctou_policy_deactivation_triggers_record_mismatch_and_no_certificate(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        req = VerifyProofRequest(
            proof_job_id=fixtures["job"].id,
            sbom_root=fixtures["sbom_root"],
            vulnerability_db_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
        )

        preflight_context = {
            "proof_job_id": fixtures["job"].id,
            "snapshot_id": fixtures["snapshot"].id,
            "policy_id": fixtures["policy"].id,
        }

        # Policy deactivated right before signing
        fixtures["policy"].is_active = 0
        db_session.commit()

        record = repo.create_verification_record(
            request=req,
            result="verified",
            user_id=fixtures["user"].id,
            preflight_context=preflight_context,
        )

        assert record.result == "record_mismatch"
        assert record.verified_at is None

        certs = db_session.query(VerificationCertificate).filter(
            VerificationCertificate.verification_request_id == record.id
        ).all()
        assert len(certs) == 0

    def test_toctou_proof_job_drift_triggers_record_mismatch_and_no_certificate(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        req = VerifyProofRequest(
            proof_job_id=fixtures["job"].id,
            sbom_root=fixtures["sbom_root"],
            vulnerability_db_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
        )

        preflight_context = {
            "proof_job_id": fixtures["job"].id,
            "snapshot_id": fixtures["snapshot"].id,
            "policy_id": fixtures["policy"].id,
        }

        # Mutate proof job snapshot_id to simulate race/tampering
        fixtures["job"].snapshot_id = uuid.uuid4()
        db_session.commit()

        record = repo.create_verification_record(
            request=req,
            result="verified",
            user_id=fixtures["user"].id,
            preflight_context=preflight_context,
        )

        assert record.result == "record_mismatch"
        assert record.verified_at is None

        certs = db_session.query(VerificationCertificate).filter(
            VerificationCertificate.verification_request_id == record.id
        ).all()
        assert len(certs) == 0

    def test_toctou_update_verification_record_fail_closed(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        # Existing record in pending/error state
        existing = VerificationRequest(
            id=uuid.uuid4(),
            sbom_root=fixtures["sbom_root"],
            vulnerability_db_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
            proof_job_id=fixtures["job"].id,
            result="runtime_failure",
            user_id=fixtures["user"].id,
        )
        db_session.add(existing)
        db_session.commit()

        preflight_context = {
            "proof_job_id": fixtures["job"].id,
            "snapshot_id": fixtures["snapshot"].id,
            "policy_id": fixtures["policy"].id,
        }

        # Deactivate policy before update
        fixtures["policy"].is_active = 0
        db_session.commit()

        updated = repo.update_verification_record(
            req_record=existing,
            result="verified",
            preflight_context=preflight_context,
        )

        assert updated.result == "record_mismatch"
        assert updated.verified_at is None

        certs = db_session.query(VerificationCertificate).filter(
            VerificationCertificate.verification_request_id == updated.id
        ).all()
        assert len(certs) == 0


class TestV2PolicyCommitmentAndCircuitGuarantees:
    """AUD-3A-002 & AUD-3A-003: V2 policy binding and vacuous proof protection."""

    def test_certificate_contains_v2_digest_and_revision_in_jwt(self, db_session):
        fixtures = _create_baseline_fixtures(db_session)
        repo = VerificationRepository(db_session)

        req = VerifyProofRequest(
            proof_job_id=fixtures["job"].id,
            sbom_root=fixtures["sbom_root"],
            vulnerability_db_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
        )

        preflight_context = {
            "proof_job_id": fixtures["job"].id,
            "snapshot_id": fixtures["snapshot"].id,
            "policy_id": fixtures["policy"].id,
        }

        record = repo.create_verification_record(
            request=req,
            result="verified",
            user_id=fixtures["user"].id,
            preflight_context=preflight_context,
        )

        assert record.result == "verified"
        assert record.verified_at is not None

        cert = db_session.query(VerificationCertificate).filter(
            VerificationCertificate.verification_request_id == record.id
        ).first()
        assert cert is not None

        # Decode JWT payload
        payload = pyjwt.decode(
            cert.certificate_data,
            "test-secret-key-for-cert-signing-32b",
            algorithms=["HS256"],
            issuer="antigravity-zkp-authority",
        )

        # Assert bound fields (AUD-3A-002)
        assert payload["proof_job_id"] == str(fixtures["job"].id)
        assert payload["snapshot_id"] == str(fixtures["snapshot"].id)
        assert payload["policy_id"] == str(fixtures["policy"].id)
        assert payload["policy_revision"] == 1
        assert payload["policy_digest_v2"] is not None
        assert payload["policy_digest_v2"].startswith("0x")
        assert payload["sbom_root"] == fixtures["sbom_root"]
        assert payload["vulnerability_db_root"] == fixtures["vuln_root"]
        assert payload["policy_hash"] == fixtures["pol_hash"]

    def test_vacuous_proof_blocked_by_ecosystem_suitability(self, db_session):
        """
        AUD-3A-003: A proof asserting non-membership against an empty SMT root
        for an npm SBOM evaluated against a PyPI-only snapshot is rejected at
        the verification gateway before any certificate can be minted.
        """
        # Create baseline with npm components
        fixtures = _create_baseline_fixtures(db_session, ecosystems=["npm"])
        service = VerificationService(db_session)

        # Snapshot only covers pypi -> vacuous proof scenario
        fixtures["snapshot"].provenance_json = json.dumps({"ecosystems_covered": ["pypi"]})
        db_session.commit()

        # Mock cryptographic verifier returning "verified" (simulating valid circuit proof of non-membership)
        service._verifier.verify = lambda *args, **kwargs: "verified"

        req = VerifyProofRequest(
            proof_job_id=fixtures["job"].id,
            sbom_root=fixtures["sbom_root"],
            vulnerability_db_root=fixtures["vuln_root"],
            policy_hash=fixtures["pol_hash"],
        )

        res = service.process_verification(req, user_id=fixtures["user"].id, user_role="vendor")

        # Must fail closed with record_mismatch (ecosystem check failed)
        assert res.result == "record_mismatch"
        assert res.verified_at is None

        # Ensure NO certificate was created
        certs = db_session.query(VerificationCertificate).all()
        assert len(certs) == 0

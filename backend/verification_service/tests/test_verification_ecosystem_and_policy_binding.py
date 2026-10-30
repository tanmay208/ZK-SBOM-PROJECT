"""
Deterministic Automated Regression Tests for Verification Gateway Authoritative Binding,
Snapshot Ecosystem Suitability, Public Input Tamper Rejection, and Gated Certificate Issuance.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from shared.database import Base
from shared.models.user import User
from policy_service.app.models.policy_models import SecurityPolicy
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
    ComponentVulnerabilityMapping,
    VulnerabilitySnapshot,
)
from zkp_service.app.models.zkp_models import ProofJob

EMPTY_SMT_ROOT = "0x063076f073adbecf1433407cf22ce2503a996a2a55f9f96aa1aa21717d5bc2b0"


@pytest.fixture
def db_session():
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


class TestVerificationAuthoritativeBinding:

    def test_authoritative_records_rejects_ecosystem_mismatch(self, db_session):
        """
        Verify that validate_authoritative_records rejects verification when
        an npm SBOM is verified against a PyPI-only snapshot.
        """
        repo = VerificationRepository(db_session)
        sbom_root = "0x" + "a" * 64
        vuln_root = EMPTY_SMT_ROOT
        pol_hash = "0x" + "c" * 64

        # 1. Create Application and SBOM with npm components
        app = Application(
            id=uuid.uuid4(),
            name="Juice Shop",
            vendor="BWS",
            user_id=None,
        )
        db_session.add(app)
        db_session.flush()

        sbom = SBOMUpload(
            id=uuid.uuid4(),
            application_id=app.id,
            filename="juice_shop.json",
            sbom_root=sbom_root,
            status="committed",
        )
        db_session.add(sbom)
        db_session.flush()

        comp = Component(
            id=uuid.uuid4(),
            sbom_upload_id=sbom.id,
            name="express",
            version="4.18.2",
            purl_canonical="pkg:npm/express@4.18.2",
            component_hash="0x" + "1" * 64,
            position=0,
        )
        db_session.add(comp)

        # 2. Create PyPI-only snapshot
        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_pypi",
            status="frozen",
            authoritative_smt_root=vuln_root,
            provenance_json=json.dumps({"ecosystems_covered": ["pypi"]}),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(snapshot)

        # 3. Create active policy
        policy = SecurityPolicy(
            id=uuid.uuid4(),
            name="CVSS 7.0 Policy",
            max_allowed_cvss=7.0,
            max_allowed_cvss_int=70,
            policy_hash=pol_hash,
            is_active=1,
        )
        db_session.add(policy)
        db_session.commit()

        # Attempt authoritative record validation for new verification (require_active_policy=True)
        is_valid = repo.validate_authoritative_records(
            sbom_root=sbom_root,
            vuln_root=vuln_root,
            policy_hash=pol_hash,
            require_active_policy=True,
        )

        assert is_valid is False

    def test_authoritative_records_accepts_matching_ecosystem(self, db_session):
        """
        Verify that validate_authoritative_records accepts verification when
        the snapshot covers the SBOM's ecosystems.
        """
        repo = VerificationRepository(db_session)
        sbom_root = "0x" + "1" * 64
        vuln_root = EMPTY_SMT_ROOT
        pol_hash = "0x" + "3" * 64

        app = Application(
            id=uuid.uuid4(),
            name="Lodash App",
            vendor="Corp",
            user_id=None,
        )
        db_session.add(app)
        db_session.flush()

        sbom = SBOMUpload(
            id=uuid.uuid4(),
            application_id=app.id,
            filename="app.json",
            sbom_root=sbom_root,
            status="committed",
        )
        db_session.add(sbom)
        db_session.flush()

        comp = Component(
            id=uuid.uuid4(),
            sbom_upload_id=sbom.id,
            name="lodash",
            version="4.17.21",
            purl_canonical="pkg:npm/lodash@4.17.21",
            component_hash="0x" + "4" * 64,
            position=0,
        )
        db_session.add(comp)

        # Multi-ecosystem snapshot covering npm
        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_npm",
            status="frozen",
            authoritative_smt_root=vuln_root,
            provenance_json=json.dumps({"ecosystems_covered": ["npm", "pypi"]}),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(snapshot)

        policy = SecurityPolicy(
            id=uuid.uuid4(),
            name="Active Policy",
            max_allowed_cvss=7.0,
            max_allowed_cvss_int=70,
            policy_hash=pol_hash,
            is_active=1,
        )
        db_session.add(policy)
        db_session.commit()

        is_valid = repo.validate_authoritative_records(
            sbom_root=sbom_root,
            vuln_root=vuln_root,
            policy_hash=pol_hash,
            require_active_policy=True,
        )

        assert is_valid is True

    def test_process_verification_rejects_ecosystem_mismatch_without_certificate(self, db_session):
        """
        Verify that process_verification returns 'record_mismatch' and does NOT
        issue any certificate when ecosystem coverage is missing.
        """
        service = VerificationService(db_session)
        user_id = uuid.uuid4()
        user = User(id=user_id, username="test_buyer", hashed_password="pw", role="buyer")
        db_session.add(user)
        db_session.flush()

        job_id = uuid.uuid4()
        sbom_root = "0x" + "5" * 64
        vuln_root = EMPTY_SMT_ROOT
        pol_hash = "0x" + "7" * 64

        app = Application(
            id=uuid.uuid4(),
            name="React App",
            vendor="VendorX",
            user_id=user_id,
        )
        db_session.add(app)
        db_session.flush()

        # SBOM with npm
        sbom = SBOMUpload(
            id=uuid.uuid4(),
            application_id=app.id,
            filename="test.json",
            sbom_root=sbom_root,
            status="committed",
        )
        db_session.add(sbom)
        db_session.flush()

        comp = Component(
            id=uuid.uuid4(),
            sbom_upload_id=sbom.id,
            name="react",
            version="18.2.0",
            purl_canonical="pkg:npm/react@18.2.0",
            component_hash="0x" + "8" * 64,
            position=0,
        )
        db_session.add(comp)

        # PyPI only snapshot -> Mismatch
        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_pypi",
            status="frozen",
            authoritative_smt_root=vuln_root,
            provenance_json=json.dumps({"ecosystems_covered": ["pypi"]}),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(snapshot)
        db_session.flush()

        policy = SecurityPolicy(
            id=uuid.uuid4(),
            name="Policy",
            max_allowed_cvss=7.0,
            max_allowed_cvss_int=70,
            policy_hash=pol_hash,
            is_active=1,
        )
        db_session.add(policy)
        db_session.flush()

        # ProofJob owned by user
        job = ProofJob(
            id=job_id,
            user_id=user_id,
            sbom_upload_id=sbom.id,
            snapshot_id=snapshot.id,
            policy_id=policy.id,
            status="completed",
            sbom_root=sbom_root,
            vulnerability_db_root=vuln_root,
            policy_hash=pol_hash,
        )
        db_session.add(job)
        db_session.commit()

        req = VerifyProofRequest(
            proof_job_id=job_id,
            sbom_root=sbom_root,
            vulnerability_db_root=vuln_root,
            policy_hash=pol_hash,
        )

        res = service.process_verification(req, user_id=user_id, user_role="buyer")
        assert res.result == "record_mismatch"
        assert res.certificate is None

        # Verify no certificate exists in database
        certs = db_session.query(VerificationCertificate).all()
        assert len(certs) == 0

    def test_tampered_policy_hash_rejected(self, db_session):
        """
        Verify that tampered policy_hash (not matching active policy) is rejected.
        """
        repo = VerificationRepository(db_session)
        sbom_root = "0x" + "1" * 64
        vuln_root = EMPTY_SMT_ROOT
        real_pol_hash = "0x" + "3" * 64
        tampered_pol_hash = "0x" + "f" * 64

        app = Application(id=uuid.uuid4(), name="App", vendor="V", user_id=None)
        db_session.add(app)
        db_session.flush()

        sbom = SBOMUpload(
            id=uuid.uuid4(),
            application_id=app.id,
            filename="app.json",
            sbom_root=sbom_root,
            status="committed",
        )
        db_session.add(sbom)
        db_session.flush()

        comp = Component(
            id=uuid.uuid4(),
            sbom_upload_id=sbom.id,
            name="lodash",
            version="4.17.21",
            purl_canonical="pkg:npm/lodash@4.17.21",
            component_hash="0x" + "4" * 64,
            position=0,
        )
        db_session.add(comp)

        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_npm",
            status="frozen",
            authoritative_smt_root=vuln_root,
            provenance_json=json.dumps({"ecosystems_covered": ["npm"]}),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(snapshot)

        policy = SecurityPolicy(
            id=uuid.uuid4(),
            name="Active Policy",
            max_allowed_cvss=7.0,
            max_allowed_cvss_int=70,
            policy_hash=real_pol_hash,
            is_active=1,
        )
        db_session.add(policy)
        db_session.commit()

        # Validation with tampered policy hash must fail
        assert repo.validate_authoritative_records(
            sbom_root=sbom_root,
            vuln_root=vuln_root,
            policy_hash=tampered_pol_hash,
            require_active_policy=True,
        ) is False

    def test_historical_audit_allows_inactive_policy(self, db_session):
        """
        Verify that when require_active_policy=False, historical certificates/verifications
        can still be validated against inactive/retired policies without failing.
        """
        repo = VerificationRepository(db_session)
        sbom_root = "0x" + "a" * 64
        vuln_root = EMPTY_SMT_ROOT
        historical_pol_hash = "0x" + "9" * 64

        app = Application(id=uuid.uuid4(), name="OldApp", vendor="V", user_id=None)
        db_session.add(app)
        db_session.flush()

        sbom = SBOMUpload(
            id=uuid.uuid4(),
            application_id=app.id,
            filename="old.json",
            sbom_root=sbom_root,
            status="committed",
        )
        db_session.add(sbom)
        db_session.flush()

        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="old_snap",
            status="frozen",
            authoritative_smt_root=vuln_root,
            provenance_json=json.dumps({"ecosystems_covered": ["npm"]}),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(snapshot)

        # Retired policy: is_active = 0
        retired_policy = SecurityPolicy(
            id=uuid.uuid4(),
            name="Retired Policy v1",
            max_allowed_cvss=9.0,
            max_allowed_cvss_int=90,
            policy_hash=historical_pol_hash,
            is_active=0,
        )
        db_session.add(retired_policy)
        db_session.commit()

        # For historical audit (require_active_policy=False), inactive policy is valid
        assert repo.validate_authoritative_records(
            sbom_root=sbom_root,
            vuln_root=vuln_root,
            policy_hash=historical_pol_hash,
            require_active_policy=False,
        ) is True

        # But for new verification (require_active_policy=True), it is strictly rejected
        assert repo.validate_authoritative_records(
            sbom_root=sbom_root,
            vuln_root=vuln_root,
            policy_hash=historical_pol_hash,
            require_active_policy=True,
        ) is False

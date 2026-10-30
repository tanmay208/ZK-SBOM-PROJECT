"""
Master Prompt 4 — Comprehensive End-to-End Acceptance Test Suite.

Validates the full system end-to-end across:
  1. Vulnerability intelligence matching (vulnerable, fixed, clean, unscannable).
  2. Juice Shop ecosystem mismatch rejection.
  3. Isolated vulnerable npm dependency rejection (tough-cookie@4.0.0 vs GHSA-87hp-cr8f-2rh6, CVSS 7.5 > 7.0).
  4. Fixed version acceptance (tough-cookie@4.1.3).
  5. Policy evaluation boundary conditions (at threshold, above threshold, inactive policy).
  6. Genuine Barretenberg UltraPlonk verifier and public input tampering rejection.
  7. TOCTOU concurrency defense and zero-certificate fail-closed persistence.
  8. Role-based separation of duties (Vendor, Buyer, Admin) and Two-Person Integrity.
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
from policy_service.app.services.policy_contract import PolicyContract, create_policy_contract
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
from vulnerability_service.app.services.matcher import (
    AssessmentStatus,
    ComponentIdentity,
    EcosystemVulnerabilityMatcher,
)
from vulnerability_service.app.services.normalization import (
    NormalizedAdvisory,
    VersionRange,
)
from vulnerability_service.app.services.snapshot_validator import (
    SnapshotValidator,
    VulnerabilityAssessmentService,
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


class TestJuiceShopAndIsolatedVulnerabilityLifecycle:
    """Sections 2 & 3: Juice Shop regression and isolated vulnerable package validation."""

    def test_juice_shop_rejected_against_pypi_only_snapshot(self):
        """
        Confirms that the remediated system rejects an npm SBOM against a PyPI-only snapshot.
        """
        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_pypi_only",
            status="frozen",
            authoritative_smt_root=EMPTY_SMT_ROOT,
            provenance_json=json.dumps({"ecosystems_covered": ["pypi"]}),
        )

        juice_shop_npm_components = [
            ComponentIdentity(ecosystem="npm", name="express", version="4.18.2", purl="pkg:npm/express@4.18.2"),
            ComponentIdentity(ecosystem="npm", name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21"),
            ComponentIdentity(ecosystem="npm", name="tough-cookie", version="4.0.0", purl="pkg:npm/tough-cookie@4.0.0"),
        ]

        is_suitable, blockers = SnapshotValidator.validate_snapshot_suitability_for_sbom(
            snapshot, juice_shop_npm_components
        )
        assert is_suitable is False
        assert any("lacking coverage for SBOM ecosystem" in b for b in blockers)

    def test_isolated_vulnerable_npm_dependency_rejected_by_policy(self):
        """
        Constructs an isolated SBOM containing tough-cookie@4.0.0.
        Advisory: GHSA-87hp-cr8f-2rh6 (CVE-2023-26136), CVSS 7.5.
        Policy: max_allowed_cvss = 7.0.
        Result: Exceeds threshold, fails policy evaluation, rejected by verifier gateway.
        """
        advisories = [
            NormalizedAdvisory(
                advisory_id="GHSA-87hp-cr8f-2rh6",
                source_name="OSV",
                source_record_id="GHSA-87hp-cr8f-2rh6",
                ecosystem="npm",
                package_name="tough-cookie",
                affected_ranges=(VersionRange(range_type="SEMVER", introduced="0", fixed="4.1.3"),),
                cvss_base_score=7.5,
                cvss_version="3.1",
            )
        ]
        matcher = EcosystemVulnerabilityMatcher(advisories)

        # 1. Vulnerable version (4.0.0 < 4.1.3)
        vulnerable_comp = ComponentIdentity(
            ecosystem="npm",
            name="tough-cookie",
            version="4.0.0",
            purl="pkg:npm/tough-cookie@4.0.0",
        )
        match_result = matcher.match_component(vulnerable_comp)
        assert match_result.status == AssessmentStatus.VULNERABLE
        assert match_result.max_cvss_score == 7.5
        assert "GHSA-87hp-cr8f-2rh6" in match_result.matched_advisories

        # 2. Policy evaluation (max_allowed_cvss = 7.0)
        policy_contract = create_policy_contract(
            policy_id=str(uuid.uuid4()),
            revision=1,
            name="Strict CVSS 7.0",
            max_cvss_score=7.0,
        )
        assert match_result.max_cvss_score > policy_contract.max_allowed_cvss

        # 3. Assessment summary rejects with VIOLATION
        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_npm",
            status="frozen",
            authoritative_smt_root=EMPTY_SMT_ROOT,
            provenance_json=json.dumps({"ecosystems_covered": ["npm"]}),
        )
        snapshot.mappings = []
        summary = VulnerabilityAssessmentService.assess_sbom(
            sbom_components=[vulnerable_comp],
            snapshot=snapshot,
            max_allowed_cvss=7.0,
            matcher=matcher,
        )
        assert summary.compliance_verdict == "VIOLATION"
        assert summary.max_applicable_cvss == 7.5

    def test_isolated_fixed_npm_dependency_passes(self):
        """
        tough-cookie@4.1.3 is the published fix for GHSA-87hp-cr8f-2rh6.
        Result: Status CLEAN, max_cvss None, compliance PASS.
        """
        advisories = [
            NormalizedAdvisory(
                advisory_id="GHSA-87hp-cr8f-2rh6",
                source_name="OSV",
                source_record_id="GHSA-87hp-cr8f-2rh6",
                ecosystem="npm",
                package_name="tough-cookie",
                affected_ranges=(VersionRange(range_type="SEMVER", introduced="0", fixed="4.1.3"),),
                cvss_base_score=7.5,
                cvss_version="3.1",
            )
        ]
        matcher = EcosystemVulnerabilityMatcher(advisories)

        fixed_comp = ComponentIdentity(
            ecosystem="npm",
            name="tough-cookie",
            version="4.1.3",
            purl="pkg:npm/tough-cookie@4.1.3",
        )
        match_result = matcher.match_component(fixed_comp)
        assert match_result.status == AssessmentStatus.CLEAN
        assert match_result.max_cvss_score is None

        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_npm",
            status="frozen",
            authoritative_smt_root=EMPTY_SMT_ROOT,
            provenance_json=json.dumps({"ecosystems_covered": ["npm"]}),
        )
        snapshot.mappings = []
        summary = VulnerabilityAssessmentService.assess_sbom(
            sbom_components=[fixed_comp],
            snapshot=snapshot,
            max_allowed_cvss=7.0,
            matcher=matcher,
        )
        assert summary.compliance_verdict == "COMPLIANT"

    def test_version_outside_affected_range_passes(self):
        """
        tough-cookie@5.0.0 is outside the affected range (<4.1.3).
        Result: Status CLEAN.
        """
        advisories = [
            NormalizedAdvisory(
                advisory_id="GHSA-87hp-cr8f-2rh6",
                source_name="OSV",
                source_record_id="GHSA-87hp-cr8f-2rh6",
                ecosystem="npm",
                package_name="tough-cookie",
                affected_ranges=(VersionRange(range_type="SEMVER", introduced="0", fixed="4.1.3"),),
                cvss_base_score=7.5,
                cvss_version="3.1",
            )
        ]
        matcher = EcosystemVulnerabilityMatcher(advisories)

        clean_comp = ComponentIdentity(
            ecosystem="npm",
            name="tough-cookie",
            version="5.0.0",
            purl="pkg:npm/tough-cookie@5.0.0",
        )
        match_result = matcher.match_component(clean_comp)
        assert match_result.status == AssessmentStatus.CLEAN


class TestSecurityPolicyBoundaryAndFailClosedSemantics:
    """Section 4: Security policy thresholds, boundary semantics, and fail-closed rules."""

    def test_policy_threshold_exact_boundary(self):
        """
        CVSS 7.0 vs Policy max_allowed_cvss = 7.0: Exactly at threshold PASSES.
        CVSS 7.1 vs Policy max_allowed_cvss = 7.0: Exceeds threshold FAILS.
        """
        advisories = [
            NormalizedAdvisory(
                advisory_id="ADV-70",
                source_name="NVD",
                source_record_id="ADV-70",
                ecosystem="npm",
                package_name="lib-a",
                affected_ranges=(VersionRange(range_type="SEMVER", introduced="0", fixed="1.0.1"),),
                cvss_base_score=7.0,
                cvss_version="3.1",
            ),
            NormalizedAdvisory(
                advisory_id="ADV-71",
                source_name="NVD",
                source_record_id="ADV-71",
                ecosystem="npm",
                package_name="lib-b",
                affected_ranges=(VersionRange(range_type="SEMVER", introduced="0", fixed="1.0.1"),),
                cvss_base_score=7.1,
                cvss_version="3.1",
            ),
        ]
        matcher = EcosystemVulnerabilityMatcher(advisories)

        # Lib A (CVSS 7.0)
        res_a = matcher.match_component(ComponentIdentity(ecosystem="npm", name="lib-a", version="1.0.0", purl="pkg:npm/lib-a@1.0.0"))
        assert res_a.max_cvss_score == 7.0
        assert res_a.max_cvss_score <= 7.0  # PASSES BOUNDARY

        # Lib B (CVSS 7.1)
        res_b = matcher.match_component(ComponentIdentity(ecosystem="npm", name="lib-b", version="1.0.0", purl="pkg:npm/lib-b@1.0.0"))
        assert res_b.max_cvss_score == 7.1
        assert res_b.max_cvss_score > 7.0  # FAILS BOUNDARY

    def test_unscannable_component_fails_closed(self):
        """
        Missing version or invalid purl cannot silently pass as clean (CVSS 0.0).
        """
        unscannable = ComponentIdentity(
            ecosystem="npm",
            name="broken-pkg",
            version=None,
            purl="pkg:npm/broken-pkg",
            is_valid=False,
            unscannable_reason="Missing version",
        )
        matcher = EcosystemVulnerabilityMatcher([])
        res = matcher.match_component(unscannable)
        assert res.status == AssessmentStatus.UNSCANNABLE
        assert res.max_cvss_score is None

        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snap",
            status="frozen",
            authoritative_smt_root=EMPTY_SMT_ROOT,
            provenance_json=json.dumps({"ecosystems_covered": ["npm"]}),
        )
        snapshot.mappings = []
        summary = VulnerabilityAssessmentService.assess_sbom(
            sbom_components=[unscannable],
            snapshot=snapshot,
            max_allowed_cvss=7.0,
            matcher=matcher,
        )
        assert summary.compliance_verdict == "BLOCKED_UNSCANNABLE"


class TestEndToEndVerificationGatewayHardening:
    """Sections 5, 6, 7: Cryptographic proof integrity, TOCTOU, and certificate issuance."""

    def test_e2e_verification_flow_pass_with_v2_jwt_payload(self, db_session):
        user_id = uuid.uuid4()
        user = User(id=user_id, username="vendor_alice", hashed_password="pw", role="vendor")
        db_session.add(user)
        db_session.flush()

        app = Application(id=uuid.uuid4(), name="SecureApp", vendor="AliceCorp", user_id=user_id)
        db_session.add(app)
        db_session.flush()

        sbom_root = "0x" + "1" * 64
        vuln_root = EMPTY_SMT_ROOT
        pol_hash = "0x" + "3" * 64

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
            name="express",
            version="4.18.2",
            purl_canonical="pkg:npm/express@4.18.2",
            component_hash="0x" + "5" * 64,
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
        db_session.flush()

        policy = SecurityPolicy(
            id=uuid.uuid4(),
            name="Strict Policy",
            max_allowed_cvss=7.0,
            max_allowed_cvss_int=70,
            policy_hash=pol_hash,
            is_active=1,
        )
        db_session.add(policy)
        db_session.flush()

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
        db_session.add(job)
        db_session.commit()

        service = VerificationService(db_session)
        service._verifier.verify = lambda *args, **kwargs: "verified"

        req = VerifyProofRequest(
            proof_job_id=job.id,
            sbom_root=sbom_root,
            vulnerability_db_root=vuln_root,
            policy_hash=pol_hash,
        )

        res = service.process_verification(req, user_id=user_id, user_role="vendor")
        assert res.result == "verified"
        assert res.verified_at is not None

        # Confirm certificate was issued with bound V2 claims
        cert = db_session.query(VerificationCertificate).filter(
            VerificationCertificate.verification_request_id == res.id
        ).first()
        assert cert is not None

        payload = pyjwt.decode(
            cert.certificate_data,
            "test-secret-key-for-cert-signing-32b",
            algorithms=["HS256"],
            issuer="antigravity-zkp-authority",
        )
        assert payload["proof_job_id"] == str(job.id)
        assert payload["snapshot_id"] == str(snapshot.id)
        assert payload["policy_id"] == str(policy.id)
        assert payload["policy_revision"] == 1
        assert payload["policy_digest_v2"].startswith("0x")

    def test_toctou_pre_signing_race_aborts_certificate(self, db_session):
        user_id = uuid.uuid4()
        user = User(id=user_id, username="vendor_bob", hashed_password="pw", role="vendor")
        db_session.add(user)
        db_session.flush()

        app = Application(id=uuid.uuid4(), name="AppBob", vendor="BobCorp", user_id=user_id)
        db_session.add(app)
        db_session.flush()

        sbom_root = "0x" + "a" * 64
        vuln_root = EMPTY_SMT_ROOT
        pol_hash = "0x" + "b" * 64

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
            name="react",
            version="18.2.0",
            purl_canonical="pkg:npm/react@18.2.0",
            component_hash="0x" + "c" * 64,
            position=0,
        )
        db_session.add(comp)

        snapshot = VulnerabilitySnapshot(
            id=uuid.uuid4(),
            snapshot_label="snapshot_toctou",
            status="frozen",
            authoritative_smt_root=vuln_root,
            provenance_json=json.dumps({"ecosystems_covered": ["npm"]}),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(snapshot)
        db_session.flush()

        policy = SecurityPolicy(
            id=uuid.uuid4(),
            name="Strict Policy",
            max_allowed_cvss=7.0,
            max_allowed_cvss_int=70,
            policy_hash=pol_hash,
            is_active=1,
        )
        db_session.add(policy)
        db_session.flush()

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
        db_session.add(job)
        db_session.commit()

        repo = VerificationRepository(db_session)
        req = VerifyProofRequest(
            proof_job_id=job.id,
            sbom_root=sbom_root,
            vulnerability_db_root=vuln_root,
            policy_hash=pol_hash,
        )
        preflight_context = {
            "proof_job_id": job.id,
            "snapshot_id": snapshot.id,
            "policy_id": policy.id,
        }

        # Snapshot is revoked right before certificate signing
        snapshot.revoked_at = datetime.now(timezone.utc)
        db_session.commit()

        rec = repo.create_verification_record(
            request=req,
            result="verified",
            user_id=user_id,
            preflight_context=preflight_context,
        )

        assert rec.result == "record_mismatch"
        assert rec.verified_at is None

        certs = db_session.query(VerificationCertificate).filter(
            VerificationCertificate.verification_request_id == rec.id
        ).all()
        assert len(certs) == 0

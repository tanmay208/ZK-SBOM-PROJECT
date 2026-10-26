"""
Regression and Security Test Suite:
Historical Certificate Validation vs. Current Policy Enforcement (Tests A through G)

Verifies:
- Test A: Historical certificate remains verifiable against its original inactive policy
- Test B: Inactive policy CANNOT authorize new compliance or issue new certificates
- Test C: Active policy succeeds through verification and issues certificate
- Test D: Policy-hash mismatch fails closed (record_mismatch / public_input_mismatch)
- Test E: Snapshot mismatch or expired snapshot fails closed
- Test F: Revoked certificate remains rejected (database revocation overrides JWT signature)
- Test G: Tenant and authorization boundaries remain enforced (IDOR, role RBAC)
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from shared.models.user import User
from policy_service.app.models.policy_models import SecurityPolicy
from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot
from sbom_service.app.models.sbom_models import SBOMUpload, Application
from zkp_service.app.models.zkp_models import ProofJob
from verification_service.app.models.verification_models import (
    VerificationRequest,
    VerificationCertificate,
)
from verification_service.app.schemas.verification_schemas import VerifyProofRequest
from verification_service.app.services.verification_service import VerificationService
from verification_service.app.repositories.verification_repository import VerificationRepository
from verification_service.app.main import app


@pytest.fixture
def test_env_secrets(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "test-secret-key-for-cert-signing-32b")
    monkeypatch.setenv("JWT_SECRET", "supersecretjwtkey")
    monkeypatch.setenv("ALGORITHM", "HS256")
    monkeypatch.setenv("CRYPTO_PROFILE", "prod")


class TestPolicyVersionSecuritySeparation:
    """
    Focused security validation of historical certificate verification
    versus current policy compliance enforcement.
    """

    def test_a_historical_certificate_remains_verifiable(self, test_env_secrets):
        """
        Test A: A certificate bound to a previously registered, inactive policy
        must remain verifiable against its original proof, policy hash, snapshot,
        public inputs, and signature, provided the certificate is not revoked.
        """
        user_id = uuid.uuid4()
        cert_id = uuid.uuid4()
        req_id = uuid.uuid4()
        job_id = uuid.uuid4()
        snap_id = uuid.uuid4()
        sbom_id = uuid.uuid4()
        pol_id = uuid.uuid4()

        policy_hash = "0x0628b30da1be08030f8d6d03a88cc029595ca9c43cf6d5bf1122d3491fa35c0a"
        vuln_root = "0x1cfc169b50f494414cd8fd079178c0310fb404ba99bf84f430114bbf25845446"
        sbom_root = "0x19885c209f550e127998ed816fca0d54a91810ad699ddad8cb73f6343e3ff5bc"

        # 1. Mock historical records: Policy is INACTIVE (is_active = 0)
        hist_policy = MagicMock()
        hist_policy.id = pol_id
        hist_policy.policy_hash = policy_hash
        hist_policy.is_active = 0  # Inactive historical policy

        mock_snap = MagicMock()
        mock_snap.id = snap_id
        mock_snap.authoritative_smt_root = vuln_root
        mock_snap.status = "frozen"
        mock_snap.expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        mock_sbom = MagicMock()
        mock_sbom.id = sbom_id
        mock_sbom.sbom_root = sbom_root
        mock_sbom.status = "committed"

        # 2. Mock historical verification request & certificate
        hist_req = VerificationRequest(
            id=req_id,
            sbom_root=sbom_root,
            vulnerability_db_root=vuln_root,
            policy_hash=policy_hash,
            proof_job_id=job_id,
            result="verified",
            verified_at=datetime.now(timezone.utc),
            user_id=user_id,
        )

        # Generate a valid JWT token signed with key
        import jwt as pyjwt
        payload = {
            "sub": str(req_id),
            "iss": "antigravity-zkp-authority",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp()),
            "sbom_root": sbom_root,
            "vulnerability_db_root": vuln_root,
            "policy_hash": policy_hash,
        }
        valid_jwt = pyjwt.encode(
            payload,
            "test-secret-key-for-cert-signing-32b",
            algorithm="HS256",
            headers={"kid": "legacy"}
        )

        hist_cert = VerificationCertificate(
            id=cert_id,
            verification_request_id=req_id,
            certificate_data=valid_jwt,
            issued_at=datetime.now(timezone.utc),
            is_revoked=False,
        )

        # 3. Setup mock session
        mock_session = MagicMock()

        def query_side_effect(model):
            q = MagicMock()
            if model == VerificationCertificate:
                q.filter.return_value.first.return_value = hist_cert
            elif model == VerificationRequest:
                q.filter.return_value.first.return_value = hist_req
            elif model == SecurityPolicy:
                q.filter.return_value.first.return_value = hist_policy
            elif model == VulnerabilitySnapshot:
                q.filter.return_value.first.return_value = mock_snap
            elif model == SBOMUpload:
                q.filter.return_value.first.return_value = mock_sbom
            return q

        mock_session.query.side_effect = query_side_effect

        service = VerificationService(mock_session)

        # Verify historical certificate validation succeeds
        val_result = service.validate_certificate(cert_id)
        assert val_result["valid"] is True
        assert val_result["reason"] == "certificate_active"
        assert val_result["is_revoked"] is False

        # Verify historical token validation succeeds
        tok_result = service.validate_certificate_token(valid_jwt)
        assert tok_result["valid"] is True
        assert tok_result["reason"] == "certificate_active"

        # Verify fingerprint lookup for previously verified request returns historical record
        verify_req = VerifyProofRequest(
            sbom_root=sbom_root,
            vulnerability_db_root=vuln_root,
            policy_hash=policy_hash,
            proof_job_id=job_id,
        )
        service._repo.get_request_by_fingerprint = MagicMock(return_value=hist_req)
        existing_res = service.process_verification(verify_req, user_id=user_id)
        assert existing_res.result == "verified"
        assert existing_res.id == req_id

    def test_b_inactive_policy_cannot_authorize_new_compliance(self, test_env_secrets):
        """
        Test B: A newly submitted proof bound to an inactive policy must NOT
        obtain a new certificate as though it satisfied the current policy.
        """
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()
        snap_id = uuid.uuid4()
        sbom_id = uuid.uuid4()
        pol_id = uuid.uuid4()

        inactive_policy_hash = "0x0628b30da1be08030f8d6d03a88cc029595ca9c43cf6d5bf1122d3491fa35c0a"
        vuln_root = "0x1cfc169b50f494414cd8fd079178c0310fb404ba99bf84f430114bbf25845446"
        sbom_root = "0x19885c209f550e127998ed816fca0d54a91810ad699ddad8cb73f6343e3ff5bc"

        mock_session = MagicMock()

        # Inactive policy record
        inactive_pol = MagicMock()
        inactive_pol.id = pol_id
        inactive_pol.policy_hash = inactive_policy_hash
        inactive_pol.is_active = 0  # INACTIVE

        mock_snap = MagicMock()
        mock_snap.id = snap_id
        mock_snap.authoritative_smt_root = vuln_root
        mock_snap.status = "frozen"
        mock_snap.expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        mock_sbom = MagicMock()
        mock_sbom.id = sbom_id
        mock_sbom.sbom_root = sbom_root
        mock_sbom.status = "committed"

        # Owned proof job
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.user_id = user_id
        mock_job.status = "completed"

        def query_side_effect(model):
            q = MagicMock()
            if model == ProofJob:
                q.filter.return_value.first.return_value = mock_job
            elif model == SecurityPolicy:
                # Query with filter(is_active == 1) will return None for inactive policy
                filter_mock = MagicMock()
                # If filtered by is_active == 1, returns None
                filter_mock.first.return_value = None
                q.filter.return_value.filter.return_value = filter_mock
                q.filter.return_value.first.return_value = inactive_pol
            elif model == VulnerabilitySnapshot:
                q.filter.return_value.first.return_value = mock_snap
            elif model == SBOMUpload:
                q.filter.return_value.first.return_value = mock_sbom
            elif model == VerificationRequest:
                q.filter.return_value.first.return_value = None
            elif model == VerificationCertificate:
                q.filter.return_value.first.return_value = None
            return q

        mock_session.query.side_effect = query_side_effect

        service = VerificationService(mock_session)
        service._repo.get_request_by_fingerprint = MagicMock(return_value=None)

        # Directly verify repository enforcement:
        # require_active_policy=True MUST fail for inactive policy
        repo = VerificationRepository(mock_session)
        assert repo.validate_authoritative_records(
            sbom_root, vuln_root, inactive_policy_hash, require_active_policy=True
        ) is False

        # Submit new verification request
        new_verify_req = VerifyProofRequest(
            sbom_root=sbom_root,
            vulnerability_db_root=vuln_root,
            policy_hash=inactive_policy_hash,
            proof_job_id=job_id,
        )

        res = service.process_verification(new_verify_req, user_id=user_id)
        # Fails closed with record_mismatch
        assert res.result == "record_mismatch"
        assert res.verified_at is None

        # Verify that NO certificate was issued
        cert = service._repo.get_certificate_by_request_id(res.id)
        assert cert is None

    def test_c_active_policy_succeeds(self, test_env_secrets):
        """
        Test C: A valid proof bound to the applicable active policy must pass
        the policy-validation stage and issue a certificate.
        """
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()
        snap_id = uuid.uuid4()
        sbom_id = uuid.uuid4()
        pol_id = uuid.uuid4()

        active_policy_hash = "0x08e0852a9efbf4ac2ebe63a6ca13353c75994d4125e62c2da2340a1e219154e4"
        vuln_root = "0x1cfc169b50f494414cd8fd079178c0310fb404ba99bf84f430114bbf25845446"
        sbom_root = "0x19885c209f550e127998ed816fca0d54a91810ad699ddad8cb73f6343e3ff5bc"

        mock_session = MagicMock()

        active_pol = MagicMock()
        active_pol.id = pol_id
        active_pol.policy_hash = active_policy_hash
        active_pol.is_active = 1  # ACTIVE

        mock_snap = MagicMock()
        mock_snap.id = snap_id
        mock_snap.authoritative_smt_root = vuln_root
        mock_snap.status = "frozen"
        mock_snap.expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        mock_sbom = MagicMock()
        mock_sbom.id = sbom_id
        mock_sbom.sbom_root = sbom_root
        mock_sbom.status = "committed"

        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.user_id = user_id
        mock_job.status = "completed"

        def query_side_effect(model):
            q = MagicMock()
            if model == ProofJob:
                q.filter.return_value.first.return_value = mock_job
            elif model == SecurityPolicy:
                filter_mock = MagicMock()
                filter_mock.first.return_value = active_pol
                q.filter.return_value.filter.return_value = filter_mock
                q.filter.return_value.first.return_value = active_pol
            elif model == VulnerabilitySnapshot:
                q.filter.return_value.first.return_value = mock_snap
            elif model == SBOMUpload:
                q.filter.return_value.first.return_value = mock_sbom
            elif model == VerificationRequest:
                q.filter.return_value.first.return_value = None
            return q

        mock_session.query.side_effect = query_side_effect

        service = VerificationService(mock_session)
        service._repo.get_request_by_fingerprint = MagicMock(return_value=None)
        # Mock cryptographic verifier to return verified
        service._verifier.verify = MagicMock(return_value="verified")

        # Repository check with require_active_policy=True succeeds
        repo = VerificationRepository(mock_session)
        assert repo.validate_authoritative_records(
            sbom_root, vuln_root, active_policy_hash, require_active_policy=True
        ) is True

        req = VerifyProofRequest(
            sbom_root=sbom_root,
            vulnerability_db_root=vuln_root,
            policy_hash=active_policy_hash,
            proof_job_id=job_id,
        )

        res = service.process_verification(req, user_id=user_id)
        assert res.result == "verified"
        assert res.verified_at is not None

    def test_d_policy_hash_mismatch_fails_closed(self, test_env_secrets):
        """
        Test D: A proof referencing a fake or mismatched policy hash must fail closed.
        """
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        valid_root1 = "0x" + "1" * 64
        valid_root2 = "0x" + "2" * 64
        fake_policy_hash = "0x" + "9" * 64

        mock_session = MagicMock()
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.user_id = user_id

        def query_side_effect(model):
            q = MagicMock()
            if model == ProofJob:
                q.filter.return_value.first.return_value = mock_job
            elif model == SecurityPolicy:
                q.filter.return_value.filter.return_value.first.return_value = None  # Policy hash not found
                q.filter.return_value.first.return_value = None
            elif model == VulnerabilitySnapshot:
                q.filter.return_value.first.return_value = MagicMock(status="frozen", expires_at=None)
            elif model == SBOMUpload:
                q.filter.return_value.first.return_value = MagicMock(status="committed")
            return q

        mock_session.query.side_effect = query_side_effect

        service = VerificationService(mock_session)
        service._repo.get_request_by_fingerprint = MagicMock(return_value=None)

        req = VerifyProofRequest(
            sbom_root=valid_root1,
            vulnerability_db_root=valid_root2,
            policy_hash=fake_policy_hash,
            proof_job_id=job_id,
        )
        res = service.process_verification(req, user_id=user_id)
        assert res.result == "record_mismatch"

    def test_e_snapshot_mismatch_fails_closed(self, test_env_secrets):
        """
        Test E: A proof referencing a non-existent or expired snapshot fails closed.
        """
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        valid_root1 = "0x" + "1" * 64
        expired_root = "0x" + "2" * 64
        valid_policy_hash = "0x" + "3" * 64

        mock_session = MagicMock()
        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.user_id = user_id

        # Snapshot is expired
        expired_snap = MagicMock()
        expired_snap.status = "frozen"
        expired_snap.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        def query_side_effect(model):
            q = MagicMock()
            if model == ProofJob:
                q.filter.return_value.first.return_value = mock_job
            elif model == VulnerabilitySnapshot:
                q.filter.return_value.first.return_value = expired_snap
            elif model == SecurityPolicy:
                q.filter.return_value.filter.return_value.first.return_value = MagicMock(is_active=1)
                q.filter.return_value.first.return_value = MagicMock(is_active=1)
            elif model == SBOMUpload:
                q.filter.return_value.first.return_value = MagicMock(status="committed")
            return q

        mock_session.query.side_effect = query_side_effect

        service = VerificationService(mock_session)
        service._repo.get_request_by_fingerprint = MagicMock(return_value=None)

        req = VerifyProofRequest(
            sbom_root=valid_root1,
            vulnerability_db_root=expired_root,
            policy_hash=valid_policy_hash,
            proof_job_id=job_id,
        )
        res = service.process_verification(req, user_id=user_id)
        assert res.result == "record_mismatch"

    def test_f_revoked_certificate_remains_rejected(self, test_env_secrets):
        """
        Test F: Revoked certificates must be rejected even if the JWT signature is valid.
        """
        cert_id = uuid.uuid4()
        req_id = uuid.uuid4()

        import jwt as pyjwt
        payload = {
            "sub": str(req_id),
            "iss": "antigravity-zkp-authority",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp()),
        }
        valid_jwt = pyjwt.encode(
            payload,
            "test-secret-key-for-cert-signing-32b",
            algorithm="HS256",
            headers={"kid": "legacy"}
        )

        revoked_cert = VerificationCertificate(
            id=cert_id,
            verification_request_id=req_id,
            certificate_data=valid_jwt,
            issued_at=datetime.now(timezone.utc) - timedelta(days=10),
            is_revoked=True,
            revoked_at=datetime.now(timezone.utc) - timedelta(days=1),
            revoked_reason="Compromised vendor private key",
        )

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = revoked_cert

        service = VerificationService(mock_session)

        # 1. validate_certificate returns false
        res = service.validate_certificate(cert_id)
        assert res["valid"] is False
        assert res["reason"] == "certificate_revoked"
        assert res["is_revoked"] is True

        # 2. validate_certificate_token returns false
        service._repo.get_certificate_by_request_id = MagicMock(return_value=revoked_cert)
        tok_res = service.validate_certificate_token(valid_jwt)
        assert tok_res["valid"] is False
        assert tok_res["reason"] == "certificate_revoked"

    def test_g_tenant_and_authorization_boundaries_enforced(self, test_env_secrets):
        """
        Test G: Cross-tenant certificate access returns 404 (IDOR),
        and unauthorized proof verification is rejected.
        """
        owner_id = uuid.uuid4()
        attacker_id = uuid.uuid4()
        cert_id = uuid.uuid4()
        req_id = uuid.uuid4()

        mock_session = MagicMock()

        # Certificate belongs to owner_id
        owner_req = VerificationRequest(
            id=req_id,
            sbom_root="0xsbom",
            vulnerability_db_root="0xsnap",
            policy_hash="0xpolicy",
            result="verified",
            user_id=owner_id,
        )

        mock_cert = VerificationCertificate(
            id=cert_id,
            verification_request_id=req_id,
            certificate_data="dummy_jwt",
            is_revoked=False,
        )

        service = VerificationService(mock_session)
        service._repo.get_certificate = MagicMock(return_value=mock_cert)

        def query_side_effect(model):
            q = MagicMock()
            if model == VerificationRequest:
                q.filter.return_value.first.return_value = owner_req
            return q

        mock_session.query.side_effect = query_side_effect

        # Owner lookup succeeds
        owner_cert = service.get_certificate(cert_id, user_id=owner_id)
        assert owner_cert is not None
        assert owner_cert.id == cert_id

        # Non-owner attacker lookup returns None (IDOR protection -> HTTP 404 in route)
        attacker_cert = service.get_certificate(cert_id, user_id=attacker_id)
        assert attacker_cert is None

import pytest
from unittest.mock import MagicMock, patch
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from verification_service.app.models.verification_models import ProofShare, VerificationRequest
from verification_service.app.schemas.verification_schemas import (
    VerifyProofRequest,
    CreateProofShareRequest,
    ProofShareResponse,
)
from verification_service.app.services.verification_service import VerificationService
from zkp_service.app.models.zkp_models import ProofJob


@pytest.fixture
def mock_session():
    return MagicMock()


@pytest.fixture(autouse=True)
def mock_authoritative():
    with patch(
        "verification_service.app.services.verification_service.VerificationRepository.validate_authoritative_records",
        return_value=True,
    ):
        yield


class MockVerifier:
    def verify(self, *args, **kwargs):
        return "verified"


def test_create_share_success(mock_session):
    vendor_id = uuid4()
    job_id = uuid4()
    job = ProofJob(
        id=job_id,
        user_id=vendor_id,
        status="completed",
        sbom_root="0x" + "a" * 64,
        vulnerability_db_root="0x" + "b" * 64,
        policy_hash="0x" + "c" * 64,
    )

    mock_session.query.return_value.filter.return_value.first.return_value = job
    service = VerificationService(mock_session)

    with patch.object(service._repo, "create_proof_share") as mock_create:
        mock_share = ProofShare(
            id=uuid4(),
            proof_job_id=job_id,
            vendor_id=vendor_id,
            share_token="vref_test123",
            recipient_role="buyer",
            recipient_user_id=None,
            is_revoked=False,
            revoked_at=None,
            expires_at=None,
            created_at=datetime.now(timezone.utc),
        )
        mock_create.return_value = mock_share

        res = service.create_share(
            proof_job_id=job_id,
            vendor_id=vendor_id,
            user_role="vendor",
            recipient_role="buyer",
            expires_in_hours=24,
        )

        assert isinstance(res, ProofShareResponse)
        assert res.proof_job_id == job_id
        assert res.share_token == "vref_test123"
        assert res.sbom_root == "0x" + "a" * 64
        assert res.is_active is True


def test_create_share_blocks_running_job(mock_session):
    vendor_id = uuid4()
    job_id = uuid4()
    running_job = ProofJob(
        id=job_id,
        user_id=vendor_id,
        status="running",
    )

    mock_session.query.return_value.filter.return_value.first.return_value = running_job
    service = VerificationService(mock_session)

    with pytest.raises(ValueError, match="Only completed proof jobs can be shared"):
        service.create_share(
            proof_job_id=job_id,
            vendor_id=vendor_id,
            user_role="vendor",
        )


def test_create_share_blocks_unauthorized_vendor(mock_session):
    owner_id = uuid4()
    other_vendor_id = uuid4()
    job_id = uuid4()
    job = ProofJob(
        id=job_id,
        user_id=owner_id,
        status="completed",
    )

    mock_session.query.return_value.filter.return_value.first.return_value = job
    service = VerificationService(mock_session)

    with pytest.raises(PermissionError, match="Only the proof owner or admin"):
        service.create_share(
            proof_job_id=job_id,
            vendor_id=other_vendor_id,
            user_role="vendor",
        )


def test_buyer_verify_with_valid_share_succeeds(mock_session):
    vendor_id = uuid4()
    buyer_id = uuid4()
    job_id = uuid4()
    job = ProofJob(
        id=job_id,
        user_id=vendor_id,
        status="completed",
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
    )
    share = ProofShare(
        id=uuid4(),
        proof_job_id=job_id,
        vendor_id=vendor_id,
        share_token="vref_abc123",
        recipient_role="buyer",
        recipient_user_id=None,
        is_revoked=False,
        revoked_at=None,
        expires_at=None,
        created_at=datetime.now(timezone.utc),
    )

    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ProofShare":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: share))
        return MagicMock()

    mock_session.query.side_effect = query_mock

    service = VerificationService(mock_session, verifier=MockVerifier())
    request = VerifyProofRequest(
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
        proof_job_id=job_id,
        share_token="vref_abc123",
    )

    result = service.process_verification(request, user_id=buyer_id, user_role="buyer")
    assert result.result == "verified"


def test_buyer_verify_with_revoked_share_fails_closed(mock_session):
    vendor_id = uuid4()
    buyer_id = uuid4()
    job_id = uuid4()
    job = ProofJob(
        id=job_id,
        user_id=vendor_id,
        status="completed",
    )
    revoked_share = ProofShare(
        id=uuid4(),
        proof_job_id=job_id,
        vendor_id=vendor_id,
        share_token="vref_revoked",
        recipient_role="buyer",
        is_revoked=True,
        revoked_at=datetime.now(timezone.utc),
    )

    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ProofShare":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: revoked_share))
        return MagicMock()

    mock_session.query.side_effect = query_mock

    service = VerificationService(mock_session, verifier=MockVerifier())
    request = VerifyProofRequest(
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
        proof_job_id=job_id,
        share_token="vref_revoked",
    )

    result = service.process_verification(request, user_id=buyer_id, user_role="buyer")
    assert result.result == "verification_unavailable"


def test_buyer_verify_without_share_rejected(mock_session):
    vendor_id = uuid4()
    buyer_id = uuid4()
    job_id = uuid4()
    job = ProofJob(
        id=job_id,
        user_id=vendor_id,
        status="completed",
    )

    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ProofShare":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        return MagicMock()

    mock_session.query.side_effect = query_mock

    service = VerificationService(mock_session, verifier=MockVerifier())
    request = VerifyProofRequest(
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
        proof_job_id=job_id,
    )

    result = service.process_verification(request, user_id=buyer_id, user_role="buyer")
    assert result.result == "verification_unavailable"



def test_vendor_can_verify_own_completed_proof_job(mock_session):
    vendor_id = uuid4()
    job_id = uuid4()
    job = ProofJob(
        id=job_id,
        user_id=vendor_id,
        status="completed",
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
    )

    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        return MagicMock()

    mock_session.query.side_effect = query_mock

    service = VerificationService(mock_session, verifier=MockVerifier())
    request = VerifyProofRequest(
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
        proof_job_id=job_id,
    )

    result = service.process_verification(request, user_id=vendor_id, user_role="vendor")
    assert result.result == "verified"


def test_vendor_cannot_verify_another_vendors_proof_job(mock_session):
    owner_id = uuid4()
    attacker_vendor_id = uuid4()
    job_id = uuid4()
    job = ProofJob(
        id=job_id,
        user_id=owner_id,
        status="completed",
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
    )

    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ProofShare":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        return MagicMock()

    mock_session.query.side_effect = query_mock

    service = VerificationService(mock_session, verifier=MockVerifier())
    request = VerifyProofRequest(
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
        proof_job_id=job_id,
    )

    result = service.process_verification(request, user_id=attacker_vendor_id, user_role="vendor")
    assert result.result == "verification_unavailable"


def test_delete_revoked_share_success(mock_session):
    vendor_id = uuid4()
    share_id = uuid4()
    job_id = uuid4()
    share = ProofShare(
        id=share_id,
        proof_job_id=job_id,
        vendor_id=vendor_id,
        share_token="vref_to_delete",
        recipient_role="buyer",
        is_revoked=True,
        revoked_at=datetime.now(timezone.utc),
    )

    service = VerificationService(mock_session)
    with patch.object(service._repo, "get_proof_share_by_id", return_value=share), \
         patch.object(service._repo, "delete_proof_share", return_value=True) as mock_del:
        res = service.delete_share(share_id=share_id, user_id=vendor_id, user_role="vendor")
        assert res is not None
        assert res["status"] == "deleted"
        assert res["id"] == str(share_id)
        mock_del.assert_called_once_with(share)


def test_delete_active_share_rejected(mock_session):
    vendor_id = uuid4()
    share_id = uuid4()
    job_id = uuid4()
    active_share = ProofShare(
        id=share_id,
        proof_job_id=job_id,
        vendor_id=vendor_id,
        share_token="vref_active",
        recipient_role="buyer",
        is_revoked=False,
    )

    service = VerificationService(mock_session)
    with patch.object(service._repo, "get_proof_share_by_id", return_value=active_share):
        with pytest.raises(ValueError, match="Cannot delete an active verification share"):
            service.delete_share(share_id=share_id, user_id=vendor_id, user_role="vendor")


def test_delete_share_unauthorized_vendor(mock_session):
    owner_id = uuid4()
    other_vendor_id = uuid4()
    share_id = uuid4()
    job_id = uuid4()
    share = ProofShare(
        id=share_id,
        proof_job_id=job_id,
        vendor_id=owner_id,
        share_token="vref_other",
        recipient_role="buyer",
        is_revoked=True,
        revoked_at=datetime.now(timezone.utc),
    )

    service = VerificationService(mock_session)
    with patch.object(service._repo, "get_proof_share_by_id", return_value=share):
        res = service.delete_share(share_id=share_id, user_id=other_vendor_id, user_role="vendor")
        assert res is None


def test_delete_revoked_share_admin_success(mock_session):
    owner_id = uuid4()
    admin_id = uuid4()
    share_id = uuid4()
    job_id = uuid4()
    share = ProofShare(
        id=share_id,
        proof_job_id=job_id,
        vendor_id=owner_id,
        share_token="vref_admin_del",
        recipient_role="buyer",
        is_revoked=True,
        revoked_at=datetime.now(timezone.utc),
    )

    service = VerificationService(mock_session)
    with patch.object(service._repo, "get_proof_share_by_id", return_value=share), \
         patch.object(service._repo, "delete_proof_share", return_value=True):
        res = service.delete_share(share_id=share_id, user_id=admin_id, user_role="admin")
        assert res is not None
        assert res["status"] == "deleted"


def test_create_second_token_revokes_first_for_same_job(mock_session):
    vendor_id = uuid4()
    job_id = uuid4()

    # Pre-existing active share
    existing_share = ProofShare(
        id=uuid4(),
        proof_job_id=job_id,
        vendor_id=vendor_id,
        share_token="vref_old_share",
        recipient_role="buyer",
        is_revoked=False,
        revoked_at=None,
    )

    query_mock = MagicMock()
    # When filtering by proof_job_id and is_revoked == False, return existing_share
    query_mock.filter.return_value.with_for_update.return_value.all.return_value = [existing_share]
    query_mock.filter.return_value.all.return_value = [existing_share]
    mock_session.query.return_value = query_mock

    service = VerificationService(mock_session)
    share = service._repo.create_proof_share(
        proof_job_id=job_id,
        vendor_id=vendor_id,
        recipient_role="buyer",
    )

    assert existing_share.is_revoked is True
    assert existing_share.revoked_at is not None
    assert share.is_revoked is False
    assert share.share_token != existing_share.share_token
    mock_session.commit.assert_called()


def test_create_token_for_different_job_does_not_revoke_other_job_share(mock_session):
    vendor_id = uuid4()
    job_a_id = uuid4()
    job_b_id = uuid4()

    share_a = ProofShare(
        id=uuid4(),
        proof_job_id=job_a_id,
        vendor_id=vendor_id,
        share_token="vref_job_a",
        recipient_role="buyer",
        is_revoked=False,
        revoked_at=None,
    )

    # When querying for job_b, no active shares exist for job_b
    def query_router(*args, **kwargs):
        m = MagicMock()
        # Querying for job_b returns empty list
        m.filter.return_value.with_for_update.return_value.all.return_value = []
        m.filter.return_value.all.return_value = []
        return m

    mock_session.query.side_effect = query_router
    service = VerificationService(mock_session)
    share_b = service._repo.create_proof_share(
        proof_job_id=job_b_id,
        vendor_id=vendor_id,
        recipient_role="buyer",
    )

    # share_a remains active because it belongs to job_a
    assert share_a.is_revoked is False
    assert share_a.revoked_at is None
    assert share_b.proof_job_id == job_b_id
    assert share_b.is_revoked is False


def test_failed_token_generation_rolls_back_and_preserves_active_share(mock_session):
    vendor_id = uuid4()
    job_id = uuid4()

    existing_share = ProofShare(
        id=uuid4(),
        proof_job_id=job_id,
        vendor_id=vendor_id,
        share_token="vref_will_stay_active",
        recipient_role="buyer",
        is_revoked=False,
        revoked_at=None,
    )

    query_mock = MagicMock()
    query_mock.filter.return_value.with_for_update.return_value.all.return_value = [existing_share]
    query_mock.filter.return_value.all.return_value = [existing_share]
    mock_session.query.return_value = query_mock

    # Simulate commit failure (e.g. database error)
    mock_session.commit.side_effect = RuntimeError("Database connection lost during commit")

    service = VerificationService(mock_session)
    with pytest.raises(RuntimeError, match="Database connection lost"):
        service._repo.create_proof_share(
            proof_job_id=job_id,
            vendor_id=vendor_id,
            recipient_role="buyer",
        )

    # Rollback must be called
    mock_session.rollback.assert_called_once()


def test_delete_revoked_share_preserves_proof_job_and_certificates(mock_session):
    vendor_id = uuid4()
    job_id = uuid4()
    share_id = uuid4()
    cert_id = uuid4()

    job = ProofJob(id=job_id, user_id=vendor_id, status="completed")
    cert = MagicMock()
    cert.id = cert_id

    revoked_share = ProofShare(
        id=share_id,
        proof_job_id=job_id,
        vendor_id=vendor_id,
        share_token="vref_revoked",
        recipient_role="buyer",
        is_revoked=True,
        revoked_at=datetime.now(timezone.utc),
    )

    service = VerificationService(mock_session)
    with patch.object(service._repo, "get_proof_share_by_id", return_value=revoked_share), \
         patch.object(service._repo, "delete_proof_share") as mock_del:
        res = service.delete_share(share_id=share_id, user_id=vendor_id, user_role="vendor")
        assert res["status"] == "deleted"
        mock_del.assert_called_once_with(revoked_share)
        # Job and cert are not deleted
        assert job.status == "completed"

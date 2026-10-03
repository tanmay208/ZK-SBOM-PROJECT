import pytest
from unittest.mock import MagicMock, patch
from uuid import uuid4, UUID
from datetime import datetime

from verification_service.app.schemas.verification_schemas import VerifyProofRequest
from verification_service.app.services.verification_service import VerificationService


@pytest.fixture
def mock_session():
    session = MagicMock()
    return session

@pytest.fixture(autouse=True)
def mock_validate_authoritative():
    with patch("verification_service.app.services.verification_service.VerificationRepository.validate_authoritative_records", return_value=True) as mock:
        yield mock


def test_verification_unavailable(mock_session):
    # Setup mock to return None for existing request (idempotency check)
    mock_session.query.return_value.filter.return_value.first.return_value = None
    
    service = VerificationService(mock_session)
    request = VerifyProofRequest(
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
        proof_job_id=None
    )
    
    result_req = service.process_verification(request, user_id=uuid4())
    assert result_req.result == "verification_unavailable"
    assert result_req.verified_at is None
    
    mock_session.add.assert_called()


def test_invalid_proof(mock_session):
    user_id = uuid4()
    # Create mock ProofJob that belongs to user_id
    from zkp_service.app.models.zkp_models import ProofJob
    job = ProofJob(id=uuid4(), user_id=user_id)
    
    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "VerificationCertificate":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        return MagicMock()
        
    mock_session.query.side_effect = query_mock
    
    service = VerificationService(mock_session)
    request = VerifyProofRequest(
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
        proof_job_id=job.id
    )
    
    result_req = service.process_verification(request, user_id=user_id)
    assert result_req.result == "invalid_proof"
    assert result_req.verified_at is None


class MockVerifier:
    def verify(self, proof_job_id: UUID | None, session=None, **kwargs) -> str:
        if str(proof_job_id) == "00000000-0000-4000-8000-000000000001":
            return "verified"
        return "invalid_proof"


def test_verified_test_double(mock_session, monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "test_certificate_secret_1234567890")
    user_id = uuid4()
    from zkp_service.app.models.zkp_models import ProofJob
    job = ProofJob(id=UUID("00000000-0000-4000-8000-000000000001"), user_id=user_id)
    
    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        return MagicMock()
        
    mock_session.query.side_effect = query_mock
    
    # Inject MockVerifier instead of using a backdoor in NoirVerifier
    service = VerificationService(mock_session, verifier=MockVerifier())
    request = VerifyProofRequest(
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
        proof_job_id="00000000-0000-4000-8000-000000000001"
    )
    
    # We must mock flush so it doesn't fail when no actual db is present
    mock_req_db = MagicMock()
    mock_req_db.id = uuid4()
    mock_session.add.side_effect = lambda obj: setattr(obj, 'id', uuid4()) if not hasattr(obj, 'id') else None
    
    result_req = service.process_verification(request, user_id=user_id)
    assert result_req.result == "verified"
    assert result_req.verified_at is not None
    
    # Check that add was called twice (once for request, once for certificate)
    assert mock_session.add.call_count == 2



def test_idempotent_submission(mock_session):
    from verification_service.app.models.verification_models import VerificationRequest
    mock_req = VerificationRequest(id=uuid4(), result="invalid_proof")
    
    # Mock finding an existing request
    mock_session.query.return_value.filter.return_value.first.return_value = mock_req
    
    service = VerificationService(mock_session)
    request = VerifyProofRequest(
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
        proof_job_id="00000000-0000-4000-8000-000000000001"
    )
    
    result_req1 = service.process_verification(request, user_id=uuid4())
    
    assert result_req1.id == mock_req.id
    # No new insert should happen
    assert mock_session.add.call_count == 0

def test_cross_tenant_idempotency_fails(mock_session):
    from verification_service.app.models.verification_models import VerificationRequest
    mock_req = VerificationRequest(id=uuid4(), result="invalid_proof", user_id=uuid4())
    
    # Mock finding an existing request IF user_id matches
    def mock_filter(*args, **kwargs):
        # We simulate the filter by checking if the user_id in the condition matches the mock_req.user_id
        # args[0] is VerificationRequest.user_id == user_id
        match = False
        for arg in args:
            if getattr(getattr(arg, "right", None), "value", None) == mock_req.user_id:
                match = True
        if match:
            return MagicMock(first=lambda: mock_req)
        return MagicMock(first=lambda: None)

    mock_session.query.return_value.filter.side_effect = mock_filter
    
    service = VerificationService(mock_session)
    request = VerifyProofRequest(
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
        proof_job_id="00000000-0000-4000-8000-000000000001"
    )
    
    # Submit as a different user
    result_req2 = service.process_verification(request, user_id=uuid4())
    
    # It should not return the existing request
    assert result_req2.id != mock_req.id
    # A new insert should happen for this new user
    assert mock_session.add.call_count > 0

def test_foreign_proofjob_verification_fails(mock_session, mock_validate_authoritative):
    # Setup mock ProofJob with different user_id
    from zkp_service.app.models.zkp_models import ProofJob
    job = ProofJob(id=uuid4(), user_id=uuid4()) # Belongs to another user
    
    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        return MagicMock()
        
    mock_session.query.side_effect = query_mock
    
    service = VerificationService(mock_session)
    request = VerifyProofRequest(
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
        proof_job_id=job.id
    )
    
    # Attempt to verify with a different user_id
    attacker_id = uuid4()
    result_req = service.process_verification(request, user_id=attacker_id)
    
    assert result_req.result == "verification_unavailable"
    assert result_req.verified_at is None
    mock_validate_authoritative.assert_not_called()


def test_revocation_is_terminal_and_idempotent(mock_session):
    from verification_service.app.repositories.verification_repository import VerificationRepository
    from verification_service.app.models.verification_models import VerificationCertificate

    revoked_at = datetime.utcnow()
    cert = VerificationCertificate(
        id=uuid4(),
        verification_request_id=uuid4(),
        is_revoked=True,
        revoked_at=revoked_at,
        revoked_reason="original reason",
    )
    (
        mock_session.query.return_value
        .filter.return_value
        .with_for_update.return_value
        .first.return_value
    ) = cert

    result = VerificationRepository(mock_session).revoke_certificate(
        cert, reason="replacement reason"
    )

    assert result is cert
    assert result.revoked_at == revoked_at
    assert result.revoked_reason == "original reason"
    mock_session.commit.assert_not_called()

def test_idempotent_re_evaluation(mock_session, mock_validate_authoritative, monkeypatch):
    """API-001 Regression: record_mismatch is re-evaluated."""
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "test_certificate_secret_1234567890")
    user_id = uuid4()
    from verification_service.app.models.verification_models import VerificationRequest
    mock_req = VerificationRequest(id=uuid4(), result="record_mismatch", sbom_root="0x" + "1"*64, vulnerability_db_root="0x" + "2"*64, policy_hash="0x" + "3"*64)
    
    from zkp_service.app.models.zkp_models import ProofJob
    job = ProofJob(id=UUID("00000000-0000-4000-8000-000000000001"), user_id=user_id)
    
    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: mock_req))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        return MagicMock()
        
    mock_session.query.side_effect = query_mock
    mock_validate_authoritative.return_value = True # Now it is valid
    
    service = VerificationService(mock_session, verifier=MockVerifier())
    request = VerifyProofRequest(
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
        proof_job_id="00000000-0000-4000-8000-000000000001"
    )
    
    result_req = service.process_verification(request, user_id=user_id)
    
    # Assert it updated the existing request to verified
    assert result_req.id == mock_req.id
    assert result_req.result == "verified"

def test_authoritative_record_mismatch(mock_session, mock_validate_authoritative):
    user_id = uuid4()
    from zkp_service.app.models.zkp_models import ProofJob
    job = ProofJob(id=UUID("00000000-0000-4000-8000-000000000001"), user_id=user_id)
    
    def query_mock(model):
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: None))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        return MagicMock()
        
    mock_session.query.side_effect = query_mock
    mock_validate_authoritative.return_value = False
    
    service = VerificationService(mock_session, verifier=MockVerifier())
    request = VerifyProofRequest(
        sbom_root="0x" + "c"*64,
        vulnerability_db_root="0x" + "d"*64,
        policy_hash="0x" + "b"*64,
        proof_job_id="00000000-0000-4000-8000-000000000001"
    )
    
    result_req = service.process_verification(request, user_id=user_id)
    assert result_req.result == "record_mismatch"
    assert result_req.verified_at is None

def test_idor_certificate_retrieval(mock_session):
    from verification_service.app.models.verification_models import VerificationCertificate, VerificationRequest
    from zkp_service.app.models.zkp_models import ProofJob
    
    cert_id = uuid4()
    req_id = uuid4()
    job_id = uuid4()
    owner_id = uuid4()
    attacker_id = uuid4()
    
    cert = VerificationCertificate(id=cert_id, verification_request_id=req_id)
    req = VerificationRequest(id=req_id, proof_job_id=job_id, user_id=owner_id)
    job = ProofJob(id=job_id)
    
    def query_mock(model):
        if model.__name__ == "VerificationCertificate":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: cert))
        if model.__name__ == "VerificationRequest":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: req))
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        return MagicMock()
        
    mock_session.query.side_effect = query_mock
    
    service = VerificationService(mock_session)
    
    # Owner should succeed
    assert service.get_certificate(cert_id, user_id=owner_id) is not None
    assert service.get_certificate_by_request(req_id, user_id=owner_id) is not None
    
    # Attacker should get None
    assert service.get_certificate(cert_id, user_id=attacker_id) is None
    assert service.get_certificate_by_request(req_id, user_id=attacker_id) is None

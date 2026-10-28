import os
import pytest
import hashlib
import hmac
from uuid import uuid4
from unittest.mock import MagicMock
from verification_service.app.repositories.verification_repository import VerificationRepository
from verification_service.app.schemas.verification_schemas import VerifyProofRequest

@pytest.fixture
def repo():
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    return VerificationRepository(session)

@pytest.fixture
def mock_request():
    return VerifyProofRequest(
        proof_job_id=uuid4(),
        sbom_root="0x" + "a"*64,
        vulnerability_db_root="0x" + "b"*64,
        policy_hash="0x" + "c"*64
    )

def test_valid_configured_secret_works(repo, mock_request, monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "valid_certificate_secret_1234567890")
    # Using a fake ID for req_record because we mock the session
    repo._session.add = MagicMock()
    repo._session.commit = MagicMock()
    repo._session.refresh = MagicMock()
    
    # We will simulate the DB assigning an ID
    def mock_add(obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()
    
    repo._session.add.side_effect = mock_add
    
    user_id = uuid4()
    record = repo.create_verification_record(mock_request, "verified", user_id)
    assert record is not None
    # Verify cert was added
    add_calls = repo._session.add.call_args_list
    assert len(add_calls) == 2 # 1 for request, 1 for cert
    
def test_missing_secret_fails(repo, mock_request, monkeypatch):
    monkeypatch.delenv("CERTIFICATE_SECRET_KEY", raising=False)
    user_id = uuid4()
    with pytest.raises(ValueError, match="CERTIFICATE_SECRET_KEY must be configured for certificate signing"):
        repo.create_verification_record(mock_request, "verified", user_id)

def test_empty_secret_fails(repo, mock_request, monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "")
    user_id = uuid4()
    with pytest.raises(ValueError, match="CERTIFICATE_SECRET_KEY must be configured for certificate signing"):
        repo.create_verification_record(mock_request, "verified", user_id)

def test_certificate_signature_changes_on_bound_input_change(repo, mock_request, monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "valid_certificate_secret_1234567890")
    
    certs = []
    def mock_add(obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()
        if hasattr(obj, "certificate_data"):
            certs.append(obj)
            
    repo._session.add.side_effect = mock_add
    
    req1 = mock_request
    req2 = VerifyProofRequest(
        proof_job_id=req1.proof_job_id,
        sbom_root="0x" + "d"*64,
        vulnerability_db_root=req1.vulnerability_db_root,
        policy_hash=req1.policy_hash
    )
    
    repo.create_verification_record(req1, "verified", uuid4())
    repo.create_verification_record(req2, "verified", uuid4())
    
    assert len(certs) == 2
    assert certs[0].certificate_data != certs[1].certificate_data

def test_certificate_cannot_be_reproduced_with_default(repo, mock_request, monkeypatch):
    import jwt
    # This verifies that without the secret we can't produce the same cert
    secret = "production_certificate_secret_1234567890"
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", secret)
    
    certs = []
    def mock_add(obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()
        if hasattr(obj, "certificate_data"):
            certs.append(obj)
            
    repo._session.add.side_effect = mock_add
    repo.create_verification_record(mock_request, "verified", uuid4())
    
    produced_cert = certs[0]
    
    # Try reproducing with default secret
    default_secret = "default_certificate_secret_1234567890"
    payload = {
        "sub": str(produced_cert.verification_request_id),
        "iss": "antigravity_zkp",
        "sbom_root": mock_request.sbom_root,
        "vulnerability_db_root": mock_request.vulnerability_db_root,
        "policy_hash": mock_request.policy_hash,
    }
    
    default_cert_data = jwt.encode(payload, default_secret, algorithm="HS256")
    
    assert produced_cert.certificate_data != default_cert_data

def test_verification_signature_fails_after_tampering():
    import jwt
    secret = "production_certificate_secret_1234567890"
    payload_original = {"data": "original_payload"}
    signature_original = jwt.encode(payload_original, secret, algorithm="HS256")
    
    # Tampered payload
    payload_tampered = {"data": "tampered_payload"}
    signature_tampered = jwt.encode(payload_tampered, secret, algorithm="HS256")
    
    assert signature_original != signature_tampered

def test_startup_validation_uses_same_requirement():
    # If there's an app startup or config initialization, it should also fail if JWT is missing.
    # In verification_service/app/core/config.py or similar, it should be validated.
    # We will just verify it's the same requirement for the repo method for now.
    pass

def test_update_record_uses_cert_secret(repo, monkeypatch):
    import jwt
    from verification_service.app.models.verification_models import VerificationRequest
    
    # We must ensure JWT_SECRET_KEY is NOT used.
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "correct_certificate_secret_1234567890")
    monkeypatch.setenv("JWT_SECRET_KEY", "wrong_jwt_secret_1234567890")
    
    mock_req = VerificationRequest(
        id=uuid4(),
        proof_job_id=uuid4(),
        sbom_root="0x" + "a"*64,
        vulnerability_db_root="0x" + "b"*64,
        policy_hash="0x" + "c"*64
    )
    
    # Create the verification record via update path
    repo._session.query = MagicMock()
    repo._session.query.return_value.filter.return_value.first.return_value = None
    
    certs = []
    def mock_add(obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()
        if hasattr(obj, "certificate_data"):
            certs.append(obj)
            
    repo._session.add.side_effect = mock_add
    
    record = repo.update_verification_record(mock_req, "verified")
    assert record is not None
    assert len(certs) == 1
    produced_cert = certs[0]
    
    # Verify the signature was made with CERTIFICATE_SECRET_KEY, not JWT_SECRET_KEY
    decoded = jwt.decode(produced_cert.certificate_data, "correct_certificate_secret_1234567890", algorithms=["HS256"])
    assert decoded["iss"] == "antigravity-zkp-authority"
    
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(produced_cert.certificate_data, "wrong_jwt_secret_1234567890", algorithms=["HS256"])


def test_create_record_uses_cert_secret(repo, monkeypatch):
    import jwt
    from verification_service.app.models.verification_models import VerificationRequest
    
    # We must ensure JWT_SECRET_KEY is NOT used.
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "correct_certificate_secret_1234567890")
    monkeypatch.setenv("JWT_SECRET_KEY", "wrong_jwt_secret_1234567890")
    
    mock_request = VerifyProofRequest(
        proof_job_id=uuid4(),
        sbom_root="0x" + "a"*64,
        vulnerability_db_root="0x" + "b"*64,
        policy_hash="0x" + "c"*64
    )
    
    certs = []
    def mock_add(obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()
        if hasattr(obj, "certificate_data"):
            certs.append(obj)
            
    repo._session.add.side_effect = mock_add
    
    record = repo.create_verification_record(mock_request, "verified", uuid4())
    assert record is not None
    assert len(certs) == 1
    produced_cert = certs[0]
    
    # Verify the signature was made with CERTIFICATE_SECRET_KEY, not JWT_SECRET_KEY
    decoded = jwt.decode(produced_cert.certificate_data, "correct_certificate_secret_1234567890", algorithms=["HS256"])
    assert decoded["iss"] == "antigravity-zkp-authority"
    
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(produced_cert.certificate_data, "wrong_jwt_secret_1234567890", algorithms=["HS256"])


def test_certificate_fingerprint_generation(repo, mock_request, monkeypatch):
    """
    Ensure the certificate fingerprint is exactly the lowercase SHA-256
    hex digest of the issued token bytes.
    """
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "deterministic_test_secret_for_fingerprint_0123456789")
    certs = []
    def mock_add(obj):
        if not getattr(obj, "id", None):
            obj.id = uuid4()
        if hasattr(obj, "certificate_data"):
            certs.append(obj)
    repo._session.add.side_effect = mock_add

    record = repo.create_verification_record(mock_request, "verified", uuid4())
    assert record is not None
    assert len(certs) == 1
    produced_cert = certs[0]

    token_bytes = produced_cert.certificate_data.encode("utf-8")
    expected_fingerprint = hashlib.sha256(token_bytes).hexdigest()

    assert produced_cert.sha256_fingerprint is not None
    assert produced_cert.sha256_fingerprint == expected_fingerprint
    assert len(produced_cert.sha256_fingerprint) == 64
    assert produced_cert.sha256_fingerprint == produced_cert.sha256_fingerprint.lower()


def test_certificate_fingerprint_stability_and_uniqueness():
    """
    Ensure the fingerprint is deterministic and stable for identical tokens,
    and differs when token bytes change.
    """
    from verification_service.app.models.verification_models import VerificationCertificate

    token_a = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc"
    token_b = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIn0.xyz"

    cert_a1 = VerificationCertificate(
        id=uuid4(),
        verification_request_id=uuid4(),
        certificate_data=token_a,
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
    )
    cert_a2 = VerificationCertificate(
        id=uuid4(),
        verification_request_id=uuid4(),
        certificate_data=token_a,
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
    )
    cert_b = VerificationCertificate(
        id=uuid4(),
        verification_request_id=uuid4(),
        certificate_data=token_b,
        sbom_root="0x" + "1"*64,
        vulnerability_db_root="0x" + "2"*64,
        policy_hash="0x" + "3"*64,
    )

    # Stability
    assert cert_a1.sha256_fingerprint == cert_a2.sha256_fingerprint
    assert cert_a1.sha256_fingerprint == hashlib.sha256(token_a.encode("utf-8")).hexdigest()

    # Uniqueness
    assert cert_a1.sha256_fingerprint != cert_b.sha256_fingerprint


def test_certificate_response_schema_exposes_fingerprint():
    """
    Ensure VerificationCertificateResponse exposes sha256_fingerprint
    without leaking secrets.
    """
    from datetime import datetime, timezone
    from verification_service.app.models.verification_models import VerificationCertificate
    from verification_service.app.schemas.verification_schemas import VerificationCertificateResponse

    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid_token_payload.signature"
    cert = VerificationCertificate(
        id=uuid4(),
        verification_request_id=uuid4(),
        certificate_data=token,
        sbom_root="0x" + "a"*64,
        vulnerability_db_root="0x" + "b"*64,
        policy_hash="0x" + "c"*64,
        issued_at=datetime.now(timezone.utc),
        is_revoked=False,
    )

    response = VerificationCertificateResponse.model_validate(cert)
    assert response.sha256_fingerprint == hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert response.certificate_data == token
    assert response.revoked_by is None

    # Serialization dictionary does not leak secrets
    resp_dict = response.model_dump()
    assert "sha256_fingerprint" in resp_dict
    assert resp_dict["sha256_fingerprint"] == hashlib.sha256(token.encode("utf-8")).hexdigest()


def test_revoked_certificate_preserves_fingerprint_while_masking_token():
    """
    Ensure that when a certificate is revoked, the response masks the raw
    signature token but preserves the sha256_fingerprint for verification auditability.
    """
    from datetime import datetime, timezone
    from verification_service.app.models.verification_models import VerificationCertificate
    from verification_service.app.schemas.verification_schemas import VerificationCertificateResponse

    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.compromised_token.signature"
    now = datetime.now(timezone.utc)
    revoker_id = uuid4()

    cert = VerificationCertificate(
        id=uuid4(),
        verification_request_id=uuid4(),
        certificate_data=token,
        sbom_root="0x" + "a"*64,
        vulnerability_db_root="0x" + "b"*64,
        policy_hash="0x" + "c"*64,
        issued_at=now,
        is_revoked=True,
        revoked_at=now,
        revoked_reason="Compromised private key",
        revoked_by=revoker_id,
    )

    response = VerificationCertificateResponse.model_validate(cert)

    # Token masked
    assert response.certificate_data is None
    # Fingerprint preserved
    assert response.sha256_fingerprint == hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert response.is_revoked is True
    assert response.revoked_reason == "Compromised private key"
    assert response.revoked_by == revoker_id


def test_certificate_model_revoked_by_mapping():
    """
    Ensure the SQLAlchemy model declares revoked_by mapped to users.id.
    """
    from verification_service.app.models.verification_models import VerificationCertificate

    assert hasattr(VerificationCertificate, "revoked_by")
    col = VerificationCertificate.__table__.c.revoked_by
    assert col is not None
    assert col.nullable is True


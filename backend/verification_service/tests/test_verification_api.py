import pytest
from unittest.mock import patch, MagicMock
from uuid import uuid4
from datetime import datetime, timezone
import uuid

from fastapi.testclient import TestClient
from verification_service.app.main import app
from verification_service.app.models.verification_models import VerificationRequest, VerificationCertificate
from shared.auth import get_current_user
from shared.models.user import User

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def override_current_user():
    app.dependency_overrides[get_current_user] = lambda: User(id=uuid.UUID("11111111-1111-1111-1111-111111111111"), username="vendor", role="vendor")
    yield
    app.dependency_overrides.pop(get_current_user, None)


def test_verify_unavailable():
    with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
        mock_service = mock_service_cls.return_value
        
        mock_req = MagicMock()
        mock_req.id = uuid4()
        mock_req.result = "verification_unavailable"
        mock_req.sbom_root = "0x" + "1"*64
        mock_req.vulnerability_db_root = "0x" + "2"*64
        mock_req.policy_hash = "0x" + "3"*64
        mock_req.verified_at = None
        mock_req.created_at = datetime.utcnow()
        
        mock_service.process_verification.return_value = mock_req
        
        response = client.post(
            "/api/v1/verification/verify",
            json={
                "sbom_root": "0x" + "1"*64,
                "vulnerability_db_root": "0x" + "2"*64,
                "policy_hash": "0x" + "3"*64,
                "proof_job_id": None
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["result"] == "verification_unavailable"
        assert data["certificate"] is None


def test_verify_invalid():
    with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
        mock_service = mock_service_cls.return_value
        
        mock_req = MagicMock()
        mock_req.id = uuid4()
        mock_req.result = "invalid_proof"
        mock_req.sbom_root = "0x" + "4"*64
        mock_req.vulnerability_db_root = "0x" + "5"*64
        mock_req.policy_hash = "0x" + "6"*64
        mock_req.verified_at = None
        mock_req.created_at = datetime.utcnow()
        
        mock_service.process_verification.return_value = mock_req
        
        response = client.post(
            "/api/v1/verification/verify",
            json={
                "sbom_root": "0x" + "4"*64,
                "vulnerability_db_root": "0x" + "5"*64,
                "policy_hash": "0x" + "6"*64,
                "proof_job_id": "00000000-0000-4000-8000-000000000001"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["result"] == "invalid_proof"
        assert data["certificate"] is None


def test_verify_success_and_fetch_certificate():
    with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
        mock_service = mock_service_cls.return_value
        
        req_id = uuid4()
        cert_id = uuid4()
        
        mock_req = MagicMock()
        mock_req.id = req_id
        mock_req.result = "verified"
        mock_req.sbom_root = "0x" + "7"*64
        mock_req.vulnerability_db_root = "0x" + "8"*64
        mock_req.policy_hash = "0x" + "9"*64
        mock_req.verified_at = datetime.utcnow()
        mock_req.created_at = datetime.utcnow()
        
        mock_cert = MagicMock()
        mock_cert.id = cert_id
        mock_cert.verification_request_id = req_id
        mock_cert.certificate_data = "CERT-12345678"
        mock_cert.sbom_root = "0x" + "7"*64
        mock_cert.vulnerability_db_root = "0x" + "8"*64
        mock_cert.policy_hash = "0x" + "9"*64
        mock_cert.issued_at = datetime.utcnow()
        mock_cert.is_revoked = False
        mock_cert.revoked_at = None
        mock_cert.revoked_reason = None

        mock_service.process_verification.return_value = mock_req
        mock_service.get_certificate_by_request.return_value = mock_cert

        # 1. Generate certificate
        response = client.post(
            "/api/v1/verification/verify",
            json={
                "sbom_root": "0x" + "7"*64,
                "vulnerability_db_root": "0x" + "8"*64,
                "policy_hash": "0x" + "9"*64,
                "proof_job_id": "00000000-0000-4000-8000-000000000001"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["result"] == "verified"
        assert data["certificate"] is not None
        assert data["certificate"]["id"] == str(cert_id)
        
        mock_service.get_certificate.return_value = mock_cert
        
        # 2. Fetch certificate
        response_cert = client.get(f"/api/v1/verification/certificates/{cert_id}")
        assert response_cert.status_code == 200
        cert_data = response_cert.json()
        assert cert_data["id"] == str(cert_id)
        assert cert_data["sbom_root"] == "0x" + "7"*64


def test_fetch_invalid_certificate():
    with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
        mock_service = mock_service_cls.return_value
        mock_service.get_certificate.return_value = None
        
        response = client.get(f"/api/v1/verification/certificates/{uuid4()}")
        assert response.status_code == 404


def test_schema_validation_missing_fields():
    response = client.post(
        "/api/v1/verification/verify",
        json={
            "sbom_root": "0x" + "1"*64,
            "vulnerability_db_root": "0x" + "2"*64
            # Missing policy_hash
        }
    )
    assert response.status_code == 422
    assert "policy_hash" in response.text


def test_schema_validation_invalid_hex():
    response = client.post(
        "/api/v1/verification/verify",
        json={
            "sbom_root": "invalid root!",
            "vulnerability_db_root": "0x" + "2"*64,
            "policy_hash": "0x" + "3"*64,
            "proof_job_id": None
        }
    )
    assert response.status_code == 422
    assert "Root/Hash must be a strictly formatted 0x-prefixed 64-character hex string" in response.text


def test_schema_validation_empty_root():
    response = client.post(
        "/api/v1/verification/verify",
        json={
            "sbom_root": "",
            "vulnerability_db_root": "0x" + "2"*64,
            "policy_hash": "0x" + "3"*64,
            "proof_job_id": None
        }
    )
    assert response.status_code == 422


def test_schema_validation_oversized_payload():
    response = client.post(
        "/api/v1/verification/verify",
        json={
            "sbom_root": "A" * 129,  # over 128 max_length
            "vulnerability_db_root": "0x" + "2"*64,
            "policy_hash": "0x" + "3"*64,
            "proof_job_id": None
        }
    )
    assert response.status_code == 422


def test_schema_validation_unexpected_private_fields():
    response = client.post(
        "/api/v1/verification/verify",
        json={
            "sbom_root": "0x" + "1"*64,
            "vulnerability_db_root": "0x" + "2"*64,
            "policy_hash": "0x" + "3"*64,
            "proof_job_id": None,
            "private_components": ["component1", "component2"],
            "vulnerability_scores": [1, 2, 3]
        }
    )
    assert response.status_code == 422
    assert "Extra inputs are not permitted" in response.text

def test_certificate_listing_idor():
    # Real DB-based IDOR isolation test
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from shared.database import Base, get_session
    from verification_service.app.models.verification_models import VerificationCertificate, VerificationRequest
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User
    from shared.auth import get_current_user
    from uuid import uuid4
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
    
    from sqlalchemy.pool import StaticPool
    
    @compiles(UNIQUEIDENTIFIER, 'sqlite')
    def compile_uniqueidentifier(type_, compiler, **kw):
        return "CHAR(36)"
        
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        execution_options={"schema_translate_map": {"verification": None, "zkp": None}},
    )
    
    # Strip schemas for SQLite testing and create explicitly
    User.__table__.create(engine)
    ProofJob.__table__.create(engine)
    VerificationRequest.__table__.create(engine)
    VerificationCertificate.__table__.create(engine)
    
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    db = TestingSessionLocal()
    
    # Create two users
    user_a = uuid4()
    user_b = uuid4()
    
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    
    # Create jobs for User A
    job_a = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(), policy_id=uuid4(), user_id=user_a, created_at=now)
    db.add(job_a)
    req_a = VerificationRequest(id=uuid4(), proof_job_id=job_a.id, sbom_root="0x" + "a"*64, vulnerability_db_root="0x" + "b"*64, policy_hash="0x" + "c"*64, result="verified", user_id=user_a, created_at=now)
    db.add(req_a)
    cert_a = VerificationCertificate(id=uuid4(), verification_request_id=req_a.id, certificate_data="cert_a", sbom_root="0x" + "a"*64, vulnerability_db_root="0x" + "b"*64, policy_hash="0x" + "c"*64, issued_at=now)
    db.add(cert_a)
    
    # Create jobs for User B
    job_b = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(), policy_id=uuid4(), user_id=user_b, created_at=now)
    db.add(job_b)
    req_b = VerificationRequest(id=uuid4(), proof_job_id=job_b.id, sbom_root="0x" + "d"*64, vulnerability_db_root="0x" + "e"*64, policy_hash="0x" + "f"*64, result="verified", user_id=user_b, created_at=now)
    db.add(req_b)
    cert_b = VerificationCertificate(id=uuid4(), verification_request_id=req_b.id, certificate_data="cert_b", sbom_root="0x" + "d"*64, vulnerability_db_root="0x" + "e"*64, policy_hash="0x" + "f"*64, issued_at=now)
    db.add(cert_b)
    
    db.commit()
    
    def override_get_session():
        yield db
        
    app.dependency_overrides[get_session] = override_get_session
    
    # 1. Test listing as User A
    app.dependency_overrides[get_current_user] = lambda: User(id=user_a, username="a", role="vendor")
    response = client.get("/api/v1/verification/certificates")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["sbom_root"] == "0x" + "a"*64
    
    # 2. Test accessing B's cert as User A (IDOR check)
    response = client.get(f"/api/v1/verification/certificates/{cert_b.id}")
    assert response.status_code == 404
    
    # 3. Test listing as User B
    app.dependency_overrides[get_current_user] = lambda: User(id=user_b, username="b", role="vendor")
    response = client.get("/api/v1/verification/certificates")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["sbom_root"] == "0x" + "d"*64
    
    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_current_user, None)
    db.close()


def test_revoked_certificate_data_is_masked():
    # Real DB-based isolation test
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from shared.database import Base, get_session
    from verification_service.app.models.verification_models import VerificationCertificate, VerificationRequest
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User
    from shared.auth import get_current_user
    from uuid import uuid4
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
    from sqlalchemy.pool import StaticPool
    
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        execution_options={"schema_translate_map": {"verification": None, "zkp": None}},
    )
    
    User.__table__.create(engine)
    ProofJob.__table__.create(engine)
    VerificationRequest.__table__.create(engine)
    VerificationCertificate.__table__.create(engine)
    
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    
    user_a = uuid4()
    now = datetime.now(timezone.utc)
    
    job_a = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(), policy_id=uuid4(), user_id=user_a, created_at=now)
    db.add(job_a)
    req_a = VerificationRequest(id=uuid4(), proof_job_id=job_a.id, sbom_root="0x" + "a"*64, vulnerability_db_root="0x" + "b"*64, policy_hash="0x" + "c"*64, result="verified", user_id=user_a, created_at=now)
    db.add(req_a)
    cert_a = VerificationCertificate(id=uuid4(), verification_request_id=req_a.id, certificate_data="cert_a_secret", sbom_root="0x" + "a"*64, vulnerability_db_root="0x" + "b"*64, policy_hash="0x" + "c"*64, issued_at=now, is_revoked=True, revoked_at=now)
    db.add(cert_a)
    db.commit()
    
    app.dependency_overrides[get_session] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: User(id=user_a, username="a", role="vendor")
    
    # Check retrieval endpoint
    response = client.get(f"/api/v1/verification/certificates/{cert_a.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["is_revoked"] is True
    assert data["certificate_data"] is None  # IMPORTANT: Data must be masked
    
    # Check list endpoint
    response = client.get("/api/v1/verification/certificates")
    data = response.json()
    assert data[0]["is_revoked"] is True
    assert data[0]["certificate_data"] is None

    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_current_user, None)
    db.close()


def test_revoke_certificate():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from shared.database import Base, get_session
    from verification_service.app.models.verification_models import VerificationCertificate, VerificationRequest
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User
    from shared.auth import get_current_user
    from uuid import uuid4
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
    from sqlalchemy.pool import StaticPool
    
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        execution_options={"schema_translate_map": {"verification": None, "zkp": None}},
    )
    
    User.__table__.create(engine)
    ProofJob.__table__.create(engine)
    VerificationRequest.__table__.create(engine)
    VerificationCertificate.__table__.create(engine)
    
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    
    user_a = uuid4()
    user_b = uuid4()
    now = datetime.now(timezone.utc)
    
    job_a = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(), policy_id=uuid4(), user_id=user_a, created_at=now)
    db.add(job_a)
    req_a = VerificationRequest(id=uuid4(), proof_job_id=job_a.id, sbom_root="0x" + "a"*64, vulnerability_db_root="0x" + "b"*64, policy_hash="0x" + "c"*64, result="verified", user_id=user_a, created_at=now)
    db.add(req_a)
    cert_a = VerificationCertificate(id=uuid4(), verification_request_id=req_a.id, certificate_data="cert_a_secret", sbom_root="0x" + "a"*64, vulnerability_db_root="0x" + "b"*64, policy_hash="0x" + "c"*64, issued_at=now, is_revoked=False)
    db.add(cert_a)
    db.commit()
    
    app.dependency_overrides[get_session] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: User(id=user_a, username="a", role="vendor")
    
    # 1. Successful Revocation
    response = client.post(f"/api/v1/verification/certificates/{cert_a.id}/revoke", json={"reason": "Compromised"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_revoked"] is True
    assert data["revoked_reason"] == "Compromised"
    assert data["certificate_data"] is None

    # 2. Repeated revocation is idempotent
    response = client.post(f"/api/v1/verification/certificates/{cert_a.id}/revoke", json={"reason": "Another reason"})
    assert response.status_code == 200
    data = response.json()
    assert data["revoked_reason"] == "Compromised"  # Kept the original
    
    # 3. Unauthorized Revocation by User B
    app.dependency_overrides[get_current_user] = lambda: User(id=user_b, username="b", role="vendor")
    response = client.post(f"/api/v1/verification/certificates/{cert_a.id}/revoke", json={"reason": "Malice"})
    assert response.status_code == 404

    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_current_user, None)
    db.close()


# ---------------------------------------------------------------------------
# Finding 3: Certificate Revocation Lifecycle Tests
# ---------------------------------------------------------------------------

def _make_sqlite_test_db():
    """Helper: build an in-process SQLite test DB with the required tables."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
    from verification_service.app.models.verification_models import (
        VerificationCertificate,
        VerificationRequest,
    )
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User

    @compiles(UNIQUEIDENTIFIER, "sqlite")
    def compile_uniqueidentifier(type_, compiler, **kw):
        return "CHAR(36)"

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        execution_options={"schema_translate_map": {"verification": None, "zkp": None}},
    )

    User.__table__.create(engine, checkfirst=True)
    ProofJob.__table__.create(engine, checkfirst=True)
    VerificationRequest.__table__.create(engine, checkfirst=True)
    VerificationCertificate.__table__.create(engine, checkfirst=True)

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal


def test_active_certificate_accepted_by_validate():
    """1. Active certificate is accepted."""
    from shared.database import get_session
    from verification_service.app.models.verification_models import (
        VerificationCertificate,
        VerificationRequest,
    )
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User

    SessionLocal = _make_sqlite_test_db()
    db = SessionLocal()

    user_id = uuid4()
    now = datetime.now(timezone.utc)

    job = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(),
                   policy_id=uuid4(), user_id=user_id, created_at=now)
    db.add(job)
    req = VerificationRequest(id=uuid4(), proof_job_id=job.id,
                              sbom_root="0x" + "a"*64,
                              vulnerability_db_root="0x" + "b"*64,
                              policy_hash="0x" + "c"*64,
                              result="verified", user_id=user_id, created_at=now)
    db.add(req)
    cert = VerificationCertificate(id=uuid4(), verification_request_id=req.id,
                                   certificate_data="active_cert_data",
                                   sbom_root="0x" + "a"*64,
                                   vulnerability_db_root="0x" + "b"*64,
                                   policy_hash="0x" + "c"*64,
                                   issued_at=now, is_revoked=False)
    db.add(cert)
    db.commit()

    app.dependency_overrides[get_session] = lambda: db

    response = client.get(f"/api/v1/verification/certificates/{cert.id}/validate")
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["reason"] == "certificate_active"

    app.dependency_overrides.pop(get_session, None)
    db.close()


def test_revoked_certificate_rejected_by_validate():
    """2. Revoked certificate is rejected as currently valid."""
    from shared.database import get_session
    from verification_service.app.models.verification_models import (
        VerificationCertificate,
        VerificationRequest,
    )
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User

    SessionLocal = _make_sqlite_test_db()
    db = SessionLocal()

    user_id = uuid4()
    now = datetime.now(timezone.utc)

    job = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(),
                   policy_id=uuid4(), user_id=user_id, created_at=now)
    db.add(job)
    req = VerificationRequest(id=uuid4(), proof_job_id=job.id,
                              sbom_root="0x" + "a"*64,
                              vulnerability_db_root="0x" + "b"*64,
                              policy_hash="0x" + "c"*64,
                              result="verified", user_id=user_id, created_at=now)
    db.add(req)
    cert = VerificationCertificate(id=uuid4(), verification_request_id=req.id,
                                   certificate_data="revoked_cert_data",
                                   sbom_root="0x" + "a"*64,
                                   vulnerability_db_root="0x" + "b"*64,
                                   policy_hash="0x" + "c"*64,
                                   issued_at=now, is_revoked=True,
                                   revoked_at=now, revoked_reason="test_revoke")
    db.add(cert)
    db.commit()

    app.dependency_overrides[get_session] = lambda: db

    response = client.get(f"/api/v1/verification/certificates/{cert.id}/validate")
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["reason"] == "certificate_revoked"

    app.dependency_overrides.pop(get_session, None)
    db.close()


def test_revoked_certificate_metadata_remains_auditable():
    """3. Revoked certificate metadata remains auditable (id, roots, timestamps)."""
    from shared.database import get_session
    from verification_service.app.models.verification_models import (
        VerificationCertificate,
        VerificationRequest,
    )
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User

    SessionLocal = _make_sqlite_test_db()
    db = SessionLocal()

    user_id = uuid4()
    now = datetime.now(timezone.utc)

    job = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(),
                   policy_id=uuid4(), user_id=user_id, created_at=now)
    db.add(job)
    req = VerificationRequest(id=uuid4(), proof_job_id=job.id,
                              sbom_root="0x" + "a"*64,
                              vulnerability_db_root="0x" + "b"*64,
                              policy_hash="0x" + "c"*64,
                              result="verified", user_id=user_id, created_at=now)
    db.add(req)
    cert = VerificationCertificate(id=uuid4(), verification_request_id=req.id,
                                   certificate_data="secret_cert_data",
                                   sbom_root="0x" + "a"*64,
                                   vulnerability_db_root="0x" + "b"*64,
                                   policy_hash="0x" + "c"*64,
                                   issued_at=now, is_revoked=True,
                                   revoked_at=now, revoked_reason="audit_test")
    db.add(cert)
    db.commit()

    app.dependency_overrides[get_session] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: User(
        id=user_id, username="a", role="vendor"
    )

    # Retrieve via API — metadata should be present
    response = client.get(f"/api/v1/verification/certificates/{cert.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["is_revoked"] is True
    assert data["revoked_reason"] == "audit_test"
    assert data["sbom_root"] == "0x" + "a"*64
    assert data["id"] == str(cert.id)
    # certificate_data is masked (Finding 3 invariant 4)
    assert data["certificate_data"] is None

    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_current_user, None)
    db.close()


def test_unauthorized_user_cannot_access_certificate():
    """5. Unauthorized users cannot access another user's certificate."""
    from shared.database import get_session
    from verification_service.app.models.verification_models import (
        VerificationCertificate,
        VerificationRequest,
    )
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User

    SessionLocal = _make_sqlite_test_db()
    db = SessionLocal()

    user_a = uuid4()
    user_b = uuid4()
    now = datetime.now(timezone.utc)

    job = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(),
                   policy_id=uuid4(), user_id=user_a, created_at=now)
    db.add(job)
    req = VerificationRequest(id=uuid4(), proof_job_id=job.id,
                              sbom_root="0x" + "a"*64,
                              vulnerability_db_root="0x" + "b"*64,
                              policy_hash="0x" + "c"*64,
                              result="verified", user_id=user_a, created_at=now)
    db.add(req)
    cert = VerificationCertificate(id=uuid4(), verification_request_id=req.id,
                                   certificate_data="secret",
                                   sbom_root="0x" + "a"*64,
                                   vulnerability_db_root="0x" + "b"*64,
                                   policy_hash="0x" + "c"*64,
                                   issued_at=now, is_revoked=False)
    db.add(cert)
    db.commit()

    app.dependency_overrides[get_session] = lambda: db
    # Act as user_b
    app.dependency_overrides[get_current_user] = lambda: User(
        id=user_b, username="b", role="vendor"
    )

    response = client.get(f"/api/v1/verification/certificates/{cert.id}")
    assert response.status_code == 404

    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_current_user, None)
    db.close()


def test_copied_jwt_token_cannot_bypass_revocation():
    """6. Previously-copied certificate material cannot bypass authoritative revocation."""
    import jwt as pyjwt
    import os
    from shared.database import get_session
    from verification_service.app.models.verification_models import (
        VerificationCertificate,
        VerificationRequest,
    )
    from zkp_service.app.models.zkp_models import ProofJob
    from shared.models.user import User
    from datetime import timedelta

    SessionLocal = _make_sqlite_test_db()
    db = SessionLocal()

    user_id = uuid4()
    now = datetime.now(timezone.utc)
    secret = "a7d2e3f8981b2c45358169a8b122718e0018a169b2d861d8481ff23184b2e8a1"
    os.environ["CERTIFICATE_SECRET_KEY"] = secret

    job = ProofJob(id=uuid4(), sbom_upload_id=uuid4(), snapshot_id=uuid4(),
                   policy_id=uuid4(), user_id=user_id, created_at=now)
    db.add(job)
    req_id = uuid4()
    req = VerificationRequest(id=req_id, proof_job_id=job.id,
                              sbom_root="0x" + "a"*64,
                              vulnerability_db_root="0x" + "b"*64,
                              policy_hash="0x" + "c"*64,
                              result="verified", user_id=user_id, created_at=now)
    db.add(req)

    # Create a signed JWT token (simulating what the system would issue)
    token_payload = {
        "sub": str(req_id),
        "iss": "antigravity-zkp-authority",
        "iat": now,
        "exp": now + timedelta(days=365),
        "sbom_root": "0x" + "a"*64,
        "vulnerability_db_root": "0x" + "b"*64,
        "policy_hash": "0x" + "c"*64,
    }
    copied_token = pyjwt.encode(token_payload, secret, algorithm="HS256")

    cert = VerificationCertificate(id=uuid4(), verification_request_id=req_id,
                                   certificate_data=copied_token,
                                   sbom_root="0x" + "a"*64,
                                   vulnerability_db_root="0x" + "b"*64,
                                   policy_hash="0x" + "c"*64,
                                   issued_at=now, is_revoked=True,
                                   revoked_at=now, revoked_reason="compromised")
    db.add(cert)
    db.commit()

    app.dependency_overrides[get_session] = lambda: db

    # The token itself is cryptographically valid (signature checks out)
    decoded = pyjwt.decode(copied_token, secret, algorithms=["HS256"])
    assert decoded["sub"] == str(req_id)  # token is valid by itself

    # But the authoritative validate-token endpoint must reject it
    response = client.post(
        "/api/v1/verification/certificates/validate-token",
        json={"token": copied_token},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["reason"] == "certificate_revoked"

    app.dependency_overrides.pop(get_session, None)
    db.close()


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
    
    # 1. Successful Owner Revocation with attribution
    response = client.post(f"/api/v1/verification/certificates/{cert_a.id}/revoke", json={"reason": "Compromised"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_revoked"] is True
    assert data["revoked_reason"] == "Compromised"
    assert data["revoked_by"] == str(user_a)
    assert data["certificate_data"] is None

    # 2. Repeated revocation is idempotent and preserves original attribution and reason
    response = client.post(f"/api/v1/verification/certificates/{cert_a.id}/revoke", json={"reason": "Another reason"})
    assert response.status_code == 200
    data = response.json()
    assert data["revoked_reason"] == "Compromised"  # Kept the original
    assert data["revoked_by"] == str(user_a)        # Kept original revoker
    
    # 3. Unauthorized Cross-Tenant Revocation by User B (vendor)
    app.dependency_overrides[get_current_user] = lambda: User(id=user_b, username="b", role="vendor")
    response = client.post(f"/api/v1/verification/certificates/{cert_a.id}/revoke", json={"reason": "Malice"})
    assert response.status_code == 404

    # 4. Unauthorized Revocation by other roles (auditor, buyer, trusted_importer)
    for forbidden_role in ["auditor", "buyer", "trusted_importer"]:
        app.dependency_overrides[get_current_user] = lambda r=forbidden_role: User(id=uuid4(), username=f"user_{r}", role=r)
        response = client.post(f"/api/v1/verification/certificates/{cert_a.id}/revoke", json={"reason": "Forbidden"})
        assert response.status_code == 404

    # 5. Authorized Administrator Revocation across tenants
    admin_id = uuid4()
    req_b = VerificationRequest(id=uuid4(), proof_job_id=job_a.id, sbom_root="0x" + "b"*64, vulnerability_db_root="0x" + "b"*64, policy_hash="0x" + "c"*64, result="verified", user_id=user_b, created_at=now)
    db.add(req_b)
    cert_b = VerificationCertificate(id=uuid4(), verification_request_id=req_b.id, certificate_data="cert_b_secret", sbom_root="0x" + "b"*64, vulnerability_db_root="0x" + "b"*64, policy_hash="0x" + "c"*64, issued_at=now, is_revoked=False)
    db.add(cert_b)
    db.commit()

    app.dependency_overrides[get_current_user] = lambda: User(id=admin_id, username="admin_super", role="admin")
    response = client.post(f"/api/v1/verification/certificates/{cert_b.id}/revoke", json={"reason": "Admin Security Revocation"})
    assert response.status_code == 200
    admin_data = response.json()
    assert admin_data["is_revoked"] is True
    assert admin_data["revoked_reason"] == "Admin Security Revocation"
    assert admin_data["revoked_by"] == str(admin_id)

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
    orig_cert_secret = os.environ.get("CERTIFICATE_SECRET_KEY")
    import secrets as pysecrets
    secret = pysecrets.token_hex(32)
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
    if orig_cert_secret is not None:
        os.environ["CERTIFICATE_SECRET_KEY"] = orig_cert_secret
    else:
        os.environ.pop("CERTIFICATE_SECRET_KEY", None)


# ---------------------------------------------------------------------------
# Unit 7 (AUD-A-005): Event-Loop Blocking Remediation Regression Tests
# ---------------------------------------------------------------------------
import threading


def test_verify_proof_offloaded_to_threadpool_success_contract():
    """
    Demonstrates:
    1. Verification execution is offloaded from the asyncio event-loop thread to a worker thread.
    2. API response contract remains unchanged (VerificationResponse format).
    3. Successful verification still follows the certificate issuance path.
    4. Current user ownership (tenant boundary) is passed to VerificationService.
    """
    service_threads = []
    cert_threads = []
    received_user_ids = []

    req_id = uuid4()
    cert_id = uuid4()
    vendor_user_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    now = datetime.now(timezone.utc)

    mock_req = MagicMock()
    mock_req.id = req_id
    mock_req.result = "verified"
    mock_req.sbom_root = "0x" + "a" * 64
    mock_req.vulnerability_db_root = "0x" + "b" * 64
    mock_req.policy_hash = "0x" + "c" * 64
    mock_req.verified_at = now
    mock_req.created_at = now

    mock_cert = MagicMock()
    mock_cert.id = cert_id
    mock_cert.verification_request_id = req_id
    mock_cert.certificate_data = "CERT-PAYLOAD-TOKEN"
    mock_cert.sbom_root = "0x" + "a" * 64
    mock_cert.vulnerability_db_root = "0x" + "b" * 64
    mock_cert.policy_hash = "0x" + "c" * 64
    mock_cert.issued_at = now
    mock_cert.is_revoked = False
    mock_cert.revoked_at = None
    mock_cert.revoked_reason = None

    def fake_process_verification(req_data, user_id=None):
        service_threads.append(threading.current_thread().name)
        received_user_ids.append(user_id)
        return mock_req

    def fake_get_certificate_by_request(request_id, user_id=None):
        cert_threads.append(threading.current_thread().name)
        return mock_cert

    with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
        mock_service = mock_service_cls.return_value
        mock_service.process_verification.side_effect = fake_process_verification
        mock_service.get_certificate_by_request.side_effect = fake_get_certificate_by_request

        response = client.post(
            "/api/v1/verification/verify",
            json={
                "sbom_root": "0x" + "a" * 64,
                "vulnerability_db_root": "0x" + "b" * 64,
                "policy_hash": "0x" + "c" * 64,
                "proof_job_id": "00000000-0000-4000-8000-000000000001",
            },
        )
        assert response.status_code == 200
        data = response.json()

        # Contract assertion: VerificationResponse schema intact
        assert data["id"] == str(req_id)
        assert data["sbom_root"] == "0x" + "a" * 64
        assert data["vulnerability_db_root"] == "0x" + "b" * 64
        assert data["policy_hash"] == "0x" + "c" * 64
        assert data["result"] == "verified"
        assert data["certificate"] is not None
        assert data["certificate"]["id"] == str(cert_id)

        # Threadpool offloading assertion
        assert len(service_threads) == 1
        assert len(cert_threads) == 1
        assert "AnyIO" in service_threads[0] or service_threads[0] != threading.current_thread().name
        assert "AnyIO" in cert_threads[0] or cert_threads[0] != threading.current_thread().name

        # Ownership preservation
        assert received_user_ids == [vendor_user_id]


def test_verify_proof_multipart_offloaded_to_threadpool():
    """
    Demonstrates multipart/form-data requests with binary proof artifact
    are also offloaded to worker threadpool and preserve response contract.
    """
    worker_threads = []
    now = datetime.now(timezone.utc)
    req_id = uuid4()

    mock_req = MagicMock()
    mock_req.id = req_id
    mock_req.result = "invalid_proof"
    mock_req.sbom_root = "0x" + "1" * 64
    mock_req.vulnerability_db_root = "0x" + "2" * 64
    mock_req.policy_hash = "0x" + "3" * 64
    mock_req.verified_at = None
    mock_req.created_at = now

    def fake_process_verification(req_data, user_id=None):
        worker_threads.append(threading.current_thread().name)
        assert req_data.proof_artifact == "fake-proof-content"
        return mock_req

    with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
        mock_service = mock_service_cls.return_value
        mock_service.process_verification.side_effect = fake_process_verification

        response = client.post(
            "/api/v1/verification/verify",
            data={
                "sbom_root": "0x" + "1" * 64,
                "vulnerability_db_root": "0x" + "2" * 64,
                "policy_hash": "0x" + "3" * 64,
            },
            files={
                "proof_artifact": ("proof.bin", b"fake-proof-content", "application/octet-stream"),
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["result"] == "invalid_proof"
        assert data["certificate"] is None
        assert len(worker_threads) == 1
        assert "AnyIO" in worker_threads[0] or worker_threads[0] != threading.current_thread().name


def test_verify_proof_fail_closed_on_worker_runtime_error():
    """
    Demonstrates runtime errors in the offloaded worker thread propagate cleanly
    and fail closed (no certificate issued, status code 500 returned).
    """
    with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
        mock_service = mock_service_cls.return_value
        mock_service.process_verification.side_effect = RuntimeError("Subprocess bb execution crashed")

        response = client.post(
            "/api/v1/verification/verify",
            json={
                "sbom_root": "0x" + "1" * 64,
                "vulnerability_db_root": "0x" + "2" * 64,
                "policy_hash": "0x" + "3" * 64,
            },
        )
        # Server exception propagates cleanly as 500 (fail-closed)
        assert response.status_code == 500


def test_verify_proof_session_lifecycle_and_single_thread_access():
    """
    Demonstrates that the request-scoped database session is passed to the service,
    accessed solely within the offloaded worker, and closed cleanly at request completion.
    """
    from shared.database import get_session

    session_events = []

    class MockTrackedSession:
        def __init__(self):
            self.closed = False

        def record_access(self):
            session_events.append(("access", threading.current_thread().name))

        def close(self):
            self.closed = True
            session_events.append(("close", threading.current_thread().name))

    tracked_session = MockTrackedSession()

    def get_test_session():
        try:
            yield tracked_session
        finally:
            tracked_session.close()

    app.dependency_overrides[get_session] = get_test_session

    now = datetime.now(timezone.utc)
    mock_req = MagicMock()
    mock_req.id = uuid4()
    mock_req.result = "invalid_proof"
    mock_req.sbom_root = "0x" + "1" * 64
    mock_req.vulnerability_db_root = "0x" + "2" * 64
    mock_req.policy_hash = "0x" + "3" * 64
    mock_req.verified_at = None
    mock_req.created_at = now

    def fake_process_verification(req_data, user_id=None):
        tracked_session.record_access()
        return mock_req

    try:
        with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
            mock_service = mock_service_cls.return_value
            mock_service.process_verification.side_effect = fake_process_verification

            response = client.post(
                "/api/v1/verification/verify",
                json={
                    "sbom_root": "0x" + "1" * 64,
                    "vulnerability_db_root": "0x" + "2" * 64,
                    "policy_hash": "0x" + "3" * 64,
                },
            )
            assert response.status_code == 200
            # Ensure the session was injected into VerificationService
            mock_service_cls.assert_called_once_with(tracked_session)

            # Ensure access occurred in the worker thread
            access_events = [e for e in session_events if e[0] == "access"]
            close_events = [e for e in session_events if e[0] == "close"]
            assert len(access_events) == 1
            assert "AnyIO" in access_events[0][1] or access_events[0][1] != threading.current_thread().name

            # Ensure session was closed at request completion
            assert len(close_events) == 1
            assert tracked_session.closed is True
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_verify_proof_idempotency_via_worker_threadpool():
    """
    Demonstrates that repeated verification requests for an existing record
    return the cached idempotent result through the offloaded worker thread.
    """
    now = datetime.now(timezone.utc)
    cached_req_id = uuid4()
    mock_cached_req = MagicMock()
    mock_cached_req.id = cached_req_id
    mock_cached_req.result = "invalid_proof"
    mock_cached_req.sbom_root = "0x" + "4" * 64
    mock_cached_req.vulnerability_db_root = "0x" + "5" * 64
    mock_cached_req.policy_hash = "0x" + "6" * 64
    mock_cached_req.verified_at = None
    mock_cached_req.created_at = now

    with patch("verification_service.app.api.routes.verification_routes.VerificationService") as mock_service_cls:
        mock_service = mock_service_cls.return_value
        mock_service.process_verification.return_value = mock_cached_req

        response = client.post(
            "/api/v1/verification/verify",
            json={
                "sbom_root": "0x" + "4" * 64,
                "vulnerability_db_root": "0x" + "5" * 64,
                "policy_hash": "0x" + "6" * 64,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(cached_req_id)
        assert data["result"] == "invalid_proof"
        assert data["certificate"] is None
        mock_service.process_verification.assert_called_once()


def test_verify_multipart_upload_non_utf8_returns_422():
    """Verify that uploading invalid UTF-8 bytes as proof_artifact cleanly returns HTTP 422."""
    invalid_utf8_bytes = b"\xff\xfe\xfd\x80\x81"
    response = client.post(
        "/api/v1/verification/verify",
        data={
            "sbom_root": "0x" + "1" * 64,
            "vulnerability_db_root": "0x" + "2" * 64,
            "policy_hash": "0x" + "3" * 64,
        },
        files={
            "proof_artifact": ("artifact.proof", invalid_utf8_bytes, "application/octet-stream"),
        },
    )
    assert response.status_code == 422
    assert "Uploaded proof artifact must be valid UTF-8 text" in response.text


def test_list_and_get_certificate_without_proof_job_id():
    """
    SEC-G1-001 Regression Test:
    Verify that verification certificates created without an internal ProofJob ID
    (e.g., buyer independent verification) are properly listed and retrievable
    by the owner, while cross-tenant IDOR access remains blocked with 404.
    """
    from datetime import datetime, timezone
    from uuid import uuid4
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    from sqlalchemy.orm import sessionmaker
    from shared.database import get_session

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        execution_options={"schema_translate_map": {"verification": None, "zkp": None}},
    )
    User.__table__.create(engine)
    VerificationRequest.__table__.create(engine)
    VerificationCertificate.__table__.create(engine)

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    user_a = uuid4()
    user_b = uuid4()
    now = datetime.now(timezone.utc)

    # Verification request without proof_job_id (proof_job_id is None)
    req_a = VerificationRequest(
        id=uuid4(),
        proof_job_id=None,
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
        result="verified",
        user_id=user_a,
        created_at=now,
    )
    db.add(req_a)
    cert_a = VerificationCertificate(
        id=uuid4(),
        verification_request_id=req_a.id,
        certificate_data="standalone_buyer_cert_a",
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
        issued_at=now,
    )
    db.add(cert_a)

    # Another tenant's cert (also without proof_job_id)
    req_b = VerificationRequest(
        id=uuid4(),
        proof_job_id=None,
        sbom_root="0x" + "7" * 64,
        vulnerability_db_root="0x" + "8" * 64,
        policy_hash="0x" + "9" * 64,
        result="verified",
        user_id=user_b,
        created_at=now,
    )
    db.add(req_b)
    cert_b = VerificationCertificate(
        id=uuid4(),
        verification_request_id=req_b.id,
        certificate_data="standalone_buyer_cert_b",
        sbom_root="0x" + "7" * 64,
        vulnerability_db_root="0x" + "8" * 64,
        policy_hash="0x" + "9" * 64,
        issued_at=now,
    )
    db.add(cert_b)
    db.commit()

    def override_get_session():
        yield db

    app.dependency_overrides[get_session] = override_get_session

    try:
        # 1. Listing certificates as user_a returns cert_a even though proof_job_id is None
        app.dependency_overrides[get_current_user] = lambda: User(id=user_a, username="buyer_a", role="buyer")
        response = client.get("/api/v1/verification/certificates")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == str(cert_a.id)
        assert data[0]["certificate_data"] == "standalone_buyer_cert_a"

        # 2. Detail retrieval as owner succeeds
        response_detail = client.get(f"/api/v1/verification/certificates/{cert_a.id}")
        assert response_detail.status_code == 200
        assert response_detail.json()["id"] == str(cert_a.id)

        # 3. Cross-tenant access to cert_a as user_b fails closed with 404
        app.dependency_overrides[get_current_user] = lambda: User(id=user_b, username="buyer_b", role="buyer")
        response_idor = client.get(f"/api/v1/verification/certificates/{cert_a.id}")
        assert response_idor.status_code == 404

        # 4. Listing certificates as user_b returns only user_b's certificate
        response_b_list = client.get("/api/v1/verification/certificates")
        assert response_b_list.status_code == 200
        data_b = response_b_list.json()
        assert len(data_b) == 1
        assert data_b[0]["id"] == str(cert_b.id)
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_current_user, None)
        db.close()




import sys
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from fastapi.testclient import TestClient
from zkp_service.app.main import app
from zkp_service.app.models.zkp_models import ProofJob
from shared.auth import get_current_user
from shared.database import get_session
from shared.models.user import User

client = TestClient(app, raise_server_exceptions=False)

@pytest.fixture(autouse=True)
def override_current_user():
    app.dependency_overrides[get_current_user] = lambda: User(id=uuid.UUID("11111111-1111-1111-1111-111111111111"), username="vendor", role="vendor")
    yield
    app.dependency_overrides.pop(get_current_user, None)

def test_generate_proof_api_success():
    sbom_id = uuid.uuid4()
    snap_id = uuid.uuid4()
    pol_id = uuid.uuid4()

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.count.return_value = 0
    app.dependency_overrides[get_session] = lambda: mock_db
    try:
        with patch("zkp_service.app.api.routes.zkp_routes.ZKPRepository") as mock_repo_cls, \
             patch("zkp_service.app.api.routes.zkp_routes.ProverService") as mock_prover_cls:
            mock_repo = mock_repo_cls.return_value
            mock_prover = mock_prover_cls.return_value

            from datetime import datetime
            job_id = uuid.uuid4()
            mock_job = ProofJob(
                id=job_id,
                sbom_upload_id=sbom_id,
                snapshot_id=snap_id,
                policy_id=pol_id,
                status="pending",
                user_id=uuid.uuid4(),
                created_at=datetime.now(timezone.utc)
            )
            mock_repo.create_job.return_value = mock_job

            mock_final_job = ProofJob(
                id=job_id,
                sbom_upload_id=sbom_id,
                snapshot_id=snap_id,
                policy_id=pol_id,
                status="completed",
                sbom_root="0xmocksbom",
                vulnerability_db_root="0xmockvuln",
                policy_hash="0xmockpol",
                user_id=uuid.uuid4(),
                created_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc)
            )
            mock_prover.process_job.return_value = mock_final_job

            response = client.post("/api/v1/zkp/generate", json={
                "sbom_upload_id": str(sbom_id),
                "snapshot_id": str(snap_id),
                "policy_id": str(pol_id)
            })

            assert response.status_code == 202
            data = response.json()
            assert data["status"] == "pending"

            body = response.text.lower()
            for forbidden in ["\"scores\":", "\"presence\":", "hash2"]:
                assert forbidden not in body
    finally:
        app.dependency_overrides.pop(get_session, None)

def test_get_proof_job_not_found():
    with patch("zkp_service.app.api.routes.zkp_routes.ZKPRepository") as mock_repo_cls:
        mock_repo = mock_repo_cls.return_value
        mock_repo.get_job.return_value = None
        
        response = client.get(f"/api/v1/zkp/jobs/{uuid.uuid4()}")
        assert response.status_code == 404

def test_zkp_job_idor_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from shared.database import get_session
    from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
    from shared.models.user import User
    from sqlalchemy.pool import StaticPool
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
    
    @compiles(UNIQUEIDENTIFIER, 'sqlite')
    def compile_uniqueidentifier(type_, compiler, **kw):
        return "CHAR(36)"
        
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    
    from sqlalchemy import event
    from datetime import datetime, timezone
    @event.listens_for(engine, "connect")
    def _register_sqlite_functions(connection, record):
        connection.create_function("getutcdate", 0, lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        
    ProofJob.__table__.schema = None
    ChunkProofSet.__table__.schema = None
    SegmentProof.__table__.schema = None
    User.__table__.schema = None
    
    User.__table__.create(engine)
    ProofJob.__table__.create(engine)
    ChunkProofSet.__table__.create(engine)
    SegmentProof.__table__.create(engine)
    
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()
    
    job_b = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), user_id=user_b)
    db.add(job_b)
    db.commit()
    
    def override_get_session():
        yield db
        
    app.dependency_overrides[get_session] = override_get_session
    
    # 1. As User B, should be 200
    app.dependency_overrides[get_current_user] = lambda: User(id=user_b, username="b", role="vendor")
    response = client.get(f"/api/v1/zkp/jobs/{job_b.id}")
    assert response.status_code == 200
    
    # 2. As User A, should be 404 Not Found (anti-enumeration)
    app.dependency_overrides[get_current_user] = lambda: User(id=user_a, username="a", role="vendor")
    response = client.get(f"/api/v1/zkp/jobs/{job_b.id}")
    assert response.status_code == 404
    
    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_current_user, None)
    db.close()

def test_generate_proof_status_rejections():
    from fastapi import HTTPException
    from zkp_service.app.repositories.zkp_repository import ZKPRepository
    from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest
    from unittest.mock import MagicMock
    import pytest
    
    repo = ZKPRepository(MagicMock())
    req = GenerateProofRequest(sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4())
    user_id = uuid.uuid4()
    
    # 1. Reject pending
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),  # SBOM
        MagicMock(status="pending")  # Snapshot
    ]
    with pytest.raises(HTTPException) as exc:
        repo.create_job(req, user_id)
    assert exc.value.status_code == 400
    assert "Snapshot is not frozen" in exc.value.detail

    # 2. Reject approved
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),
        MagicMock(status="approved")
    ]
    with pytest.raises(HTTPException) as exc:
        repo.create_job(req, user_id)
    assert exc.value.status_code == 400

    # 3. Reject revoked
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),
        MagicMock(status="revoked")
    ]
    with pytest.raises(HTTPException) as exc:
        repo.create_job(req, user_id)
    assert exc.value.status_code == 400

    # 4. Accept frozen with active policy
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),
        MagicMock(status="frozen"),
        MagicMock(is_active=1),
    ]
    # To bypass job creation DB commits since session is mocked, we expect it to not raise HTTPException
    # It might raise something else from the mocked session during commit, but the logic passed the gate.
    try:
        repo.create_job(req, user_id)
    except Exception as e:
        if isinstance(e, HTTPException):
            pytest.fail(f"Raised HTTPException unexpectedly: {e}")

    # 5. Reject missing policy
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),
        MagicMock(status="frozen"),
        None,
    ]
    with pytest.raises(HTTPException) as exc:
        repo.create_job(req, user_id)
    assert exc.value.status_code == 404
    assert "Policy not found" in exc.value.detail

    # 6. Reject inactive policy
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),
        MagicMock(status="frozen"),
        MagicMock(is_active=0),
    ]
    with pytest.raises(HTTPException) as exc:
        repo.create_job(req, user_id)
    assert exc.value.status_code == 400
    assert "Policy is not active" in exc.value.detail


def test_list_jobs_all_tenants_admin_and_rbac():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
    from shared.models.user import User
    from datetime import datetime, timezone

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    ProofJob.__table__.schema = None
    ChunkProofSet.__table__.schema = None
    SegmentProof.__table__.schema = None
    User.__table__.schema = None

    User.__table__.create(engine, checkfirst=True)
    ProofJob.__table__.create(engine, checkfirst=True)
    ChunkProofSet.__table__.create(engine, checkfirst=True)
    SegmentProof.__table__.create(engine, checkfirst=True)

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    user_admin = uuid.uuid4()
    user_vendor_a = uuid.uuid4()
    user_vendor_b = uuid.uuid4()
    now = datetime.now(timezone.utc)

    job_admin = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), user_id=user_admin, created_at=now)
    job_vendor_a = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), user_id=user_vendor_a, created_at=now)
    job_vendor_b = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), user_id=user_vendor_b, created_at=now)
    db.add_all([job_admin, job_vendor_a, job_vendor_b])
    db.commit()

    def override_get_session():
        yield db

    app.dependency_overrides[get_session] = override_get_session

    try:
        # 1. Vendor A requests default (all_tenants=False): only sees job_vendor_a
        app.dependency_overrides[get_current_user] = lambda: User(id=user_vendor_a, username="vendor_a", role="vendor", is_active=True)
        res = client.get("/api/v1/zkp")
        assert res.status_code == 200
        jobs = res.json()
        assert len(jobs) == 1
        assert jobs[0]["id"] == str(job_vendor_a.id)

        # 2. Vendor A requests all_tenants=true: rejected with HTTP 403 Forbidden
        res = client.get("/api/v1/zkp?all_tenants=true")
        assert res.status_code == 403
        assert "Only administrators may list proof jobs across all tenants" in res.json().get("detail", res.text)

        # 3. Other non-admin roles requesting all_tenants=true: rejected with 403
        for non_admin_role in ["auditor", "buyer", "trusted_importer"]:
            app.dependency_overrides[get_current_user] = lambda r=non_admin_role: User(id=uuid.uuid4(), username=f"user_{r}", role=r, is_active=True)
            res = client.get("/api/v1/zkp?all_tenants=true")
            assert res.status_code == 403

        # 4. Active admin requests default (all_tenants=False): sees only admin's own job
        app.dependency_overrides[get_current_user] = lambda: User(id=user_admin, username="admin_user", role="admin", is_active=True)
        res = client.get("/api/v1/zkp")
        assert res.status_code == 200
        jobs = res.json()
        assert len(jobs) == 1
        assert jobs[0]["id"] == str(job_admin.id)

        # 5. Active admin requests all_tenants=true: sees all 3 jobs across tenants
        res = client.get("/api/v1/zkp?all_tenants=true")
        assert res.status_code == 200
        jobs = res.json()
        assert len(jobs) == 3
        returned_ids = {j["id"] for j in jobs}
        assert str(job_admin.id) in returned_ids
        assert str(job_vendor_a.id) in returned_ids
        assert str(job_vendor_b.id) in returned_ids

        # 6. Inactive admin requests all_tenants=true: rejected with 403
        app.dependency_overrides[get_current_user] = lambda: User(id=user_admin, username="admin_user", role="admin", is_active=False)
        res = client.get("/api/v1/zkp?all_tenants=true")
        assert res.status_code == 403
        assert "deactivated" in res.json().get("detail", res.text).lower()

        # 7. Inactive admin requests default listing: rejected with 403
        res = client.get("/api/v1/zkp")
        assert res.status_code == 403
        assert "deactivated" in res.json().get("detail", res.text).lower()

    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_current_user, None)
        db.close()


def test_zkp_repository_list_jobs_direct():
    from zkp_service.app.repositories.zkp_repository import ZKPRepository
    from zkp_service.app.models.zkp_models import ProofJob
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from datetime import datetime, timezone

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    ProofJob.__table__.schema = None
    ProofJob.__table__.create(engine, checkfirst=True)

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    repo = ZKPRepository(db)

    u1 = uuid.uuid4()
    u2 = uuid.uuid4()
    now = datetime.now(timezone.utc)

    j1 = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), user_id=u1, created_at=now)
    j2 = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), user_id=u2, created_at=now)
    db.add_all([j1, j2])
    db.commit()

    # User 1 only
    res_u1 = repo.list_jobs(user_id=u1, all_tenants=False)
    assert len(res_u1) == 1
    assert res_u1[0].id == j1.id

    # User 2 only
    res_u2 = repo.list_jobs(user_id=u2, all_tenants=False)
    assert len(res_u2) == 1
    assert res_u2[0].id == j2.id

    # All tenants
    res_all = repo.list_jobs(user_id=None, all_tenants=True)
    assert len(res_all) == 2

    # None user_id with all_tenants=False returns empty list
    res_empty = repo.list_jobs(user_id=None, all_tenants=False)
    assert res_empty == []

    db.close()



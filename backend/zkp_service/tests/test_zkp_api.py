import sys
import os
import uuid
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
                created_at=datetime.utcnow()
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
                created_at=datetime.utcnow(),
                completed_at=datetime.utcnow()
            )
            mock_prover.process_job.return_value = mock_final_job

            response = client.post("/api/v1/zkp/generate", json={
                "sbom_upload_id": str(sbom_id),
                "snapshot_id": str(snap_id),
                "policy_id": str(pol_id)
            })

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "completed"
            assert data["sbom_root"] == "0xmocksbom"

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

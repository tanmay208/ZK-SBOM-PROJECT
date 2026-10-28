import uuid
from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from fastapi.testclient import TestClient
from zkp_service.app.main import app
from zkp_service.app.models.zkp_models import ProofJob
from shared.auth import get_current_user
from shared.models.user import User

client = TestClient(app, raise_server_exceptions=False)

USER_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
USER_B = uuid.UUID("22222222-2222-2222-2222-222222222222")

@pytest.fixture
def override_current_user_a():
    app.dependency_overrides[get_current_user] = lambda: User(id=USER_A, username="user_a", role="vendor")
    yield
    app.dependency_overrides.pop(get_current_user, None)

def test_job_isolation_get_job(override_current_user_a):
    job_id = uuid.uuid4()
    with patch("zkp_service.app.api.routes.zkp_routes.ZKPRepository") as mock_repo_cls:
        mock_repo = mock_repo_cls.return_value
        
        # User A makes request, but we simulate that repo.get_job returns None 
        # (because the repository filters by user_id and it belongs to User B)
        mock_repo.get_job.return_value = None
        
        response = client.get(f"/api/v1/zkp/jobs/{job_id}")
        assert response.status_code == 404

def test_job_isolation_list_jobs(override_current_user_a):
    from shared.database import get_session
    mock_session = patch("sqlalchemy.orm.Session").start()
    mock_session.query.return_value.filter.return_value.count.return_value = 0
    mock_session.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
    
    def override_get_session():
        yield mock_session
        
    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get("/api/v1/zkp")
        assert response.status_code == 200
        assert response.json() == []
    finally:
        app.dependency_overrides.pop(get_session, None)

def test_job_isolation_generate_job(override_current_user_a):
    from shared.database import get_session
    mock_session = patch("sqlalchemy.orm.Session").start()
    mock_session.query.return_value.filter.return_value.count.return_value = 0
    
    from sbom_service.app.models.sbom_models import SBOMUpload
    # Simulate SBOM owned by USER_B
    mock_sbom = SBOMUpload(id=uuid.uuid4(), user_id=USER_B)
    mock_session.query.return_value.filter.return_value.first.return_value = mock_sbom
    
    def override_get_session():
        yield mock_session
        
    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.post("/api/v1/zkp/generate", json={
            "sbom_upload_id": str(mock_sbom.id),
            "snapshot_id": str(uuid.uuid4()),
            "policy_id": str(uuid.uuid4())
        })
        assert response.status_code == 403
        assert response.json()["error"] == "Forbidden: You do not own this SBOM"
        assert response.json()["code"] == "FORBIDDEN"
    finally:
        app.dependency_overrides.pop(get_session, None)

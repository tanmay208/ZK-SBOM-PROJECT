import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest

from fastapi.testclient import TestClient
from sbom_service.app.main import app
from shared.auth import get_current_user
from shared.database import get_session
from shared.models.user import User

client = TestClient(app, raise_server_exceptions=False)

USER_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
USER_B = uuid.UUID("22222222-2222-2222-2222-222222222222")
ADMIN_USER = uuid.UUID("33333333-3333-3333-3333-333333333333")


class MockSBOMUpload:
    def __init__(
        self,
        upload_id: uuid.UUID,
        user_id: uuid.UUID,
        application_id: uuid.UUID | None = None,
        status: str = "completed",
        format: str = "CycloneDX",
        filename: str = "sbom.json",
        sbom_root: str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        component_count: int = 42,
        raw_content: str = "SECRET_PROPRIETARY_RAW_CONTENT_DO_NOT_LEAK",
    ):
        self.id = upload_id
        self.user_id = user_id
        self.application_id = application_id or uuid.uuid4()
        self.status = status
        self.format = format
        self.filename = filename
        self.sbom_root = sbom_root
        self.component_count = component_count
        self.raw_content = raw_content
        self.created_at = datetime.now(timezone.utc)


@pytest.fixture
def override_current_user_a():
    app.dependency_overrides[get_current_user] = lambda: User(id=USER_A, username="user_a", role="vendor")
    yield
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def override_current_user_b():
    app.dependency_overrides[get_current_user] = lambda: User(id=USER_B, username="user_b", role="vendor")
    yield
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def override_admin_user():
    app.dependency_overrides[get_current_user] = lambda: User(id=ADMIN_USER, username="admin_user", role="admin")
    yield
    app.dependency_overrides.pop(get_current_user, None)


def test_sbom_isolation_list_sboms(override_current_user_a):
    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
    
    def override_get_session():
        yield mock_session
        
    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get("/api/v1/sbom")
        assert response.status_code == 200
        assert response.json() == []
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_sbom_owner_access(override_current_user_a):
    """Owner successfully retrieves their own SBOM detail with safe response schema."""
    upload_id = uuid.uuid4()
    mock_upload = MockSBOMUpload(upload_id=upload_id, user_id=USER_A)
    
    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = mock_upload
    
    def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(f"/api/v1/sbom/{upload_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["upload_id"] == str(upload_id)
        assert data["application_id"] == str(mock_upload.application_id)
        assert data["status"] == "completed"
        assert data["format"] == "CycloneDX"
        assert data["sbom_root"] == mock_upload.sbom_root
        assert data["component_count"] == 42
        
        # Verify confidentiality boundary: raw_content and components strictly omitted
        expected_keys = {
            "upload_id", "application_id", "status", "format",
            "filename", "sbom_root", "component_count", "created_at",
            "application_name", "vendor"
        }
        assert set(data.keys()) == expected_keys
        assert "raw_content" not in data
        assert "components" not in data
        assert "SECRET_PROPRIETARY" not in response.text
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_sbom_missing_object(override_current_user_a):
    """Missing SBOM returns 404."""
    upload_id = uuid.uuid4()
    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = None
    
    def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(f"/api/v1/sbom/{upload_id}")
        assert response.status_code == 404
        assert response.json()["error"] == "SBOM not found"
        assert response.json()["code"] == "NOT_FOUND"
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_sbom_cross_tenant_denial(override_current_user_b):
    """Tenant B attempting to access Tenant A's SBOM receives 404 (non-disclosure convention)."""
    upload_id = uuid.uuid4()
    # SBOM belongs to USER_A
    mock_upload = MockSBOMUpload(upload_id=upload_id, user_id=USER_A)
    
    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = mock_upload
    
    def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    try:
        # Request is made by USER_B
        response = client.get(f"/api/v1/sbom/{upload_id}")
        assert response.status_code == 404
        assert response.json()["error"] == "SBOM not found"
        assert response.json()["code"] == "NOT_FOUND"
        assert "SECRET_PROPRIETARY" not in response.text
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_sbom_admin_access(override_admin_user):
    """Admin role can inspect any tenant's SBOM metadata while preserving privacy boundary."""
    upload_id = uuid.uuid4()
    mock_upload = MockSBOMUpload(upload_id=upload_id, user_id=USER_A)
    
    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = mock_upload
    
    def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(f"/api/v1/sbom/{upload_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["upload_id"] == str(upload_id)
        assert "raw_content" not in data
        assert "SECRET_PROPRIETARY" not in response.text
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_sbom_unauthenticated():
    """Unauthenticated access is denied with 401."""
    upload_id = uuid.uuid4()
    response = client.get(f"/api/v1/sbom/{upload_id}")
    assert response.status_code == 401

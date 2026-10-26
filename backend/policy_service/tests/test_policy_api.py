import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest

from fastapi.testclient import TestClient
from policy_service.app.main import app
from shared.auth import get_current_user
from shared.database import get_session
from shared.models.user import User

client = TestClient(app, raise_server_exceptions=False)

AUDITOR_USER = uuid.UUID("11111111-1111-1111-1111-111111111111")
VENDOR_USER = uuid.UUID("22222222-2222-2222-2222-222222222222")
ADMIN_USER = uuid.UUID("33333333-3333-3333-3333-333333333333")


class MockPolicy:
    def __init__(
        self,
        policy_id: uuid.UUID,
        name: str = "Standard CVSS Policy",
        description: str = "Allow CVSS <= 7.0",
        max_allowed_cvss: float = 7.0,
        policy_hash: str = "0x0000000000000000000000000000000000000000000000000000000000000046",
        is_active: int = 1,
    ):
        self.id = policy_id
        self.name = name
        self.description = description
        self.max_allowed_cvss = max_allowed_cvss
        self.max_cvss_score = max_allowed_cvss
        self.policy_hash = policy_hash
        self.is_active = is_active
        self.created_at = datetime.now(timezone.utc)


@pytest.fixture
def override_current_user_auditor():
    app.dependency_overrides[get_current_user] = lambda: User(id=AUDITOR_USER, username="auditor_user", role="auditor")
    yield
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def override_current_user_vendor():
    app.dependency_overrides[get_current_user] = lambda: User(id=VENDOR_USER, username="vendor_user", role="vendor")
    yield
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def override_current_user_admin():
    app.dependency_overrides[get_current_user] = lambda: User(id=ADMIN_USER, username="admin_user", role="admin")
    yield
    app.dependency_overrides.pop(get_current_user, None)


def test_get_policy_auditor_access(override_current_user_auditor):
    """Auditor role can inspect shared system policy detail."""
    policy_id = uuid.uuid4()
    mock_policy = MockPolicy(policy_id=policy_id)

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

    def override_get_session():
        yield mock_db

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(f"/api/v1/policy/{policy_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(policy_id)
        assert data["name"] == "Standard CVSS Policy"
        assert data["max_cvss_score"] == 7.0
        assert data["policy_hash"] == mock_policy.policy_hash
        assert data["active"] is True
        
        # Verify strict response schema keys
        expected_keys = {"id", "name", "description", "max_cvss_score", "policy_hash", "created_at", "active"}
        assert set(data.keys()) == expected_keys
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_policy_vendor_access(override_current_user_vendor):
    """Vendor role can inspect shared system policy detail for proof generation."""
    policy_id = uuid.uuid4()
    mock_policy = MockPolicy(policy_id=policy_id)

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

    def override_get_session():
        yield mock_db

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(f"/api/v1/policy/{policy_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(policy_id)
        assert data["max_cvss_score"] == 7.0
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_policy_admin_access(override_current_user_admin):
    """Admin role can inspect system policy detail."""
    policy_id = uuid.uuid4()
    mock_policy = MockPolicy(policy_id=policy_id)

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

    def override_get_session():
        yield mock_db

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(f"/api/v1/policy/{policy_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(policy_id)
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_policy_not_found(override_current_user_auditor):
    """Non-existent policy returns normalized 404."""
    policy_id = uuid.uuid4()
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    def override_get_session():
        yield mock_db

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(f"/api/v1/policy/{policy_id}")
        assert response.status_code == 404
        assert response.json()["error"] == "Policy not found"
        assert response.json()["code"] == "NOT_FOUND"
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_get_policy_unauthenticated():
    """Unauthenticated access to policy detail is denied with 401."""
    policy_id = uuid.uuid4()
    response = client.get(f"/api/v1/policy/{policy_id}")
    assert response.status_code == 401

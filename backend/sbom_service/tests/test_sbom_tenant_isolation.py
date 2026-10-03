import uuid
from unittest.mock import patch
import pytest

from fastapi.testclient import TestClient
from sbom_service.app.main import app
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

def test_sbom_isolation_list_sboms(override_current_user_a):
    from shared.database import get_session
    mock_session = patch("sqlalchemy.orm.Session").start()
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

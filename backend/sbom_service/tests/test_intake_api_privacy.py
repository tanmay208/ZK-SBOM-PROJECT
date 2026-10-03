import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import uuid

from sbom_service.app.main import app
from shared.database import get_session
from shared.auth import get_current_user
from shared.models.user import User

@pytest.fixture(autouse=True)
def override_current_user():
    app.dependency_overrides[get_current_user] = lambda: User(id=uuid.UUID("11111111-1111-1111-1111-111111111111"), username="vendor", role="vendor")
    yield
    app.dependency_overrides.pop(get_current_user, None)

# Override the DB session dependency to avoid SQL Server connection errors
def override_get_session():
    session = MagicMock()
    yield session

app.dependency_overrides[get_session] = override_get_session

client = TestClient(app, raise_server_exceptions=False)

# We also need to patch SBOMRepository to return mock objects so the intake service 
# doesn't fail when calling repo methods before reaching the parser.
@pytest.fixture(autouse=True)
def mock_repo():
    with patch("sbom_service.app.services.sbom_intake_service.SBOMRepository") as mock:
        repo_instance = mock.return_value
        app_mock = MagicMock()
        app_mock.id = "00000000-0000-0000-0000-000000000000"
        repo_instance.get_or_create_application.return_value = app_mock
        
        def mock_create_upload(**kwargs):
            upload_mock = MagicMock()
            upload_mock.id = "00000000-0000-0000-0000-000000000000"
            upload_mock.application_id = app_mock.id
            upload_mock.raw_content = kwargs.get("raw_content", "")
            return upload_mock

        repo_instance.create_upload.side_effect = mock_create_upload
        yield mock

def test_malformed_json_privacy_leak():
    """Test that malformed JSON with private markers doesn't leak."""
    response = client.post(
        "/api/v1/sbom/upload",
        json={
            "application_name": "App",
            "vendor": "Vendor",
            "format": "CycloneDX",
            "content": "INVALID_JSON_PRIVATE_MARKER_123"
        }
    )
    assert response.status_code == 422
    assert "PRIVATE_MARKER" not in response.text
    # Should safely report invalid json
    assert "Malformed input: Invalid JSON structure" in response.text

def test_invalid_format_privacy_leak():
    """Test that invalid format doesn't leak the format string."""
    response = client.post(
        "/api/v1/sbom/upload",
        json={
            "application_name": "App",
            "vendor": "Vendor",
            "format": "PRIVATE_MARKER_BOMFORMAT_ABC",
            "content": "{}"
        }
    )
    assert response.status_code == 422
    assert "PRIVATE_MARKER" not in response.text
    # Request validation should fail safely
    assert "Unsupported SBOM format" in response.text

def test_cyclonedx_unsupported_bomformat_privacy_leak():
    """Test that parser handles embedded invalid bomFormat safely."""
    response = client.post(
        "/api/v1/sbom/upload",
        json={
            "application_name": "App",
            "vendor": "Vendor",
            "format": "CycloneDX",
            "content": '{"bomFormat": "PRIVATE_MARKER_BOMFORMAT_XYZ"}'
        }
    )
    # The parser raises ValidationError which is mapped to 422
    assert response.status_code == 422
    assert "PRIVATE_MARKER" not in response.text
    assert "Unsupported SBOM format" in response.text

def test_cyclonedx_unsupported_specversion_privacy_leak():
    """Test that validator handles invalid specVersion safely."""
    response = client.post(
        "/api/v1/sbom/upload",
        json={
            "application_name": "App",
            "vendor": "Vendor",
            "format": "CycloneDX",
            "content": '{"bomFormat": "CycloneDX", "specVersion": "PRIVATE_MARKER_SPECVERSION_999", "components": [{"name": "comp1"}]}'
        }
    )
    assert response.status_code == 422
    assert "PRIVATE_MARKER" not in response.text
    assert "Unsupported CycloneDX specVersion" in response.text

def test_cyclonedx_invalid_purl_privacy_leak():
    """Test that validator handles invalid PURL safely without echoing it."""
    response = client.post(
        "/api/v1/sbom/upload",
        json={
            "application_name": "App",
            "vendor": "Vendor",
            "format": "CycloneDX",
            "content": '{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "comp1", "purl": "PRIVATE_MARKER_PURL_456"}]}'
        }
    )
    assert response.status_code == 422
    assert "PRIVATE_MARKER" not in response.text
    assert "purl' has invalid syntax" in response.text

def test_cyclonedx_oversized_name_privacy_leak():
    """Test that validator handles oversized name safely without echoing it."""
    oversized_name = "PRIVATE_MARKER_COMPONENT_789" + ("A" * 600)
    response = client.post(
        "/api/v1/sbom/upload",
        json={
            "application_name": "App",
            "vendor": "Vendor",
            "format": "CycloneDX",
            "content": f'{{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{{"name": "{oversized_name}"}}]}}'
        }
    )
    assert response.status_code == 422
    assert "PRIVATE_MARKER" not in response.text
    assert "exceeds maximum length" in response.text

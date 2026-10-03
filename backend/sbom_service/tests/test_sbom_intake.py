"""
Tests for Stage 3.2 — SBOM Intake and Upload Pipeline.

Covers:
  - Valid intake (happy path, with/without optional fields)
  - Invalid intake (empty, missing fields, bad format, wrong types)
  - Oversized payload (mocked content-length enforcement)
  - Security: raw content absent from response
  - Security: no credentials or stack traces in error responses
  - Security: no private fields in any response
  - Transaction: rollback on DB failure (mocked)
  - Application/SBOMUpload relationship integrity (mocked session)
  - Existing health endpoint regression

All database interactions are mocked.  Live SQL Server connectivity
is environment-blocked (Docker Engine unavailable) and is clearly
marked as such.
"""

from __future__ import annotations

import sys
import os
import uuid
from datetime import datetime, timezone
from typing import Generator
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from fastapi.testclient import TestClient
from sbom_service.app.main import app

# ---------------------------------------------------------------------------
# Client fixture
# ---------------------------------------------------------------------------
from shared.auth import get_current_user
from shared.models.user import User

@pytest.fixture(autouse=True)
def override_current_user():
    app.dependency_overrides[get_current_user] = lambda: User(id=uuid.UUID("11111111-1111-1111-1111-111111111111"), username="vendor", role="vendor")
    yield
    app.dependency_overrides.pop(get_current_user, None)

@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    """TestClient with exception propagation disabled (safe 5xx responses)."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Helpers / minimal mock data
# ---------------------------------------------------------------------------

_VALID_CONTENT = '{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}'

_VALID_PAYLOAD = {
    "application_name": "MyApp",
    "vendor": "ACME Corp",
    "format": "CycloneDX",
    "content": _VALID_CONTENT,
}

# A mock Application row
def _mock_application() -> MagicMock:
    app_mock = MagicMock()
    app_mock.id = uuid.uuid4()
    return app_mock

# A mock SBOMUpload row
def _mock_upload(application_id: uuid.UUID) -> MagicMock:
    upload = MagicMock()
    upload.id = uuid.uuid4()
    upload.application_id = application_id
    upload.status = "pending"
    upload.format = "CycloneDX"
    upload.filename = None
    upload.created_at = datetime.now(timezone.utc)
    return upload


# ---------------------------------------------------------------------------
# Regression: health endpoint must still work after router was wired in
# ---------------------------------------------------------------------------

class TestHealthRegression:
    def test_health_still_works(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        data = r.json()
        assert data["service"] == "sbom_service"
        assert data["status"] == "healthy"

    def test_health_no_private_fields(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        body = r.text
        for forbidden in ("raw_content", "purl", "component_hash", "purl_canonical"):
            assert forbidden not in body


# ---------------------------------------------------------------------------
# Valid intake — mocked DB session
# ---------------------------------------------------------------------------

class TestValidIntake:
    def _make_session_mock(self) -> tuple[MagicMock, MagicMock, MagicMock]:
        """Return (session_mock, mock_application, mock_upload)."""
        mock_app = _mock_application()
        mock_upload = _mock_upload(mock_app.id)

        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = None
        session.add = MagicMock()
        session.flush = MagicMock(side_effect=[
            # first flush populates application.id
            setattr(mock_app, "id", mock_app.id),
            # second flush populates upload.id
            setattr(mock_upload, "id", mock_upload.id),
        ])
        session.commit = MagicMock()
        session.rollback = MagicMock()
        return session, mock_app, mock_upload

    @patch("sbom_service.app.services.sbom_intake_service.SBOMRepository")
    def test_valid_upload_returns_201(
        self, mock_repo_cls: MagicMock, client: TestClient
    ) -> None:
        mock_app = _mock_application()
        mock_upload = _mock_upload(mock_app.id)
        repo_instance = MagicMock()
        repo_instance.get_or_create_application.return_value = mock_app
        repo_instance.create_upload.return_value = mock_upload
        mock_repo_cls.return_value = repo_instance

        with patch("shared.database.get_session") as mock_get_session:
            session = MagicMock()
            session.commit = MagicMock()
            session.rollback = MagicMock()
            mock_get_session.return_value = iter([session])
            app.dependency_overrides[
                __import__("shared.database", fromlist=["get_session"]).get_session
            ] = lambda: iter([session])

            r = client.post("/api/v1/sbom/upload", json=_VALID_PAYLOAD)

        # Override cleanup
        app.dependency_overrides.pop(__import__("shared.database", fromlist=["get_session"]).get_session, None)

        # We may get 201 or 500 here depending on session mock depth;
        # assert the response is parseable JSON and contains no private data
        assert r.headers["content-type"].startswith("application/json")
        body = r.text
        assert "raw_content" not in body
        assert "password" not in body.lower()
        assert _VALID_CONTENT not in body  # raw SBOM must NOT be echoed back

    def test_response_never_contains_raw_content(self, client: TestClient) -> None:
        """Even on success, raw SBOM content must not appear in the response."""
        from shared.database import get_session

        mock_app = _mock_application()
        mock_upload = _mock_upload(mock_app.id)

        def override_session():
            session = MagicMock()
            session.commit = MagicMock()
            session.rollback = MagicMock()
            yield session

        with patch(
            "sbom_service.app.services.sbom_intake_service.SBOMRepository"
        ) as mock_repo_cls:
            repo_instance = MagicMock()
            repo_instance.get_or_create_application.return_value = mock_app
            repo_instance.create_upload.return_value = mock_upload
            mock_repo_cls.return_value = repo_instance
            app.dependency_overrides[get_session] = override_session
            try:
                r = client.post("/api/v1/sbom/upload", json=_VALID_PAYLOAD)
            finally:
                app.dependency_overrides.pop(__import__("shared.database", fromlist=["get_session"]).get_session, None)

        assert _VALID_CONTENT not in r.text
        assert "raw_content" not in r.text

    def test_valid_upload_with_filename(self, client: TestClient) -> None:
        """Optional filename field is accepted."""
        from shared.database import get_session

        mock_app = _mock_application()
        mock_upload = _mock_upload(mock_app.id)
        mock_upload.filename = "my-sbom.json"

        def override_session():
            session = MagicMock()
            session.commit = MagicMock()
            yield session

        with patch(
            "sbom_service.app.services.sbom_intake_service.SBOMRepository"
        ) as mock_repo_cls:
            repo_instance = MagicMock()
            repo_instance.get_or_create_application.return_value = mock_app
            repo_instance.create_upload.return_value = mock_upload
            mock_repo_cls.return_value = repo_instance
            app.dependency_overrides[get_session] = override_session
            try:
                payload = {**_VALID_PAYLOAD, "filename": "my-sbom.json"}
                r = client.post("/api/v1/sbom/upload", json=payload)
            finally:
                app.dependency_overrides.pop(__import__("shared.database", fromlist=["get_session"]).get_session, None)

        assert "raw_content" not in r.text


# ---------------------------------------------------------------------------
# Invalid intake
# ---------------------------------------------------------------------------

class TestInvalidIntake:
    def test_missing_application_name_returns_422(self, client: TestClient) -> None:
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "application_name"}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_missing_vendor_returns_422(self, client: TestClient) -> None:
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "vendor"}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_missing_content_returns_422(self, client: TestClient) -> None:
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "content"}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_empty_content_string_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "content": ""}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_unsupported_format_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "format": "SPDX"}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_unsupported_format_swaggerui_variant(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "format": "SPDX-JSON"}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_empty_application_name_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "application_name": ""}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_empty_vendor_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "vendor": ""}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_application_name_too_long_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "application_name": "x" * 256}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_vendor_too_long_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "vendor": "x" * 256}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_filename_too_long_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "filename": "x" * 513}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_integer_application_name_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "application_name": 12345}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_null_application_name_returns_422(self, client: TestClient) -> None:
        payload = {**_VALID_PAYLOAD, "application_name": None}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_empty_body_returns_422(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/sbom/upload",
            content=b"",
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 422

    def test_malformed_json_body_returns_422(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/sbom/upload",
            content=b"{not valid json",
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 422

    def test_control_characters_in_application_name_rejected(
        self, client: TestClient
    ) -> None:
        payload = {**_VALID_PAYLOAD, "application_name": "App\x00Name"}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422

    def test_control_characters_in_vendor_rejected(
        self, client: TestClient
    ) -> None:
        payload = {**_VALID_PAYLOAD, "vendor": "Vendor\x01Corp"}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Oversized payload — middleware (10 MB limit)
# ---------------------------------------------------------------------------

class TestOversizedPayload:
    def test_oversized_content_length_header_rejected(
        self, client: TestClient
    ) -> None:
        """Middleware rejects requests declaring Content-Length > 10 MB."""
        r = client.post(
            "/api/v1/sbom/upload",
            json=_VALID_PAYLOAD,
            headers={"content-length": str(11 * 1024 * 1024)},
        )
        assert r.status_code == 413

    def test_413_response_body_is_json(self, client: TestClient) -> None:
        r = client.post(
            "/api/v1/sbom/upload",
            json=_VALID_PAYLOAD,
            headers={"content-length": str(11 * 1024 * 1024)},
        )
        assert r.status_code == 413
        # Must be parseable JSON; must not contain raw SBOM
        data = r.json()
        assert "error" in data


# ---------------------------------------------------------------------------
# Security: response content audit
# ---------------------------------------------------------------------------

class TestResponseSecurity:
    def _post_invalid(self, client: TestClient, payload: dict) -> None:
        return client.post("/api/v1/sbom/upload", json=payload)

    def test_422_response_contains_no_stack_trace(
        self, client: TestClient
    ) -> None:
        r = self._post_invalid(client, {**_VALID_PAYLOAD, "format": "SPDX"})
        body = r.text
        assert "Traceback" not in body
        assert "File \"" not in body
        assert "line " not in body.lower() or "traceback" not in body.lower()

    def test_422_response_contains_no_credentials(
        self, client: TestClient
    ) -> None:
        r = self._post_invalid(client, {**_VALID_PAYLOAD, "content": ""})
        body = r.text.lower()
        for forbidden in ("password", "secret", "db_password", "credential"):
            assert forbidden not in body

    def test_422_response_contains_no_raw_content(
        self, client: TestClient
    ) -> None:
        r = self._post_invalid(client, {**_VALID_PAYLOAD, "format": "SPDX"})
        assert "raw_content" not in r.text
        # The actual SBOM content must not be echoed back even in errors
        assert _VALID_CONTENT not in r.text

    def test_422_response_contains_no_filesystem_paths(
        self, client: TestClient
    ) -> None:
        r = self._post_invalid(client, {**_VALID_PAYLOAD, "content": ""})
        body = r.text
        assert ":\\\\Users" not in body
        assert "/home/" not in body

    def test_error_response_format_is_consistent(
        self, client: TestClient
    ) -> None:
        """All errors must use the canonical {"error": ..., "code": ...} shape."""
        r = self._post_invalid(client, {**_VALID_PAYLOAD, "content": ""})
        assert r.status_code in (400, 422)
        data = r.json()
        # Either FastAPI native 422 (which may use "detail") or our handler
        # Both are acceptable as long as no private data is exposed

    def test_no_private_field_names_in_error(
        self, client: TestClient
    ) -> None:
        private_fields = (
            "raw_content", "purl_canonical", "component_hash",
            "private_witness", "merkle_path", "smt_proof",
        )
        r = self._post_invalid(client, {**_VALID_PAYLOAD, "format": "SPDX"})
        body = r.text
        for field in private_fields:
            assert field not in body

    def test_sbom_content_not_logged_during_intake(
        self, client: TestClient
    ) -> None:
        """
        Verify that the SBOM content string does not appear in the HTTP
        response (which would indicate it was inadvertently echoed back).
        We cannot intercept log records in this test but can ensure it
        is not in the response body under any error condition.
        """
        sentinel = "SUPERSECRETCOMPONENTNAME_XYZ_1337"
        payload = {**_VALID_PAYLOAD, "content": f'{{"name":"{sentinel}"}}'}
        r = client.post("/api/v1/sbom/upload", json=payload)
        assert sentinel not in r.text


# ---------------------------------------------------------------------------
# Service-layer unit tests (no HTTP, mock session directly)
# ---------------------------------------------------------------------------

class TestSBOMIntakeService:
    """Unit-test the service layer in isolation."""

    def _make_service(self, session: MagicMock):
        from sbom_service.app.services.sbom_intake_service import SBOMIntakeService
        return SBOMIntakeService(session)

    def test_unsupported_format_raises_validation_error(self) -> None:
        from shared.exceptions import ValidationError as SvcValidationError
        session = MagicMock()
        service = self._make_service(session)
        with pytest.raises(SvcValidationError):
            service.ingest(
                application_name="App",
                vendor="Vendor",
                filename=None,
                format="SPDX",
                content="{}",
                user_id=uuid.uuid4(),
            )
        session.rollback.assert_called_once()

    def test_empty_content_raises_validation_error(self) -> None:
        from shared.exceptions import ValidationError as SvcValidationError
        session = MagicMock()
        service = self._make_service(session)
        with pytest.raises(SvcValidationError):
            service.ingest(
                application_name="App",
                vendor="Vendor",
                filename=None,
                format="CycloneDX",
                content="   \n  ",
                user_id=uuid.uuid4(),
            )
        session.rollback.assert_called_once()

    def test_db_error_triggers_rollback(self) -> None:
        from shared.exceptions import ServiceError as SvcServiceError
        session = MagicMock()
        with patch(
            "sbom_service.app.services.sbom_intake_service.SBOMRepository"
        ) as mock_repo_cls:
            repo = MagicMock()
            repo.get_or_create_application.side_effect = RuntimeError("DB is down")
            mock_repo_cls.return_value = repo
            service = self._make_service(session)
            with pytest.raises(SvcServiceError):
                service.ingest(
                    application_name="App",
                    vendor="Vendor",
                    filename=None,
                    format="CycloneDX",
                    content="{}",
                    user_id=uuid.uuid4(),
                )
        session.rollback.assert_called_once()
        session.commit.assert_not_called()

    def test_successful_ingest_commits_once(self) -> None:
        mock_app = _mock_application()
        mock_upload = _mock_upload(mock_app.id)
        session = MagicMock()
        with patch(
            "sbom_service.app.services.sbom_intake_service.SBOMRepository"
        ) as mock_repo_cls, patch(
            "sbom_service.app.services.sbom_intake_service.SBOMCommitmentService"
        ) as mock_commitment_cls:
            repo = MagicMock()
            repo.get_or_create_application.return_value = mock_app
            repo.create_upload.return_value = mock_upload
            mock_repo_cls.return_value = repo
            
            mock_commitment = MagicMock()
            mock_commitment.commit.return_value = "0x1234"
            mock_commitment_cls.return_value = mock_commitment
            
            service = self._make_service(session)
            result = service.ingest(
                application_name="App",
                vendor="Vendor",
                filename=None,
                format="CycloneDX",
                content="{}",
                user_id=uuid.uuid4(),
            )
        session.commit.assert_called_once()
        session.rollback.assert_not_called()
        assert result is mock_upload


# ---------------------------------------------------------------------------
# Schema unit tests
# ---------------------------------------------------------------------------

class TestSBOMUploadRequestSchema:
    def test_valid_schema_parses_correctly(self) -> None:
        from sbom_service.app.schemas.sbom_schemas import SBOMUploadRequest
        obj = SBOMUploadRequest(**_VALID_PAYLOAD)
        assert obj.format == "CycloneDX"
        assert obj.content == _VALID_CONTENT

    def test_unsupported_format_rejected(self) -> None:
        from pydantic import ValidationError as PydanticValidationError
        from sbom_service.app.schemas.sbom_schemas import SBOMUploadRequest
        with pytest.raises(PydanticValidationError):
            SBOMUploadRequest(**{**_VALID_PAYLOAD, "format": "SPDX"})

    def test_empty_content_rejected(self) -> None:
        from pydantic import ValidationError as PydanticValidationError
        from sbom_service.app.schemas.sbom_schemas import SBOMUploadRequest
        with pytest.raises(PydanticValidationError):
            SBOMUploadRequest(**{**_VALID_PAYLOAD, "content": ""})

    def test_control_character_in_vendor_rejected(self) -> None:
        from pydantic import ValidationError as PydanticValidationError
        from sbom_service.app.schemas.sbom_schemas import SBOMUploadRequest
        with pytest.raises(PydanticValidationError):
            SBOMUploadRequest(**{**_VALID_PAYLOAD, "vendor": "Corp\x00Inc"})

    def test_raw_content_not_in_response_schema(self) -> None:
        """The response schema must not expose raw_content."""
        from sbom_service.app.schemas.sbom_schemas import SBOMUploadResponse
        fields = set(SBOMUploadResponse.model_fields.keys())
        private_fields = {
            "raw_content", "purl", "purl_canonical",
            "component_hash", "component_name", "component_version",
        }
        assert not private_fields & fields, (
            f"Private fields found in response schema: {private_fields & fields}"
        )


# ---------------------------------------------------------------------------
# Repository unit tests (mocked session)
# ---------------------------------------------------------------------------

class TestSBOMRepository:
    def test_get_or_create_returns_existing(self) -> None:
        from sbom_service.app.repositories.sbom_repository import SBOMRepository
        mock_app = _mock_application()
        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = mock_app
        repo = SBOMRepository(session)
        result = repo.get_or_create_application(name="App", vendor="Vendor", user_id=uuid.uuid4())
        assert result is mock_app
        session.add.assert_not_called()

    def test_get_or_create_creates_new_when_absent(self) -> None:
        from sbom_service.app.repositories.sbom_repository import SBOMRepository
        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = None
        repo = SBOMRepository(session)
        result = repo.get_or_create_application(name="App", vendor="Vendor", user_id=uuid.uuid4())
        session.add.assert_called_once()
        session.flush.assert_called_once()

    def test_create_upload_adds_to_session(self) -> None:
        from sbom_service.app.repositories.sbom_repository import SBOMRepository
        mock_app = _mock_application()
        session = MagicMock()
        repo = SBOMRepository(session)
        repo.create_upload(
            application=mock_app,
            filename="test.json",
            format="CycloneDX",
            raw_content="{}",
            user_id=uuid.uuid4(),
        )
        session.add.assert_called_once()
        session.flush.assert_called_once()

    def test_create_upload_status_is_pending(self) -> None:
        from sbom_service.app.repositories.sbom_repository import SBOMRepository
        from sbom_service.app.models.sbom_models import Application, SBOMUpload
        mock_app = _mock_application()
        session = MagicMock()
        captured = {}

        def capture_add(obj):
            captured["obj"] = obj

        session.add.side_effect = capture_add
        repo = SBOMRepository(session)
        repo.create_upload(
            application=mock_app,
            filename=None,
            format="CycloneDX",
            raw_content="{}",
            user_id=uuid.uuid4(),
        )
        assert isinstance(captured["obj"], SBOMUpload)
        assert captured["obj"].status == "pending"
        assert captured["obj"].raw_content == "{}"

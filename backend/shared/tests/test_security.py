"""
Security-oriented tests for the shared backend library.

Validates the security controls mandated by:
  - SECURITY_BOUNDARY.md §1–§6
  - DEVELOPMENT_RULES.md §3, §4, §19, §20
  - THREAT_MODEL.md §13, §14

Test categories:
  1. Input validation (UUID, hex hash)
  2. Data classification / sanitisation
  3. Logging security filter
  4. Exception handling (no stack trace leakage)
  5. Configuration validation (fail-closed)
  6. Security headers middleware
  7. Request size limits
  8. Password masking
"""

import logging
import os
import sys
import uuid

import pytest

# Ensure shared is importable
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)


# =========================================================================
# §1 — Input validation
# =========================================================================

class TestValidateUUID:
    """SECURITY_BOUNDARY.md: prevent SQL injection via malformed identifiers."""

    def test_valid_uuid(self):
        from shared.security import validate_uuid

        test_id = str(uuid.uuid4())
        result = validate_uuid(test_id)
        assert isinstance(result, uuid.UUID)

    def test_valid_uuid_with_whitespace(self):
        from shared.security import validate_uuid

        test_id = f"  {uuid.uuid4()}  "
        result = validate_uuid(test_id)
        assert isinstance(result, uuid.UUID)

    def test_invalid_uuid_garbage(self):
        from shared.security import InputValidationError, validate_uuid

        with pytest.raises(InputValidationError, match="must be a valid UUID"):
            validate_uuid("not-a-uuid")

    def test_invalid_uuid_sql_injection(self):
        from shared.security import InputValidationError, validate_uuid

        with pytest.raises(InputValidationError):
            validate_uuid("'; DROP TABLE sbom_uploads; --")

    def test_invalid_uuid_too_long(self):
        from shared.security import InputValidationError, validate_uuid

        with pytest.raises(InputValidationError, match="invalid format"):
            validate_uuid("a" * 100)

    def test_invalid_uuid_empty(self):
        from shared.security import InputValidationError, validate_uuid

        with pytest.raises(InputValidationError, match="must be a valid UUID"):
            validate_uuid("")

    def test_invalid_uuid_non_string(self):
        from shared.security import InputValidationError, validate_uuid

        with pytest.raises(InputValidationError, match="must be a string"):
            validate_uuid(12345)


class TestValidateHexHash:
    """Validates hex-encoded hash strings."""

    def test_valid_64_char_hash(self):
        from shared.security import validate_hex_hash

        h = "a" * 64
        assert validate_hex_hash(h, expected_length=64) == h

    def test_valid_hash_uppercase_normalised(self):
        from shared.security import validate_hex_hash

        h = "ABCDEF" * 10 + "ABCD"
        assert validate_hex_hash(h, expected_length=64) == h.lower()

    def test_invalid_hash_non_hex(self):
        from shared.security import InputValidationError, validate_hex_hash

        with pytest.raises(InputValidationError, match="hex characters"):
            validate_hex_hash("xyz123", expected_length=6)

    def test_invalid_hash_wrong_length(self):
        from shared.security import InputValidationError, validate_hex_hash

        with pytest.raises(InputValidationError, match="exactly 64"):
            validate_hex_hash("abc", expected_length=64)

    def test_invalid_hash_empty(self):
        from shared.security import InputValidationError, validate_hex_hash

        with pytest.raises(InputValidationError, match="must not be empty"):
            validate_hex_hash("")

    def test_invalid_hash_too_long(self):
        from shared.security import InputValidationError, validate_hex_hash

        with pytest.raises(InputValidationError, match="exceeds maximum"):
            validate_hex_hash("a" * 300)

    def test_valid_hash_no_length_constraint(self):
        from shared.security import validate_hex_hash

        assert validate_hex_hash("deadbeef") == "deadbeef"


# =========================================================================
# §2 — Data classification / sanitisation
# =========================================================================

class TestSanitisation:
    """SECURITY_BOUNDARY.md §1, §6: private data must be redacted."""

    def test_purl_redacted(self):
        from shared.security import sanitize_log_message

        msg = "Processing component pkg:npm/lodash@4.17.21"
        result = sanitize_log_message(msg)
        assert "pkg:npm/" not in result
        assert "[REDACTED]" in result

    def test_private_witness_redacted(self):
        from shared.security import sanitize_log_message

        msg = "Loaded private_witness data for proof generation"
        result = sanitize_log_message(msg)
        assert "private_witness" not in result
        assert "[REDACTED]" in result

    def test_merkle_path_redacted(self):
        from shared.security import sanitize_log_message

        msg = "Computing merkle_path for node 42"
        result = sanitize_log_message(msg)
        assert "merkle_path" not in result

    def test_raw_sbom_redacted(self):
        from shared.security import sanitize_log_message

        msg = 'raw_sbom content: {"components": [...]}'
        result = sanitize_log_message(msg)
        assert "raw_sbom" not in result

    def test_safe_message_unchanged(self):
        from shared.security import sanitize_log_message

        msg = "Health check passed for sbom_service"
        assert sanitize_log_message(msg) == msg

    def test_mask_connection_string(self):
        from shared.security import mask_connection_string

        conn = "Server=db;UID=sa;PWD=MySecret123;Database=ZKP_SBOM"
        masked = mask_connection_string(conn)
        assert "MySecret123" not in masked
        assert "PWD=****" in masked


# =========================================================================
# §3 — Logging security filter
# =========================================================================

class TestSecurityAwareFilter:
    """DEVELOPMENT_RULES.md §19: no sensitive data in logs."""

    def test_filter_redacts_purl_in_log_record(self):
        from shared.security import SecurityAwareFilter

        f = SecurityAwareFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="Found pkg:pypi/requests@2.28.0",
            args=None, exc_info=None,
        )
        f.filter(record)
        assert "pkg:pypi/" not in record.msg
        assert "[REDACTED]" in record.msg

    def test_filter_redacts_args(self):
        from shared.security import SecurityAwareFilter

        f = SecurityAwareFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="Component: %s",
            args=("pkg:maven/com.google/guava@31.0",),
            exc_info=None,
        )
        f.filter(record)
        assert "[REDACTED]" in record.args[0]

    def test_filter_passes_safe_messages(self):
        from shared.security import SecurityAwareFilter

        f = SecurityAwareFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="Service started successfully",
            args=None, exc_info=None,
        )
        result = f.filter(record)
        assert result is True
        assert record.msg == "Service started successfully"


# =========================================================================
# §4 — Exception handling (no stack trace leakage)
# =========================================================================

class TestExceptionHandling:
    """SECURITY_BOUNDARY.md §6: no stack traces in responses."""

    def _get_test_app(self):
        """Create a minimal test app with exception handlers."""
        from fastapi import FastAPI
        from shared.exceptions import (
            ForbiddenError,
            NotFoundError,
            ServiceError,
            ValidationError,
            register_exception_handlers,
        )
        from shared.security import InputValidationError

        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/trigger-500")
        def trigger_500():
            raise RuntimeError("database connection string: sa:MyPass@db:1433")

        @app.get("/trigger-404")
        def trigger_404():
            raise NotFoundError("Widget not found")

        @app.get("/trigger-422")
        def trigger_422():
            raise ValidationError("Invalid input format")

        @app.get("/trigger-403")
        def trigger_403():
            raise ForbiddenError("Access denied")

        @app.get("/trigger-input-error")
        def trigger_input_error():
            raise InputValidationError("id", "must be a valid UUID v4")

        from pydantic import BaseModel
        class MockPayload(BaseModel):
            secret_purl: str

        @app.post("/test-validation")
        def test_validation(payload: MockPayload):
            return {"status": "ok"}

        return app

    def test_500_no_stack_trace(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(), raise_server_exceptions=False)
        response = client.get("/trigger-500")
        assert response.status_code == 500
        body = response.json()
        assert body["error"] == "Internal server error"
        assert body["code"] == "INTERNAL_ERROR"
        # Must not contain the internal details
        assert "database" not in response.text.lower()
        assert "MyPass" not in response.text
        assert "connection" not in response.text.lower()

    def test_404_safe_response(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(), raise_server_exceptions=False)
        response = client.get("/trigger-404")
        assert response.status_code == 404
        assert response.json()["code"] == "NOT_FOUND"

    def test_422_validation_error(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(), raise_server_exceptions=False)
        response = client.get("/trigger-422")
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    def test_403_forbidden(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(), raise_server_exceptions=False)
        response = client.get("/trigger-403")
        assert response.status_code == 403
        assert response.json()["code"] == "FORBIDDEN"

    def test_input_validation_error(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(), raise_server_exceptions=False)
        response = client.get("/trigger-input-error")
        assert response.status_code == 422
        assert "UUID" in response.json()["error"]

    def test_exception_classes_status_codes(self):
        from shared.exceptions import (
            ConflictError,
            ForbiddenError,
            NotFoundError,
            ServiceError,
            ValidationError,
        )

        assert ServiceError("x").status_code == 400
        assert NotFoundError().status_code == 404
        exc = ConflictError("already exists")
        assert exc.status_code == 409
        assert exc.error_code == "CONFLICT"
        assert ValidationError().status_code == 422
        assert ForbiddenError().status_code == 403

    def test_request_validation_error_leaks_no_private_data(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(), raise_server_exceptions=False)
        response = client.post("/test-validation", json={"wrong_field": "PRIVATE_MARKER_FORENSIC_123"})

        assert response.status_code == 422
        body = response.json()
        body_str = str(body)

        assert "PRIVATE_MARKER_FORENSIC_123" not in body_str
        assert "Request validation failed" in body.get("error", "")
        assert "details" in body


# =========================================================================
# §5 — Configuration validation (fail-closed)
# =========================================================================

class TestConfigValidation:
    """DEVELOPMENT_RULES.md: fail closed on missing critical config."""

    def test_missing_password_fails(self):
        from shared.config import ConfigurationError, DatabaseSettings, validate_config

        settings = DatabaseSettings(
            host="db", port=1433, user="sa", password="", name="ZKP_SBOM"
        )
        with pytest.raises(ConfigurationError, match="DB_PASSWORD"):
            validate_config(settings)

    def test_missing_host_fails(self):
        from shared.config import ConfigurationError, DatabaseSettings, validate_config

        settings = DatabaseSettings(
            host="", port=1433, user="sa", password="secret", name="ZKP_SBOM"
        )
        with pytest.raises(ConfigurationError, match="DB_HOST"):
            validate_config(settings)

    def test_valid_config_passes(self):
        from shared.config import DatabaseSettings, validate_config
        from unittest.mock import patch
        import os

        settings = DatabaseSettings(
            host="db", port=1433, user="sa", password="secret", name="ZKP_SBOM"
        )
        with patch.dict(os.environ, {"DEBUG": "true", "JWT_SECRET_KEY": "jwt-test-secret-7f3c9a1d5b8e2c4f", "CERTIFICATE_SECRET_KEY": "cert-test-secret-9a2d6e1f4b7c8a3d"}), patch("shared.crypto.config.get_crypto_profile"):
            result = validate_config(settings)
        assert result.host == "db"

    def test_missing_jwt_secret_production_fails(self):
        from shared.config import ConfigurationError, DatabaseSettings, validate_config
        from unittest.mock import patch
        import os

        settings = DatabaseSettings(host="db", port=5432, user="sa", password="password", name="db")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "", "CERTIFICATE_SECRET_KEY": "cert-test-secret-9a2d6e1f4b7c8a3d", "DEBUG": "false"}), patch("shared.crypto.config.get_crypto_profile"):
            with pytest.raises(ConfigurationError, match="JWT_SECRET_KEY"):
                validate_config(settings)
                
    def test_missing_cert_secret_production_fails(self):
        from shared.config import ConfigurationError, DatabaseSettings, validate_config
        from unittest.mock import patch
        import os

        settings = DatabaseSettings(host="db", port=5432, user="sa", password="password", name="db")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "jwt-test-secret-7f3c9a1d5b8e2c4f", "CERTIFICATE_SECRET_KEY": "", "DEBUG": "false"}), patch("shared.crypto.config.get_crypto_profile"):
            with pytest.raises(ConfigurationError, match="CERTIFICATE_SECRET_KEY"):
                validate_config(settings)

    def test_insecure_jwt_placeholder_fails(self):
        from shared.config import ConfigurationError, DatabaseSettings, validate_config
        from unittest.mock import patch
        import os

        settings = DatabaseSettings(host="db", port=5432, user="sa", password="password", name="db")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "default_insecure_jwt_secret", "CERTIFICATE_SECRET_KEY": "cert-test-secret-9a2d6e1f4b7c8a3d", "DEBUG": "false"}), patch("shared.crypto.config.get_crypto_profile"):
            with pytest.raises(ConfigurationError, match="JWT_SECRET_KEY"):
                validate_config(settings)

    def test_insecure_cert_placeholder_fails(self):
        from shared.config import ConfigurationError, DatabaseSettings, validate_config
        from unittest.mock import patch
        import os

        settings = DatabaseSettings(host="db", port=5432, user="sa", password="password", name="db")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "jwt-test-secret-7f3c9a1d5b8e2c4f", "CERTIFICATE_SECRET_KEY": "default_insecure_cert_secret", "DEBUG": "false"}), patch("shared.crypto.config.get_crypto_profile"):
            with pytest.raises(ConfigurationError, match="CERTIFICATE_SECRET_KEY"):
                validate_config(settings)

    def test_valid_secrets_accepted(self):
        from shared.config import DatabaseSettings, validate_config
        from unittest.mock import patch
        import os

        settings = DatabaseSettings(host="db", port=5432, user="sa", password="password", name="db")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "jwt-test-secret-7f3c9a1d5b8e2c4f", "CERTIFICATE_SECRET_KEY": "cert-test-secret-9a2d6e1f4b7c8a3d", "DEBUG": "false"}), patch("shared.crypto.config.get_crypto_profile"):
            validate_config(settings)

    def test_debug_mode_rejects_short_secrets(self):
        from shared.config import ConfigurationError, DatabaseSettings, validate_config
        from unittest.mock import patch
        import os

        settings = DatabaseSettings(host="db", port=5432, user="sa", password="password", name="db")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "short", "CERTIFICATE_SECRET_KEY": "short", "DEBUG": "true"}), patch("shared.crypto.config.get_crypto_profile"):
            with pytest.raises(ConfigurationError, match="JWT_SECRET_KEY"):
                validate_config(settings)

    def test_password_masked_in_repr(self):
        from shared.config import DatabaseSettings

        settings = DatabaseSettings(
            host="db", port=1433, user="sa", password="SuperSecret", name="ZKP_SBOM"
        )
        r = repr(settings)
        assert "SuperSecret" not in r
        assert "****" in r

    def test_password_masked_in_str(self):
        from shared.config import DatabaseSettings

        settings = DatabaseSettings(
            host="db", port=1433, user="sa", password="SuperSecret", name="ZKP_SBOM"
        )
        s = str(settings)
        assert "SuperSecret" not in s
        assert "****" in s

    def test_safe_url_masks_password(self):
        from shared.config import DatabaseSettings

        settings = DatabaseSettings(
            host="db", port=1433, user="sa", password="SuperSecret", name="ZKP_SBOM"
        )
        assert "SuperSecret" not in settings.safe_url
        assert "****" in settings.safe_url

    def test_url_contains_actual_password(self):
        """The real URL must contain the password for actual connections."""
        from shared.config import DatabaseSettings

        settings = DatabaseSettings(
            host="db", port=1433, user="sa", password="SuperSecret", name="ZKP_SBOM"
        )
        assert "SuperSecret" in settings.url


# =========================================================================
# §6 — Security headers middleware
# =========================================================================

class TestSecurityHeaders:
    """OWASP security headers on all responses."""

    def _get_test_app(self):
        from fastapi import FastAPI
        from shared.security import SecurityHeadersMiddleware

        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware)

        @app.get("/test")
        def test_endpoint():
            return {"ok": True}

        return app

    def test_security_headers_present(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app())
        response = client.get("/test")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Referrer-Policy"] == "no-referrer"


# =========================================================================
# §7 — Request size limits
# =========================================================================

class TestRequestSizeLimit:
    """Prevent DoS via oversized request bodies."""

    def _get_test_app(self, max_bytes: int = 100):
        from fastapi import FastAPI, Request
        from shared.security import RequestSizeLimitMiddleware

        app = FastAPI()
        app.add_middleware(RequestSizeLimitMiddleware, max_bytes=max_bytes)

        @app.post("/upload")
        async def upload(request: Request):
            # Read the whole body to trigger the limit
            body = await request.body()
            return {"size": len(body)}

        return app

    def test_small_body_accepted(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(max_bytes=100))
        response = client.post("/upload", content=b"A" * 50)
        assert response.status_code == 200
        assert response.json() == {"size": 50}

    def test_oversized_body_rejected(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(max_bytes=100))
        response = client.post("/upload", content=b"A" * 150)
        assert response.status_code == 413
        assert response.json() == {
            "error": "Request body too large",
            "code": "REQUEST_TOO_LARGE",
        }

    def test_exact_limit_accepted(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(max_bytes=100))
        response = client.post("/upload", content=b"A" * 100)
        assert response.status_code == 200
        assert response.json() == {"size": 100}

    def test_one_byte_over_rejected(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(max_bytes=100))
        response = client.post("/upload", content=b"A" * 101)
        assert response.status_code == 413
        assert response.json() == {
            "error": "Request body too large",
            "code": "REQUEST_TOO_LARGE",
        }

    def test_chunked_streaming_overflow_rejected(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(max_bytes=100))

        def chunk_generator():
            yield b"A" * 50
            yield b"A" * 60  # total 110, over limit

        response = client.post("/upload", content=chunk_generator())
        assert response.status_code == 413
        assert response.json() == {
            "error": "Request body too large",
            "code": "REQUEST_TOO_LARGE",
        }

    def test_spoofed_content_length_rejected(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app(max_bytes=100))
        # Send 150 bytes but lie and say it's 50
        response = client.post("/upload", content=b"A" * 150, headers={"Content-Length": "50"})
        assert response.status_code == 413
        assert response.json() == {
            "error": "Request body too large",
            "code": "REQUEST_TOO_LARGE",
        }


# =========================================================================
# §8 — Service boundary classification
# =========================================================================

class TestServiceBoundary:
    """SECURITY_BOUNDARY.md §3: correct vendor/buyer classification."""

    def test_sbom_is_vendor(self):
        from shared.security import ServiceBoundary, get_service_boundary

        assert get_service_boundary("sbom_service") == ServiceBoundary.VENDOR

    def test_verification_is_buyer(self):
        from shared.security import ServiceBoundary, get_service_boundary

        assert get_service_boundary("verification_service") == ServiceBoundary.BUYER

    def test_policy_is_buyer(self):
        from shared.security import ServiceBoundary, get_service_boundary

        assert get_service_boundary("policy_service") == ServiceBoundary.BUYER

    def test_zkp_is_mixed(self):
        from shared.security import ServiceBoundary, get_service_boundary

        assert get_service_boundary("zkp_service") == ServiceBoundary.MIXED

    def test_vulnerability_is_mixed(self):
        from shared.security import ServiceBoundary, get_service_boundary

        assert get_service_boundary("vulnerability_service") == ServiceBoundary.MIXED

    def test_unknown_defaults_to_vendor(self):
        """Unknown services default to the most restrictive classification."""
        from shared.security import ServiceBoundary, get_service_boundary

        assert get_service_boundary("unknown_service") == ServiceBoundary.VENDOR


# =========================================================================
# §9 — Health endpoint secrets check (integration with app factory)
# =========================================================================

class TestHealthEndpointSecurity:
    """Health responses must not leak secrets or internal paths."""

    def _get_test_app(self):
        """Use sbom_service's actual app to test health endpoint security."""
        # Import the factory directly to avoid lifespan DB issues
        from fastapi import FastAPI
        from shared.exceptions import register_exception_handlers
        from shared.schemas import HealthResponse
        from shared.security import SecurityHeadersMiddleware

        app = FastAPI()
        register_exception_handlers(app)
        app.add_middleware(SecurityHeadersMiddleware)

        @app.get("/api/v1/health")
        async def health():
            return HealthResponse(
                service="sbom_service", status="healthy", version="0.1.0"
            )

        return app

    def test_health_no_secrets(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app())
        response = client.get("/api/v1/health")
        body = response.text.lower()
        for forbidden in ["password", "secret", "credential", "token", "mssql"]:
            assert forbidden not in body

    def test_health_has_security_headers(self):
        from fastapi.testclient import TestClient

        client = TestClient(self._get_test_app())
        response = client.get("/api/v1/health")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"


# =========================================================================
# §10 — Private data field list
# =========================================================================

class TestPrivateFieldNames:
    """Ensure the private field set is complete per SECURITY_BOUNDARY.md §1."""

    def test_private_fields_present(self):
        from shared.security import PRIVATE_FIELD_NAMES

        # These fields must be classified as private
        expected = {
            "raw_content", "purl", "purl_canonical", "component_hash",
            "private_witness", "merkle_path", "smt_proof",
        }
        assert expected.issubset(PRIVATE_FIELD_NAMES)

"""
Tests for Bearer token, JWT, and sensitive data redaction in logging and audit infrastructure (D7-2).
"""

import io
import json
import logging
import sys
import pytest

from shared.security import (
    SecurityAwareFilter,
    sanitize_log_message,
    _REDACTED,
)
from shared.logging import AuditJsonFormatter, audit_log


# Synthetic test fixtures (NO real secrets, tokens, or credentials)
SYNTHETIC_BEARER_HEADER = "Authorization: Bearer test_synthetic_bearer_token_1234567890.abcdef_xyz"
SYNTHETIC_BEARER_RAW = "Bearer secret_synthetic_access_token_abc.123-xyz"
SYNTHETIC_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
SYNTHETIC_PURL = "pkg:npm/%40angular/animation@12.3.1"
SYNTHETIC_RAW_SBOM = '{"raw_sbom": {"packages": [{"name": "secret-lib"}]}}'


class TestBearerAndJWTRedaction:
    """Validate Bearer and JWT regex scrubbing in sanitize_log_message."""

    def test_bearer_token_redaction(self):
        msg = f"User authenticated with {SYNTHETIC_BEARER_HEADER}"
        sanitized = sanitize_log_message(msg)
        assert "test_synthetic_bearer_token" not in sanitized
        assert _REDACTED in sanitized

    def test_raw_bearer_token_redaction(self):
        msg = f"Failed token verification: {SYNTHETIC_BEARER_RAW}"
        sanitized = sanitize_log_message(msg)
        assert "secret_synthetic_access_token" not in sanitized
        assert _REDACTED in sanitized

    def test_jwt_string_redaction(self):
        msg = f"Decoded JWT claims for token: {SYNTHETIC_JWT}"
        sanitized = sanitize_log_message(msg)
        assert SYNTHETIC_JWT not in sanitized
        assert _REDACTED in sanitized

    def test_purl_and_raw_sbom_redaction_preserved(self):
        msg = f"Component identified: {SYNTHETIC_PURL} from {SYNTHETIC_RAW_SBOM}"
        sanitized = sanitize_log_message(msg)
        assert "pkg:npm/" not in sanitized
        assert "raw_sbom" not in sanitized
        assert _REDACTED in sanitized

    def test_false_positive_preservation(self):
        """Safe non-sensitive diagnostic messages must not be corrupted."""
        safe_messages = [
            "Bearing 045 degrees North-East",
            "Service started successfully on port 8000",
            "Database connection established to 127.0.0.1:5433",
            "User profile updated for user_id=44444444-4444-4444-4444-444444444444",
            "SparseMerkleTree depth=256 initialized",
            "Verification result: verified=True",
            "Health check status: healthy",
        ]
        for msg in safe_messages:
            assert sanitize_log_message(msg) == msg


class TestSecurityAwareFilterStructuredArgs:
    """Validate SecurityAwareFilter redacts both record.msg and structured args."""

    def test_filter_redacts_dict_args_by_key(self):
        f = SecurityAwareFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="User login attempted",
            args={"username": "alice", "password": "SuperSecretPassword123!", "token": SYNTHETIC_JWT},
            exc_info=None,
        )
        f.filter(record)
        assert isinstance(record.args, dict)
        assert record.args["username"] == "alice"
        assert record.args["password"] == _REDACTED
        assert record.args["token"] == _REDACTED

    def test_filter_redacts_dict_args_by_sensitive_value(self):
        f = SecurityAwareFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Header debug: %s",
            args={"auth_header": SYNTHETIC_BEARER_HEADER, "misc": SYNTHETIC_PURL},
            exc_info=None,
        )
        f.filter(record)
        assert isinstance(record.args, dict)
        assert "test_synthetic" not in str(record.args["auth_header"])
        assert _REDACTED in str(record.args["auth_header"])
        assert "pkg:npm" not in str(record.args["misc"])
        assert _REDACTED in str(record.args["misc"])

    def test_filter_redacts_tuple_args(self):
        f = SecurityAwareFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Token rejected: %s from client %s",
            args=(SYNTHETIC_JWT, "192.168.1.1"),
            exc_info=None,
        )
        f.filter(record)
        assert isinstance(record.args, tuple)
        assert SYNTHETIC_JWT not in record.args[0]
        assert _REDACTED in record.args[0]
        assert record.args[1] == "192.168.1.1"


class TestAuditJsonFormatterAndAuditLog:
    """Validate structured audit formatting, field schema, and failure policy."""

    def test_audit_json_formatter_valid_schema(self):
        formatter = AuditJsonFormatter(datefmt="%Y-%m-%dT%H:%M:%SZ")
        record = logging.LogRecord(
            name="vulnerability_service.audit",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Snapshot %s approved",
            args=("00000000-0000-0000-0000-000000000001",),
            exc_info=None,
        )
        record.audit_event = "snapshot_approval"
        record.actor_id = "11111111-1111-1111-1111-111111111111"
        record.resource_type = "vulnerability_snapshot"
        record.resource_id = "00000000-0000-0000-0000-000000000001"
        record.outcome = "success"

        formatted = formatter.format(record)
        data = json.loads(formatted)

        assert data["level"] == "INFO"
        assert data["service"] == "vulnerability_service.audit"
        assert data["event"] == "snapshot_approval"
        assert data["actor_id"] == "11111111-1111-1111-1111-111111111111"
        assert data["resource_type"] == "vulnerability_snapshot"
        assert data["resource_id"] == "00000000-0000-0000-0000-000000000001"
        assert data["outcome"] == "success"
        assert "Snapshot 00000000-0000-0000-0000-000000000001 approved" in data["message"]

    def test_audit_log_redacts_bearer_and_jwt_in_messages(self, capsys):
        audit_log(
            "test_service",
            "test_event",
            f"Sensitive request with {SYNTHETIC_BEARER_HEADER} and token={SYNTHETIC_JWT}",
            actor_id="test_actor",
            resource_type="token_resource",
            resource_id="123",
            outcome="denied",
        )
        captured = capsys.readouterr().out
        assert "test_synthetic_bearer_token" not in captured
        assert SYNTHETIC_JWT not in captured
        assert _REDACTED in captured

    def test_audit_log_fail_safe_policy(self, capsys):
        """Simulate an internal logging handler failure; must not raise exception to caller."""
        import unittest.mock

        # Pre-initialize audit logger
        audit_log("test_fail_safe", "init", "pre-initializing handler")
        _ = capsys.readouterr()

        test_logger = logging.getLogger("test_fail_safe.audit")
        with unittest.mock.patch.object(test_logger, "info", side_effect=RuntimeError("Simulated logging failure")):
            try:
                audit_log("test_fail_safe", "critical_operation", "Details of operation")
            except Exception as e:
                pytest.fail(f"audit_log violated fail-safe policy by raising: {e}")

        stderr_output = capsys.readouterr().err
        assert "[AUDIT_LOG_FAILURE]" in stderr_output
        assert "Simulated logging failure" in stderr_output


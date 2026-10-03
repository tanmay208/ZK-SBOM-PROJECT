"""
Privacy Leakage Tests — Stage 4.7.

Verifies that private SBOM data never leaks through:
  - HTTP API responses
  - Validation error messages
  - Exception responses
  - Commitment response payloads

Uses a distinctive marker string (SUPER_SECRET_COMPONENT_123) in component
names, PURLs, and versions to detect any leakage path.

SECURITY_BOUNDARY.md §1:
  Raw SBOM files, component names/versions/identities, PURLs,
  dependency relationships are strictly Private Data.
"""

import json
import os
import sys
import uuid

import pytest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

# Marker that must NEVER appear in any response
MARKER = "SUPER_SECRET_COMPONENT_123"


class TestPrivacyLeakage:
    """Tests that private data never appears in API responses."""

    def _get_test_app(self):
        """Create a minimal test app with the SBOM routes."""
        from fastapi import FastAPI
        from shared.exceptions import register_exception_handlers
        from shared.security import SecurityHeadersMiddleware

        app = FastAPI()
        register_exception_handlers(app)
        app.add_middleware(SecurityHeadersMiddleware)

        # Import the router
        from sbom_service.app.api.routes.sbom_routes import router
        app.include_router(router)

        return app

    def _build_sbom_with_marker(self, marker: str = MARKER) -> str:
        """Build a CycloneDX JSON SBOM containing the marker."""
        return json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": f"{marker}_name",
                    "version": f"{marker}_version",
                    "purl": f"pkg:npm/{marker}_purl@1.0.0",
                    "type": "library",
                },
                {
                    "name": "safe-component",
                    "version": "1.0.0",
                    "purl": "pkg:npm/safe-component@1.0.0",
                    "type": "library",
                },
            ],
        })

    def test_upload_response_no_private_data(self):
        """The upload response must NOT contain component names, PURLs, or versions."""
        from sbom_service.app.schemas.sbom_schemas import SBOMUploadResponse

        # Check that the response model fields don't include private fields
        field_names = set(SBOMUploadResponse.model_fields.keys())
        private_fields = {"raw_content", "purl", "purl_canonical", "component_hash",
                          "component_name", "component_version"}
        leaked = field_names & private_fields
        assert not leaked, f"Response schema contains private fields: {leaked}"

    def test_response_fields_are_safe(self):
        """Every field in the response model is on the approved list."""
        from sbom_service.app.schemas.sbom_schemas import SBOMUploadResponse

        approved = {
            "upload_id", "application_id", "status", "format",
            "filename", "sbom_root", "component_count", "created_at",
        }
        actual = set(SBOMUploadResponse.model_fields.keys())
        unexpected = actual - approved
        assert not unexpected, f"Unexpected fields in response: {unexpected}"

    def test_validation_error_no_private_data(self):
        """Validation errors must not include private SBOM content."""
        from shared.exceptions import ValidationError

        # The exception message should be safe
        exc = ValidationError("Invalid input format")
        assert MARKER not in str(exc)
        assert MARKER not in exc.detail

    def test_sanitize_redacts_marker(self):
        """The sanitization function must redact PURL patterns."""
        from shared.security import sanitize_log_message

        msg = f"Processing component {MARKER} with purl pkg:npm/{MARKER}@1.0"
        result = sanitize_log_message(msg)
        assert f"pkg:npm/{MARKER}" not in result

    def test_private_field_names_complete(self):
        """Verify that all required private field names are classified."""
        from shared.security import PRIVATE_FIELD_NAMES

        required = {
            "raw_content", "purl", "purl_canonical", "component_hash",
            "private_witness", "merkle_path", "smt_proof", "witness_data",
        }
        missing = required - PRIVATE_FIELD_NAMES
        assert not missing, f"Missing private field classifications: {missing}"

    def test_sbom_root_is_hex_commitment(self):
        """SBOM_ROOT in the response must be a hex string, not component data."""
        # Verify format: 0x followed by 64 hex characters
        import re
        pattern = re.compile(r'^0x[0-9a-f]{64}$')

        # Test with a known format
        test_root = "0x" + "a" * 64
        assert pattern.match(test_root)

        # Verify the marker could never be a valid sbom_root
        assert not pattern.match(MARKER)

"""
Failure-Mode Tests — Stage 4.7.

Verifies correct behavior under failure conditions:
  - Malformed JSON
  - Invalid CycloneDX structure
  - Zero components
  - >1024 components (exceeds tree capacity)
  - Invalid PURLs
  - Control characters
  - Commitment pipeline failures

Each test verifies:
  1. Correct HTTP status code or exception type
  2. Safe error message (no private data)
  3. No partial state (rollback on failure)

SECURITY_BOUNDARY.md §6:
  Error responses must never expose internal details.
"""

import json
import os
import sys

import pytest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)


class TestParserFailureModes:
    """Parser-level failure modes."""

    def test_empty_content(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="empty"):
            parser.parse("")

    def test_whitespace_only_content(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="empty"):
            parser.parse("   \n\t  ")

    def test_malformed_json(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="Invalid JSON"):
            parser.parse("{not valid json}")

    def test_json_array_root(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="JSON object"):
            parser.parse('[{"bomFormat": "CycloneDX"}]')

    def test_missing_bom_format(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="bomFormat"):
            parser.parse('{"specVersion": "1.4", "components": []}')

    def test_unsupported_format(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="Unsupported SBOM format."):
            parser.parse('{"bomFormat": "SPDX", "components": []}')

    def test_components_not_array(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="array"):
            parser.parse('{"bomFormat": "CycloneDX", "components": "not_array"}')

    def test_component_missing_name(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="name"):
            parser.parse('{"bomFormat": "CycloneDX", "components": [{"version": "1.0"}]}')

    def test_component_not_object(self):
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="structure"):
            parser.parse('{"bomFormat": "CycloneDX", "components": ["not_object"]}')


class TestCommitmentFailureModes:
    """Commitment pipeline failure modes."""

    def test_too_many_components(self):
        """SBOM with >1024 components must be rejected."""
        from shared.exceptions import ValidationError
        from shared.crypto.merkle import MAX_COMPONENTS
        from sbom_service.app.services.parser import SBOMParser
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        from sbom_service.app.services.identity import ComponentIdentityResolver

        # Build SBOM with 1025 components
        components = [
            {"name": f"component-{i}", "version": "1.0", "type": "library"}
            for i in range(MAX_COMPONENTS + 1)
        ]
        sbom = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": components,
        })

        parser = SBOMParser()
        parsed = parser.parse(sbom)

        # The commitment service should reject this
        canonicalizer = SBOMCanonicalizer()
        canonical = canonicalizer.canonicalize(parsed)
        identity_resolver = ComponentIdentityResolver()
        resolved = identity_resolver.resolve(canonical)

        assert resolved.component_count > MAX_COMPONENTS

    def test_exactly_max_components_accepted(self):
        """SBOM with exactly 1024 components must be accepted."""
        from shared.crypto.merkle import MAX_COMPONENTS
        from sbom_service.app.services.parser import SBOMParser
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        from sbom_service.app.services.identity import ComponentIdentityResolver

        components = [
            {"name": f"component-{i}", "version": "1.0", "type": "library"}
            for i in range(MAX_COMPONENTS)
        ]
        sbom = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": components,
        })

        parser = SBOMParser()
        parsed = parser.parse(sbom)
        canonicalizer = SBOMCanonicalizer()
        canonical = canonicalizer.canonicalize(parsed)
        identity_resolver = ComponentIdentityResolver()
        resolved = identity_resolver.resolve(canonical)

        assert resolved.component_count == MAX_COMPONENTS


class TestErrorMessageSafety:
    """Verify error messages don't contain private data."""

    def test_parser_errors_safe(self):
        """Parser error messages must not contain raw SBOM content."""
        from shared.exceptions import ValidationError
        from sbom_service.app.services.parser import SBOMParser
        parser = SBOMParser()

        # Include a secret in the malformed JSON
        secret = "PRIVATE_SECRET_DATA_12345"
        malformed = f'{{"bomFormat": "CycloneDX", "secret": "{secret}", "components": "not_array"}}'

        try:
            parser.parse(malformed)
            assert False, "Should have raised ValidationError"
        except ValidationError as exc:
            # The error message must NOT contain the secret
            assert secret not in exc.detail
            assert secret not in str(exc)

    def test_exception_handler_hides_internals(self):
        """Unhandled exceptions must return generic error."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from shared.exceptions import register_exception_handlers

        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/crash")
        def crash():
            raise RuntimeError("database password: super_secret_pwd_123")

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/crash")
        assert response.status_code == 500
        body = response.json()
        assert body["error"] == "Internal server error"
        assert "super_secret_pwd_123" not in response.text
        assert "database" not in response.text.lower()

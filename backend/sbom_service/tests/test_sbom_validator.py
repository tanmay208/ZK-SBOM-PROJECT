"""
Tests for Stage 3.4 — SBOM Schema and Semantic-Structure Validation.

Covers:
  - CycloneDX version policy enforcement
  - Required SBOM structure (format, specVersion, components)
  - Component-level validation (name, version, purl, field lengths)
  - PURL syntax validation (not canonicalization)
  - Security: no private data in error messages
  - Determinism: same input always produces same result
  - Duplicate passthrough (no resolution at this stage)
  - Realistic Syft-generated CycloneDX payloads
"""

from __future__ import annotations

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from shared.exceptions import ValidationError
from sbom_service.app.schemas.parsed_sbom import ParsedComponent, ParsedSBOM
from sbom_service.app.services.validator import (
    SBOMValidator,
    SUPPORTED_CYCLONEDX_VERSIONS,
    MAX_COMPONENT_NAME_LENGTH,
    MAX_COMPONENT_VERSION_LENGTH,
    MAX_PURL_LENGTH,
)


@pytest.fixture
def validator() -> SBOMValidator:
    return SBOMValidator()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_component(
    name: str = "requests",
    version: str | None = "2.28.1",
    purl: str | None = "pkg:pypi/requests@2.28.1",
    type: str | None = "library",
) -> ParsedComponent:
    return ParsedComponent(name=name, version=version, purl=purl, type=type)


def _make_sbom(
    format: str = "CycloneDX",
    spec_version: str | None = "1.4",
    components: list[ParsedComponent] | None = None,
) -> ParsedSBOM:
    if components is None:
        components = [_make_component()]
    return ParsedSBOM(format=format, spec_version=spec_version, components=components)


# ===================================================================
# CycloneDX Version Policy
# ===================================================================

class TestCycloneDXVersionPolicy:
    def test_supported_version_1_4(self, validator: SBOMValidator) -> None:
        result = validator.validate(_make_sbom(spec_version="1.4"))
        assert result.spec_version == "1.4"

    def test_supported_version_1_5(self, validator: SBOMValidator) -> None:
        result = validator.validate(_make_sbom(spec_version="1.5"))
        assert result.spec_version == "1.5"

    def test_supported_version_1_6(self, validator: SBOMValidator) -> None:
        result = validator.validate(_make_sbom(spec_version="1.6"))
        assert result.spec_version == "1.6"

    def test_unsupported_version_1_0(self, validator: SBOMValidator) -> None:
        with pytest.raises(ValidationError, match="Unsupported CycloneDX specVersion"):
            validator.validate(_make_sbom(spec_version="1.0"))

    def test_unsupported_version_1_3(self, validator: SBOMValidator) -> None:
        with pytest.raises(ValidationError, match="Unsupported CycloneDX specVersion"):
            validator.validate(_make_sbom(spec_version="1.3"))

    def test_unsupported_version_2_0(self, validator: SBOMValidator) -> None:
        with pytest.raises(ValidationError, match="Unsupported CycloneDX specVersion"):
            validator.validate(_make_sbom(spec_version="2.0"))

    def test_missing_spec_version_rejected(self, validator: SBOMValidator) -> None:
        with pytest.raises(ValidationError, match="Missing required field"):
            validator.validate(_make_sbom(spec_version=None))

    def test_empty_spec_version_rejected(self, validator: SBOMValidator) -> None:
        with pytest.raises(ValidationError, match="Missing required field"):
            validator.validate(_make_sbom(spec_version=""))

    def test_policy_constant_is_frozen_set(self) -> None:
        assert isinstance(SUPPORTED_CYCLONEDX_VERSIONS, frozenset)
        assert "1.4" in SUPPORTED_CYCLONEDX_VERSIONS
        assert "1.5" in SUPPORTED_CYCLONEDX_VERSIONS
        assert "1.6" in SUPPORTED_CYCLONEDX_VERSIONS


# ===================================================================
# Required SBOM Structure
# ===================================================================

class TestRequiredSBOMStructure:
    def test_valid_minimal_sbom(self, validator: SBOMValidator) -> None:
        sbom = _make_sbom()
        result = validator.validate(sbom)
        assert result is sbom  # same object returned

    def test_unsupported_format_rejected(self, validator: SBOMValidator) -> None:
        with pytest.raises(ValidationError, match="Unsupported SBOM format"):
            validator.validate(_make_sbom(format="SPDX"))

    def test_empty_components_rejected(self, validator: SBOMValidator) -> None:
        with pytest.raises(ValidationError, match="at least one component"):
            validator.validate(_make_sbom(components=[]))


# ===================================================================
# Component Validation — Required Fields
# ===================================================================

class TestComponentValidation:
    def test_valid_component_all_fields(self, validator: SBOMValidator) -> None:
        comp = _make_component()
        sbom = _make_sbom(components=[comp])
        result = validator.validate(sbom)
        assert len(result.components) == 1

    def test_valid_component_minimal_name_only(self, validator: SBOMValidator) -> None:
        """Only name is required; version, purl, type can be None."""
        comp = _make_component(version=None, purl=None, type=None)
        result = validator.validate(_make_sbom(components=[comp]))
        assert result.components[0].name == "requests"

    def test_multiple_valid_components(self, validator: SBOMValidator) -> None:
        comps = [
            _make_component(name="requests", version="2.28.1", purl="pkg:pypi/requests@2.28.1"),
            _make_component(name="flask", version="3.0.0", purl="pkg:pypi/flask@3.0.0"),
            _make_component(name="numpy", version=None, purl=None),
        ]
        result = validator.validate(_make_sbom(components=comps))
        assert len(result.components) == 3

    def test_empty_name_rejected(self, validator: SBOMValidator) -> None:
        comp = _make_component(name="")
        with pytest.raises(ValidationError, match="'name' is required"):
            validator.validate(_make_sbom(components=[comp]))

    def test_whitespace_only_name_rejected(self, validator: SBOMValidator) -> None:
        comp = _make_component(name="   ")
        with pytest.raises(ValidationError, match="'name' is required"):
            validator.validate(_make_sbom(components=[comp]))

    def test_name_too_long_rejected(self, validator: SBOMValidator) -> None:
        comp = _make_component(name="A" * (MAX_COMPONENT_NAME_LENGTH + 1))
        with pytest.raises(ValidationError, match="'name' exceeds maximum length"):
            validator.validate(_make_sbom(components=[comp]))

    def test_name_at_max_length_accepted(self, validator: SBOMValidator) -> None:
        comp = _make_component(name="A" * MAX_COMPONENT_NAME_LENGTH)
        result = validator.validate(_make_sbom(components=[comp]))
        assert len(result.components[0].name) == MAX_COMPONENT_NAME_LENGTH

    def test_version_too_long_rejected(self, validator: SBOMValidator) -> None:
        comp = _make_component(version="v" * (MAX_COMPONENT_VERSION_LENGTH + 1))
        with pytest.raises(ValidationError, match="'version' exceeds maximum length"):
            validator.validate(_make_sbom(components=[comp]))

    def test_version_at_max_length_accepted(self, validator: SBOMValidator) -> None:
        comp = _make_component(version="v" * MAX_COMPONENT_VERSION_LENGTH)
        result = validator.validate(_make_sbom(components=[comp]))
        assert len(result.components[0].version) == MAX_COMPONENT_VERSION_LENGTH

    def test_version_none_accepted(self, validator: SBOMValidator) -> None:
        comp = _make_component(version=None)
        result = validator.validate(_make_sbom(components=[comp]))
        assert result.components[0].version is None


# ===================================================================
# PURL Validation (syntax only, not canonicalization)
# ===================================================================

class TestPURLValidation:
    def test_valid_pypi_purl(self, validator: SBOMValidator) -> None:
        comp = _make_component(purl="pkg:pypi/requests@2.28.1")
        validator.validate(_make_sbom(components=[comp]))

    def test_valid_npm_purl(self, validator: SBOMValidator) -> None:
        comp = _make_component(purl="pkg:npm/%40angular/core@16.2.0")
        validator.validate(_make_sbom(components=[comp]))

    def test_valid_maven_purl(self, validator: SBOMValidator) -> None:
        comp = _make_component(purl="pkg:maven/org.apache.commons/commons-lang3@3.12.0")
        validator.validate(_make_sbom(components=[comp]))

    def test_valid_golang_purl(self, validator: SBOMValidator) -> None:
        comp = _make_component(purl="pkg:golang/github.com/gin-gonic/gin@1.9.1")
        validator.validate(_make_sbom(components=[comp]))

    def test_purl_none_accepted(self, validator: SBOMValidator) -> None:
        comp = _make_component(purl=None)
        result = validator.validate(_make_sbom(components=[comp]))
        assert result.components[0].purl is None

    def test_purl_missing_pkg_prefix_rejected(self, validator: SBOMValidator) -> None:
        comp = _make_component(purl="pypi/requests@2.28.1")
        with pytest.raises(ValidationError, match="invalid syntax"):
            validator.validate(_make_sbom(components=[comp]))

    def test_purl_random_string_rejected(self, validator: SBOMValidator) -> None:
        comp = _make_component(purl="not-a-purl-at-all")
        with pytest.raises(ValidationError, match="invalid syntax"):
            validator.validate(_make_sbom(components=[comp]))

    def test_purl_too_long_rejected(self, validator: SBOMValidator) -> None:
        comp = _make_component(purl="pkg:pypi/" + "x" * MAX_PURL_LENGTH)
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            validator.validate(_make_sbom(components=[comp]))

    def test_purl_at_max_length_accepted(self, validator: SBOMValidator) -> None:
        purl = "pkg:pypi/" + "x" * (MAX_PURL_LENGTH - len("pkg:pypi/"))
        comp = _make_component(purl=purl)
        result = validator.validate(_make_sbom(components=[comp]))
        assert len(result.components[0].purl) == MAX_PURL_LENGTH


# ===================================================================
# Duplicate Passthrough (no resolution at this stage)
# ===================================================================

class TestDuplicatePassthrough:
    def test_duplicate_components_not_rejected(self, validator: SBOMValidator) -> None:
        """Duplicates are preserved exactly — Stage 3.6 owns resolution."""
        comp1 = _make_component(name="requests", version="2.28.1")
        comp2 = _make_component(name="requests", version="2.28.1")
        result = validator.validate(_make_sbom(components=[comp1, comp2]))
        assert len(result.components) == 2

    def test_duplicate_purls_not_rejected(self, validator: SBOMValidator) -> None:
        comp1 = _make_component(purl="pkg:pypi/requests@2.28.1")
        comp2 = _make_component(name="requests-dup", purl="pkg:pypi/requests@2.28.1")
        result = validator.validate(_make_sbom(components=[comp1, comp2]))
        assert len(result.components) == 2


# ===================================================================
# Security: Error Messages
# ===================================================================

class TestSecurityErrorMessages:
    def test_no_component_name_in_error(self, validator: SBOMValidator) -> None:
        """Validation errors must not include the actual component name."""
        secret_name = "SUPER_SECRET_INTERNAL_LIB_v42"
        comp = _make_component(name=secret_name, purl="not-valid")
        with pytest.raises(ValidationError) as exc_info:
            validator.validate(_make_sbom(components=[comp]))
        assert secret_name not in str(exc_info.value)

    def test_no_purl_in_error(self, validator: SBOMValidator) -> None:
        """Validation errors must not include the actual PURL."""
        secret_purl = "pkg:pypi/TOP_SECRET_LIB@9.9.9"
        # Trigger a name-too-long error on the same component
        comp = _make_component(name="x" * 600, purl=secret_purl)
        with pytest.raises(ValidationError) as exc_info:
            validator.validate(_make_sbom(components=[comp]))
        assert secret_purl not in str(exc_info.value)

    def test_no_version_in_error(self, validator: SBOMValidator) -> None:
        secret_version = "99.88.77-internal-build-9001"
        comp = _make_component(version="v" * 200)
        with pytest.raises(ValidationError) as exc_info:
            validator.validate(_make_sbom(components=[comp]))
        # The generic length error should not contain the actual version string
        assert "v" * 200 not in str(exc_info.value)

    def test_error_format_is_safe(self, validator: SBOMValidator) -> None:
        """Error messages follow safe format with no stack traces."""
        with pytest.raises(ValidationError) as exc_info:
            validator.validate(_make_sbom(spec_version="0.1"))
        err = str(exc_info.value)
        assert "Traceback" not in err
        assert "File \"" not in err


# ===================================================================
# Determinism
# ===================================================================

class TestDeterminism:
    def test_same_input_same_result(self, validator: SBOMValidator) -> None:
        """Validation must be deterministic — same input, same output."""
        sbom = _make_sbom(components=[
            _make_component(name="a", version="1.0", purl="pkg:pypi/a@1.0"),
            _make_component(name="b", version="2.0", purl="pkg:npm/b@2.0"),
        ])
        result1 = validator.validate(sbom)
        result2 = validator.validate(sbom)
        assert result1 is result2  # same frozen object

    def test_rejection_is_deterministic(self, validator: SBOMValidator) -> None:
        sbom = _make_sbom(spec_version="0.9")
        for _ in range(5):
            with pytest.raises(ValidationError, match="Unsupported CycloneDX specVersion"):
                validator.validate(sbom)


# ===================================================================
# Realistic Syft-Generated CycloneDX
# ===================================================================

class TestSyftRealistic:
    def test_syft_generated_sbom_passes(self, validator: SBOMValidator) -> None:
        """A realistic Syft-produced CycloneDX 1.4 SBOM should pass."""
        comps = [
            _make_component(
                name="urllib3",
                version="1.26.18",
                purl="pkg:pypi/urllib3@1.26.18",
                type="library",
            ),
            _make_component(
                name="certifi",
                version="2023.7.22",
                purl="pkg:pypi/certifi@2023.7.22",
                type="library",
            ),
            _make_component(
                name="idna",
                version="3.4",
                purl="pkg:pypi/idna@3.4",
                type="library",
            ),
        ]
        result = validator.validate(_make_sbom(spec_version="1.4", components=comps))
        assert len(result.components) == 3

    def test_syft_1_5_sbom_passes(self, validator: SBOMValidator) -> None:
        """Syft also produces CycloneDX 1.5 output."""
        comps = [_make_component(name="flask", version="3.0.0", purl="pkg:pypi/flask@3.0.0")]
        result = validator.validate(_make_sbom(spec_version="1.5", components=comps))
        assert result.spec_version == "1.5"


# ===================================================================
# Edge Cases
# ===================================================================

class TestEdgeCases:
    def test_component_with_type_none(self, validator: SBOMValidator) -> None:
        comp = _make_component(type=None)
        result = validator.validate(_make_sbom(components=[comp]))
        assert result.components[0].type is None

    def test_component_with_empty_version_string(self, validator: SBOMValidator) -> None:
        """An empty version string is technically valid (not None, just empty)."""
        comp = _make_component(version="")
        result = validator.validate(_make_sbom(components=[comp]))
        assert result.components[0].version == ""

    def test_second_component_invalid_fails_entire_sbom(self, validator: SBOMValidator) -> None:
        """If any component is invalid, the entire SBOM fails validation."""
        comps = [
            _make_component(name="good"),
            _make_component(name=""),  # invalid
        ]
        with pytest.raises(ValidationError, match="index 1"):
            validator.validate(_make_sbom(components=comps))

    def test_large_component_count_within_10mb(self, validator: SBOMValidator) -> None:
        """Many small components within reasonable bounds should pass."""
        comps = [
            _make_component(name=f"lib-{i}", version="1.0", purl=f"pkg:pypi/lib-{i}@1.0")
            for i in range(500)
        ]
        result = validator.validate(_make_sbom(components=comps))
        assert len(result.components) == 500

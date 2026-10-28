"""
Tests for Stage 3.3 — SBOM Format Detection and Parsing.

Covers:
  - Valid input (CycloneDX JSON, Syft generated)
  - Format detection boundaries (missing/unsupported bomFormat)
  - Invalid input (malformed JSON, empty, wrong root types)
  - Invalid component structures (missing names, wrong types)
  - Security (no private data leaked in exceptions, robustness against large strings)
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from shared.exceptions import ValidationError
from sbom_service.app.schemas.parsed_sbom import ParsedSBOM, ParsedComponent
from sbom_service.app.services.parser import SBOMParser


@pytest.fixture
def parser() -> SBOMParser:
    return SBOMParser()


# ---------------------------------------------------------------------------
# Valid Input Tests
# ---------------------------------------------------------------------------

def test_parse_minimal_valid_cyclonedx(parser: SBOMParser) -> None:
    raw_content = '''
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": []
    }
    '''
    result = parser.parse(raw_content)
    assert isinstance(result, ParsedSBOM)
    assert result.format == "CycloneDX"
    assert result.spec_version == "1.4"
    assert len(result.components) == 0


def test_parse_valid_cyclonedx_with_components(parser: SBOMParser) -> None:
    raw_content = '''
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.28.1",
                "purl": "pkg:pypi/requests@2.28.1"
            },
            {
                "type": "framework",
                "name": "fastapi"
            }
        ]
    }
    '''
    result = parser.parse(raw_content)
    assert len(result.components) == 2
    
    comp1 = result.components[0]
    assert comp1.name == "requests"
    assert comp1.version == "2.28.1"
    assert comp1.purl == "pkg:pypi/requests@2.28.1"
    assert comp1.type == "library"

    comp2 = result.components[1]
    assert comp2.name == "fastapi"
    assert comp2.version is None
    assert comp2.purl is None
    assert comp2.type == "framework"


def test_parse_syft_generated_cyclonedx(parser: SBOMParser) -> None:
    """Syft produces standard CycloneDX JSON when configured with -o cyclonedx-json."""
    raw_content = '''
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:7b2672fa-7cb4-49c0-84c1-f2fbe4f69f41",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "anchore", "name": "syft", "version": "0.100.0"}]
        },
        "components": [
            {
                "type": "library",
                "name": "urllib3",
                "version": "1.26.18",
                "purl": "pkg:pypi/urllib3@1.26.18",
                "properties": [{"name": "syft:package:foundBy", "value": "python-package-cataloger"}]
            }
        ]
    }
    '''
    result = parser.parse(raw_content)
    assert result.format == "CycloneDX"
    assert len(result.components) == 1
    assert result.components[0].name == "urllib3"
    # the parser must safely ignore unknown fields like metadata, properties, etc.


# ---------------------------------------------------------------------------
# Invalid Input Tests
# ---------------------------------------------------------------------------

def test_parse_empty_content(parser: SBOMParser) -> None:
    with pytest.raises(ValidationError, match="Raw SBOM content is empty"):
        parser.parse("")
        
    with pytest.raises(ValidationError, match="Raw SBOM content is empty"):
        parser.parse("   \n\t  ")


def test_parse_malformed_json(parser: SBOMParser) -> None:
    with pytest.raises(ValidationError, match="Invalid JSON structure"):
        parser.parse("{ not valid json ]")


def test_parse_json_array_root(parser: SBOMParser) -> None:
    with pytest.raises(ValidationError, match="Expected a JSON object at root"):
        parser.parse('[{"bomFormat": "CycloneDX"}]')


def test_parse_missing_bom_format(parser: SBOMParser) -> None:
    raw_content = '{"specVersion": "1.4", "components": []}'
    with pytest.raises(ValidationError, match="missing 'bomFormat'"):
        parser.parse(raw_content)


def test_parse_unsupported_bom_format(parser: SBOMParser) -> None:
    """An SBOM with an unknown bomFormat should fail Stage 2."""
    raw_content = '{"bomFormat": "SPDX", "specVersion": "2.3", "components": []}'
    with pytest.raises(ValidationError, match="Unsupported SBOM format."):
        parser.parse(raw_content)


def test_parse_components_not_array(parser: SBOMParser) -> None:
    raw_content = '{"bomFormat": "CycloneDX", "components": {}}'
    with pytest.raises(ValidationError, match="'components' must be an array"):
        parser.parse(raw_content)


def test_parse_invalid_component_structure(parser: SBOMParser) -> None:
    raw_content = '{"bomFormat": "CycloneDX", "components": ["just_a_string"]}'
    with pytest.raises(ValidationError, match="invalid component structure at index 0"):
        parser.parse(raw_content)


def test_parse_component_missing_name(parser: SBOMParser) -> None:
    raw_content = '{"bomFormat": "CycloneDX", "components": [{"version": "1.0"}]}'
    with pytest.raises(ValidationError, match="missing required 'name' field"):
        parser.parse(raw_content)


def test_parse_component_name_wrong_type(parser: SBOMParser) -> None:
    raw_content = '{"bomFormat": "CycloneDX", "components": [{"name": 123}]}'
    with pytest.raises(ValidationError, match="missing required 'name' field"):
        parser.parse(raw_content)


# ---------------------------------------------------------------------------
# Security and Boundary Tests
# ---------------------------------------------------------------------------

def test_parse_does_not_leak_private_data_in_exception(parser: SBOMParser) -> None:
    secret_purl = "pkg:pypi/TOP_SECRET_LIB@9.9.9"
    # This will fail because name is missing, but it contains a secret PURL
    raw_content = f'{{"bomFormat": "CycloneDX", "components": [{{"purl": "{secret_purl}"}}]}}'
    
    with pytest.raises(ValidationError) as exc_info:
        parser.parse(raw_content)
        
    err_msg = str(exc_info.value)
    assert secret_purl not in err_msg
    assert "TOP_SECRET_LIB" not in err_msg


def test_parse_ignores_arbitrary_nested_structures(parser: SBOMParser) -> None:
    """The parser must not crash or traverse arbitrarily deep unrelated JSON."""
    deep_json = '{"a": ' * 50 + '1' + '}' * 50
    raw_content = f'{{"bomFormat": "CycloneDX", "components": [{{"name": "test"}}], "deep": {deep_json}}}'
    result = parser.parse(raw_content)
    assert len(result.components) == 1
    assert result.components[0].name == "test"


def test_parse_handles_massive_strings_safely(parser: SBOMParser) -> None:
    """Extremely long strings should not break the extraction logic."""
    massive_name = "A" * 100000
    raw_content = f'{{"bomFormat": "CycloneDX", "components": [{{"name": "{massive_name}"}}]}}'
    result = parser.parse(raw_content)
    assert result.components[0].name == massive_name


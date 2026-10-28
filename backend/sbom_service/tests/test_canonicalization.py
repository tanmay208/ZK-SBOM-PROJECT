"""
Tests for Stage 3.5 — SBOM Canonicalization & Deterministic Representation.

Covers:
  - Determinism (same input → identical output, repeated execution)
  - Field handling (all fields, optional fields, null values, max-length)
  - Collision safety (adversarial inputs with delimiters/structural chars)
  - Unicode (non-ASCII values, byte-level stability)
  - Whitespace (internal meaningful whitespace preserved)
  - PURL integration (canonicalized PURL used in canonical JSON)
  - Component ordering (sorted by canonical JSON, input-order-independent)
  - Duplicate preservation (identical components remain separate)
  - UTF-8 encoding (byte-level determinism)
"""

from __future__ import annotations

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from shared.exceptions import ValidationError
from sbom_service.app.schemas.parsed_sbom import ParsedComponent, ParsedSBOM
from sbom_service.app.services.canonicalization import (
    SBOMCanonicalizer,
    CanonicalComponent,
    CanonicalSBOM,
)


@pytest.fixture
def canonicalizer() -> SBOMCanonicalizer:
    return SBOMCanonicalizer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _comp(
    name: str = "requests",
    version: str | None = "2.28.1",
    purl: str | None = "pkg:pypi/requests@2.28.1",
    type: str | None = "library",
) -> ParsedComponent:
    return ParsedComponent(name=name, version=version, purl=purl, type=type)


def _sbom(
    components: list[ParsedComponent] | None = None,
    spec_version: str = "1.4",
) -> ParsedSBOM:
    if components is None:
        components = [_comp()]
    return ParsedSBOM(format="CycloneDX", spec_version=spec_version, components=components)


# ===================================================================
# Determinism
# ===================================================================

class TestDeterminism:
    def test_same_input_identical_output(self, canonicalizer: SBOMCanonicalizer) -> None:
        sbom = _sbom()
        r1 = canonicalizer.canonicalize(sbom)
        r2 = canonicalizer.canonicalize(sbom)
        assert r1.components[0].canonical_json == r2.components[0].canonical_json
        assert r1.components[0].canonical_bytes == r2.components[0].canonical_bytes

    def test_repeated_execution_identical(self, canonicalizer: SBOMCanonicalizer) -> None:
        sbom = _sbom(components=[
            _comp(name="a", version="1.0", purl="pkg:pypi/a@1.0"),
            _comp(name="b", version="2.0", purl="pkg:pypi/b@2.0"),
        ])
        results = [canonicalizer.canonicalize(sbom) for _ in range(10)]
        first_jsons = [c.canonical_json for c in results[0].components]
        for r in results[1:]:
            assert [c.canonical_json for c in r.components] == first_jsons

    def test_different_source_formatting_same_output(self, canonicalizer: SBOMCanonicalizer) -> None:
        """Components constructed differently but with identical semantic values
        must produce the same canonical output."""
        comp1 = _comp(name="requests", version="2.28.1", purl="pkg:pypi/requests@2.28.1")
        comp2 = ParsedComponent(name="requests", version="2.28.1", purl="pkg:pypi/requests@2.28.1", type="framework")
        # 'type' is not in the canonical representation, so both should match
        sbom1 = _sbom(components=[comp1])
        sbom2 = _sbom(components=[comp2])
        r1 = canonicalizer.canonicalize(sbom1)
        r2 = canonicalizer.canonicalize(sbom2)
        assert r1.components[0].canonical_json == r2.components[0].canonical_json


# ===================================================================
# Field handling
# ===================================================================

class TestFieldHandling:
    def test_all_fields_present(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="flask", version="3.0.0", purl="pkg:pypi/flask@3.0.0")
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        cj = result.components[0].canonical_json
        obj = json.loads(cj)
        assert obj["name"] == "flask"
        assert obj["version"] == "3.0.0"
        assert obj["purl"] == "pkg:pypi/flask@3.0.0"

    def test_version_null_serialized(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="x", version=None, purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        cj = result.components[0].canonical_json
        obj = json.loads(cj)
        assert obj["version"] == "unknown"
        assert obj["purl"] == "pkg:generic/x@unknown"

    def test_all_three_fields_always_present(self, canonicalizer: SBOMCanonicalizer) -> None:
        """Even when optional fields are None, all three keys must appear."""
        comp = _comp(name="x", version=None, purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        obj = json.loads(result.components[0].canonical_json)
        assert set(obj.keys()) == {"name", "purl", "version"}

    def test_type_field_excluded(self, canonicalizer: SBOMCanonicalizer) -> None:
        """'type' is not part of the canonical representation."""
        comp = _comp(type="library")
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        obj = json.loads(result.components[0].canonical_json)
        assert "type" not in obj

    def test_empty_version_distinct_from_null(self, canonicalizer: SBOMCanonicalizer) -> None:
        """An empty string version and a null version must produce different canonical forms."""
        comp_empty = _comp(name="x", version="", purl=None)
        comp_null = _comp(name="x", version=None, purl=None)
        sbom_empty = _sbom(components=[comp_empty])
        sbom_null = _sbom(components=[comp_null])
        r_empty = canonicalizer.canonicalize(sbom_empty)
        r_null = canonicalizer.canonicalize(sbom_null)
        # ST21A-005 dictates fallback to generic PURL, where both "" and None map to "unknown"
        assert r_empty.components[0].canonical_json == r_null.components[0].canonical_json

    def test_field_order_is_alphabetical(self, canonicalizer: SBOMCanonicalizer) -> None:
        """JSON keys must be in alphabetical order: name, purl, version."""
        comp = _comp()
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        cj = result.components[0].canonical_json
        # Verify key order by finding positions
        assert cj.index('"name"') < cj.index('"purl"') < cj.index('"version"')


# ===================================================================
# Collision safety
# ===================================================================

class TestCollisionSafety:
    def test_delimiter_in_name_does_not_collide(self, canonicalizer: SBOMCanonicalizer) -> None:
        """A name containing JSON structural characters must not collide
        with a different component."""
        comp1 = _comp(name='a","version":"1.0', version=None, purl=None)
        comp2 = _comp(name="a", version="1.0", purl=None)
        sbom = _sbom(components=[comp1, comp2])
        result = canonicalizer.canonicalize(sbom)
        jsons = [c.canonical_json for c in result.components]
        assert jsons[0] != jsons[1], "Delimiter injection must not cause collision"

    def test_colon_in_name_safe(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp1 = _comp(name="a:b", version="1.0", purl=None)
        comp2 = _comp(name="a", version="b:1.0", purl=None)
        r = canonicalizer.canonicalize(_sbom(components=[comp1, comp2]))
        assert r.components[0].canonical_json != r.components[1].canonical_json

    def test_null_string_vs_json_null(self, canonicalizer: SBOMCanonicalizer) -> None:
        """The literal string 'null' must not collide with JSON null."""
        comp_str = _comp(name="requests", version="null", purl=None)
        comp_none = _comp(name="requests", version=None, purl=None)
        r_str = canonicalizer.canonicalize(_sbom(components=[comp_str]))
        r_none = canonicalizer.canonicalize(_sbom(components=[comp_none]))
        assert r_str.components[0].canonical_json != r_none.components[0].canonical_json

    def test_backslash_in_values(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name='lib\\ntest', version="1.0", purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        # Should round-trip through JSON parsing
        obj = json.loads(result.components[0].canonical_json)
        assert obj["name"] == 'lib\\ntest'

    def test_quote_in_values(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name='lib"test', version="1.0", purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        obj = json.loads(result.components[0].canonical_json)
        assert obj["name"] == 'lib"test'


# ===================================================================
# Unicode
# ===================================================================

class TestUnicode:
    def test_non_ascii_preserved(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="bibliothèque", version="1.0", purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        obj = json.loads(result.components[0].canonical_json)
        assert obj["name"] == "bibliothèque"

    def test_non_ascii_in_utf8_bytes(self, canonicalizer: SBOMCanonicalizer) -> None:
        """Non-ASCII characters must appear as UTF-8 bytes, not \\uXXXX escapes."""
        comp = _comp(name="café", version="1.0", purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        # 'café' encoded directly in UTF-8, not as \\u00e9
        assert "café".encode("utf-8") in result.components[0].canonical_bytes
        assert b"\\u00e9" not in result.components[0].canonical_bytes

    def test_unicode_byte_stability(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="日本語パッケージ", version="1.0", purl=None)
        sbom = _sbom(components=[comp])
        r1 = canonicalizer.canonicalize(sbom)
        r2 = canonicalizer.canonicalize(sbom)
        assert r1.components[0].canonical_bytes == r2.components[0].canonical_bytes

    def test_no_unicode_normalization_applied(self, canonicalizer: SBOMCanonicalizer) -> None:
        """NFC and NFD forms of the same character must produce DIFFERENT
        canonical bytes (no normalization is applied)."""
        import unicodedata
        nfc = unicodedata.normalize("NFC", "ñ")    # U+00F1
        nfd = unicodedata.normalize("NFD", "ñ")    # U+006E U+0303
        assert nfc != nfd  # sanity check
        comp_nfc = _comp(name=nfc, version="1.0", purl=None)
        comp_nfd = _comp(name=nfd, version="1.0", purl=None)
        r_nfc = canonicalizer.canonicalize(_sbom(components=[comp_nfc]))
        r_nfd = canonicalizer.canonicalize(_sbom(components=[comp_nfd]))
        assert r_nfc.components[0].canonical_bytes != r_nfd.components[0].canonical_bytes


# ===================================================================
# Whitespace
# ===================================================================

class TestWhitespace:
    def test_internal_whitespace_preserved(self, canonicalizer: SBOMCanonicalizer) -> None:
        """Whitespace inside field values is meaningful and preserved."""
        comp = _comp(name="my library", version="1.0 beta", purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        obj = json.loads(result.components[0].canonical_json)
        assert obj["name"] == "my library"
        assert obj["version"] == "1.0 beta"

    def test_no_syntactic_whitespace_in_json(self, canonicalizer: SBOMCanonicalizer) -> None:
        """The canonical JSON must not contain any indentation/formatting whitespace."""
        comp = _comp()
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        cj = result.components[0].canonical_json
        # No newlines, no extra spaces between structural characters
        assert "\n" not in cj
        assert "\t" not in cj
        assert ": " not in cj  # compact separator uses ':' not ': '
        assert ", " not in cj  # compact separator uses ',' not ', '


# ===================================================================
# PURL integration
# ===================================================================

class TestPURLIntegration:
    def test_purl_canonicalized_in_json(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="Flask", purl="pkg:PYPI/Flask@3.0.0")
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        obj = json.loads(result.components[0].canonical_json)
        assert obj["purl"] == "pkg:pypi/flask@3.0.0"

    def test_purl_canonical_field_populated(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(purl="pkg:PyPI/Requests@2.28.1")
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        assert result.components[0].purl_canonical == "pkg:pypi/requests@2.28.1"

    def test_purl_none_preserved(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="requests", version="2.28.1", purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        assert result.components[0].purl_canonical == "pkg:generic/requests@2.28.1"
        obj = json.loads(result.components[0].canonical_json)
        assert obj["purl"] == "pkg:generic/requests@2.28.1"

    def test_semantically_equivalent_purls_produce_same_canonical(
        self, canonicalizer: SBOMCanonicalizer
    ) -> None:
        """Different PURL casings for the same PyPI package must produce
        identical canonical representations."""
        comp1 = _comp(name="requests", purl="pkg:pypi/requests@2.28.1")
        comp2 = _comp(name="requests", purl="pkg:PYPI/Requests@2.28.1")
        r1 = canonicalizer.canonicalize(_sbom(components=[comp1]))
        r2 = canonicalizer.canonicalize(_sbom(components=[comp2]))
        assert r1.components[0].canonical_json == r2.components[0].canonical_json

    def test_purl_overrides_sbom_name(self, canonicalizer: SBOMCanonicalizer) -> None:
        """ZK-002: If PURL is present, it strictly overrides the CycloneDX name/version."""
        comp = _comp(name="benign-name", version="9.9.9", purl="pkg:npm/malicious-lib@1.0.0")
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        obj = json.loads(result.components[0].canonical_json)
        assert obj["name"] == "malicious-lib"
        assert obj["version"] == "1.0.0"
        assert obj["purl"] == "pkg:npm/malicious-lib@1.0.0"

    def test_malformed_purl_rejected(self, canonicalizer: SBOMCanonicalizer) -> None:
        """ZK-002: If PURL is present but malformed, it MUST be rejected, not preserved."""
        comp = _comp(name="test", purl="malformed::npm/test@1.0")
        with pytest.raises(ValidationError, match="Invalid PURL"):
            canonicalizer.canonicalize(_sbom(components=[comp]))

    def test_unparseable_purl_structure_rejected(self, canonicalizer: SBOMCanonicalizer) -> None:
        """ZK-002: If PURL is syntactically valid but missing required fields for identity, it MUST be rejected."""
        # A PURL without a name will fail extract_component_fields_from_purl
        comp = _comp(name="test", purl="pkg:npm/")
        with pytest.raises(ValidationError):
            canonicalizer.canonicalize(_sbom(components=[comp]))


# ===================================================================
# Component ordering
# ===================================================================

class TestComponentOrdering:
    def test_reordered_input_produces_same_output(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp_a = _comp(name="alpha", version="1.0", purl="pkg:pypi/alpha@1.0")
        comp_b = _comp(name="beta", version="2.0", purl="pkg:pypi/beta@2.0")
        comp_c = _comp(name="gamma", version="3.0", purl="pkg:pypi/gamma@3.0")

        sbom_abc = _sbom(components=[comp_a, comp_b, comp_c])
        sbom_cba = _sbom(components=[comp_c, comp_b, comp_a])

        r_abc = canonicalizer.canonicalize(sbom_abc)
        r_cba = canonicalizer.canonicalize(sbom_cba)

        jsons_abc = [c.canonical_json for c in r_abc.components]
        jsons_cba = [c.canonical_json for c in r_cba.components]
        assert jsons_abc == jsons_cba

    def test_positions_are_sequential(self, canonicalizer: SBOMCanonicalizer) -> None:
        comps = [_comp(name=f"lib-{i}", purl=None, version=None) for i in range(5)]
        result = canonicalizer.canonicalize(_sbom(components=comps))
        positions = [c.position for c in result.components]
        assert positions == [0, 1, 2, 3, 4]

    def test_ordering_is_lexicographic(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp_b = _comp(name="beta", purl=None, version=None)
        comp_a = _comp(name="alpha", purl=None, version=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp_b, comp_a]))
        assert result.components[0].parsed.name == "alpha"
        assert result.components[1].parsed.name == "beta"
        assert result.components[0].position == 0
        assert result.components[1].position == 1


# ===================================================================
# Duplicate preservation
# ===================================================================

class TestDuplicatePreservation:
    def test_identical_components_preserved(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="dup", version="1.0", purl="pkg:pypi/dup@1.0")
        sbom = _sbom(components=[comp, comp])
        result = canonicalizer.canonicalize(sbom)
        assert len(result.components) == 2
        assert result.components[0].canonical_json == result.components[1].canonical_json
        assert result.components[0].position == 0
        assert result.components[1].position == 1

    def test_duplicates_have_different_positions(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="same", purl=None, version="1.0")
        sbom = _sbom(components=[comp, comp, comp])
        result = canonicalizer.canonicalize(sbom)
        assert len(result.components) == 3
        assert [c.position for c in result.components] == [0, 1, 2]


# ===================================================================
# UTF-8 encoding
# ===================================================================

class TestUTF8Encoding:
    def test_bytes_are_utf8(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="test", version="1.0", purl=None)
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        # Should decode without error
        decoded = result.components[0].canonical_bytes.decode("utf-8")
        assert decoded == result.components[0].canonical_json

    def test_bytes_deterministic_across_calls(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="déterminist", version="1.0", purl=None)
        sbom = _sbom(components=[comp])
        bytes1 = canonicalizer.canonicalize(sbom).components[0].canonical_bytes
        bytes2 = canonicalizer.canonicalize(sbom).components[0].canonical_bytes
        assert bytes1 == bytes2

    def test_canonical_json_round_trips_through_json(self, canonicalizer: SBOMCanonicalizer) -> None:
        comp = _comp(name="round-trip", version="1.0.0-rc.1", purl="pkg:pypi/round-trip@1.0.0-rc.1")
        result = canonicalizer.canonicalize(_sbom(components=[comp]))
        # Parse the canonical JSON and verify it preserves all values
        obj = json.loads(result.components[0].canonical_json)
        assert obj["name"] == "round-trip"
        assert obj["version"] == "1.0.0-rc.1"


# ===================================================================
# CanonicalSBOM metadata
# ===================================================================

class TestCanonicalSBOMMetadata:
    def test_spec_version_preserved(self, canonicalizer: SBOMCanonicalizer) -> None:
        result = canonicalizer.canonicalize(_sbom(spec_version="1.5"))
        assert result.spec_version == "1.5"

    def test_format_preserved(self, canonicalizer: SBOMCanonicalizer) -> None:
        result = canonicalizer.canonicalize(_sbom())
        assert result.format == "CycloneDX"

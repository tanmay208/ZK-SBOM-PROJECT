"""
Security & Adversarial SBOM Testing — Stage 3.7.

Red-team testing for the complete SBOM pipeline:
- Input Size / Resource Exhaustion
- JSON Parser Attacks
- CycloneDX Format Confusion
- Version Validation Attacks
- Component Validation Attacks
- Control Character Attacks
- PURL Adversarial Testing
- Canonicalization Collision Testing
- Unicode Adversarial Testing
- Whitespace Attacks
- Identity Confusion Testing
- Duplicate Abuse
- Ordering Manipulation
- Component Count Attacks
- Transaction / Persistence Attacks
- Error Message / Information Leakage
- Log Injection
- Mass Assignment / Extra Field Testing
- Pollution / Cross-Request Isolation
- Determinism Regression
"""

from __future__ import annotations

import json
import logging
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from shared.exceptions import ValidationError
from sbom_service.app.services.parser import SBOMParser
from sbom_service.app.services.validator import SBOMValidator
from sbom_service.app.services.canonicalization import SBOMCanonicalizer
from sbom_service.app.services.identity import ComponentIdentityResolver, DuplicateClass

@pytest.fixture
def parser(): return SBOMParser()

@pytest.fixture
def validator(): return SBOMValidator()

@pytest.fixture
def canonicalizer(): return SBOMCanonicalizer()

@pytest.fixture
def identity_resolver(): return ComponentIdentityResolver()


# -------------------------------------------------------------------
# Helper to run the full pipeline
# -------------------------------------------------------------------
def process_pipeline(raw_json: str, parser, validator, canonicalizer, identity_resolver):
    parsed = parser.parse(raw_json)
    validated = validator.validate(parsed)
    canonical = canonicalizer.canonicalize(validated)
    resolved = identity_resolver.resolve(canonical)
    return resolved


# -------------------------------------------------------------------
# 4. INPUT SIZE / RESOURCE EXHAUSTION
# -------------------------------------------------------------------
class TestResourceExhaustion:
    def test_many_duplicate_components(self, parser, validator, canonicalizer, identity_resolver):
        # Create an SBOM with 10,000 components
        comp = {"name": "test", "version": "1.0", "purl": "pkg:pypi/test@1.0"}
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [comp] * 10000
        }
        raw = json.dumps(sbom)
        resolved = process_pipeline(raw, parser, validator, canonicalizer, identity_resolver)
        assert resolved.component_count == 10000
        assert resolved.unique_identity_count == 1
        
    def test_deeply_nested_json(self, parser):
        # We test how json.loads handles it. The standard library handles some depth but will RecursionError eventually.
        # We just want to ensure it doesn't crash the worker ungracefully or leak data.
        # Python json handles ~1000 depth by default before erroring or reaching C stack limit.
        nested = '{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": ['
        nested += '{"name": "a", "nested": ' * 500 + '"end"' + '}' * 500
        nested += ']}'
        try:
            parser.parse(nested)
        except Exception as e:
            # Must not leak the payload
            assert "nested" not in str(e)


# -------------------------------------------------------------------
# 5. JSON PARSER ATTACKS
# -------------------------------------------------------------------
class TestJSONParserAttacks:
    def test_truncated_json(self, parser):
        raw = '{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "a"'
        with pytest.raises(ValidationError, match="Invalid JSON structure"):
            parser.parse(raw)

    def test_unexpected_root_array(self, parser):
        raw = '[{"bomFormat": "CycloneDX"}]'
        with pytest.raises(ValidationError, match="Expected a JSON object at root"):
            parser.parse(raw)


# -------------------------------------------------------------------
# 6. FORMAT CONFUSION
# -------------------------------------------------------------------
class TestFormatConfusion:
    def test_bomformat_trailing_whitespace(self):
        raw = '{"bomFormat": "CycloneDX ", "specVersion": "1.4", "components": []}'
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="Unsupported SBOM format."):
            parser.parse(raw)

    def test_bomformat_array(self):
        raw = '{"bomFormat": ["CycloneDX"], "specVersion": "1.4", "components": []}'
        parser = SBOMParser()
        with pytest.raises(ValidationError, match="Unsupported SBOM format."):
            parser.parse(raw)


# -------------------------------------------------------------------
# 7. VERSION VALIDATION ATTACKS
# -------------------------------------------------------------------
class TestVersionAttacks:
    def test_version_whitespace(self, parser, validator):
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": " 1.4", "components": [{"name": "a"}]})
        parsed = parser.parse(raw)
        with pytest.raises(ValidationError, match="Unsupported CycloneDX specVersion"):
            validator.validate(parsed)

    def test_version_unsupported(self, parser, validator):
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.3", "components": [{"name": "a"}]})
        parsed = parser.parse(raw)
        with pytest.raises(ValidationError, match="Unsupported CycloneDX specVersion"):
            validator.validate(parsed)


# -------------------------------------------------------------------
# 8. COMPONENT VALIDATION & 9. CONTROL CHARACTERS
# -------------------------------------------------------------------
class TestComponentAttacks:
    def test_embedded_null_byte_in_name(self, parser, validator, canonicalizer, identity_resolver):
        # We don't strip null bytes during validation unless configured, let's see current behavior.
        # DB limits: string length. Null bytes might be allowed by json, but rejected by DB.
        # Actually, python strings can contain null bytes.
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "a\x00b"}]})
        resolved = process_pipeline(raw, parser, validator, canonicalizer, identity_resolver)
        assert "\x00" in resolved.components[0].canonical.parsed.name

    def test_whitespace_only_name(self, parser, validator):
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "   "}]})
        parsed = parser.parse(raw)
        with pytest.raises(ValidationError, match="'name' is required and must not be empty"):
            validator.validate(parsed)


# -------------------------------------------------------------------
# 11. CANONICALIZATION COLLISION TESTING
# -------------------------------------------------------------------
class TestCanonicalizationCollision:
    def test_delimiter_injection_cannot_collide(self, parser, validator, canonicalizer, identity_resolver):
        c1 = {"name": 'a","purl":"pkg:pypi/attack', "version": "1", "purl": None}
        c2 = {"name": "a", "version": "1", "purl": "pkg:pypi/attack"}
        raw1 = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c1]})
        raw2 = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c2]})
        
        r1 = process_pipeline(raw1, parser, validator, canonicalizer, identity_resolver)
        r2 = process_pipeline(raw2, parser, validator, canonicalizer, identity_resolver)
        
        assert r1.components[0].canonical.canonical_json != r2.components[0].canonical.canonical_json
        assert r1.components[0].identity_key != r2.components[0].identity_key

    def test_null_vs_string_null(self, parser, validator, canonicalizer, identity_resolver):
        c1 = {"name": "a", "version": "null", "purl": None}
        c2 = {"name": "a", "version": None, "purl": None}
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c1, c2]})
        resolved = process_pipeline(raw, parser, validator, canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key != resolved.components[1].identity_key


# -------------------------------------------------------------------
# 12. UNICODE ADVERSARIAL TESTING
# -------------------------------------------------------------------
class TestUnicodeAttacks:
    def test_no_normalization_applied(self, parser, validator, canonicalizer, identity_resolver):
        import unicodedata
        nfc = unicodedata.normalize("NFC", "ñ")
        nfd = unicodedata.normalize("NFD", "ñ")
        c1 = {"name": nfc, "version": "1"}
        c2 = {"name": nfd, "version": "1"}
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c1, c2]})
        resolved = process_pipeline(raw, parser, validator, canonicalizer, identity_resolver)
        
        # Must be distinct identities
        assert resolved.components[0].identity_key != resolved.components[1].identity_key
        assert resolved.unique_identity_count == 2


# -------------------------------------------------------------------
# 14. IDENTITY CONFUSION TESTING
# -------------------------------------------------------------------
class TestIdentityConfusion:
    def test_purl_vs_fallback(self, parser, validator, canonicalizer, identity_resolver):
        # One component has PURL matching the fallback identity format (which isn't valid purl syntax anyway)
        # but let's test if we can trick the fallback vs PURL.
        c1 = {"name": "a", "version": "1", "purl": "pkg:pypi/a@1"}
        c2 = {"name": "a", "version": "1", "purl": None}
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c1, c2]})
        resolved = process_pipeline(raw, parser, validator, canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key != resolved.components[1].identity_key


# -------------------------------------------------------------------
# 16. ORDERING MANIPULATION
# -------------------------------------------------------------------
class TestOrderingManipulation:
    def test_deterministic_ordering_ignores_input_order(self, parser, validator, canonicalizer, identity_resolver):
        c1 = {"name": "z", "version": "1"}
        c2 = {"name": "a", "version": "2"}
        raw1 = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c1, c2]})
        raw2 = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c2, c1]})
        
        r1 = process_pipeline(raw1, parser, validator, canonicalizer, identity_resolver)
        r2 = process_pipeline(raw2, parser, validator, canonicalizer, identity_resolver)
        
        assert r1.components[0].identity_key == r2.components[0].identity_key
        assert r1.components[1].identity_key == r2.components[1].identity_key


# -------------------------------------------------------------------
# 22. MASS ASSIGNMENT / EXTRA FIELD TESTING
# -------------------------------------------------------------------
class TestMassAssignment:
    def test_unexpected_fields_ignored(self, parser, validator, canonicalizer, identity_resolver):
        c1 = {"name": "a", "version": "1", "is_admin": True, "policy_hash": "bad"}
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c1], "verified": True})
        resolved = process_pipeline(raw, parser, validator, canonicalizer, identity_resolver)
        
        cj = resolved.components[0].canonical.canonical_json
        assert "is_admin" not in cj
        assert "policy_hash" not in cj


# -------------------------------------------------------------------
# 19. ERROR MESSAGE / INFORMATION LEAKAGE
# -------------------------------------------------------------------
class TestErrorLeakage:
    def test_invalid_purl_error_leakage(self, parser, validator):
        secret = "SUPER_SECRET_COMPONENT_123"
        c1 = {"name": "a", "purl": secret * 50}
        raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [c1]})
        parsed = parser.parse(raw)
        with pytest.raises(ValidationError) as exc:
            validator.validate(parsed)
        
        assert secret not in str(exc.value)


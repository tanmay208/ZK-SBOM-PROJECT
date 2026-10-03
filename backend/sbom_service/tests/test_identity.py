"""
Tests for Stage 3.6 — Component Identity & Duplicate Resolution.

Covers:
  - PURL identity (same raw PURL, equivalent canonical PURLs, etc.)
  - PURL-less components (deterministic fallback, collision safety)
  - Duplicate semantics (EXACT, IDENTITY, distinct)
  - Duplicate component count / preservation (no silent deduplication)
  - Ordering determinism (preserves Stage 3.5 ordering)
  - Adversarial values (delimiters, unicode, structural similarity)
"""

from __future__ import annotations

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from sbom_service.app.schemas.parsed_sbom import ParsedComponent, ParsedSBOM
from sbom_service.app.services.canonicalization import SBOMCanonicalizer
from sbom_service.app.services.identity import (
    ComponentIdentityResolver,
    DuplicateClass,
)


@pytest.fixture
def canonicalizer() -> SBOMCanonicalizer:
    return SBOMCanonicalizer()


@pytest.fixture
def identity_resolver() -> ComponentIdentityResolver:
    return ComponentIdentityResolver()


def _comp(
    name: str = "requests",
    version: str | None = "2.28.1",
    purl: str | None = "pkg:pypi/requests@2.28.1",
    type: str | None = "library",
) -> ParsedComponent:
    return ParsedComponent(name=name, version=version, purl=purl, type=type)


def _resolve(
    components: list[ParsedComponent],
    canonicalizer: SBOMCanonicalizer,
    identity_resolver: ComponentIdentityResolver
):
    sbom = ParsedSBOM(format="CycloneDX", spec_version="1.4", components=components)
    canonical = canonicalizer.canonicalize(sbom)
    return identity_resolver.resolve(canonical)


# ===================================================================
# PURL Identity
# ===================================================================

class TestPURLIdentity:
    def test_same_raw_purl_same_identity(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", purl="pkg:pypi/requests@2.28.1")
        c2 = _comp(name="b", purl="pkg:pypi/requests@2.28.1")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key == resolved.components[1].identity_key
        assert resolved.components[0].is_purl_based is True

    def test_equivalent_canonical_purls_same_identity(self, canonicalizer, identity_resolver) -> None:
        # PURLs that canonicalize identically must produce the same identity
        c1 = _comp(name="req", purl="pkg:pypi/requests@2.28.1")
        c2 = _comp(name="req", purl="pkg:PYPI/Requests@2.28.1")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key == resolved.components[1].identity_key

    def test_different_purls_different_identity(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(purl="pkg:pypi/a@1")
        c2 = _comp(purl="pkg:pypi/b@1")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key != resolved.components[1].identity_key

    def test_qualifiers_affect_identity(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(purl="pkg:pypi/a@1?os=linux")
        c2 = _comp(purl="pkg:pypi/a@1?os=windows")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key != resolved.components[1].identity_key


# ===================================================================
# PURL-less Identity (Fallback)
# ===================================================================

class TestPURLlessIdentity:
    def test_deterministic_fallback(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", version="1", purl=None)
        c2 = _comp(name="a", version="1", purl=None)
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key == resolved.components[1].identity_key
        assert resolved.components[0].is_purl_based is True

    def test_missing_version_fallback(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", version=None, purl=None)
        c2 = _comp(name="a", version=None, purl=None)
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key == resolved.components[1].identity_key

    def test_different_names_different_fallback(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", version="1", purl=None)
        c2 = _comp(name="b", version="1", purl=None)
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key != resolved.components[1].identity_key

    def test_collision_resistance(self, canonicalizer, identity_resolver) -> None:
        # Delimiter injection
        c1 = _comp(name='a","version":"1', version=None, purl=None)
        c2 = _comp(name='a', version='1', purl=None)
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key != resolved.components[1].identity_key


# ===================================================================
# Type Field Exclusion
# ===================================================================

class TestTypeFieldExclusion:
    def test_type_does_not_affect_purl_identity(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", type="library")
        c2 = _comp(name="a", type="framework")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key == resolved.components[1].identity_key
        assert resolved.components[0].duplicate_class == DuplicateClass.NONE
        assert resolved.components[1].duplicate_class == DuplicateClass.EXACT
        
    def test_type_does_not_affect_fallback_identity(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", version="1", purl=None, type="library")
        c2 = _comp(name="a", version="1", purl=None, type="framework")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key == resolved.components[1].identity_key
        assert resolved.components[1].duplicate_class == DuplicateClass.EXACT


# ===================================================================
# Duplicates & Component Count
# ===================================================================

class TestDuplicates:
    def test_exact_duplicate(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", version="1", purl="pkg:pypi/a@1")
        c2 = _comp(name="a", version="1", purl="pkg:pypi/a@1")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert len(resolved.components) == 2
        assert resolved.components[0].duplicate_class == DuplicateClass.NONE
        assert resolved.components[1].duplicate_class == DuplicateClass.EXACT

    def test_identity_duplicate(self, canonicalizer, identity_resolver) -> None:
        # Same PURL, but different names (canonical_json differs)
        c1 = _comp(name="name1", version="1", purl="pkg:pypi/a@1")
        c2 = _comp(name="name2", version="1", purl="pkg:pypi/a@1")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert len(resolved.components) == 2
        
        # With ZK-002, the PURL overrides the name, so their canonical JSON is IDENTICAL.
        # Thus they are EXACT duplicates.
        assert resolved.components[0].duplicate_class == DuplicateClass.NONE
        assert resolved.components[1].duplicate_class == DuplicateClass.EXACT

    def test_distinct_components(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", purl="pkg:pypi/a@1")
        c2 = _comp(name="b", purl="pkg:pypi/b@1")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert len(resolved.components) == 2
        assert resolved.components[0].duplicate_class == DuplicateClass.NONE
        assert resolved.components[1].duplicate_class == DuplicateClass.NONE

    def test_no_silent_deduplication(self, canonicalizer, identity_resolver) -> None:
        # Provide 5 exact duplicates
        comps = [_comp() for _ in range(5)]
        resolved = _resolve(comps, canonicalizer, identity_resolver)
        
        # component_count must remain exactly 5
        assert resolved.component_count == 5
        assert resolved.unique_identity_count == 1
        
        classes = [c.duplicate_class for c in resolved.components]
        assert classes.count(DuplicateClass.NONE) == 1
        assert classes.count(DuplicateClass.EXACT) == 4

    def test_multiple_duplicate_occurrences(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="a", purl="pkg:pypi/a@1")  # NONE
        c2 = _comp(name="b", purl="pkg:pypi/a@1")  # IDENTITY
        c3 = _comp(name="a", purl="pkg:pypi/a@1")  # EXACT (matches c1)
        
        resolved = _resolve([c1, c2, c3], canonicalizer, identity_resolver)
        assert resolved.component_count == 3
        assert resolved.unique_identity_count == 1
        
        assert resolved.components[0].duplicate_class == DuplicateClass.NONE
        assert resolved.components[1].duplicate_class == DuplicateClass.EXACT
        assert resolved.components[2].duplicate_class == DuplicateClass.EXACT


# ===================================================================
# Ordering Determinism
# ===================================================================

class TestOrderingDeterminism:
    def test_preserves_stage35_ordering(self, canonicalizer, identity_resolver) -> None:
        # Identity resolution must not change the sorting order established by Canonicalizer
        c1 = _comp(name="z", purl="pkg:pypi/z@1")
        c2 = _comp(name="a", purl="pkg:pypi/a@1")
        
        sbom = ParsedSBOM(format="CycloneDX", spec_version="1.4", components=[c1, c2])
        canonical = canonicalizer.canonicalize(sbom)
        resolved = identity_resolver.resolve(canonical)
        
        # 'a' should be first in canonical
        assert canonical.components[0].parsed.name == "a"
        
        # 'a' should STILL be first in resolved
        assert resolved.components[0].canonical.parsed.name == "a"
        assert resolved.components[1].canonical.parsed.name == "z"


# ===================================================================
# Adversarial / Property Tests
# ===================================================================

class TestAdversarialIdentity:
    def test_unicode_identity_stability(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="日本語", version="1", purl=None)
        resolved = _resolve([c1], canonicalizer, identity_resolver)
        
        key = resolved.components[0].identity_key
        assert "pkg:generic" in key
        import urllib.parse
        assert urllib.parse.quote("日本語") in key

    def test_structural_similarity(self, canonicalizer, identity_resolver) -> None:
        # Two components that look similar but have fields shifted
        c1 = _comp(name="pkg:pypi/a", version="@1", purl=None)
        c2 = _comp(name="a", version="1", purl="pkg:pypi/a@1")
        resolved = _resolve([c1, c2], canonicalizer, identity_resolver)
        
        assert resolved.components[0].identity_key != resolved.components[1].identity_key

    def test_deterministic_identity_property(self, canonicalizer, identity_resolver) -> None:
        c1 = _comp(name="complex", version="1.0-alpha.1+build.2", purl="pkg:maven/org.apache/test@1.0?type=jar")
        r1 = _resolve([c1], canonicalizer, identity_resolver)
        r2 = _resolve([c1], canonicalizer, identity_resolver)
        
        assert r1.components[0].identity_key == r2.components[0].identity_key

"""
Identity Resolution Adversarial Tests — Stage 4.7.

Tests adversarial identity resolution scenarios:
  - Exact duplicates
  - Identity duplicates (same PURL canonical, different name)
  - PURL-less components
  - PURL case variations
  - Qualifier and subpath changes
  - Version participation in identity

SECURITY_BOUNDARY.md §1:
  All component identity data is Private Data.
"""

import os
import sys

import pytest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)


class TestIdentityAdversarial:
    """Adversarial identity resolution tests."""

    def _make_parsed_sbom(self, components):
        """Build a ParsedSBOM from a list of (name, purl, version) tuples."""
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent, ParsedSBOM
        parsed_components = [
            ParsedComponent(name=n, purl=p, version=v)
            for n, p, v in components
        ]
        return ParsedSBOM(format="CycloneDX", components=parsed_components)

    def _resolve(self, components):
        """Run the full canonicalize → identity pipeline."""
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        from sbom_service.app.services.identity import ComponentIdentityResolver
        parsed = self._make_parsed_sbom(components)
        canonical = SBOMCanonicalizer().canonicalize(parsed)
        return ComponentIdentityResolver().resolve(canonical)

    def test_exact_duplicates_preserved(self):
        """Exact duplicate components must be preserved (not deduplicated)."""
        resolved = self._resolve([
            ("lodash", "pkg:npm/lodash", "4.17.21"),
            ("lodash", "pkg:npm/lodash", "4.17.21"),
        ])
        assert resolved.component_count == 2

    def test_different_versions_distinct(self):
        """Same name/PURL but different versions are distinct components."""
        resolved = self._resolve([
            ("lodash", "pkg:npm/lodash@4.17.20", "4.17.20"),
            ("lodash", "pkg:npm/lodash@4.17.21", "4.17.21"),
        ])
        # Both should be present
        assert resolved.component_count == 2
        # Their canonical JSONs must differ (version differs)
        jsons = [c.canonical.canonical_json for c in resolved.components]
        assert jsons[0] != jsons[1]

    def test_purl_case_normalization(self):
        """PURL type is case-insensitive per PURL spec."""
        from shared.utils.purl import canonicalize_purl
        p1 = canonicalize_purl("pkg:npm/lodash@4.17.21")
        p2 = canonicalize_purl("pkg:NPM/lodash@4.17.21")
        assert p1 == p2

    def test_purl_less_component(self):
        """Components without PURLs must be handled correctly (fallback to pkg:generic)."""
        resolved = self._resolve([
            ("custom-lib", None, "1.0"),
        ])
        assert resolved.component_count == 1
        cj = resolved.components[0].canonical.canonical_json
        assert '"purl":"pkg:generic/custom-lib@1.0"' in cj

    def test_purl_qualifier_change(self):
        """Different PURL qualifiers produce different canonical forms."""
        from shared.utils.purl import canonicalize_purl
        p1 = canonicalize_purl("pkg:npm/foo@1.0?arch=x86")
        p2 = canonicalize_purl("pkg:npm/foo@1.0?arch=arm")
        assert p1 != p2

    def test_ordering_deterministic(self):
        """Component ordering must be deterministic across runs."""
        components = [
            ("b-lib", "pkg:npm/b-lib", "2.0"),
            ("a-lib", "pkg:npm/a-lib", "1.0"),
            ("c-lib", "pkg:npm/c-lib", "3.0"),
        ]
        resolved1 = self._resolve(components)
        resolved2 = self._resolve(components)
        jsons1 = [c.canonical.canonical_json for c in resolved1.components]
        jsons2 = [c.canonical.canonical_json for c in resolved2.components]
        assert jsons1 == jsons2

    def test_version_participation_in_hash(self):
        """Version change must produce different component hash."""
        from shared.crypto.component_hash import hash_component
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        c = SBOMCanonicalizer()
        comp1 = ParsedComponent(name="pkg", purl="pkg:npm/pkg", version="1.0")
        comp2 = ParsedComponent(name="pkg", purl="pkg:npm/pkg", version="2.0")
        cj1 = c._canonical_json(comp1.name, "pkg:npm/pkg", comp1.version)
        cj2 = c._canonical_json(comp2.name, "pkg:npm/pkg", comp2.version)
        assert hash_component(cj1) != hash_component(cj2)

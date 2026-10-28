"""
Tests for shared PURL canonicalization utility.

THREAT_MODEL.md §16:
  A single, shared PURL canonicalization library must be used across
  both sbom_service and vulnerability_service.

These tests verify determinism, type-specific rules, structural
canonicalization, and edge-case handling.
"""

from __future__ import annotations

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from shared.utils.purl import canonicalize_purl


# ===================================================================
# Structural canonicalization
# ===================================================================

class TestStructuralCanonicalization:
    def test_type_is_lowercased(self) -> None:
        assert canonicalize_purl("pkg:PyPI/requests@2.28.1") == "pkg:pypi/requests@2.28.1"

    def test_type_mixed_case(self) -> None:
        assert canonicalize_purl("pkg:MAVEN/org.apache/commons@1.0") == "pkg:maven/org.apache/commons@1.0"

    def test_scheme_preserved_lowercase(self) -> None:
        result = canonicalize_purl("pkg:npm/express@4.18.0")
        assert result.startswith("pkg:")

    def test_version_preserved(self) -> None:
        result = canonicalize_purl("pkg:pypi/flask@3.0.0")
        assert "@3.0.0" in result

    def test_no_version(self) -> None:
        result = canonicalize_purl("pkg:pypi/flask")
        assert result == "pkg:pypi/flask"
        assert "@" not in result


# ===================================================================
# PyPI-specific rules
# ===================================================================

class TestPyPICanonicalization:
    def test_pypi_name_lowercased(self) -> None:
        assert canonicalize_purl("pkg:pypi/Requests@2.28.1") == "pkg:pypi/requests@2.28.1"

    def test_pypi_underscores_to_hyphens(self) -> None:
        assert canonicalize_purl("pkg:pypi/my_package@1.0") == "pkg:pypi/my-package@1.0"

    def test_pypi_mixed_case_and_underscores(self) -> None:
        assert canonicalize_purl("pkg:pypi/My_Cool_Lib@0.1") == "pkg:pypi/my-cool-lib@0.1"

    def test_pypi_already_canonical(self) -> None:
        canonical = "pkg:pypi/requests@2.28.1"
        assert canonicalize_purl(canonical) == canonical

    def test_pypi_uppercase_type(self) -> None:
        assert canonicalize_purl("pkg:PYPI/Flask@3.0") == "pkg:pypi/flask@3.0"


# ===================================================================
# Namespace handling
# ===================================================================

class TestNamespaceCanonicalization:
    def test_maven_namespace_preserved(self) -> None:
        result = canonicalize_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
        assert result == "pkg:maven/org.apache.commons/commons-lang3@3.12.0"

    def test_npm_scoped_package(self) -> None:
        result = canonicalize_purl("pkg:npm/%40angular/core@16.2.0")
        assert "core" in result
        assert "@16.2.0" in result

    def test_golang_namespace(self) -> None:
        result = canonicalize_purl("pkg:golang/github.com/gin-gonic/gin@1.9.1")
        assert result == "pkg:golang/github.com/gin-gonic/gin@1.9.1"


# ===================================================================
# Qualifiers
# ===================================================================

class TestQualifierCanonicalization:
    def test_qualifiers_sorted_by_key(self) -> None:
        result = canonicalize_purl("pkg:pypi/requests@2.28.1?os=linux&arch=x86")
        assert "?arch=x86&os=linux" in result

    def test_qualifier_keys_lowercased(self) -> None:
        result = canonicalize_purl("pkg:pypi/requests@2.28.1?OS=linux")
        assert "?os=linux" in result

    def test_no_qualifiers(self) -> None:
        result = canonicalize_purl("pkg:pypi/requests@2.28.1")
        assert "?" not in result


# ===================================================================
# Subpath
# ===================================================================

class TestSubpathCanonicalization:
    def test_subpath_preserved(self) -> None:
        result = canonicalize_purl("pkg:pypi/requests@2.28.1#src/main")
        assert result.endswith("#src/main")

    def test_subpath_leading_trailing_slashes_stripped(self) -> None:
        result = canonicalize_purl("pkg:pypi/requests@2.28.1#/src/main/")
        assert result.endswith("#src/main")

    def test_no_subpath(self) -> None:
        result = canonicalize_purl("pkg:pypi/requests@2.28.1")
        assert "#" not in result


# ===================================================================
# Determinism
# ===================================================================

class TestPURLDeterminism:
    def test_repeated_calls_identical(self) -> None:
        purl = "pkg:pypi/Requests@2.28.1"
        results = [canonicalize_purl(purl) for _ in range(10)]
        assert all(r == results[0] for r in results)

    def test_semantically_equivalent_purls(self) -> None:
        """Different representations of the same PyPI package must canonicalize identically."""
        variants = [
            "pkg:pypi/Requests@2.28.1",
            "pkg:PYPI/Requests@2.28.1",
            "pkg:PyPI/requests@2.28.1",
            "pkg:pypi/requests@2.28.1",
        ]
        results = [canonicalize_purl(v) for v in variants]
        assert all(r == results[0] for r in results)


# ===================================================================
# Error handling
# ===================================================================

class TestPURLErrors:
    def test_empty_purl_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            canonicalize_purl("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            canonicalize_purl("   ")

    def test_missing_pkg_prefix_raises(self) -> None:
        with pytest.raises(ValueError, match="must start with"):
            canonicalize_purl("pypi/requests@2.28.1")

    def test_invalid_structure_raises(self) -> None:
        with pytest.raises(ValueError):
            canonicalize_purl("not-a-purl")

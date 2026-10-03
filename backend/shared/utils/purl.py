"""
Shared PURL canonicalization utility.

THREAT_MODEL.md §16:
  "A single, shared PURL canonicalization library must be used across
  both [sbom_service and vulnerability_service]."

ZKP_SPECIFICATION.md §55:
  PURL canonicalization is listed under SBOM Representation & Commitment.

ZKP_SPECIFICATION.md §97:
  PURL canonicalization is listed as a cryptographic interoperability
  parameter that must be computed identically between Python and Noir.

This module implements deterministic PURL canonicalization.  It is placed
in ``shared/utils/`` so that both sbom_service and vulnerability_service
can import it without duplication.

RESEARCH-CRITICAL PROTOCOL NOTE:
  The frozen architecture specifies that PURL canonicalization is required
  but does NOT define the exact canonicalization rules for every ecosystem.
  This implementation applies:
    1. Structural canonicalization (scheme lowercase, type lowercase,
       deterministic reassembly).
    2. PyPI-specific rules (name lowercased, underscores → hyphens) because
       Syft/CycloneDX for Python is the primary documented use case.
    3. Generic pass-through for all other types.
  Additional type-specific rules (npm scoping, Maven groupId, etc.) can be
  added before the cryptographic interoperability spec freeze without
  changing the function signature or downstream consumers.

SECURITY_BOUNDARY.md §1:
  PURLs are Private Data and must never appear in logs or buyer-facing
  API responses.
"""

from __future__ import annotations

import re
from urllib.parse import unquote
from packageurl import PackageURL

# Regex for basic structural validation
_PURL_PATTERN = re.compile(
    r"^pkg:(?P<type>[a-zA-Z][a-zA-Z0-9.+\-]*)/"
    r"(?P<remainder>.+)$"
)

# Types where the name portion is case-insensitive and underscore-normalised
_PYPI_LIKE_TYPES = frozenset({"pypi"})

def canonicalize_purl(purl: str) -> str:
    """Return the canonical form of a Package URL string."""
    if not purl or not purl.strip():
        raise ValueError("PURL must not be empty")

    if not _PURL_PATTERN.match(purl):
        raise ValueError("PURL must start with 'pkg:<type>/'")

    try:
        purl_obj = PackageURL.from_string(purl)
    except Exception as e:
        raise ValueError(f"Invalid PURL: {e}")

    # Canonicalize using packageurl-python's internal logic, which is authoritative.
    canonical_str = purl_obj.to_string()
    
    # Apply our extra ecosystem-specific rules
    if purl_obj.type in _PYPI_LIKE_TYPES:
        name = purl_obj.name.lower().replace("_", "-")
        # Re-build
        purl_obj = PackageURL(
            type=purl_obj.type,
            namespace=purl_obj.namespace,
            name=name,
            version=purl_obj.version,
            qualifiers=purl_obj.qualifiers,
            subpath=purl_obj.subpath
        )
        canonical_str = purl_obj.to_string()

    return canonical_str

def extract_component_fields_from_purl(purl: str) -> tuple[str, str | None]:
    """
    Extracts the logical 'name' and 'version' from a PURL string.
    This uses authoritative PURL parsing.
    """
    if not purl or not purl.strip():
        raise ValueError("PURL must not be empty")

    try:
        purl_obj = PackageURL.from_string(purl)
    except Exception as e:
        raise ValueError(f"Invalid PURL: {e}")

    name = purl_obj.name
    if purl_obj.namespace:
        name = f"{purl_obj.namespace}/{name}"

    if purl_obj.type in _PYPI_LIKE_TYPES:
        name = name.lower().replace("_", "-")

    return name, purl_obj.version

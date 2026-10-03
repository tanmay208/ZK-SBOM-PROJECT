"""
SBOM Component Identity & Duplicate Resolution Service — Stage 3.6.

This module establishes the authoritative identity of SBOM components and
classifies duplicates without physically removing them from the SBOM.

ARCHITECTURE REFERENCES:
  ZKP_SPECIFICATION.md §54: "canonical component identity"
  ZKP_SPECIFICATION.md §86: "component_count <= MAX_COMPONENTS"

DESIGN DECISIONS AND THEIR STATUS:
  The frozen architecture requires a "canonical component identity" but
  does not fully specify the fallback identity for PURL-less components,
  nor does it explicitly mandate physical deduplication.

  The following decisions are isolated as PROTOCOL DECISIONS requiring
  future confirmation before the cryptographic interoperability spec freeze.

  PROTOCOL DECISION 1 — Primary Identity:
    If a component has a PURL, the canonicalized PURL is its exclusive
    authoritative identity. Two components with the same canonical PURL
    share the same identity, even if their names or versions differ.

  PROTOCOL DECISION 2 — Unified Identity Regime:
    PURL canonicalization guarantees all components possess a PURL (synthesizing
    generic PURLs if missing). This eliminates dual-regime identity handling.
    The canonicalized PURL is strictly the sole identity key (ST21A-005).

  PROTOCOL DECISION 3 — Duplicate Semantics (NO PHYSICAL DEDUPLICATION):
    The ZKP specification (§53) defines the SBOM as an "ordered list of
    components" and relies on `component_count`. Physically deduplicating
    components would alter `component_count` and the Merkle tree shape.
    Since physical deduplication is not explicitly mandated, this module
    classifies duplicates via metadata (adding flags) but PRESERVES all
    components. A malicious vendor cannot use duplicate handling to omit
    components.

  PROTOCOL DECISION 4 — Deterministic Ordering:
    Ordering remains strictly tied to the canonical JSON byte
    representation (Stage 3.5), preserving stability. Components are
    NOT reordered by identity key, as this could group identical identities
    with different metadata in arbitrary ways unless a secondary sort key
    was invented.

SECURITY_BOUNDARY.md §1:
  Identity keys contain Private Data (PURLs, names) and must never be
  exposed in logs or buyer-facing APIs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Dict, Set
from enum import Enum

from sbom_service.app.services.canonicalization import (
    CanonicalComponent,
    CanonicalSBOM,
)

logger = logging.getLogger(__name__)


class DuplicateClass(str, Enum):
    """Classification of how a component duplicates a previously seen identity."""
    NONE = "none"                # First time this identity is seen
    EXACT = "exact"              # Same identity, same canonical_json
    IDENTITY = "identity"        # Same identity, different canonical_json


@dataclass(frozen=True)
class ResolvedComponent:
    """A component augmented with identity and duplicate classification."""
    canonical: CanonicalComponent
    identity_key: str
    is_purl_based: bool
    duplicate_class: DuplicateClass

    @property
    def is_duplicate(self) -> bool:
        return self.duplicate_class != DuplicateClass.NONE


@dataclass(frozen=True)
class ResolvedSBOM:
    """An SBOM with all components assigned identities and duplicate flags.
    
    Components are preserved in their original deterministic order.
    `component_count` reflects the total physical components (including
    duplicates), ensuring Merkle tree semantics remain intact.
    """
    components: List[ResolvedComponent]
    spec_version: str | None
    format: str

    @property
    def component_count(self) -> int:
        return len(self.components)

    @property
    def unique_identity_count(self) -> int:
        return len(set(c.identity_key for c in self.components))


class ComponentIdentityResolver:
    """Resolves canonical component identities and classifies duplicates."""

    def resolve(self, sbom: CanonicalSBOM) -> ResolvedSBOM:
        """Assign identities and classify duplicates for a CanonicalSBOM.

        Components are processed in their deterministic canonical order.
        The first occurrence of an identity is considered the primary;
        subsequent occurrences are classified as duplicates.

        Parameters
        ----------
        sbom:
            A CanonicalSBOM (Stage 3.5 output).

        Returns
        -------
        ResolvedSBOM
            The SBOM with identities assigned and duplicates flagged.
        """
        resolved_components: List[ResolvedComponent] = []
        
        # Track seen identities and their canonical_json representations
        # mapping identity_key -> set of seen canonical_jsons
        seen_identities: Dict[str, Set[str]] = {}

        for comp in sbom.components:
            identity_key, is_purl_based = self._derive_identity(comp)
            
            dup_class = DuplicateClass.NONE
            if identity_key in seen_identities:
                if comp.canonical_json in seen_identities[identity_key]:
                    dup_class = DuplicateClass.EXACT
                else:
                    dup_class = DuplicateClass.IDENTITY
            
            if identity_key not in seen_identities:
                seen_identities[identity_key] = set()
            seen_identities[identity_key].add(comp.canonical_json)

            resolved_components.append(
                ResolvedComponent(
                    canonical=comp,
                    identity_key=identity_key,
                    is_purl_based=is_purl_based,
                    duplicate_class=dup_class,
                )
            )

        logger.info(
            "Identity resolution complete: %d total components, %d unique identities",
            len(resolved_components),
            len(seen_identities),
        )

        return ResolvedSBOM(
            components=resolved_components,
            spec_version=sbom.spec_version,
            format=sbom.format,
        )

    @staticmethod
    def _derive_identity(comp: CanonicalComponent) -> tuple[str, bool]:
        """Determine the primary identity key for a component.

        Returns
        -------
        tuple[str, bool]
            (identity_key, is_purl_based)
        """
        # Since Stage 3.5 now guarantees a PURL for every component (ST21A-005),
        # this is the single, authoritative identity regime.
        return f"purl:{comp.purl_canonical}", True

"""
SBOM Canonicalization Service — Stage 3.5.

This module produces deterministic canonical representations of SBOM
components that will serve as the input to later cryptographic operations
(component hashing, Merkle tree construction, and ultimately ZKP proofs).

ARCHITECTURE REFERENCES:
  LOGIC_FLOW.md §107:
    "Components are normalized and canonicalized into a deterministic
    UTF-8 encoding."
  ZKP_SPECIFICATION.md §52–56:
    "ordered list of components, canonical component identity, PURL
    canonicalization, deterministic UTF-8 encoding"
  ZKP_SPECIFICATION.md §95–113:
    Cryptographic interoperability parameters — "Do NOT invent values
    for parameters that have not been finalized."

DESIGN DECISIONS AND THEIR STATUS:
  The frozen architecture specifies THAT canonicalization must happen and
  that it must be deterministic UTF-8, but does NOT specify the exact
  serialization format, field ordering, or null-value policy.

  The following decisions are made in this implementation and are clearly
  documented as PROTOCOL DECISIONS (not architecture mandates).  They are
  isolated behind this module's API so they can be revised before the
  cryptographic interoperability spec freeze (ZKP_SPECIFICATION.md §95)
  without changing downstream consumers.

  PROTOCOL DECISION 1 — Serialization format:
    Deterministic JSON with sorted keys, compact separators (',',':'),
    and ensure_ascii=False.  JSON is chosen because:
      (a) it provides built-in collision-safe escaping for all special
          characters, eliminating delimiter-injection risks;
      (b) it is well-defined, widely implemented, and reproducible
          across platforms;
      (c) it produces valid UTF-8 natively.

  PROTOCOL DECISION 2 — Participating fields:
    Three fields participate: "name", "purl", "version".  These are the
    fields that determine component identity in the database model
    (Component.name, Component.purl_canonical) and the ZKP commitment
    pipeline.  "type" is excluded because it is not present in the
    Component DB model and is not referenced in the ZKP specification.

  PROTOCOL DECISION 3 — Field order:
    Alphabetical key order in the JSON object: name, purl, version.
    Enforced by json.dumps(sort_keys=True).

  PROTOCOL DECISION 4 — Null/absent handling:
    All three fields are always present in the JSON object.  Absent values
    are serialized as JSON null.  This prevents ambiguity between "field
    absent" and "field present with empty value".
    MISSING-PURL FALLBACK SEMANTICS: When a PURL is absent, the component's
    identity is unified into the PURL regime by synthesizing a 'pkg:generic/...' 
    PURL. This strictly enforces a single identity regime and eliminates the
    possibility of collision between PURL and non-PURL components (ST21A-005).

  PROTOCOL DECISION 5 — Whitespace:
    No whitespace trimming is applied to field values.  Values are
    serialized exactly as received from the validated ParsedComponent,
    except that the PURL is canonicalized via the shared PURL utility.
    Syntactic JSON whitespace (indentation, newlines) is eliminated by
    the compact separators.

  PROTOCOL DECISION 6 — Unicode:
    No Unicode normalization (NFC/NFD/NFKC/NFKD) is applied.  Byte
    values are preserved as-is.  This avoids silently altering
    cryptographic inputs.  ensure_ascii=False is used so that non-ASCII
    characters are preserved in their UTF-8 form rather than escaped
    to \\uXXXX sequences.
    This decision MUST be revisited during the cryptographic
    interoperability spec freeze (ZKP_SPECIFICATION.md §95).

  PROTOCOL DECISION 7 — Component ordering:
    Components are sorted by their canonical JSON representation (lexicographic
    byte order on the UTF-8 canonical string).  Python's sorted() is stable,
    so duplicate components (identical canonical strings) preserve their
    original relative input order.

SECURITY_BOUNDARY.md §1:
  Canonical representations contain Private Data (names, PURLs).
  They must never be logged or exposed in buyer-facing APIs.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import List

from shared.exceptions import ValidationError
from shared.utils.purl import canonicalize_purl, extract_component_fields_from_purl
from sbom_service.app.schemas.parsed_sbom import ParsedComponent, ParsedSBOM

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------
# Canonical output types
# -----------------------------------------------------------------------

@dataclass(frozen=True)
class CanonicalComponent:
    """A component with its deterministic canonical representation.

    Attributes
    ----------
    parsed:
        The original ParsedComponent (unmodified).
    purl_canonical:
        The canonicalized PURL, or None if no PURL was present.
    canonical_json:
        The deterministic JSON string representation.
    canonical_bytes:
        The UTF-8 encoded bytes of canonical_json.
    position:
        The zero-based position in the sorted canonical order.
    """
    parsed: ParsedComponent
    purl_canonical: str | None
    canonical_json: str
    canonical_bytes: bytes
    position: int


@dataclass(frozen=True)
class CanonicalSBOM:
    """An SBOM with all components canonicalized and deterministically ordered.

    Duplicates are preserved.  Deduplication belongs to Stage 3.6.
    """
    components: List[CanonicalComponent]
    spec_version: str | None
    format: str


# -----------------------------------------------------------------------
# Canonicalization service
# -----------------------------------------------------------------------

class SBOMCanonicalizer:
    """Produces deterministic canonical representations of SBOM components.

    This service is state-free and deterministic.  The same ParsedSBOM
    always produces the same CanonicalSBOM.

    Responsibilities (Stage 3.5 only):
      - PURL canonicalization (via shared utility)
      - Deterministic per-component JSON representation
      - Deterministic UTF-8 encoding
      - Deterministic component ordering (sorted by canonical JSON)
      - Position assignment

    NOT in scope:
      - Duplicate resolution (Stage 3.6)
      - Component hashing / Poseidon (later stages)
      - Merkle tree / SBOM_ROOT (later stages)
      - ZKP witness construction (later stages)
    """

    def canonicalize(self, sbom: ParsedSBOM) -> CanonicalSBOM:
        """Canonicalize all components in the SBOM and sort them.

        Parameters
        ----------
        sbom:
            A ParsedSBOM that has already passed validation (Stage 3.4).

        Returns
        -------
        CanonicalSBOM
            Components in deterministic order with canonical representations.
        """
        # Step 1: produce canonical JSON for each component (unsorted)
        unsorted: List[tuple[str, bytes, str | None, ParsedComponent]] = []
        for comp in sbom.components:
            purl_canonical = self._canonicalize_purl(comp.purl)
            
            if not purl_canonical:
                import urllib.parse
                safe_name = urllib.parse.quote(comp.name, safe="")
                safe_ver = urllib.parse.quote(comp.version or "unknown", safe="")
                purl_canonical = f"pkg:generic/{safe_name}@{safe_ver}"
                
            try:
                c_name, c_version = extract_component_fields_from_purl(purl_canonical)
            except ValueError as exc:
                raise ValidationError(f"Malformed PURL structure: {purl_canonical}") from exc
                
            canonical_json = self._canonical_json(c_name, purl_canonical, c_version)
                
            canonical_bytes = canonical_json.encode("utf-8")
            unsorted.append((canonical_json, canonical_bytes, purl_canonical, comp))

        # Step 2: deterministic sort by canonical JSON string
        # Python's sorted() is stable, so duplicates preserve input order.
        sorted_items = sorted(unsorted, key=lambda t: t[0])

        # Step 3: assign positions and build CanonicalComponent list
        components: List[CanonicalComponent] = []
        for position, (cj, cb, pc, parsed) in enumerate(sorted_items):
            components.append(
                CanonicalComponent(
                    parsed=parsed,
                    purl_canonical=pc,
                    canonical_json=cj,
                    canonical_bytes=cb,
                    position=position,
                )
            )

        logger.info(
            "Canonicalization complete (components=%d)",
            len(components),
        )

        return CanonicalSBOM(
            components=components,
            spec_version=sbom.spec_version,
            format=sbom.format,
        )

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _canonicalize_purl(purl: str | None) -> str | None:
        """Canonicalize a PURL using the shared utility, or return None."""
        if purl is None:
            return None
        try:
            return canonicalize_purl(purl)
        except ValueError as exc:
            raise ValidationError(f"Invalid PURL: {purl}") from exc

    @staticmethod
    def _canonical_json(name: str, purl_canonical: str | None, version: str | None) -> str:
        """Produce the deterministic JSON representation of a component."""
        from shared.crypto.component_hash import build_canonical_component_json
        return build_canonical_component_json(name, purl_canonical, version)

"""
SBOM Validation Layer — Stage 3.4.

This module establishes whether a ParsedSBOM satisfies the project's
supported SBOM contract before downstream normalization and commitment.

ARCHITECTURE.md §4, SBOM Service responsibilities:
  - SBOM validation

SERVICE_CONTRACTS.md §1:
  - Handles CycloneDX processing and validation.

Validation boundary:
  - The Parser (Stage 3.3) is responsible for JSON syntax, format
    detection, and structural extraction into ParsedSBOM.
  - The Validator (this module) is responsible for semantic/schema
    validation: supported specVersion, required fields, field
    constraints, and structural consistency required by the project
    contract.

SECURITY_BOUNDARY.md §1:
  - Component names, versions, PURLs are Private Data.
  - Validation error messages must NEVER include private values.

DEVELOPMENT_RULES.md §19, §20:
  - No sensitive data in logs or buyer-facing API responses.
"""

from __future__ import annotations

import logging
import re
from typing import FrozenSet, List

from shared.exceptions import ValidationError

from sbom_service.app.schemas.parsed_sbom import ParsedComponent, ParsedSBOM

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CycloneDX Version Policy (Stage 3.1 ambiguity #1 — resolved)
# ---------------------------------------------------------------------------
# The authoritative documents do not explicitly specify CycloneDX versions.
# The project integrates with Syft (ARCHITECTURE.md §2, PROJECT_SCOPE.md §42)
# which produces CycloneDX 1.4 and 1.5 JSON output.
#
# We accept 1.4, 1.5, and 1.6 to cover Syft's current and near-future output
# range without accepting arbitrarily old or unknown future versions.
#
# This constant is isolated here so the policy can be updated in one place.
SUPPORTED_CYCLONEDX_VERSIONS: FrozenSet[str] = frozenset({"1.4", "1.5", "1.6"})

# Maximum component name/version string lengths.
# Derived from the database model constraints:
#   Component.name:    String(512)
#   Component.version: String(128)
#   Component.purl:    String(1024)
MAX_COMPONENT_NAME_LENGTH = 512
MAX_COMPONENT_VERSION_LENGTH = 128
MAX_PURL_LENGTH = 1024

# Basic PURL syntax: must start with "pkg:" per the PURL specification.
# Full canonicalization belongs to Stage 3.5 — here we only check the
# structural prefix to reject obviously invalid values.
_PURL_PREFIX_RE = re.compile(r"^pkg:[a-z]+/", re.IGNORECASE)


class SBOMValidator:
    """
    Validates a ParsedSBOM against the project's supported SBOM contract.

    This validator is deterministic and state-free.  The same ParsedSBOM
    always produces the same validation result.

    Responsibilities (this stage only):
      - CycloneDX specVersion acceptance
      - Required SBOM structure
      - Required component fields
      - Field-length constraints matching database column limits
      - Basic PURL syntax validation (not canonicalization)

    NOT in scope:
      - PURL canonicalization (Stage 3.5)
      - Duplicate component resolution (Stage 3.6)
      - Component hashing (Stage 3.5+)
      - SBOM_ROOT / Merkle trees / ZKP
    """

    def validate(self, sbom: ParsedSBOM) -> ParsedSBOM:
        """
        Validate a ParsedSBOM and return it unchanged if valid.

        Parameters
        ----------
        sbom:
            The ParsedSBOM produced by the parser (Stage 3.3).

        Returns
        -------
        ParsedSBOM
            The same object, indicating it has passed validation.

        Raises
        ------
        ValidationError
            If any validation rule is violated.  Error messages are safe
            and contain no private data (no PURLs, component names, etc.).
        """
        self._validate_format(sbom)
        self._validate_spec_version(sbom)
        self._validate_components_present(sbom)
        self._validate_each_component(sbom.components)
        logger.info(
            "SBOM validation passed (format=%s, specVersion=%s, components=%d)",
            sbom.format,
            sbom.spec_version,
            len(sbom.components),
        )
        return sbom

    # ------------------------------------------------------------------
    # Format
    # ------------------------------------------------------------------

    def _validate_format(self, sbom: ParsedSBOM) -> None:
        """Ensure the format is CycloneDX (the only supported format)."""
        if sbom.format != "CycloneDX":
            raise ValidationError("Unsupported SBOM format.")

    # ------------------------------------------------------------------
    # CycloneDX specVersion
    # ------------------------------------------------------------------

    def _validate_spec_version(self, sbom: ParsedSBOM) -> None:
        """
        Enforce the CycloneDX version policy.

        ARCHITECTURE.md §2 SBOM: CycloneDX JSON, Syft.
        Syft produces CycloneDX 1.4/1.5 JSON.  We accept 1.4–1.6.
        """
        if not sbom.spec_version:
            raise ValidationError(
                "Missing required field: CycloneDX 'specVersion'"
            )
        if sbom.spec_version not in SUPPORTED_CYCLONEDX_VERSIONS:
            raise ValidationError("Unsupported CycloneDX specVersion.")

    # ------------------------------------------------------------------
    # Components presence
    # ------------------------------------------------------------------

    def _validate_components_present(self, sbom: ParsedSBOM) -> None:
        """
        Ensure the SBOM contains at least one component.

        An SBOM with zero components is structurally valid JSON but
        meaningless for the commitment pipeline — there is nothing to
        commit or prove compliance for.
        """
        if not sbom.components:
            raise ValidationError(
                "SBOM must contain at least one component"
            )

    # ------------------------------------------------------------------
    # Per-component validation
    # ------------------------------------------------------------------

    def _validate_each_component(self, components: List[ParsedComponent]) -> None:
        """Validate every component against the project contract."""
        for idx, comp in enumerate(components):
            self._validate_component(comp, idx)

    def _validate_component(self, comp: ParsedComponent, index: int) -> None:
        """
        Validate a single ParsedComponent.

        Required by the database model and downstream commitment pipeline:
          - name: required, non-empty, max 512 chars
          - version: optional, max 128 chars
          - purl: optional, max 1024 chars, basic syntax check
          - type: optional (no length constraint in DB model)

        SECURITY_BOUNDARY.md §1:
          Error messages must NOT include the actual component name,
          version, or PURL value.
        """
        # --- name (required by Component.name NOT NULL) ---
        if not comp.name or not comp.name.strip():
            raise ValidationError(
                f"Component at index {index}: 'name' is required and must not be empty"
            )
        if len(comp.name) > MAX_COMPONENT_NAME_LENGTH:
            raise ValidationError(
                f"Component at index {index}: 'name' exceeds maximum length "
                f"({MAX_COMPONENT_NAME_LENGTH} characters)"
            )

        # --- version (optional but constrained) ---
        if comp.version is not None:
            if len(comp.version) > MAX_COMPONENT_VERSION_LENGTH:
                raise ValidationError(
                    f"Component at index {index}: 'version' exceeds maximum length "
                    f"({MAX_COMPONENT_VERSION_LENGTH} characters)"
                )

        # --- purl (optional but structurally validated) ---
        if comp.purl is not None:
            if len(comp.purl) > MAX_PURL_LENGTH:
                raise ValidationError(
                    f"Component at index {index}: 'purl' exceeds maximum length "
                    f"({MAX_PURL_LENGTH} characters)"
                )
            if not _PURL_PREFIX_RE.match(comp.purl):
                raise ValidationError(
                    f"Component at index {index}: 'purl' has invalid syntax "
                    f"(must start with 'pkg:<type>/')"
                )

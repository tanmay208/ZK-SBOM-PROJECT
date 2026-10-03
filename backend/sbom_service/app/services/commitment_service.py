"""
SBOM Commitment Service — Stage 4.7.

Orchestrates the full SBOM commitment pipeline:
  POST /api/v1/sbom/upload
      → request validation
      → SBOM parsing
      → CycloneDX semantic validation
      → canonicalization
      → identity resolution
      → component hashing
      → Merkle construction
      → SBOM_ROOT
      → private persistence / commitment metadata

ARCHITECTURE.md §4 (SBOM Service responsibilities):
  - SBOM commitment
  - SBOM_ROOT generation

SECURITY_BOUNDARY.md §1:
  - Raw SBOM, component identities, canonical data, Merkle paths
    are private and must NOT be exposed through public responses.

ZKP_SPECIFICATION.md §86:
  - component_count <= MAX_COMPONENTS (1024)
"""

from __future__ import annotations

import logging
from typing import List

from sqlalchemy.orm import Session

from shared.exceptions import ServiceError, ValidationError
from shared.crypto.component_hash import hash_component
from shared.crypto.merkle import compute_merkle_root, MAX_COMPONENTS

from sbom_service.app.models.sbom_models import Component, SBOMUpload
from sbom_service.app.services.parser import SBOMParser
from sbom_service.app.services.validator import SBOMValidator
from sbom_service.app.services.canonicalization import SBOMCanonicalizer, CanonicalSBOM
from sbom_service.app.services.identity import ComponentIdentityResolver, ResolvedSBOM

logger = logging.getLogger(__name__)


class SBOMCommitmentService:
    """Orchestrates the full SBOM commitment pipeline.

    Produces a deterministic SBOM_ROOT from raw SBOM content.
    All steps are executed within a single transaction boundary.

    Responsibilities:
      1. Parse raw CycloneDX JSON
      2. Validate SBOM structure
      3. Canonicalize components
      4. Resolve component identities
      5. Enforce component_count <= 1024
      6. Hash each component via Poseidon sponge
      7. Construct Merkle tree
      8. Produce SBOM_ROOT
      9. Persist Component records and update SBOMUpload

    Does NOT:
      - Build vulnerability processing
      - Build policy processing
      - Generate ZKP proofs
      - Expose private data
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._parser = SBOMParser()
        self._validator = SBOMValidator()
        self._canonicalizer = SBOMCanonicalizer()
        self._identity_resolver = ComponentIdentityResolver()

    def commit(self, upload: SBOMUpload) -> str:
        """Execute the full commitment pipeline for an SBOMUpload.

        Parameters
        ----------
        upload:
            An SBOMUpload record with raw_content populated.

        Returns
        -------
        str
            The SBOM_ROOT as a hex string (0x-prefixed).

        Raises
        ------
        ValidationError
            If parsing, validation, or component count fails.
        ServiceError
            If an internal error occurs during commitment.
        """
        try:
            raw_content = upload.raw_content
            if not raw_content:
                raise ValidationError("SBOM content is empty")

            # Step 1: Parse
            parsed_sbom = self._parser.parse(raw_content)

            # Step 2: Validate
            self._validator.validate(parsed_sbom)

            # Step 3: Canonicalize
            canonical_sbom: CanonicalSBOM = self._canonicalizer.canonicalize(parsed_sbom)

            # Step 4: Identity Resolution
            resolved_sbom: ResolvedSBOM = self._identity_resolver.resolve(canonical_sbom)

            # Step 5: Enforce component count limit
            component_count = resolved_sbom.component_count
            if component_count > MAX_COMPONENTS:
                raise ValidationError(
                    f"Component count ({component_count}) exceeds maximum "
                    f"tree capacity ({MAX_COMPONENTS})"
                )

            if component_count == 0:
                raise ValidationError("SBOM must contain at least one component")

            # Step 6: Component hashing
            component_hashes: List[int] = []
            for resolved_comp in resolved_sbom.components:
                ch = hash_component(resolved_comp.canonical.canonical_json)
                component_hashes.append(ch)

            # Step 7: Merkle tree construction
            sbom_root_int = compute_merkle_root(component_hashes)
            sbom_root_hex = f"0x{sbom_root_int:064x}"

            # Step 8: Update SBOMUpload record
            upload.sbom_root = sbom_root_hex
            upload.component_count = component_count
            upload.spec_version = parsed_sbom.spec_version
            upload.status = "committed"

            # Step 9: Persist Component records
            for resolved_comp in resolved_sbom.components:
                comp_record = Component(
                    sbom_upload_id=upload.id,
                    name=resolved_comp.canonical.parsed.name,
                    version=resolved_comp.canonical.parsed.version,
                    purl=resolved_comp.canonical.parsed.purl,
                    purl_canonical=resolved_comp.canonical.purl_canonical,
                    component_hash=f"0x{hash_component(resolved_comp.canonical.canonical_json):064x}",
                    position=resolved_comp.canonical.position,
                )
                self._session.add(comp_record)

            self._session.flush()

            logger.info(
                "commitment: SBOM_ROOT computed (upload_id=%s, components=%d)",
                str(upload.id),
                component_count,
            )

            return sbom_root_hex

        except (ValidationError, ServiceError):
            raise

        except Exception as exc:
            logger.error(
                "commitment: unexpected error (%s)",
                type(exc).__name__,
            )
            raise ServiceError(
                "SBOM commitment failed due to an internal error",
                status_code=500,
                error_code="INTERNAL_ERROR",
            ) from exc

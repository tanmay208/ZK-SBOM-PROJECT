"""
SBOM Service — intake service layer (Stage 3.2, updated Stage 4.7).

This layer sits between the API route handler and the repository.
It is responsible for:
  - Business-rule enforcement (content not empty, format accepted)
  - Transaction management (commit on success, rollback on failure)
  - Invoking the full SBOM commitment pipeline (Stage 4.7)
  - Propagating domain exceptions to the route layer

SECURITY_BOUNDARY.md:
  - sbom_service operates entirely within the Private vendor boundary.
  - raw_content must never be logged or returned to callers.

DEVELOPMENT_RULES.md §19:
  - No sensitive data in logs.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from shared.exceptions import ServiceError, ValidationError

from sbom_service.app.models.sbom_models import Application, SBOMUpload
from sbom_service.app.repositories.sbom_repository import SBOMRepository
from sbom_service.app.services.commitment_service import SBOMCommitmentService

logger = logging.getLogger(__name__)

# Accepted SBOM formats at this stage (ARCHITECTURE.md §2 SBOM)
_ACCEPTED_FORMATS: frozenset[str] = frozenset({"CycloneDX"})


class SBOMIntakeService:
    """Orchestrates the SBOM intake pipeline.

    Responsibilities (Stage 4.7):
      1. Validate intake preconditions (format, non-empty content).
      2. Persist Application (get-or-create) and SBOMUpload.
      3. Execute the full commitment pipeline:
         parse → validate → canonicalize → identity → hash → Merkle → SBOM_ROOT.
      4. Return the persisted SBOMUpload with SBOM_ROOT populated.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._repo = SBOMRepository(session)
        self._commitment_service = SBOMCommitmentService(session)

    def ingest(
        self,
        *,
        application_name: str,
        vendor: str,
        filename: str | None,
        format: str,
        content: str,
        user_id: uuid.UUID,
    ) -> SBOMUpload:
        """Validate, persist, and commit an incoming SBOM.

        Parameters
        ----------
        application_name:
            Vendor application name (already validated by Pydantic layer).
        vendor:
            Vendor name (already validated by Pydantic layer).
        filename:
            Optional original filename (cosmetic only).
        format:
            SBOM format string — must be in _ACCEPTED_FORMATS.
        content:
            Raw SBOM payload as a UTF-8 string.
            Persisted verbatim as SBOMUpload.raw_content.
            NEVER logged or returned to clients.

        Returns
        -------
        SBOMUpload
            The persisted record with status="committed" and
            sbom_root populated on success.

        Raises
        ------
        ValidationError
            If the format is not accepted, content is empty, or
            commitment validation fails.
        ServiceError
            If a database or unexpected error occurs (wrapped to avoid
            exposing internals).
        """
        # --- Persistence + Commitment (single transaction) -----------------
        try:
            # Pre-conditions — inside try so rollback always fires on failure
            if format not in _ACCEPTED_FORMATS:
                raise ValidationError("Unsupported SBOM format.")

            # content is already validated non-empty by Pydantic; defensive check
            if not content or not content.strip():
                raise ValidationError("SBOM content must not be empty")

            application: Application = self._repo.get_or_create_application(
                name=application_name,
                vendor=vendor,
                user_id=user_id,
            )
            upload: SBOMUpload = self._repo.create_upload(
                application=application,
                filename=filename,
                format=format,
                raw_content=content,
                user_id=user_id,
            )

            # Execute the full commitment pipeline (Stage 4.7)
            # This parses, validates, canonicalizes, hashes, builds Merkle,
            # produces SBOM_ROOT, persists Components, and updates the upload.
            sbom_root = self._commitment_service.commit(upload)

            self._session.commit()
            logger.info(
                "ingest: commitment complete (upload_id=%s, application_id=%s)",
                str(upload.id),
                str(application.id),
            )
            return upload

        except (ValidationError, ServiceError):
            self._session.rollback()
            raise

        except Exception as exc:
            self._session.rollback()
            # Log the exception type — never the content
            logger.error(
                "ingest: unexpected error during persistence (%s)",
                type(exc).__name__,
            )
            raise ServiceError(
                "SBOM intake failed due to an internal error",
                status_code=500,
                error_code="INTERNAL_ERROR",
            ) from exc

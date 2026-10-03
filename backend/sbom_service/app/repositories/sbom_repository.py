"""
SBOM Service repository — Stage 3.2: Intake persistence.

DATABASE_SCHEMA.md §1 (sbom schema):
  Owner:    sbom_service
  Purpose:  Stores private SBOM data, vendor metadata, and intermediate
            component representations required for generating the SBOM
            commitment.

SECURITY_BOUNDARY.md §4:
  sbom schema contains Private Data.  Restricted access.

This repository manages only the Application and SBOMUpload models.
Component-level persistence belongs to later normalization stages.

Transaction discipline:
  All mutating operations accept a caller-managed Session so the caller
  controls commit/rollback boundaries.  The repository NEVER commits or
  rolls back itself — that responsibility belongs to the service layer.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from sbom_service.app.models.sbom_models import Application, SBOMUpload

logger = logging.getLogger(__name__)


class SBOMRepository:
    """Data-access layer for the sbom schema.

    Only Application and SBOMUpload creation/lookup are implemented here.
    Component-level persistence belongs to later stages (normalization).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    def get_or_create_application(
        self,
        *,
        name: str,
        vendor: str,
        user_id: uuid.UUID,
        description: str | None = None,
    ) -> Application:
        """Return an existing Application or create a new one.

        Lookup is performed by (name, vendor) pair.  If a matching record
        exists it is returned unchanged.  Otherwise a new record is added
        to the session (NOT committed — the caller commits).

        Parameters are already validated by the Pydantic schema layer.
        """
        existing: Application | None = (
            self._session.query(Application)
            .filter(
                Application.name == name,
                Application.vendor == vendor,
            )
            .first()
        )
        if existing is not None:
            logger.debug(
                "get_or_create_application: existing record found (id=%s)",
                str(existing.id),
            )
            return existing

        application = Application(
            name=name,
            vendor=vendor,
            description=description,
            user_id=user_id,
        )
        self._session.add(application)
        # flush so that application.id is populated (needed for the FK
        # in SBOMUpload) without committing the outer transaction.
        self._session.flush()
        logger.info(
            "get_or_create_application: created new application (id=%s)",
            str(application.id),
        )
        return application

    # ------------------------------------------------------------------
    # SBOMUpload
    # ------------------------------------------------------------------

    def create_upload(
        self,
        *,
        application: Application,
        filename: str | None,
        format: str,
        raw_content: str,
        user_id: uuid.UUID,
    ) -> SBOMUpload:
        """Persist a new SBOMUpload record.

        raw_content is persisted verbatim as required by DATABASE_SCHEMA.md.
        It must NEVER be included in any API response (SECURITY_BOUNDARY.md §1).

        The upload is created with status="pending" and no sbom_root or
        component_count — those are set by later processing stages.

        The record is added to the session but NOT committed.
        """
        upload = SBOMUpload(
            application_id=application.id,
            filename=filename,
            format=format,
            status="pending",
            raw_content=raw_content,
            user_id=user_id,
        )
        self._session.add(upload)
        self._session.flush()
        # Log only the opaque ID — never the content or filename detail
        logger.info(
            "create_upload: SBOMUpload persisted (id=%s, status=pending)",
            str(upload.id),
        )
        return upload

    def get_upload_by_id(self, upload_id: object) -> SBOMUpload | None:
        """Return a single SBOMUpload by primary key, or None."""
        return (
            self._session.query(SBOMUpload)
            .filter(SBOMUpload.id == upload_id)
            .first()
        )

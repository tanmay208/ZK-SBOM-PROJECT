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

from datetime import datetime, timezone
import logging
import uuid

from sqlalchemy.orm import Session

from shared.exceptions import ConflictError, ValidationError
from sbom_service.app.models.sbom_models import Application, SBOMUpload

logger = logging.getLogger(__name__)


class SBOMRepository:
    """Data-access layer for the sbom schema.

    Manages Application and SBOMUpload models.
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
        """Return an existing active Application or create a new one.

        Lookup is performed by (name, vendor, user_id) triple. If a
        matching record exists:
          - If active, it is returned unchanged.
          - If archived, a ValidationError is raised to fail closed and
            prevent silent reuse of archived applications.

        The user_id filter ensures tenant isolation: two different users
        who register the same (name, vendor) pair each receive their own
        Application record (AUD-A-001 remediation).

        Parameters are already validated by the Pydantic schema layer.
        """
        existing: Application | None = (
            self._session.query(Application)
            .filter(
                Application.name == name,
                Application.vendor == vendor,
                Application.user_id == user_id,
            )
            .first()
        )
        if existing is not None:
            if not existing.is_active:
                raise ValidationError(
                    f"Application '{name}' is archived and cannot receive new SBOM uploads."
                )
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
            is_active=True,
            archived_at=None,
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

    def get_application_by_id(
        self,
        application_id: uuid.UUID,
        user_id: uuid.UUID | None = None,
    ) -> Application | None:
        """Return a single Application by ID, optionally scoped to tenant owner."""
        query = self._session.query(Application).filter(Application.id == application_id)
        if user_id is not None:
            query = query.filter(Application.user_id == user_id)
        return query.first()

    def list_applications(
        self,
        user_id: uuid.UUID,
        include_archived: bool = False,
        skip: int = 0,
        limit: int = 50,
    ) -> list[Application]:
        """List applications owned by user_id, active-only by default."""
        query = self._session.query(Application).filter(Application.user_id == user_id)
        if not include_archived:
            query = query.filter(Application.is_active == True)
        return (
            query.order_by(Application.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def create_application(
        self,
        *,
        name: str,
        vendor: str,
        user_id: uuid.UUID,
        description: str | None = None,
    ) -> Application:
        """Create a new standalone Application.

        Enforces tenant uniqueness on (name, vendor, user_id).
        """
        existing = (
            self._session.query(Application)
            .filter(
                Application.name == name,
                Application.vendor == vendor,
                Application.user_id == user_id,
            )
            .first()
        )
        if existing is not None:
            if existing.is_active:
                raise ConflictError("Application already exists for this vendor")
            else:
                raise ConflictError("Application already exists and is archived. Reactivate it to resume use.")

        application = Application(
            name=name,
            vendor=vendor,
            description=description,
            user_id=user_id,
            is_active=True,
            archived_at=None,
        )
        self._session.add(application)
        self._session.flush()
        logger.info("create_application: created application (id=%s)", str(application.id))
        return application

    def update_application(
        self,
        application: Application,
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> Application:
        """Update mutable metadata of an active application."""
        if not application.is_active:
            raise ValidationError("Cannot update an archived application. Reactivate it first.")

        if name is not None and name != application.name:
            conflict = (
                self._session.query(Application)
                .filter(
                    Application.name == name,
                    Application.vendor == application.vendor,
                    Application.user_id == application.user_id,
                    Application.id != application.id,
                )
                .first()
            )
            if conflict is not None:
                raise ConflictError("Application with this name and vendor already exists")
            application.name = name

        if description is not None:
            application.description = description

        self._session.flush()
        return application

    def archive_application(self, application: Application) -> Application:
        """Soft-archive an application. Idempotent if already archived."""
        if not application.is_active:
            logger.debug("archive_application: already archived (id=%s)", str(application.id))
            return application

        application.is_active = False
        application.archived_at = datetime.now(timezone.utc)
        self._session.flush()
        logger.info("archive_application: application archived (id=%s)", str(application.id))
        return application

    def reactivate_application(self, application: Application) -> Application:
        """Reactivate an archived application. Idempotent if already active."""
        if application.is_active:
            logger.debug("reactivate_application: already active (id=%s)", str(application.id))
            return application

        # Check if an active application with same (name, vendor, user_id) exists
        conflict = (
            self._session.query(Application)
            .filter(
                Application.name == application.name,
                Application.vendor == application.vendor,
                Application.user_id == application.user_id,
                Application.is_active == True,
                Application.id != application.id,
            )
            .first()
        )
        if conflict is not None:
            raise ConflictError("An active application with this name and vendor already exists")

        application.is_active = True
        application.archived_at = None
        self._session.flush()
        logger.info("reactivate_application: application reactivated (id=%s)", str(application.id))
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

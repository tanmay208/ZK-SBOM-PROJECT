"""
Application Service — Stage D4.1: Application Lifecycle.

SERVICE_CONTRACTS.md §1:
  Application business logic, transaction management, and lifecycle controls.

SECURITY_BOUNDARY.md §4:
  Enforces tenant ownership boundaries, non-disclosing 404 on cross-tenant
  access, and safe transaction rollbacks.
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from shared.exceptions import ConflictError, NotFoundError, ServiceError, ValidationError
from shared.models.user import User
from sbom_service.app.models.sbom_models import Application
from sbom_service.app.repositories.sbom_repository import SBOMRepository

logger = logging.getLogger(__name__)


class ApplicationService:
    """Service managing application lifecycle and tenant isolation."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._repo = SBOMRepository(session)

    def create(
        self,
        *,
        name: str,
        vendor: str,
        user_id: uuid.UUID,
        description: Optional[str] = None,
    ) -> Application:
        """Create a new application for the user."""
        try:
            app = self._repo.create_application(
                name=name,
                vendor=vendor,
                user_id=user_id,
                description=description,
            )
            self._session.commit()
            return app
        except IntegrityError as exc:
            self._session.rollback()
            err_str = str(exc).lower()
            orig = getattr(exc, "orig", None)
            diag = getattr(orig, "diag", None)
            constraint_name = getattr(diag, "constraint_name", None) or ""
            if "uq_sbom_applications_name_vendor_user" in constraint_name.lower() or "uq_sbom_applications_name_vendor_user" in err_str or "unique constraint" in err_str:
                raise ConflictError("Application already exists for this vendor") from exc
            logger.error("create_application database integrity violation (%s): %s", type(exc).__name__, exc)
            raise ServiceError("Database integrity constraint violated", status_code=400, error_code="INTEGRITY_VIOLATION") from exc
        except (ConflictError, ValidationError, ServiceError):
            self._session.rollback()
            raise
        except Exception as exc:
            self._session.rollback()
            logger.error("create_application unexpected error (%s)", type(exc).__name__)
            raise ServiceError("Failed to create application", status_code=500, error_code="INTERNAL_ERROR") from exc

    def list(
        self,
        *,
        user_id: uuid.UUID,
        include_archived: bool = False,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Application]:
        """List applications owned by user_id."""
        return self._repo.list_applications(
            user_id=user_id,
            include_archived=include_archived,
            skip=skip,
            limit=limit,
        )

    def get_by_id(
        self,
        *,
        application_id: uuid.UUID,
        current_user: User,
    ) -> Application:
        """Retrieve application by ID with tenant non-disclosure checks."""
        app = self._repo.get_application_by_id(application_id)
        if app is None:
            raise NotFoundError("Application not found")

        # Non-disclosure: non-admin, non-owner gets 404
        if app.user_id != current_user.id and current_user.role != "admin":
            raise NotFoundError("Application not found")

        return app

    def update(
        self,
        *,
        application_id: uuid.UUID,
        current_user: User,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Application:
        """Update mutable metadata of an owned, active application."""
        app = self._repo.get_application_by_id(application_id)
        if app is None:
            raise NotFoundError("Application not found")

        # Non-owners (even admin) receive 404 for mutations to preserve strict tenant ownership
        if app.user_id != current_user.id:
            raise NotFoundError("Application not found")

        try:
            updated_app = self._repo.update_application(
                app,
                name=name,
                description=description,
            )
            self._session.commit()
            return updated_app
        except (ConflictError, ValidationError, ServiceError):
            self._session.rollback()
            raise
        except Exception as exc:
            self._session.rollback()
            logger.error("update_application unexpected error (%s)", type(exc).__name__)
            raise ServiceError("Failed to update application", status_code=500, error_code="INTERNAL_ERROR") from exc

    def archive(
        self,
        *,
        application_id: uuid.UUID,
        current_user: User,
    ) -> Application:
        """Soft-archive an owned application."""
        app = self._repo.get_application_by_id(application_id)
        if app is None:
            raise NotFoundError("Application not found")

        if app.user_id != current_user.id:
            raise NotFoundError("Application not found")

        try:
            archived_app = self._repo.archive_application(app)
            self._session.commit()
            return archived_app
        except (ConflictError, ValidationError, ServiceError):
            self._session.rollback()
            raise
        except Exception as exc:
            self._session.rollback()
            logger.error("archive_application unexpected error (%s)", type(exc).__name__)
            raise ServiceError("Failed to archive application", status_code=500, error_code="INTERNAL_ERROR") from exc

    def reactivate(
        self,
        *,
        application_id: uuid.UUID,
        current_user: User,
    ) -> Application:
        """Reactivate an owned, archived application."""
        app = self._repo.get_application_by_id(application_id)
        if app is None:
            raise NotFoundError("Application not found")

        if app.user_id != current_user.id:
            raise NotFoundError("Application not found")

        try:
            reactivated_app = self._repo.reactivate_application(app)
            self._session.commit()
            return reactivated_app
        except (ConflictError, ValidationError, ServiceError):
            self._session.rollback()
            raise
        except Exception as exc:
            self._session.rollback()
            logger.error("reactivate_application unexpected error (%s)", type(exc).__name__)
            raise ServiceError("Failed to reactivate application", status_code=500, error_code="INTERNAL_ERROR") from exc

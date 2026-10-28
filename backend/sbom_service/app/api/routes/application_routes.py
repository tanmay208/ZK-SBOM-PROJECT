"""
Application Service API routes — Stage D4.1: Standalone Application Lifecycle.

SERVICE_CONTRACTS.md §1:
  Endpoint prefix: /api/v1/applications

SECURITY_BOUNDARY.md §1, §4:
  - Requires authentication on every route.
  - Non-disclosing 404 on cross-tenant lookup/mutation.
  - Role enforcement: only vendors and admins may mutate applications;
    buyers, auditors, and trusted importers cannot mutate applications.
"""

from __future__ import annotations

import logging
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from shared.database import get_session
from shared.auth import get_current_user, require_roles
from shared.models.user import User

from sbom_service.app.schemas.application_schemas import (
    ApplicationCreateRequest,
    ApplicationUpdateRequest,
    ApplicationResponse,
)
from sbom_service.app.services.application_service import ApplicationService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/applications", tags=["applications"])


@router.post(
    "",
    response_model=ApplicationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new vendor application",
    description="Registers a new standalone application owned by the authenticated vendor or admin.",
)
def create_application(
    request: ApplicationCreateRequest,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles("vendor", "admin")),
) -> ApplicationResponse:
    service = ApplicationService(session)
    app = service.create(
        name=request.name,
        vendor=request.vendor,
        user_id=current_user.id,
        description=request.description,
    )
    return ApplicationResponse.from_model(app)


@router.get(
    "",
    response_model=List[ApplicationResponse],
    summary="List applications",
    description="Returns applications owned by the authenticated user. Excludes archived applications by default.",
)
def list_applications(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    include_archived: bool = Query(default=False, description="Whether to include soft-archived applications"),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> List[ApplicationResponse]:
    service = ApplicationService(session)
    apps = service.list(
        user_id=current_user.id,
        include_archived=include_archived,
        skip=skip,
        limit=limit,
    )
    return [ApplicationResponse.from_model(a) for a in apps]


@router.get(
    "/{app_id}",
    response_model=ApplicationResponse,
    summary="Get application detail",
    description="Retrieves application metadata for an authorized application. Non-disclosing 404 for unauthorized cross-tenant requests.",
)
def get_application(
    app_id: UUID,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> ApplicationResponse:
    service = ApplicationService(session)
    app = service.get_by_id(
        application_id=app_id,
        current_user=current_user,
    )
    return ApplicationResponse.from_model(app)


@router.patch(
    "/{app_id}",
    response_model=ApplicationResponse,
    summary="Update application metadata",
    description="Updates permitted metadata (name, description) on an active owned application.",
)
def update_application(
    app_id: UUID,
    request: ApplicationUpdateRequest,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles("vendor", "admin")),
) -> ApplicationResponse:
    service = ApplicationService(session)
    app = service.update(
        application_id=app_id,
        current_user=current_user,
        name=request.name,
        description=request.description,
    )
    return ApplicationResponse.from_model(app)


@router.post(
    "/{app_id}/archive",
    response_model=ApplicationResponse,
    summary="Soft-archive an application",
    description="Soft-archives an application, preventing new SBOM uploads. Idempotent. Preserves historical SBOMs and proofs.",
)
def archive_application(
    app_id: UUID,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles("vendor", "admin")),
) -> ApplicationResponse:
    service = ApplicationService(session)
    app = service.archive(
        application_id=app_id,
        current_user=current_user,
    )
    return ApplicationResponse.from_model(app)


@router.post(
    "/{app_id}/reactivate",
    response_model=ApplicationResponse,
    summary="Reactivate an application",
    description="Reactivates an archived application so it can receive SBOM uploads again. Idempotent.",
)
def reactivate_application(
    app_id: UUID,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles("vendor", "admin")),
) -> ApplicationResponse:
    service = ApplicationService(session)
    app = service.reactivate(
        application_id=app_id,
        current_user=current_user,
    )
    return ApplicationResponse.from_model(app)

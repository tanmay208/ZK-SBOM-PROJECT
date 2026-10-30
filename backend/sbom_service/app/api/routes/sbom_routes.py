"""
SBOM Service API routes — Stage 3.2: Intake.

SERVICE_CONTRACTS.md §1:
  Endpoint prefix: /api/v1/sbom

SECURITY_BOUNDARY.md §1, §4:
  Route handlers MUST NOT return raw_content, PURLs, component hashes,
  or any other Private Data.

DEVELOPMENT_RULES.md §19, §20:
  No sensitive data in logs or buyer-facing API responses.

AMBIGUITY RECORD — Stage 3.1 open items addressed in this module
----------------------------------------------------------------
#1  CycloneDX version policy:
      Not resolved.  The schema layer accepts any JSON string whose
      `format` field equals "CycloneDX".  Version-specific validation
      belongs to Stage 3.4 (Validation).

#2  Upload protocol (multipart vs JSON body):
      Resolved pragmatically.  This endpoint accepts a JSON body
      (application/json) containing the raw SBOM as the `content`
      string field.  This decision is reversible — the service and
      repository layers are protocol-agnostic.  The ambiguity is
      carried forward for explicit resolution in Stage 3.4.

#3  Canonical representation construction:
      Not resolved here.  Stage 3.5 (Normalization).

#4  Duplicate component handling:
      Not resolved here.  Stage 3.6 (Component Identity).
"""

from __future__ import annotations

import logging

from uuid import UUID
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query as FastAPIQuery, status, Request
from sqlalchemy.orm import Session, Query, joinedload
from pydantic import ValidationError

from shared.database import get_session
from shared.auth import get_current_user, require_roles
from shared.models.user import User

from sbom_service.app.models.sbom_models import SBOMUpload
from sbom_service.app.schemas.sbom_schemas import SBOMUploadRequest, SBOMUploadResponse
from sbom_service.app.services.sbom_intake_service import SBOMIntakeService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sbom", tags=["sbom"])


@router.get(
    "",
    response_model=List[SBOMUploadResponse],
    summary="List all SBOMs",
)
def list_sboms(
    skip: int = FastAPIQuery(default=0, ge=0),
    limit: int = FastAPIQuery(default=50, ge=1, le=100),
    all_tenants: bool = FastAPIQuery(default=False, description="Admin-only: list SBOMs across all tenants"),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if all_tenants and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators may list SBOMs across all tenants",
        )

    query = session.query(SBOMUpload)
    if isinstance(query, Query):
        query = query.options(joinedload(SBOMUpload.application))
    if not (all_tenants and current_user.role == "admin"):
        query = query.filter(SBOMUpload.user_id == current_user.id)

    uploads = (
        query
        .order_by(SBOMUpload.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [SBOMUploadResponse.from_model(u) for u in uploads]


@router.get(
    "/{upload_id}",
    response_model=SBOMUploadResponse,
    summary="Get SBOM upload details",
)
def get_sbom(
    upload_id: UUID,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    query = session.query(SBOMUpload)
    if isinstance(query, Query):
        query = query.options(joinedload(SBOMUpload.application))
    upload = query.filter(SBOMUpload.id == upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="SBOM not found")

    is_admin = (current_user.role == "admin")
    if not is_admin and upload.user_id != current_user.id:
        # Non-disclosure convention: return 404 for cross-tenant access to prevent enumeration
        raise HTTPException(status_code=404, detail="SBOM not found")

    return SBOMUploadResponse.from_model(upload)


@router.post(
    "/upload",
    response_model=SBOMUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a vendor SBOM",
    description=(
        "Accepts a raw SBOM payload (CycloneDX JSON serialised as a string), "
        "persists it as a pending SBOMUpload record linked to the vendor "
        "Application, and returns the upload identifier for downstream "
        "processing.  The raw content is NEVER returned. "
        "Accepts both application/json and multipart/form-data."
    ),
    openapi_extra={
        "requestBody": {
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "application_name": {"type": "string"},
                            "vendor": {"type": "string"},
                            "filename": {"type": "string"},
                            "format": {"type": "string", "default": "CycloneDX"},
                            "content": {"type": "string", "format": "binary"}
                        },
                        "required": ["application_name", "vendor", "content"]
                    }
                },
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/SBOMUploadRequest"
                    }
                }
            },
            "required": True
        }
    }
)
async def upload_sbom(
    request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(require_roles("vendor")),
) -> SBOMUploadResponse:
    """
    POST /api/v1/sbom/upload

    Security:
      - 10 MB body limit enforced by RequestSizeLimitMiddleware.
      - Empty / whitespace-only content rejected.
      - Unsupported formats rejected with 422.
      - raw_content is never included in the response.
      - No raw SBOM or component data is logged.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
        try:
            req_data = SBOMUploadRequest(**body)
        except ValidationError as e:
            from fastapi.exceptions import RequestValidationError
            raise RequestValidationError(e.errors())
    elif "multipart/form-data" in content_type:
        form = await request.form()
        data = {
            "application_name": form.get("application_name"),
            "vendor": form.get("vendor"),
            "format": form.get("format", "CycloneDX")
        }
        if "filename" in form:
            data["filename"] = form.get("filename")
            
        content_val = form.get("content")
        if content_val is not None:
            if hasattr(content_val, "read"):
                try:
                    data["content"] = (await content_val.read()).decode("utf-8")
                except UnicodeDecodeError:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail="Uploaded SBOM file must be valid UTF-8 text",
                    )
            else:
                data["content"] = content_val
                
        try:
            req_data = SBOMUploadRequest(**data)
        except ValidationError as e:
            from fastapi.exceptions import RequestValidationError
            raise RequestValidationError(e.errors())
    else:
        raise HTTPException(status_code=415, detail="Unsupported media type")

    service = SBOMIntakeService(session)
    upload = service.ingest(
        application_name=req_data.application_name,
        vendor=req_data.vendor,
        filename=req_data.filename,
        format=req_data.format,
        content=req_data.content,
        user_id=current_user.id,
    )
    return SBOMUploadResponse.from_model(
        upload,
        application_name=req_data.application_name,
        vendor=req_data.vendor,
    )

"""
SBOM Service Pydantic schemas — Stage 3.2: Intake.

SERVICE_CONTRACTS.md §1:
  Input:  vendor raw SBOM files.
  Output: confirmation of intake, SBOMUpload id.
  Privacy Classification: Strictly Confidential / Private.

SECURITY_BOUNDARY.md §1, §4:
  - raw_content is PRIVATE and must NEVER appear in any response.
  - purl, component_hash, purl_canonical are PRIVATE field names.

AMBIGUITY NOTE (Stage 3.1 — not resolved here):
  The upload protocol ambiguity (multipart/form-data vs raw JSON body)
  is documented in the intake endpoint.  This implementation uses a
  JSON body envelope containing the SBOM as a serialized string, which
  is the least invasive choice compatible with the existing REST contract
  and the 10 MB middleware limit already in place.  See intake router
  module for full ambiguity documentation.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Intake request
# ---------------------------------------------------------------------------

class SBOMUploadRequest(BaseModel):
    """
    Request body for POST /api/v1/sbom/upload.

    Fields
    ------
    application_name:
        The registered vendor application name.  Must be 1–255 characters.
    vendor:
        The vendor organisation name.  Must be 1–255 characters.
    filename:
        Optional original filename (cosmetic; max 512 chars).
    format:
        SBOM format.  Only "CycloneDX" is accepted at this stage.
        (ARCHITECTURE.md §2 SBOM — CycloneDX JSON / Syft)
    content:
        The raw SBOM payload, serialised as a UTF-8 string.
        Maximum enforced at the middleware level (10 MB).
        This field is persisted verbatim as SBOMUpload.raw_content.
        It is NEVER returned in any response.

    AMBIGUITY NOTE — Upload protocol (Stage 3.1 ambiguity #2):
        SERVICE_CONTRACTS.md §1 states the API is /api/v1/sbom but does
        not specify multipart vs JSON body.  This implementation uses
        a JSON body envelope so that the existing RequestSizeLimitMiddleware
        (which inspects Content-Length) correctly enforces the 10 MB cap
        without additional plumbing.  If multipart/form-data is later
        mandated, the schema and router can be replaced without changing
        the service or repository layers.
    """

    application_name: Annotated[str, Field(min_length=1, max_length=255)]
    vendor: Annotated[str, Field(min_length=1, max_length=255)]
    filename: Annotated[str | None, Field(default=None, max_length=512)] = None
    format: Annotated[str, Field(default="CycloneDX")]
    content: Annotated[str, Field(min_length=1)]

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        allowed = {"CycloneDX"}
        if v not in allowed:
            raise ValueError("Unsupported SBOM format.")
        return v

    @field_validator("application_name", "vendor")
    @classmethod
    def no_control_characters(cls, v: str) -> str:
        """Reject strings containing ASCII control characters (log injection)."""
        if any(ord(c) < 32 and c not in ("\t",) for c in v):
            raise ValueError("Field contains disallowed control characters")
        return v


# ---------------------------------------------------------------------------
# Intake response  — MUST NOT include private fields
# ---------------------------------------------------------------------------

class SBOMUploadResponse(BaseModel):
    """
    Safe response returned after a successful SBOM commitment.

    SECURITY_BOUNDARY.md §1, §4:
      raw_content, purl, component_hash, purl_canonical are PRIVATE and
      must NOT appear here.

    SECURITY_BOUNDARY.md §2:
      SBOM_ROOT is PUBLIC data — safe for buyer boundary.
      component_count is safe metadata (does not reveal component identities).
    """

    upload_id: _uuid.UUID
    application_id: _uuid.UUID
    status: str
    format: str
    filename: str | None
    sbom_root: str | None = None
    component_count: int | None = None
    created_at: datetime
    application_name: str | None = None
    vendor: str | None = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(
        cls,
        upload: object,
        application_name: str | None = None,
        vendor: str | None = None,
    ) -> "SBOMUploadResponse":
        app_name = application_name
        app_vendor = vendor
        app = getattr(upload, "application", None)
        if app_name is None and app is not None:
            app_name = getattr(app, "name", None)
        if app_vendor is None and app is not None:
            app_vendor = getattr(app, "vendor", None)

        return cls(
            upload_id=getattr(upload, "id"),
            application_id=getattr(upload, "application_id"),
            status=getattr(upload, "status"),
            format=getattr(upload, "format"),
            filename=getattr(upload, "filename", None),
            sbom_root=getattr(upload, "sbom_root", None),
            component_count=getattr(upload, "component_count", None),
            created_at=getattr(upload, "created_at"),
            application_name=app_name,
            vendor=app_vendor,
        )

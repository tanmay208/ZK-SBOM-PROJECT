"""
Application Pydantic schemas — Stage D4.1: Application Lifecycle.

SERVICE_CONTRACTS.md §1:
  Vendor application registration, listing, detail, and soft archival.

SECURITY_BOUNDARY.md §1, §4:
  Application metadata contains vendor application identities.
  Does NOT contain raw SBOM content, component lists, hashes, or secrets.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ApplicationCreateRequest(BaseModel):
    """Request body for POST /api/v1/applications."""

    name: Annotated[str, Field(min_length=1, max_length=255, description="Application name")]
    vendor: Annotated[str, Field(min_length=1, max_length=255, description="Vendor organization name")]
    description: Annotated[Optional[str], Field(default=None, max_length=2000, description="Optional application description")] = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("name", "vendor")
    @classmethod
    def validate_non_empty_and_no_control_chars(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Field must not be empty or whitespace only")
        if any(ord(c) < 32 and c not in ("\t",) for c in trimmed):
            raise ValueError("Field contains disallowed control characters")
        return trimmed


class ApplicationUpdateRequest(BaseModel):
    """Request body for PATCH /api/v1/applications/{app_id}."""

    name: Annotated[Optional[str], Field(default=None, min_length=1, max_length=255)] = None
    description: Annotated[Optional[str], Field(default=None, max_length=2000)] = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Name must not be empty or whitespace only")
        if any(ord(c) < 32 and c not in ("\t",) for c in trimmed):
            raise ValueError("Name contains disallowed control characters")
        return trimmed


class ApplicationResponse(BaseModel):
    """Safe response model for Application records."""

    id: _uuid.UUID
    name: str
    vendor: str
    description: Optional[str] = None
    user_id: Optional[_uuid.UUID] = None
    is_active: bool
    archived_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_model(cls, app: object) -> "ApplicationResponse":
        return cls(
            id=getattr(app, "id"),
            name=getattr(app, "name"),
            vendor=getattr(app, "vendor"),
            description=getattr(app, "description", None),
            user_id=getattr(app, "user_id", None),
            is_active=bool(getattr(app, "is_active", True)),
            archived_at=getattr(app, "archived_at", None),
            created_at=getattr(app, "created_at"),
            updated_at=getattr(app, "updated_at"),
        )

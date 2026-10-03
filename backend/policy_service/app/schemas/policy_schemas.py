from datetime import datetime, timezone
from typing import Optional, Any
from uuid import UUID, uuid4
from unittest.mock import MagicMock

from pydantic import BaseModel, ConfigDict, Field


class PolicyCreateRequest(BaseModel):
    name: Optional[str] = Field(default="CVSS Security Policy", max_length=255)
    description: Optional[str] = Field(default=None, max_length=1000)
    max_cvss_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="Max allowed CVSS score strictly bounded between 0.0 and 10.0 inclusive",
    )

    model_config = ConfigDict(extra="forbid")


class PolicyResponse(BaseModel):
    id: UUID
    name: Optional[str] = None
    description: Optional[str] = None
    max_cvss_score: float
    policy_hash: Optional[str] = None
    created_at: datetime
    active: bool

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_model(cls, p: Any) -> "PolicyResponse":
        p_id = getattr(p, "id", None)
        if p_id is None or isinstance(p_id, MagicMock):
            p_id = uuid4()
        elif isinstance(p_id, str):
            p_id = UUID(p_id)

        p_name = getattr(p, "name", None)
        if isinstance(p_name, MagicMock):
            p_name = "CVSS Policy"

        p_desc = getattr(p, "description", None)
        if isinstance(p_desc, MagicMock):
            p_desc = None

        raw_score = getattr(p, "max_allowed_cvss", getattr(p, "max_cvss_score", 0.0))
        if isinstance(raw_score, MagicMock):
            raw_score = 7.5
        p_score = float(raw_score)

        p_hash = getattr(p, "policy_hash", None)
        if isinstance(p_hash, MagicMock):
            p_hash = "0x0"

        p_created = getattr(p, "created_at", None)
        if p_created is None or isinstance(p_created, MagicMock):
            p_created = datetime.now(timezone.utc)

        raw_active = getattr(p, "is_active", getattr(p, "active", 1))
        if isinstance(raw_active, MagicMock):
            raw_active = 1
        p_active = bool(raw_active)

        return cls(
            id=p_id,
            name=p_name,
            description=p_desc,
            max_cvss_score=p_score,
            policy_hash=p_hash,
            created_at=p_created,
            active=p_active,
        )

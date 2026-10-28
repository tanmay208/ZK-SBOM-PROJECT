"""
Policy schema models.

DATABASE_SCHEMA.md §3 — policy schema:
  Owner: policy_service
  Purpose: Stores configurable security policies.

ARCHITECTURE.md: Current authoritative ZKP policy is max_allowed_cvss.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.types import Uuid

from shared.database import Base


class SecurityPolicy(Base):
    """A configurable security policy for SBOM compliance evaluation."""

    __tablename__ = "security_policies"
    __table_args__ = {"schema": "policy"}

    id = Column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    max_allowed_cvss = Column(Float, nullable=False)
    max_allowed_cvss_int = Column(
        Integer, nullable=False,
        comment="Integer representation for ZKP circuit (e.g. 7.5 -> 75)",
    )
    policy_hash = Column(String(128), nullable=True)
    is_active = Column(Integer, nullable=False, default=1)
    created_at = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )

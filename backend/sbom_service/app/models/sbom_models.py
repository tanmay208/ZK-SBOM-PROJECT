"""
SBOM schema models.

DATABASE_SCHEMA.md §1 — sbom schema:
  Owner: sbom_service
  Purpose: Stores private SBOM data, vendor metadata, and intermediate
           component representations required for generating the SBOM commitment.

SECURITY_BOUNDARY.md §4:
  sbom schema contains Private Data. Restricted access.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.types import Uuid
from sqlalchemy.orm import relationship

from shared.database import Base


class Application(Base):
    """A registered vendor application whose SBOMs are managed."""

    __tablename__ = "applications"
    __table_args__ = (
        UniqueConstraint(
            "name", "vendor", "user_id",
            name="uq_sbom_applications_name_vendor_user",
        ),
        CheckConstraint(
            "(is_active = true AND archived_at IS NULL) OR "
            "(is_active = false AND archived_at IS NOT NULL)",
            name="chk_sbom_applications_archival",
        ),
        {"schema": "sbom"},
    )

    id = Column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    name = Column(String(255), nullable=False)
    vendor = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_active = Column(
        Boolean, nullable=False, default=True, server_default=func.true()
    )
    archived_at = Column(
        DateTime(timezone=True), nullable=True
    )
    created_at = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )

    sbom_uploads = relationship(
        "SBOMUpload", back_populates="application", cascade="all, delete-orphan"
    )


Index(
    "ix_sbom_applications_vendor",
    Application.vendor,
)
Index(
    "ix_sbom_applications_user_id",
    Application.user_id,
)
Index(
    "ix_sbom_applications_user_active",
    Application.user_id,
    Application.is_active,
)


class SBOMUpload(Base):
    """A single SBOM upload/generation event."""

    __tablename__ = "sbom_uploads"
    __table_args__ = {"schema": "sbom"}

    id = Column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    application_id = Column(
        Uuid,
        ForeignKey("sbom.applications.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id = Column(Uuid, nullable=True)
    filename = Column(String(512), nullable=True)
    format = Column(String(50), nullable=False, default="CycloneDX")
    spec_version = Column(String(20), nullable=True)
    status = Column(
        String(20),
        nullable=False,
        default="pending",
    )
    sbom_root = Column(String(128), nullable=True)
    component_count = Column(Integer, nullable=True)
    raw_content = Column(Text, nullable=True)
    created_at = Column(
        DateTime, nullable=False, server_default=func.now()
    )

    application = relationship("Application", back_populates="sbom_uploads")
    components = relationship(
        "Component", back_populates="sbom_upload", cascade="all, delete-orphan"
    )


Index(
    "ix_sbom_uploads_application_id",
    SBOMUpload.application_id,
)
Index(
    "ix_sbom_uploads_status",
    SBOMUpload.status,
)


class Component(Base):
    """A parsed/normalised component extracted from an SBOM."""

    __tablename__ = "components"
    __table_args__ = {"schema": "sbom"}

    id = Column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    sbom_upload_id = Column(
        Uuid,
        ForeignKey("sbom.sbom_uploads.id", ondelete="CASCADE"),
        nullable=False,
    )
    name = Column(String(512), nullable=False)
    version = Column(String(128), nullable=True)
    purl = Column(String(1024), nullable=True)
    purl_canonical = Column(String(1024), nullable=True)
    component_hash = Column(String(128), nullable=True)
    position = Column(Integer, nullable=True)
    created_at = Column(
        DateTime, nullable=False, server_default=func.now()
    )

    sbom_upload = relationship("SBOMUpload", back_populates="components")


Index(
    "ix_sbom_components_sbom_upload_id",
    Component.sbom_upload_id,
)
Index(
    "ix_sbom_components_purl",
    Component.purl,
)

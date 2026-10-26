"""
Verification schema models.

DATABASE_SCHEMA.md §5 — verification schema:
  Owner: verification_service
  Purpose: Stores the history of proof verifications, public inputs,
           and issued certificates for the buyer.

SECURITY_BOUNDARY.md §3:
  verification_service operates strictly on the public side of the boundary.
  It must not have endpoints that accept or return private SBOM components.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    String,
    Text,
    func,
    ForeignKey,
    UniqueConstraint,
    Boolean,
    CheckConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.types import Uuid

from shared.database import Base


class VerificationRequest(Base):
    """A buyer-initiated proof verification request."""

    __tablename__ = "verification_requests"
    __table_args__ = (
        UniqueConstraint("user_id", "sbom_root", "vulnerability_db_root", "policy_hash", "proof_job_id", name="uq_verification_request_idempotency"),
        {"schema": "verification"}
    )

    id = Column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    sbom_root = Column(String(128), nullable=False)
    vulnerability_db_root = Column(String(128), nullable=False)
    policy_hash = Column(String(128), nullable=False)
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    proof_job_id = Column(
        Uuid,
        ForeignKey("zkp.proof_jobs.id", ondelete="CASCADE"),
        nullable=True,
    )
    result = Column(String(50), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    
    certificate = relationship("VerificationCertificate", backref="request", uselist=False, cascade="all, delete-orphan")


class VerificationCertificate(Base):
    """An issued verification certificate for a successful proof verification."""

    __tablename__ = "verification_certificates"
    __table_args__ = (
        UniqueConstraint('verification_request_id', name='uq_cert_per_request'),
        CheckConstraint(
            "(is_revoked = false AND revoked_at IS NULL AND revoked_by IS NULL) OR "
            "(is_revoked = true AND revoked_at IS NOT NULL)",
            name="chk_certificate_revocation_state",
        ),
        {"schema": "verification"}
    )

    id = Column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    verification_request_id = Column(
        Uuid,
        ForeignKey("verification.verification_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    certificate_data = Column(Text, nullable=False)
    sbom_root = Column(String(128), nullable=False)
    vulnerability_db_root = Column(String(128), nullable=False)
    policy_hash = Column(String(128), nullable=False)
    issued_at = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    is_revoked = Column(Boolean, nullable=False, default=False, server_default='0')
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(255), nullable=True)
    revoked_by = Column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    @property
    def sha256_fingerprint(self) -> str | None:
        """
        Compute lowercase hexadecimal SHA-256 fingerprint of the exact
        encoded certificate token issued and persisted.
        """
        if not self.certificate_data:
            return None
        return hashlib.sha256(self.certificate_data.encode("utf-8")).hexdigest()


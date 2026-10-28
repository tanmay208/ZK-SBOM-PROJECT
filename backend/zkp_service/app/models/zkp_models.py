"""
ZKP schema models.

DATABASE_SCHEMA.md §4 — zkp schema:
  Owner: zkp_service
  Purpose: Stores intermediate proof generation state, witness preparation
           artifacts, and generated zk-SNARK proof references.

SECURITY_BOUNDARY.md §4:
  Private witness data must not be permanently stored if not strictly
  necessary, and must be secured if it is.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    func,
    ForeignKey,
    CheckConstraint,
    UniqueConstraint,
)
from sqlalchemy.types import Uuid

from shared.database import Base


class ProofJob(Base):
    """Tracks a proof generation request and its lifecycle."""

    __tablename__ = "proof_jobs"
    __table_args__ = {"schema": "zkp"}

    id = Column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    sbom_upload_id = Column(
        Uuid,
        ForeignKey("sbom.sbom_uploads.id", ondelete="CASCADE"),
        nullable=False,
    )
    snapshot_id = Column(
        Uuid,
        ForeignKey("vulnerability.vulnerability_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    policy_id = Column(
        Uuid,
        ForeignKey("policy.security_policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id = Column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    status = Column(
        String(20), nullable=False, default="pending"
    )
    sbom_root = Column(String(128), nullable=True)
    vulnerability_db_root = Column(String(128), nullable=True)
    policy_hash = Column(String(128), nullable=True)
    proof_artifact = Column(String(5000), nullable=True)
    error_message = Column(String(1024), nullable=True)
    created_at = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    completed_at = Column(DateTime, nullable=True)
    proof_archive_hash = Column(String(128), nullable=True)

    from sqlalchemy.orm import relationship
    chunks = relationship("ChunkProofSet", backref="job", cascade="all, delete-orphan")


class ChunkProofSet(Base):
    """Tracks a 32-component chunk subset of a ProofJob."""

    __tablename__ = "chunk_proof_sets"
    __table_args__ = (
        UniqueConstraint('proof_job_id', 'chunk_index', name='uq_chunk_index_per_job'),
        CheckConstraint('chunk_index >= 0 AND chunk_index < 32', name='chk_chunk_index_bounds'),
        {"schema": "zkp"}
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    proof_job_id = Column(Uuid, ForeignKey("zkp.proof_jobs.id"), nullable=False)
    chunk_index = Column(Integer, nullable=False)
    total_chunks = Column(Integer, nullable=False)
    component_start = Column(Integer, nullable=False)
    component_count = Column(Integer, nullable=False)
    components_commit = Column(String(128), nullable=True)
    status = Column(String(20), nullable=False, default="pending")
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    from sqlalchemy.orm import relationship
    segments = relationship("SegmentProof", backref="chunk", cascade="all, delete-orphan")


class SegmentProof(Base):
    """Tracks one of the 8 32-level segments within a ChunkProofSet."""

    __tablename__ = "segment_proofs"
    __table_args__ = (
        UniqueConstraint('chunk_id', 'segment_index', name='uq_segment_index_per_chunk'),
        CheckConstraint('segment_index >= 0 AND segment_index < 8', name='chk_segment_index_bounds'),
        {"schema": "zkp"}
    )

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    chunk_id = Column(Uuid, ForeignKey("zkp.chunk_proof_sets.id"), nullable=False)
    chunk_index = Column(Integer, nullable=False)
    total_chunks = Column(Integer, nullable=False)
    segment_index = Column(Integer, nullable=False)
    
    proof_artifact = Column(String(5000), nullable=True)
    proof_artifact_hash = Column(String(128), nullable=True)
    
    components_commit = Column(String(128), nullable=True)
    hash_in_commit = Column(String(128), nullable=True)
    hash_out_commit = Column(String(128), nullable=True)
    
    global_sbom_root = Column(String(128), nullable=True)
    vulnerability_db_root = Column(String(128), nullable=True)
    policy_hash = Column(String(128), nullable=True)
    
    status = Column(String(20), nullable=False, default="pending")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)

from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest


class ZKPRepository:
    """
    Repository for managing ZKP generation jobs in the database.
    """

    def __init__(self, session: Session):
        self._session = session

    def create_job(self, request: GenerateProofRequest, user_id: UUID) -> ProofJob:
        """
        Create a new proof job in the database with status 'pending'.
        Enforces tenant isolation by verifying the SBOMUpload belongs to the user.
        """
        from sbom_service.app.models.sbom_models import SBOMUpload
        from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot
        from fastapi import HTTPException
        
        sbom = self._session.query(SBOMUpload).filter(SBOMUpload.id == request.sbom_upload_id).first()
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM not found")
        if sbom.user_id != user_id:
            raise HTTPException(status_code=403, detail="Forbidden: You do not own this SBOM")

        snapshot = self._session.query(VulnerabilitySnapshot).filter(VulnerabilitySnapshot.id == request.snapshot_id).first()
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        if snapshot.status != "approved":
            raise HTTPException(status_code=400, detail="Snapshot is not approved")

        job = ProofJob(
            sbom_upload_id=request.sbom_upload_id,
            snapshot_id=request.snapshot_id,
            policy_id=request.policy_id,
            status="pending",
            user_id=user_id,
        )
        self._session.add(job)
        self._session.commit()
        self._session.refresh(job)
        return job

    def get_job(self, job_id: UUID, user_id: UUID | None = None) -> ProofJob | None:
        """
        Retrieve a proof job by its ID, optionally scoped to its owner.

        There is no implicit public-sharing mode for proof jobs. Callers
        serving tenant-facing responses must provide ``user_id``.
        """
        query = self._session.query(ProofJob).filter(ProofJob.id == job_id)
        if user_id is not None:
            query = query.filter(ProofJob.user_id == user_id)
        return query.first()

    def update_job_status(
        self,
        job_id: UUID,
        status: str,
        sbom_root: str | None = None,
        vulnerability_db_root: str | None = None,
        policy_hash: str | None = None,
        proof_artifact: str | None = None,
        proof_archive_hash: str | None = None,
        error_message: str | None = None,
    ) -> ProofJob | None:
        """
        Update the status and artifacts of a proof job.
        If the status represents a final state (e.g., 'completed', 'execution_blocked', 'failed'),
        the completed_at timestamp is automatically set.
        """
        job = self.get_job(job_id)
        if not job:
            return None

        job.status = status

        if sbom_root is not None:
            job.sbom_root = sbom_root
        if vulnerability_db_root is not None:
            job.vulnerability_db_root = vulnerability_db_root
        if policy_hash is not None:
            job.policy_hash = policy_hash
        if proof_artifact is not None:
            job.proof_artifact = proof_artifact
        if proof_archive_hash is not None:
            job.proof_archive_hash = proof_archive_hash
        if error_message is not None:
            job.error_message = error_message

        if status in ["completed", "failed", "execution_blocked"]:
            job.completed_at = datetime.utcnow()

        self._session.commit()
        self._session.refresh(job)
        return job

    def get_job_with_chunks(self, job_id: UUID, user_id: UUID | None = None) -> ProofJob | None:
        """Retrieve a proof job with its chunks and segments eagerly loaded."""
        from sqlalchemy.orm import joinedload
        query = self._session.query(ProofJob).options(
            joinedload(ProofJob.chunks).joinedload(ChunkProofSet.segments)
        ).filter(ProofJob.id == job_id)
        if user_id is not None:
            query = query.filter(ProofJob.user_id == user_id)
        return query.first()

    def create_chunk(self, proof_job_id: UUID, chunk_index: int, total_chunks: int, component_start: int, component_count: int, components_commit: str) -> ChunkProofSet:
        chunk = ChunkProofSet(
            proof_job_id=proof_job_id,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            component_start=component_start,
            component_count=component_count,
            components_commit=components_commit,
            status="pending"
        )
        self._session.add(chunk)
        self._session.commit()
        self._session.refresh(chunk)
        return chunk

    def update_chunk_status(self, chunk_id: UUID, status: str) -> None:
        chunk = self._session.query(ChunkProofSet).filter(ChunkProofSet.id == chunk_id).first()
        if chunk:
            chunk.status = status
            self._session.commit()

    def create_segment(self, chunk_id: UUID, chunk_index: int, total_chunks: int, segment_index: int) -> SegmentProof:
        seg = SegmentProof(
            chunk_id=chunk_id,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            segment_index=segment_index,
            status="pending"
        )
        self._session.add(seg)
        self._session.commit()
        self._session.refresh(seg)
        return seg

    def update_segment_artifact(self, segment_id: UUID, status: str, proof_artifact: str, proof_artifact_hash: str, 
                                components_commit: str, hash_in_commit: str, hash_out_commit: str,
                                global_sbom_root: str | None = None, vulnerability_db_root: str | None = None,
                                policy_hash: str | None = None) -> None:
        seg = self._session.query(SegmentProof).filter(SegmentProof.id == segment_id).first()
        if seg:
            seg.status = status
            seg.proof_artifact = proof_artifact
            seg.proof_artifact_hash = proof_artifact_hash
            seg.components_commit = components_commit
            seg.hash_in_commit = hash_in_commit
            seg.hash_out_commit = hash_out_commit
            if global_sbom_root: seg.global_sbom_root = global_sbom_root
            if vulnerability_db_root: seg.vulnerability_db_root = vulnerability_db_root
            if policy_hash: seg.policy_hash = policy_hash
            
            if status in ["completed", "failed"]:
                seg.completed_at = datetime.utcnow()
            self._session.commit()

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest


ALLOWED_JOB_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"pending", "assembling_witness", "running", "failed", "execution_blocked"},
    "assembling_witness": {"assembling_witness", "running", "failed", "execution_blocked"},
    "running": {"running", "completed", "failed", "execution_blocked"},
    "completed": set(),
    "failed": set(),
    "execution_blocked": set(),
}

ALLOWED_CHUNK_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"pending", "running", "failed"},
    "running": {"running", "completed", "failed"},
    "completed": set(),
    "failed": set(),
}

ALLOWED_SEGMENT_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"pending", "running", "completed", "failed"},
    "running": {"running", "completed", "failed"},
    "completed": set(),
    "failed": set(),
}


class ZKPRepository:
    """
    Repository for managing ZKP generation jobs in the database.
    """

    def __init__(self, session: Session):
        self._session = session

    def create_job(
        self,
        request: GenerateProofRequest,
        user_id: UUID,
        job_id: UUID | None = None,
    ) -> ProofJob:
        """
        Create a new proof job in the database with status 'pending'.
        Enforces tenant isolation by verifying the SBOMUpload belongs to the user.
        """
        from sbom_service.app.models.sbom_models import SBOMUpload
        from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot
        from policy_service.app.models.policy_models import SecurityPolicy
        from fastapi import HTTPException
        
        sbom = self._session.query(SBOMUpload).filter(SBOMUpload.id == request.sbom_upload_id).first()
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM not found")
        if sbom.user_id != user_id:
            raise HTTPException(status_code=403, detail="Forbidden: You do not own this SBOM")

        snapshot = self._session.query(VulnerabilitySnapshot).filter(VulnerabilitySnapshot.id == request.snapshot_id).first()
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        if snapshot.status != "frozen":
            raise HTTPException(status_code=400, detail="Snapshot is not frozen")
        from vulnerability_service.app.core.snapshot_expiry import is_snapshot_expired
        if is_snapshot_expired(snapshot):
            raise HTTPException(status_code=400, detail="Snapshot is expired and cannot be used for proving")

        policy = self._session.query(SecurityPolicy).filter(SecurityPolicy.id == request.policy_id).first()
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        if getattr(policy, "is_active", 0) != 1:
            raise HTTPException(status_code=400, detail="Policy is not active")

        job_kwargs = {
            "sbom_upload_id": request.sbom_upload_id,
            "snapshot_id": request.snapshot_id,
            "policy_id": request.policy_id,
            "status": "pending",
            "user_id": user_id,
        }
        if job_id is not None:
            job_kwargs["id"] = job_id

        job = ProofJob(**job_kwargs)
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

    def list_jobs(
        self,
        user_id: UUID | None = None,
        all_tenants: bool = False,
        skip: int = 0,
        limit: int = 50,
    ) -> list[ProofJob]:
        """
        List proof jobs ordered by creation time descending.
        If all_tenants is False, results are strictly scoped to user_id.
        """
        query = self._session.query(ProofJob)
        if not all_tenants:
            if user_id is None:
                return []
            query = query.filter(ProofJob.user_id == user_id)
        elif user_id is not None:
            query = query.filter(ProofJob.user_id == user_id)

        return (
            query.order_by(ProofJob.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

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
        Enforces state-machine invariants:
        - Rejects transitions out of terminal states ('completed', 'failed', 'execution_blocked').
        - Rejects invalid backward transitions.
        - Fails closed with ValueError on illegal transitions.
        If the status represents a final state, completed_at timestamp is automatically set.
        """
        job = self.get_job(job_id)
        if not job:
            return None

        allowed = ALLOWED_JOB_TRANSITIONS.get(job.status, set())
        if status not in allowed:
            raise ValueError(
                f"Illegal proof job transition from '{job.status}' to '{status}' for job {job_id}"
            )

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
            job.completed_at = datetime.now(timezone.utc)

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

    def create_chunks_and_segments_batch(
        self,
        proof_job_id: UUID,
        chunks_data: list[dict],
        segments_per_chunk: int = 8,
    ) -> list[ChunkProofSet]:
        """
        Atomically create the complete chunk and segment topology for a proof job
        in a single database transaction.

        If any error occurs before commit, the entire transaction is rolled back,
        ensuring no orphaned or partial chunk/segment records remain.
        """
        created_chunks: list[ChunkProofSet] = []
        try:
            for item in chunks_data:
                chunk = ChunkProofSet(
                    proof_job_id=proof_job_id,
                    chunk_index=item["chunk_index"],
                    total_chunks=item["total_chunks"],
                    component_start=item["component_start"],
                    component_count=item["component_count"],
                    components_commit=item["components_commit"],
                    status="pending",
                )
                self._session.add(chunk)
                # Flush to assign chunk.id for foreign-key referencing segment records
                self._session.flush()

                for seg_idx in range(segments_per_chunk):
                    seg = SegmentProof(
                        chunk_id=chunk.id,
                        chunk_index=item["chunk_index"],
                        total_chunks=item["total_chunks"],
                        segment_index=seg_idx,
                        status="pending",
                    )
                    self._session.add(seg)

                created_chunks.append(chunk)

            # Flush all pending segments and commit the entire batch atomically
            self._session.flush()
            self._session.commit()

            for chunk in created_chunks:
                self._session.refresh(chunk)

            return created_chunks
        except Exception:
            self._session.rollback()
            raise

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
            allowed = ALLOWED_CHUNK_TRANSITIONS.get(chunk.status, set())
            if status not in allowed:
                raise ValueError(
                    f"Illegal chunk transition from '{chunk.status}' to '{status}' for chunk {chunk_id}"
                )
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
            allowed = ALLOWED_SEGMENT_TRANSITIONS.get(seg.status, set())
            if status not in allowed:
                raise ValueError(
                    f"Illegal segment transition from '{seg.status}' to '{status}' for segment {segment_id}"
                )
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
                seg.completed_at = datetime.now(timezone.utc)
            self._session.commit()

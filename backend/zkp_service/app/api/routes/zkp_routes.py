from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from shared.database import get_session
from shared.auth import get_current_user, require_roles
from shared.models.user import User
from zkp_service.app.models.zkp_models import ProofJob
from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest, ProofJobResponse
from zkp_service.app.repositories.zkp_repository import ZKPRepository
from zkp_service.app.services.prover_service import ProverService

router = APIRouter(prefix="/api/v1/zkp", tags=["zkp"])


@router.get("", response_model=List[ProofJobResponse])
def list_jobs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    jobs = (
        db.query(ProofJob)
        .filter(ProofJob.user_id == current_user.id)
        .order_by(ProofJob.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return jobs

@router.post("/generate", response_model=ProofJobResponse)
def generate_proof(
    request: GenerateProofRequest,
    db: Session = Depends(get_session),
    current_user: User = Depends(require_roles("vendor", "admin")),
):
    """
    Initialize a ZKP generation job based on existing authoritative snapshots.
    """
    active_jobs = (
        db.query(ProofJob)
        .filter(
            ProofJob.user_id == current_user.id,
            ProofJob.status.in_(("pending", "running")),
        )
        .count()
    )
    if active_jobs:
        raise HTTPException(
            status_code=429,
            detail="A proof job is already active for this user",
        )

    repo = ZKPRepository(db)
    job = repo.create_job(request, user_id=current_user.id)
    
    prover = ProverService(db)
    # Executing synchronously since it fails fast due to environment blocks.
    # In a production environment, this would be delegated to a task queue (e.g. Celery).
    final_job = prover.process_job(job.id, user_id=current_user.id)
    
    if final_job is None:
        return job  # Fallback
        
    return final_job


@router.get("/jobs/{job_id}", response_model=ProofJobResponse)
def get_proof_job(
    job_id: UUID,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve the status and public artifacts of a proof job.
    """
    repo = ZKPRepository(db)
    job = repo.get_job(job_id, user_id=current_user.id)
    if not job:
        raise HTTPException(status_code=404, detail="Proof job not found")
    return job

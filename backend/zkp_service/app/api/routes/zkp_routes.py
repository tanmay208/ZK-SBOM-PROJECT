from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from shared.database import get_session
from shared.auth import get_current_user, require_roles
from shared.models.user import User
from shared.security import zkp_generate_rate_limiter
from zkp_service.app.core.job_lock import (
    WorkerJobLock,
    get_job_lock_manager,
    job_lock_key,
    reconcile_abandoned_job,
)
from zkp_service.app.models.zkp_models import ProofJob
from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest, ProofJobResponse
from zkp_service.app.repositories.zkp_repository import ZKPRepository
from zkp_service.app.services.prover_service import ProverService

router = APIRouter(prefix="/api/v1/zkp", tags=["zkp"])


@router.get("", response_model=List[ProofJobResponse])
def list_jobs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    all_tenants: bool = Query(default=False, description="Admin-only: list proof jobs across all tenants"),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if all_tenants and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators may list proof jobs across all tenants",
        )

    if getattr(current_user, "is_active", None) is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    repo = ZKPRepository(db)
    if all_tenants and current_user.role == "admin":
        return repo.list_jobs(user_id=None, all_tenants=True, skip=skip, limit=limit)
    return repo.list_jobs(user_id=current_user.id, all_tenants=False, skip=skip, limit=limit)


@router.post("/generate", response_model=ProofJobResponse, status_code=202)
def generate_proof(
    request: GenerateProofRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    db: Session = Depends(get_session),
    current_user: User = Depends(require_roles("vendor")),
):
    """
    Initialize a ZKP generation job based on existing authoritative snapshots.
    """
    zkp_generate_rate_limiter.check(http_request, user_id=str(current_user.id))
    engine = db.get_bind()
    mgr = get_job_lock_manager(engine)

    # Concurrency control: serialize job creation per user within transaction boundary
    bind = getattr(db, "bind", None) or engine
    if bind and getattr(getattr(bind, "dialect", None), "name", "") == "postgresql":
        user_key = job_lock_key(current_user.id)
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": user_key})

    # Check for existing active jobs belonging to this user
    active_jobs = (
        db.query(ProofJob)
        .filter(
            ProofJob.user_id == current_user.id,
            ProofJob.status.in_(("pending", "assembling_witness", "running")),
        )
        .all()
    )
    for active_job in active_jobs:
        reconciled = reconcile_abandoned_job(db, active_job)
        if not reconciled:
            # Active job holds worker lock (or is currently being recovered): reject duplicate
            raise HTTPException(
                status_code=429,
                detail="A proof job is already active for this user",
            )

    import uuid
    new_job_id = uuid.uuid4()
    worker_lock = mgr.acquire_worker_lock(new_job_id)

    repo = ZKPRepository(db)
    try:
        job = repo.create_job(request, user_id=current_user.id, job_id=new_job_id)
    except Exception:
        worker_lock.release()
        raise
    
    def background_prover(job_id: UUID, user_id: UUID, w_lock: WorkerJobLock):
        db_gen = get_session()
        bg_db = next(db_gen)
        try:
            prover = ProverService(bg_db)
            prover.process_job(job_id, user_id=user_id)
        except BaseException as e:
            # Catch all exceptions including CancelledError (though rare in background tasks)
            # Ensure the job is marked as failed.
            bg_repo = ZKPRepository(bg_db)
            bg_repo.update_job_status(job_id, "failed", error_message="Proof generation orchestration failed unexpectedly")
        finally:
            try:
                w_lock.release()
            except Exception:
                pass
            finally:
                try:
                    next(db_gen)
                except StopIteration:
                    pass
    
    background_tasks.add_task(background_prover, job.id, current_user.id, worker_lock)
    
    return job


@router.get("/jobs/{job_id}", response_model=ProofJobResponse)
def get_proof_job(
    job_id: UUID,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve the status and public artifacts of a proof job.
    - Admin: can inspect any proof job across tenants for administrative oversight.
    - Vendor: strictly limited to owned proof jobs (anti-enumeration via 404).
    - Buyer / other roles: strictly forbidden from proof job objects (HTTP 403).
    """
    if getattr(current_user, "is_active", None) is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    if current_user.role not in ("vendor", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role not authorized to access proof job records",
        )

    repo = ZKPRepository(db)
    effective_user_id = None if current_user.role == "admin" else current_user.id
    job = repo.get_job(job_id, user_id=effective_user_id)
    if not job:
        raise HTTPException(status_code=404, detail="Proof job not found")

    # On-demand abandoned job recovery:
    # If the caller-owned job is in an active state ('pending', 'assembling_witness', 'running'),
    # safely probe and reconcile it if its worker was abandoned.
    # Unconditionally refresh to guarantee that the returned state reflects the latest committed
    # database state (even if another concurrent poller performed the reconciliation).
    if job.status in ("pending", "assembling_witness", "running"):
        reconcile_abandoned_job(db, job)
        db.refresh(job)

    return job

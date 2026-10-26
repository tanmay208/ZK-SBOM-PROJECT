from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from shared.database import get_session
from shared.auth import get_current_user
from shared.models.user import User
from sbom_service.app.models.sbom_models import SBOMUpload
from verification_service.app.models.verification_models import VerificationRequest, VerificationCertificate
from zkp_service.app.models.zkp_models import ProofJob

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])


@router.get("", summary="Get dashboard metrics")
@router.get("/", summary="Get dashboard metrics (with slash)", include_in_schema=False)
def get_dashboard_metrics(
    all_tenants: bool = Query(default=False, description="Admin-only: aggregate counts across all tenants"),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Return high-level aggregate counts for dashboard metrics.
    Privacy Guarantee:
      Returns ONLY scalar aggregate counts.
      Does NOT expose private SBOM components, vulnerability scores, Merkle paths, or witness data.
    """
    if all_tenants and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators may query metrics across all tenants",
        )

    is_global = all_tenants and current_user.role == "admin"

    sbom_query = db.query(func.count(SBOMUpload.id))
    job_query = db.query(func.count(ProofJob.id))
    verification_query = db.query(func.count(VerificationRequest.id))
    cert_query = db.query(func.count(VerificationCertificate.id)).join(
        VerificationRequest,
        VerificationRequest.id == VerificationCertificate.verification_request_id,
    )

    if not is_global:
        sbom_query = sbom_query.filter(SBOMUpload.user_id == current_user.id)
        job_query = job_query.filter(ProofJob.user_id == current_user.id)
        verification_query = verification_query.filter(VerificationRequest.user_id == current_user.id)
        cert_query = cert_query.filter(VerificationRequest.user_id == current_user.id)

    total_sboms = sbom_query.scalar() or 0
    total_jobs = job_query.scalar() or 0
    total_verifications = verification_query.scalar() or 0
    total_certificates = cert_query.scalar() or 0
    
    return {
        "total_sboms": total_sboms,
        "total_jobs": total_jobs,
        "total_certificates": total_certificates,
        "total_verifications": total_verifications,
    }

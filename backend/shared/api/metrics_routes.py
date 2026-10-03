from fastapi import APIRouter, Depends
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
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Return high-level aggregate counts for dashboard metrics.
    Privacy Guarantee:
      Returns ONLY scalar aggregate counts.
      Does NOT expose private SBOM components, vulnerability scores, Merkle paths, or witness data.
    """
    total_sboms = (
        db.query(func.count(SBOMUpload.id))
        .filter(SBOMUpload.user_id == current_user.id)
        .scalar()
        or 0
    )
    total_jobs = (
        db.query(func.count(ProofJob.id))
        .filter(ProofJob.user_id == current_user.id)
        .scalar()
        or 0
    )
    total_verifications = (
        db.query(func.count(VerificationRequest.id))
        .filter(VerificationRequest.user_id == current_user.id)
        .scalar()
        or 0
    )
    total_certificates = (
        db.query(func.count(VerificationCertificate.id))
        .join(
            VerificationRequest,
            VerificationRequest.id == VerificationCertificate.verification_request_id,
        )
        .filter(VerificationRequest.user_id == current_user.id)
        .scalar()
        or 0
    )
    
    return {
        "total_sboms": total_sboms,
        "total_jobs": total_jobs,
        "total_certificates": total_certificates,
        "total_verifications": total_verifications,
    }

from datetime import datetime, timezone
from typing import Dict, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from shared.database import get_session
from shared.auth import get_current_user, require_roles
from shared.models.user import User
from sbom_service.app.models.sbom_models import Application, SBOMUpload
from verification_service.app.models.verification_models import VerificationRequest, VerificationCertificate
from zkp_service.app.models.zkp_models import ProofJob
from policy_service.app.models.policy_models import SecurityPolicy
from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])
admin_metrics_router = APIRouter(prefix="/api/v1/admin/metrics", tags=["admin_metrics"])


class GovernanceUserBreakdown(BaseModel):
    total: int
    by_role: Dict[str, int]
    by_status: Dict[str, int]


class GovernanceApplications(BaseModel):
    total: int
    active: int
    archived: int


class GovernanceSBOMs(BaseModel):
    total: int
    committed: int
    by_status: Dict[str, int]


class GovernanceProofJobs(BaseModel):
    total: int
    completed: int
    running: int
    pending: int
    failed: int
    by_status: Dict[str, int]


class GovernanceVerifications(BaseModel):
    total: int
    verified: int
    unavailable: int
    by_result: Dict[str, int]


class GovernanceCertificates(BaseModel):
    total: int
    active: int
    revoked: int


class GovernancePolicies(BaseModel):
    total: int
    active: int
    inactive: int


class GovernanceVulnerabilities(BaseModel):
    total_snapshots: int
    frozen: int
    by_status: Dict[str, int]
    latest_snapshot_root: Optional[str] = None
    latest_snapshot_created_at: Optional[str] = None


class AdminGovernanceMetricsResponse(BaseModel):
    timestamp: str
    users: GovernanceUserBreakdown
    applications: GovernanceApplications
    sboms: GovernanceSBOMs
    proof_jobs: GovernanceProofJobs
    verifications: GovernanceVerifications
    certificates: GovernanceCertificates
    policies: GovernancePolicies
    vulnerabilities: GovernanceVulnerabilities


def compute_governance_metrics(db: Session) -> AdminGovernanceMetricsResponse:
    # 1. Users
    user_roles = dict(db.query(User.role, func.count(User.id)).group_by(User.role).all())
    user_statuses = {
        ("active" if status else "deactivated"): count
        for status, count in db.query(User.is_active, func.count(User.id)).group_by(User.is_active).all()
    }
    total_users = sum(user_roles.values())

    # 2. Applications
    app_statuses = {
        ("active" if is_act else "archived"): count
        for is_act, count in db.query(Application.is_active, func.count(Application.id)).group_by(Application.is_active).all()
    }
    total_apps = sum(app_statuses.values())

    # 3. SBOMs
    sbom_statuses = dict(db.query(SBOMUpload.status, func.count(SBOMUpload.id)).group_by(SBOMUpload.status).all())
    total_sboms = sum(sbom_statuses.values())
    committed_sboms = sbom_statuses.get("committed", 0)

    # 4. Proof Jobs
    job_statuses = dict(db.query(ProofJob.status, func.count(ProofJob.id)).group_by(ProofJob.status).all())
    total_jobs = sum(job_statuses.values())

    # 5. Verifications
    verif_results = dict(db.query(VerificationRequest.result, func.count(VerificationRequest.id)).group_by(VerificationRequest.result).all())
    total_verifs = sum(verif_results.values())
    verified_verifs = verif_results.get("verified", 0) + verif_results.get("VALID", 0)
    unavailable_verifs = verif_results.get("verification_unavailable", 0) + verif_results.get("unavailable", 0)

    # 6. Certificates
    cert_statuses = {
        ("revoked" if is_rev else "active"): count
        for is_rev, count in db.query(VerificationCertificate.is_revoked, func.count(VerificationCertificate.id)).group_by(VerificationCertificate.is_revoked).all()
    }
    total_certs = sum(cert_statuses.values())

    # 7. Policies
    policy_statuses = {
        ("active" if is_act == 1 else "inactive"): count
        for is_act, count in db.query(SecurityPolicy.is_active, func.count(SecurityPolicy.id)).group_by(SecurityPolicy.is_active).all()
    }
    total_policies = sum(policy_statuses.values())

    # 8. Vulnerabilities
    vuln_statuses = dict(db.query(VulnerabilitySnapshot.status, func.count(VulnerabilitySnapshot.id)).group_by(VulnerabilitySnapshot.status).all())
    total_snapshots = sum(vuln_statuses.values())
    latest_frozen = db.query(VulnerabilitySnapshot).filter(VulnerabilitySnapshot.status == "frozen").order_by(VulnerabilitySnapshot.created_at.desc()).first()

    now_iso = datetime.now(timezone.utc).isoformat()

    return AdminGovernanceMetricsResponse(
        timestamp=now_iso,
        users=GovernanceUserBreakdown(
            total=total_users,
            by_role=user_roles,
            by_status=user_statuses,
        ),
        applications=GovernanceApplications(
            total=total_apps,
            active=app_statuses.get("active", 0),
            archived=app_statuses.get("archived", 0),
        ),
        sboms=GovernanceSBOMs(
            total=total_sboms,
            committed=committed_sboms,
            by_status=sbom_statuses,
        ),
        proof_jobs=GovernanceProofJobs(
            total=total_jobs,
            completed=job_statuses.get("completed", 0),
            running=job_statuses.get("running", 0),
            pending=job_statuses.get("pending", 0),
            failed=job_statuses.get("failed", 0),
            by_status=job_statuses,
        ),
        verifications=GovernanceVerifications(
            total=total_verifs,
            verified=verified_verifs,
            unavailable=unavailable_verifs,
            by_result=verif_results,
        ),
        certificates=GovernanceCertificates(
            total=total_certs,
            active=cert_statuses.get("active", 0),
            revoked=cert_statuses.get("revoked", 0),
        ),
        policies=GovernancePolicies(
            total=total_policies,
            active=policy_statuses.get("active", 0),
            inactive=policy_statuses.get("inactive", 0),
        ),
        vulnerabilities=GovernanceVulnerabilities(
            total_snapshots=total_snapshots,
            frozen=vuln_statuses.get("frozen", 0),
            by_status=vuln_statuses,
            latest_snapshot_root=latest_frozen.authoritative_smt_root if latest_frozen else None,
            latest_snapshot_created_at=str(latest_frozen.created_at) if latest_frozen else None,
        ),
    )


@router.get("", summary="Get dashboard metrics")
@router.get("/", summary="Get dashboard metrics (with slash)", include_in_schema=False)
def get_dashboard_metrics(
    all_tenants: Optional[bool] = Query(default=None, description="Admin-only: aggregate counts across all tenants"),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Return high-level aggregate counts for dashboard metrics.
    Admin caller automatically defaults to platform-wide aggregates unless specified.
    Vendors and Buyers are strictly scoped to their own records.
    """
    if all_tenants is True and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators may query metrics across all tenants",
        )

    # Admin defaults to global platform metrics
    is_global = (current_user.role == "admin") if all_tenants is None else (all_tenants and current_user.role == "admin")

    sbom_query = db.query(func.count(SBOMUpload.id))
    job_query = db.query(func.count(ProofJob.id))
    verification_query = db.query(func.count(VerificationRequest.id))
    cert_query = db.query(func.count(VerificationCertificate.id)).join(
        VerificationRequest,
        VerificationRequest.id == VerificationCertificate.verification_request_id,
    )
    app_query = db.query(func.count(Application.id))

    if not is_global:
        sbom_query = sbom_query.filter(SBOMUpload.user_id == current_user.id)
        job_query = job_query.filter(ProofJob.user_id == current_user.id)
        verification_query = verification_query.filter(VerificationRequest.user_id == current_user.id)
        cert_query = cert_query.filter(VerificationRequest.user_id == current_user.id)
        app_query = app_query.filter(Application.user_id == current_user.id)

    total_sboms = sbom_query.scalar() or 0
    total_jobs = job_query.scalar() or 0
    total_verifications = verification_query.scalar() or 0
    total_certificates = cert_query.scalar() or 0
    total_applications = app_query.scalar() or 0

    return {
        "total_sboms": total_sboms,
        "total_jobs": total_jobs,
        "total_certificates": total_certificates,
        "total_verifications": total_verifications,
        "total_applications": total_applications,
        "sbom_count": total_sboms,
        "proof_count": total_jobs,
        "verification_count": total_verifications,
        "certificate_count": total_certificates,
        "application_count": total_applications,
    }


@router.get("/governance", response_model=AdminGovernanceMetricsResponse, summary="Get platform-wide admin governance metrics")
@router.get("/admin", response_model=AdminGovernanceMetricsResponse, summary="Get platform-wide admin governance metrics (alias)", include_in_schema=False)
def get_metrics_governance(
    db: Session = Depends(get_session),
    current_admin: User = Depends(require_roles("admin")),
):
    """
    Return comprehensive database-backed platform governance metrics across all 8 required domains.
    Strictly restricted to administrators.
    """
    return compute_governance_metrics(db)


@admin_metrics_router.get("", response_model=AdminGovernanceMetricsResponse, summary="Get platform-wide admin governance metrics")
def get_admin_metrics(
    db: Session = Depends(get_session),
    current_admin: User = Depends(require_roles("admin")),
):
    """
    Return comprehensive database-backed platform governance metrics across all 8 required domains.
    Strictly restricted to administrators.
    """
    return compute_governance_metrics(db)

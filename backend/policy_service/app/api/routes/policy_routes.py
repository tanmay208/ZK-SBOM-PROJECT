from uuid import UUID
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from shared.database import get_session
from shared.auth import get_current_user, require_roles
from shared.models.user import User
from policy_service.app.models.policy_models import SecurityPolicy
from policy_service.app.schemas.policy_schemas import PolicyCreateRequest, PolicyResponse
from policy_service.app.services.policy_service import create_policy, activate_policy

router = APIRouter(prefix="/api/v1/policy", tags=["policy"])


@router.get("", response_model=List[PolicyResponse])
def list_policies(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    policies = (
        db.query(SecurityPolicy)
        .order_by(SecurityPolicy.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [PolicyResponse.from_model(p) for p in policies]


@router.get("/{policy_id}", response_model=PolicyResponse)
def get_policy(
    policy_id: UUID,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve security policy details by ID.

    Architecture & RBAC Boundary:
      - Security policies are authoritative, system-wide evaluation rules
        (e.g., maximum allowable CVSS threshold) managed exclusively by the
        'admin' role (SERVICE_CONTRACTS.md §3, SECURITY_RULES.md §3).
      - Policies are transparent/shared reference objects; they have no
        vendor/tenant ownership (no user_id column in database schema).
      - Any authenticated user (vendor, auditor, admin) may inspect policies
        to verify the compliance baseline used in ZKP proof generation.
      - Returns HTTP 404 if the policy does not exist.
      - Returns HTTP 401 if unauthenticated.
    """
    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return PolicyResponse.from_model(policy)




@router.post("", response_model=PolicyResponse)
def add_policy(
    request: PolicyCreateRequest,
    db: Session = Depends(get_session),
    current_user: User = Depends(require_roles("admin")),
):
    policy = create_policy(
        db,
        max_cvss_score=request.max_cvss_score,
        name=request.name or "CVSS Security Policy",
        description=request.description,
    )
    return PolicyResponse.from_model(policy)


@router.post("/{policy_id}/activate", response_model=PolicyResponse)
def activate_policy_route(
    policy_id: UUID,
    db: Session = Depends(get_session),
    current_user: User = Depends(require_roles("admin")),
):
    """
    Explicitly activate an existing security policy.

    Architecture & RBAC Boundary:
      - Admin-only endpoint. Requires authenticated active administrator.
      - Enforces the single-active-policy invariant by deactivating any other
        active policies within the same transaction.
      - Safe and idempotent on repeated activations.
      - Returns non-disclosing HTTP 404 if the policy does not exist.
    """
    policy = activate_policy(db, policy_id=policy_id)
    return PolicyResponse.from_model(policy)


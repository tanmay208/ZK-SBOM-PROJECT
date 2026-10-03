from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from shared.database import get_session
from shared.auth import get_current_user, require_roles
from shared.models.user import User
from policy_service.app.models.policy_models import SecurityPolicy
from policy_service.app.schemas.policy_schemas import PolicyCreateRequest, PolicyResponse
from policy_service.app.services.policy_service import create_policy

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

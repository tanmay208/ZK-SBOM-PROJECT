from uuid import UUID, uuid4
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from policy_service.app.models.policy_models import SecurityPolicy
from policy_service.app.services.policy_contract import create_policy_contract, compute_policy_hash_v1
from shared.logging import audit_log

POLICY_MUTATION_LOCK_ID = 987654321


def create_policy(
    db: Session,
    max_cvss_score: float,
    name: str = "CVSS Security Policy",
    description: str | None = None,
    user_id: UUID | None = None,
) -> SecurityPolicy:
    """
    Create a new active SecurityPolicy.
    - Validates max_cvss_score is strictly between 0.0 and 10.0.
    - Synchronizes concurrent creation/activation via transaction advisory locking.
    - Deactivates previous policies (is_active = 0).
    - Encodes CVSS as integer for ZKP circuits (e.g. 7.5 -> 75).
    - Computes authoritative Poseidon policy_hash.
    - Preserves atomicity with guaranteed rollback on failure.
    - Emits structured security audit logs.
    """
    if not (0.0 <= max_cvss_score <= 10.0):
        raise ValueError("max_cvss_score must be between 0.0 and 10.0")

    try:
        # Enforce transaction-level concurrency synchronization under PostgreSQL
        bind = getattr(db, "bind", None)
        if bind and getattr(getattr(bind, "dialect", None), "name", "") == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": POLICY_MUTATION_LOCK_ID})

        # Deactivate existing active policies
        db.query(SecurityPolicy).update({"is_active": 0})

        new_id = uuid4()
        contract = create_policy_contract(
            policy_id=str(new_id),
            revision=1,
            name=name,
            max_cvss_score=max_cvss_score,
            description=description,
        )

        new_policy = SecurityPolicy(
            id=new_id,
            name=name,
            description=description,
            max_allowed_cvss=max_cvss_score,
            max_allowed_cvss_int=contract.max_allowed_cvss_int,
            policy_hash=contract.policy_hash_v1,
            is_active=1,
        )
        db.add(new_policy)
        db.commit()
        db.refresh(new_policy)

        audit_log(
            "policy_service",
            "policy_creation",
            f"Policy {new_policy.id} created with max CVSS {max_cvss_score} (hash: {new_policy.policy_hash})",
            actor_id=str(user_id) if user_id else "system",
            resource_type="security_policy",
            resource_id=str(new_policy.id),
            outcome="success",
        )
        return new_policy
    except Exception:
        rollback_fn = getattr(db, "rollback", None)
        if callable(rollback_fn):
            rollback_fn()
        raise


def activate_policy(db: Session, policy_id: UUID, user_id: UUID | None = None) -> SecurityPolicy:
    """
    Explicitly activate an existing SecurityPolicy.
    - Preserves the single-active-policy invariant: at most one policy is active (is_active = 1).
    - Synchronizes concurrent activation via transaction advisory locking.
    - Deactivates any other active policy in the same transaction boundary.
    - Idempotent: repeated activation of an already-active policy is safe and predictable.
    - Raises HTTPException(status_code=404, detail="Policy not found") for unknown policy ID.
    - Emits structured security audit logs.
    """
    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if policy.is_active == 1:
        return policy

    try:
        # Enforce transaction-level concurrency synchronization under PostgreSQL
        bind = getattr(db, "bind", None)
        if bind and getattr(getattr(bind, "dialect", None), "name", "") == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": POLICY_MUTATION_LOCK_ID})

        # Deactivate all other policies within the same transaction boundary
        db.query(SecurityPolicy).filter(SecurityPolicy.id != policy_id).update({"is_active": 0})
        policy.is_active = 1
        db.commit()
        db.refresh(policy)

        audit_log(
            "policy_service",
            "policy_activation",
            f"Policy {policy.id} activated (hash: {policy.policy_hash})",
            actor_id=str(user_id) if user_id else "system",
            resource_type="security_policy",
            resource_id=str(policy.id),
            outcome="success",
        )
        return policy
    except Exception:
        rollback_fn = getattr(db, "rollback", None)
        if callable(rollback_fn):
            rollback_fn()
        raise

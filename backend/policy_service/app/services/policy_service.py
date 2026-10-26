from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from policy_service.app.models.policy_models import SecurityPolicy
from shared.crypto.poseidon_bn254 import poseidon_hash

POLICY_MUTATION_LOCK_ID = 987654321


def create_policy(
    db: Session,
    max_cvss_score: float,
    name: str = "CVSS Security Policy",
    description: str | None = None,
) -> SecurityPolicy:
    """
    Create a new active SecurityPolicy.
    - Validates max_cvss_score is strictly between 0.0 and 10.0.
    - Synchronizes concurrent creation/activation via transaction advisory locking.
    - Deactivates previous policies (is_active = 0).
    - Encodes CVSS as integer for ZKP circuits (e.g. 7.5 -> 75).
    - Computes authoritative Poseidon policy_hash.
    - Preserves atomicity with guaranteed rollback on failure.
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

        cvss_int = int(round(max_cvss_score * 10))
        pol_hash = f"0x{poseidon_hash([cvss_int]):064x}"

        new_policy = SecurityPolicy(
            name=name,
            description=description,
            max_allowed_cvss=max_cvss_score,
            max_allowed_cvss_int=cvss_int,
            policy_hash=pol_hash,
            is_active=1,
        )
        db.add(new_policy)
        db.commit()
        db.refresh(new_policy)
        return new_policy
    except Exception:
        rollback_fn = getattr(db, "rollback", None)
        if callable(rollback_fn):
            rollback_fn()
        raise


def activate_policy(db: Session, policy_id: UUID) -> SecurityPolicy:
    """
    Explicitly activate an existing SecurityPolicy.
    - Preserves the single-active-policy invariant: at most one policy is active (is_active = 1).
    - Synchronizes concurrent activation via transaction advisory locking.
    - Deactivates any other active policy in the same transaction boundary.
    - Idempotent: repeated activation of an already-active policy is safe and predictable.
    - Raises HTTPException(status_code=404, detail="Policy not found") for unknown policy ID.
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
        return policy
    except Exception:
        rollback_fn = getattr(db, "rollback", None)
        if callable(rollback_fn):
            rollback_fn()
        raise


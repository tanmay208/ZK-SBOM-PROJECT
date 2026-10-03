from sqlalchemy.orm import Session

from policy_service.app.models.policy_models import SecurityPolicy
from shared.crypto.poseidon_bn254 import poseidon_hash


def create_policy(
    db: Session,
    max_cvss_score: float,
    name: str = "CVSS Security Policy",
    description: str | None = None,
) -> SecurityPolicy:
    """
    Create a new active SecurityPolicy.
    - Validates max_cvss_score is strictly between 0.0 and 10.0.
    - Deactivates previous policies (is_active = 0).
    - Encodes CVSS as integer for ZKP circuits (e.g. 7.5 -> 75).
    - Computes authoritative Poseidon policy_hash.
    """
    if not (0.0 <= max_cvss_score <= 10.0):
        raise ValueError("max_cvss_score must be between 0.0 and 10.0")

    # Deactivate existing active policies
    db.query(SecurityPolicy).update({"is_active": 0})

    cvss_int = int(round(max_cvss_score * 10))
    pol_hash = hex(poseidon_hash([cvss_int]))

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

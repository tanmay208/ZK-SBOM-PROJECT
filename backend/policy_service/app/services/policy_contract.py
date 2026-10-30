"""
Formal Security Policy Contract and Cryptographic Identity Engine.

Establishes deterministic, versioned, and domain-separated policy semantics
and commitments. Binds policy revision, CVSS thresholds, supported scoring
versions, coverage requirements, and fail-closed evaluation rules.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from shared.crypto.poseidon_bn254 import poseidon_hash
from vulnerability_service.app.services.snapshot_validator import AssessmentSummary

logger = logging.getLogger(__name__)

# Domain separation constant for Policy Digest V2
POLICY_V2_DOMAIN_SEPARATOR = 0x504F4C4943595F5632  # "POLICY_V2" in ASCII hex


class PolicyEvaluationVerdict(str, Enum):
    PASS = "compliant"
    FAIL_CVSS_THRESHOLD = "cvss_threshold_exceeded"
    FAIL_UNKNOWN_SEVERITY = "blocked_unknown_severity"
    FAIL_UNSCANNABLE = "blocked_unscannable_components"
    FAIL_INSUFFICIENT_COVERAGE = "blocked_insufficient_coverage"
    FAIL_EXPIRED_SNAPSHOT = "blocked_expired_snapshot"
    FAIL_POLICY_INACTIVE = "blocked_policy_inactive"


@dataclass(frozen=True)
class PolicyContract:
    """Formal, immutable security policy specification."""
    policy_id: str
    revision: int
    name: str
    max_allowed_cvss: float
    max_allowed_cvss_int: int
    min_coverage_pct: int = 100
    allow_unscored: bool = False
    allow_unscannable: bool = False
    supported_cvss_versions: Tuple[str, ...] = ("3.1", "4.0")
    permitted_ecosystems: Tuple[str, ...] = ("npm", "pypi")
    description: Optional[str] = None
    created_at: Optional[str] = None
    policy_hash_v1: str = ""
    policy_digest_v2: str = ""
    canonical_spec_hash: str = ""


def compute_policy_hash_v1(max_cvss_int: int) -> str:
    """
    Authoritative circuit-compatible Poseidon policy hash (Noir 0.32.0).
    Computes Poseidon_1([max_cvss_int as Field]).
    """
    if not (0 <= max_cvss_int <= 100):
        raise ValueError(f"max_cvss_int must be in [0, 100], got {max_cvss_int}")
    h = poseidon_hash([max_cvss_int])
    return f"0x{h:064x}"


def compute_ecosystem_mask(ecosystems: Tuple[str, ...]) -> int:
    """Computes a deterministic bitmask for permitted ecosystems."""
    mask = 0
    eco_map = {"npm": 1, "pypi": 2, "maven": 4, "golang": 8, "cargo": 16}
    for e in ecosystems:
        mask |= eco_map.get(e.strip().lower(), 0)
    return mask


def compute_policy_digest_v2(
    max_cvss_int: int,
    revision: int,
    min_coverage_pct: int = 100,
    allow_unscored: bool = False,
    ecosystem_mask: int = 3,
) -> str:
    """
    Computes domain-separated multi-attribute Policy Digest V2 using Poseidon Sponge.
    Inputs: [DOMAIN, max_cvss_int, revision, min_coverage_pct, allow_unscored, ecosystem_mask]
    """
    unscored_flag = 1 if allow_unscored else 0
    elements = [
        POLICY_V2_DOMAIN_SEPARATOR,
        max_cvss_int,
        revision,
        min_coverage_pct,
        unscored_flag,
        ecosystem_mask,
    ]
    # In BN254 Poseidon sponge:
    current = elements[0]
    for el in elements[1:]:
        current = poseidon_hash([current, el])
    return f"0x{current:064x}"


def build_canonical_policy_spec_json(
    policy_id: str,
    revision: int,
    name: str,
    max_allowed_cvss: float,
    min_coverage_pct: int = 100,
    allow_unscored: bool = False,
    allow_unscannable: bool = False,
    supported_cvss_versions: Tuple[str, ...] = ("3.1", "4.0"),
    permitted_ecosystems: Tuple[str, ...] = ("npm", "pypi"),
    description: Optional[str] = None,
) -> str:
    """Builds deterministic, sorted canonical JSON of the policy specification."""
    obj = {
        "allow_unscannable": allow_unscannable,
        "allow_unscored": allow_unscored,
        "description": description or "",
        "max_allowed_cvss": round(max_allowed_cvss, 1),
        "min_coverage_pct": min_coverage_pct,
        "name": name.strip(),
        "permitted_ecosystems": sorted(permitted_ecosystems),
        "policy_id": str(policy_id),
        "revision": revision,
        "supported_cvss_versions": sorted(supported_cvss_versions),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_policy_spec_hash(canonical_json: str) -> str:
    """Computes SHA-256 over canonical policy JSON."""
    return f"0x{hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()}"


def create_policy_contract(
    policy_id: str,
    revision: int,
    name: str,
    max_cvss_score: float,
    description: Optional[str] = None,
    min_coverage_pct: int = 100,
    allow_unscored: bool = False,
    allow_unscannable: bool = False,
    supported_cvss_versions: Tuple[str, ...] = ("3.1", "4.0"),
    permitted_ecosystems: Tuple[str, ...] = ("npm", "pypi"),
    created_at: Optional[str] = None,
) -> PolicyContract:
    """Factory function producing an authoritative, validated PolicyContract."""
    if not (0.0 <= max_cvss_score <= 10.0):
        raise ValueError(f"max_cvss_score must be between 0.0 and 10.0, got {max_cvss_score}")

    cvss_int = int(round(max_cvss_score * 10))
    hash_v1 = compute_policy_hash_v1(cvss_int)
    eco_mask = compute_ecosystem_mask(permitted_ecosystems)
    digest_v2 = compute_policy_digest_v2(
        max_cvss_int=cvss_int,
        revision=revision,
        min_coverage_pct=min_coverage_pct,
        allow_unscored=allow_unscored,
        ecosystem_mask=eco_mask,
    )
    canon_json = build_canonical_policy_spec_json(
        policy_id=policy_id,
        revision=revision,
        name=name,
        max_allowed_cvss=max_cvss_score,
        min_coverage_pct=min_coverage_pct,
        allow_unscored=allow_unscored,
        allow_unscannable=allow_unscannable,
        supported_cvss_versions=supported_cvss_versions,
        permitted_ecosystems=permitted_ecosystems,
        description=description,
    )
    spec_hash = compute_policy_spec_hash(canon_json)

    return PolicyContract(
        policy_id=str(policy_id),
        revision=revision,
        name=name,
        max_allowed_cvss=max_cvss_score,
        max_allowed_cvss_int=cvss_int,
        min_coverage_pct=min_coverage_pct,
        allow_unscored=allow_unscored,
        allow_unscannable=allow_unscannable,
        supported_cvss_versions=supported_cvss_versions,
        permitted_ecosystems=permitted_ecosystems,
        description=description,
        created_at=created_at or datetime.now(timezone.utc).isoformat(),
        policy_hash_v1=hash_v1,
        policy_digest_v2=digest_v2,
        canonical_spec_hash=spec_hash,
    )


@dataclass(frozen=True)
class PolicyEvaluationResult:
    """Detailed evaluation outcome of an SBOM assessment against a policy contract."""
    verdict: PolicyEvaluationVerdict
    is_compliant: bool
    policy_id: str
    policy_revision: int
    policy_hash: str
    max_detected_cvss: Optional[float]
    allowed_cvss_threshold: float
    reasons: Tuple[str, ...] = field(default_factory=tuple)


class PolicyEvaluationEngine:
    """Evaluates SBOM assessment summaries against a formal policy contract."""

    @staticmethod
    def evaluate(
        assessment: AssessmentSummary,
        contract: PolicyContract,
        is_policy_active: bool = True,
    ) -> PolicyEvaluationResult:
        """Evaluate an AssessmentSummary against a formal PolicyContract."""
        reasons: List[str] = []

        if not is_policy_active:
            return PolicyEvaluationResult(
                verdict=PolicyEvaluationVerdict.FAIL_POLICY_INACTIVE,
                is_compliant=False,
                policy_id=contract.policy_id,
                policy_revision=contract.revision,
                policy_hash=contract.policy_hash_v1,
                max_detected_cvss=assessment.max_applicable_cvss,
                allowed_cvss_threshold=contract.max_allowed_cvss,
                reasons=("Security policy is not active for authoritative compliance evaluation",),
            )

        # 1. Snapshot suitability and ecosystem coverage
        if not assessment.is_snapshot_sufficient:
            return PolicyEvaluationResult(
                verdict=PolicyEvaluationVerdict.FAIL_INSUFFICIENT_COVERAGE,
                is_compliant=False,
                policy_id=contract.policy_id,
                policy_revision=contract.revision,
                policy_hash=contract.policy_hash_v1,
                max_detected_cvss=assessment.max_applicable_cvss,
                allowed_cvss_threshold=contract.max_allowed_cvss,
                reasons=assessment.limitations_and_blockers,
            )

        # 2. Unscannable components check
        if assessment.components_unscannable > 0 and not contract.allow_unscannable:
            return PolicyEvaluationResult(
                verdict=PolicyEvaluationVerdict.FAIL_UNSCANNABLE,
                is_compliant=False,
                policy_id=contract.policy_id,
                policy_revision=contract.revision,
                policy_hash=contract.policy_hash_v1,
                max_detected_cvss=assessment.max_applicable_cvss,
                allowed_cvss_threshold=contract.max_allowed_cvss,
                reasons=(f"SBOM contains {assessment.components_unscannable} unscannable or invalid components",),
            )

        # 3. Unknown severity check
        if assessment.components_unknown_severity > 0 and not contract.allow_unscored:
            return PolicyEvaluationResult(
                verdict=PolicyEvaluationVerdict.FAIL_UNKNOWN_SEVERITY,
                is_compliant=False,
                policy_id=contract.policy_id,
                policy_revision=contract.revision,
                policy_hash=contract.policy_hash_v1,
                max_detected_cvss=assessment.max_applicable_cvss,
                allowed_cvss_threshold=contract.max_allowed_cvss,
                reasons=(f"SBOM contains {assessment.components_unknown_severity} vulnerabilities with unresolvable severity",),
            )

        # 4. CVSS threshold check
        if assessment.max_applicable_cvss is not None:
            if assessment.max_applicable_cvss > contract.max_allowed_cvss:
                return PolicyEvaluationResult(
                    verdict=PolicyEvaluationVerdict.FAIL_CVSS_THRESHOLD,
                    is_compliant=False,
                    policy_id=contract.policy_id,
                    policy_revision=contract.revision,
                    policy_hash=contract.policy_hash_v1,
                    max_detected_cvss=assessment.max_applicable_cvss,
                    allowed_cvss_threshold=contract.max_allowed_cvss,
                    reasons=(f"Maximum CVSS {assessment.max_applicable_cvss} exceeds allowed threshold {contract.max_allowed_cvss}",),
                )

        # 5. Compliant pass
        return PolicyEvaluationResult(
            verdict=PolicyEvaluationVerdict.PASS,
            is_compliant=True,
            policy_id=contract.policy_id,
            policy_revision=contract.revision,
            policy_hash=contract.policy_hash_v1,
            max_detected_cvss=assessment.max_applicable_cvss,
            allowed_cvss_threshold=contract.max_allowed_cvss,
            reasons=("All components verified against active snapshot within allowed CVSS threshold",),
        )

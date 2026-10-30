"""
Deterministic Automated Unit and Property Tests for Formal Policy Contract,
Cryptographic Digest V1/V2, and Fail-Closed Evaluation Engine.
"""

import json
from uuid import uuid4
import pytest

from policy_service.app.services.policy_contract import (
    PolicyContract,
    PolicyEvaluationEngine,
    PolicyEvaluationVerdict,
    compute_policy_digest_v2,
    compute_policy_hash_v1,
    compute_policy_spec_hash,
    create_policy_contract,
)
from shared.crypto.poseidon_bn254 import poseidon_hash
from vulnerability_service.app.services.snapshot_validator import AssessmentSummary


class TestPolicyContractAndDigests:

    def test_canonical_digest_v1_matches_circuit_assertion(self):
        """
        Verify that compute_policy_hash_v1 matches Noir 0.32.0's exact
        Poseidon bn254 hash_1([policy_max_cvss as Field]).
        """
        # For threshold 7.0 -> 70
        h_v1 = compute_policy_hash_v1(70)
        expected = f"0x{poseidon_hash([70]):064x}"
        assert h_v1 == expected
        assert h_v1 == "0x08e0852a9efbf4ac2ebe63a6ca13353c75994d4125e62c2da2340a1e219154e4"

    def test_changing_threshold_changes_digest(self):
        h_70 = compute_policy_hash_v1(70)
        h_75 = compute_policy_hash_v1(75)
        h_90 = compute_policy_hash_v1(90)

        assert h_70 != h_75
        assert h_75 != h_90

    def test_digest_v2_domain_separation_and_determinism(self):
        """
        Verify that Policy Digest V2 changes if revision, threshold, or coverage rules change.
        """
        d1 = compute_policy_digest_v2(max_cvss_int=70, revision=1, min_coverage_pct=100, allow_unscored=False)
        d1_dup = compute_policy_digest_v2(max_cvss_int=70, revision=1, min_coverage_pct=100, allow_unscored=False)
        # Determinism
        assert d1 == d1_dup

        # Changing revision
        d2 = compute_policy_digest_v2(max_cvss_int=70, revision=2, min_coverage_pct=100, allow_unscored=False)
        assert d1 != d2

        # Changing threshold
        d3 = compute_policy_digest_v2(max_cvss_int=75, revision=1, min_coverage_pct=100, allow_unscored=False)
        assert d1 != d3

        # Changing unscored policy
        d4 = compute_policy_digest_v2(max_cvss_int=70, revision=1, min_coverage_pct=100, allow_unscored=True)
        assert d1 != d4

    def test_invalid_cvss_score_rejected(self):
        with pytest.raises(ValueError, match="between 0.0 and 10.0"):
            create_policy_contract(policy_id=str(uuid4()), revision=1, name="bad", max_cvss_score=10.5)

        with pytest.raises(ValueError, match="between 0.0 and 10.0"):
            create_policy_contract(policy_id=str(uuid4()), revision=1, name="bad", max_cvss_score=-0.1)


class TestPolicyEvaluationEngine:

    @pytest.fixture
    def strict_policy(self):
        return create_policy_contract(
            policy_id=str(uuid4()),
            revision=1,
            name="Strict CVSS 7.0 Policy",
            max_cvss_score=7.0,
            allow_unscored=False,
            allow_unscannable=False,
        )

    def test_compliant_assessment_passes(self, strict_policy):
        assessment = AssessmentSummary(
            total_parsed_components=10,
            components_valid_identity=10,
            components_supported_ecosystem=10,
            components_matched_advisories=2,
            known_affected_components=2,
            components_no_matching_advisory=8,
            components_unscannable=0,
            components_unknown_severity=0,
            ecosystems_in_sbom=("npm",),
            ecosystems_in_snapshot=("npm",),
            is_snapshot_sufficient=True,
            snapshot_id=str(uuid4()),
            snapshot_status="frozen",
            authoritative_smt_root="0x123",
            policy_hash=strict_policy.policy_hash_v1,
            max_applicable_cvss=6.5,  # <= 7.0
            compliance_verdict="COMPLIANT",
        )

        res = PolicyEvaluationEngine.evaluate(assessment, strict_policy, is_policy_active=True)
        assert res.is_compliant is True
        assert res.verdict == PolicyEvaluationVerdict.PASS

    def test_cvss_threshold_exceeded_fails(self, strict_policy):
        assessment = AssessmentSummary(
            total_parsed_components=5,
            components_valid_identity=5,
            components_supported_ecosystem=5,
            components_matched_advisories=1,
            known_affected_components=1,
            components_no_matching_advisory=4,
            components_unscannable=0,
            components_unknown_severity=0,
            ecosystems_in_sbom=("npm",),
            ecosystems_in_snapshot=("npm",),
            is_snapshot_sufficient=True,
            snapshot_id=str(uuid4()),
            snapshot_status="frozen",
            authoritative_smt_root="0x123",
            policy_hash=strict_policy.policy_hash_v1,
            max_applicable_cvss=7.5,  # > 7.0
            compliance_verdict="VIOLATION",
        )

        res = PolicyEvaluationEngine.evaluate(assessment, strict_policy, is_policy_active=True)
        assert res.is_compliant is False
        assert res.verdict == PolicyEvaluationVerdict.FAIL_CVSS_THRESHOLD
        assert any("exceeds allowed threshold" in r for r in res.reasons)

    def test_unscannable_components_fail_closed(self, strict_policy):
        assessment = AssessmentSummary(
            total_parsed_components=5,
            components_valid_identity=4,
            components_supported_ecosystem=4,
            components_matched_advisories=0,
            known_affected_components=0,
            components_no_matching_advisory=4,
            components_unscannable=1,  # 1 unscannable
            components_unknown_severity=0,
            ecosystems_in_sbom=("npm",),
            ecosystems_in_snapshot=("npm",),
            is_snapshot_sufficient=True,
            snapshot_id=str(uuid4()),
            snapshot_status="frozen",
            authoritative_smt_root="0x123",
            policy_hash=strict_policy.policy_hash_v1,
            max_applicable_cvss=None,
            compliance_verdict="BLOCKED_UNSCANNABLE",
        )

        res = PolicyEvaluationEngine.evaluate(assessment, strict_policy, is_policy_active=True)
        assert res.is_compliant is False
        assert res.verdict == PolicyEvaluationVerdict.FAIL_UNSCANNABLE

    def test_unknown_severity_fails_closed(self, strict_policy):
        assessment = AssessmentSummary(
            total_parsed_components=5,
            components_valid_identity=5,
            components_supported_ecosystem=5,
            components_matched_advisories=1,
            known_affected_components=1,
            components_no_matching_advisory=4,
            components_unscannable=0,
            components_unknown_severity=1,  # 1 unknown severity
            ecosystems_in_sbom=("npm",),
            ecosystems_in_snapshot=("npm",),
            is_snapshot_sufficient=True,
            snapshot_id=str(uuid4()),
            snapshot_status="frozen",
            authoritative_smt_root="0x123",
            policy_hash=strict_policy.policy_hash_v1,
            max_applicable_cvss=None,
            compliance_verdict="BLOCKED_UNKNOWN_SEVERITY",
        )

        res = PolicyEvaluationEngine.evaluate(assessment, strict_policy, is_policy_active=True)
        assert res.is_compliant is False
        assert res.verdict == PolicyEvaluationVerdict.FAIL_UNKNOWN_SEVERITY

    def test_insufficient_snapshot_coverage_fails_closed(self, strict_policy):
        assessment = AssessmentSummary(
            total_parsed_components=837,
            components_valid_identity=837,
            components_supported_ecosystem=837,
            components_matched_advisories=0,
            known_affected_components=0,
            components_no_matching_advisory=837,
            components_unscannable=0,
            components_unknown_severity=0,
            ecosystems_in_sbom=("npm",),
            ecosystems_in_snapshot=("pypi",),  # Mismatch
            is_snapshot_sufficient=False,
            snapshot_id=str(uuid4()),
            snapshot_status="frozen",
            authoritative_smt_root="0x123",
            policy_hash=strict_policy.policy_hash_v1,
            max_applicable_cvss=None,
            compliance_verdict="BLOCKED_INSUFFICIENT_COVERAGE",
            limitations_and_blockers=("Snapshot only covers ['pypi'], lacking coverage for ['npm']",),
        )

        res = PolicyEvaluationEngine.evaluate(assessment, strict_policy, is_policy_active=True)
        assert res.is_compliant is False
        assert res.verdict == PolicyEvaluationVerdict.FAIL_INSUFFICIENT_COVERAGE

    def test_inactive_policy_blocks_evaluation(self, strict_policy):
        assessment = AssessmentSummary(
            total_parsed_components=1,
            components_valid_identity=1,
            components_supported_ecosystem=1,
            components_matched_advisories=0,
            known_affected_components=0,
            components_no_matching_advisory=1,
            components_unscannable=0,
            components_unknown_severity=0,
            ecosystems_in_sbom=("npm",),
            ecosystems_in_snapshot=("npm",),
            is_snapshot_sufficient=True,
            snapshot_id=str(uuid4()),
            snapshot_status="frozen",
            authoritative_smt_root="0x123",
            policy_hash=strict_policy.policy_hash_v1,
            max_applicable_cvss=None,
            compliance_verdict="COMPLIANT",
        )

        res = PolicyEvaluationEngine.evaluate(assessment, strict_policy, is_policy_active=False)
        assert res.is_compliant is False
        assert res.verdict == PolicyEvaluationVerdict.FAIL_POLICY_INACTIVE

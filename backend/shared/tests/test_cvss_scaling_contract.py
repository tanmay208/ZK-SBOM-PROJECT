"""
Regression test suite for CVSS scaling contract across policy serialization,
vulnerability ingestion, component-vulnerability mappings, and Noir circuit constraints.

Contract Invariants:
1. Canonical integer scale is 10x: float [0.0, 10.0] -> integer [0, 100].
2. Function: int(round(score * 10)) with banker's rounding.
3. Policy threshold constraint in circuit: assert(scores[i] <= policy_max_cvss).
4. Below threshold (< 7.0 -> < 70): satisfies constraint.
5. Equal to threshold (== 7.0 -> == 70): satisfies constraint.
6. Above threshold (> 7.0 -> > 70), including CVSS 10.0 (100): strictly violates constraint.
7. Explains why a legacy policy_max_cvss of 700 fails to reject CVSS 10.0 (100 <= 700 is True).
"""

import math
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
import pytest
from pydantic import ValidationError

from shared.crypto.poseidon_bn254 import poseidon_hash
from vulnerability_service.app.schemas.vulnerability_schemas import VulnerabilityIngestionItem
from policy_service.app.schemas.policy_schemas import PolicyCreateRequest


def canonical_scale(val: float) -> int:
    """Canonical integer scaling contract used across the application."""
    return int(round(val * 10))


class TestCVSSScalingContract:
    """Tests the canonical CVSS scaling contract across boundary values."""

    def test_cvss_scaling_canonical_values(self):
        """Verify standard CVSS scores scale deterministically by 10x."""
        cases = [
            (0.0, 0),
            (0.1, 1),
            (1.0, 10),
            (3.3, 33),
            (5.0, 50),
            (6.9, 69),
            (7.0, 70),
            (7.1, 71),
            (7.5, 75),
            (9.8, 98),
            (10.0, 100),
        ]
        for score_float, expected_int in cases:
            assert canonical_scale(score_float) == expected_int

    def test_scores_below_threshold(self):
        """Scores strictly below threshold 7.0 must satisfy circuit constraint (score_int <= 70)."""
        policy_threshold_float = 7.0
        policy_threshold_int = canonical_scale(policy_threshold_float)
        assert policy_threshold_int == 70

        below_scores = [0.0, 0.5, 1.0, 2.5, 4.0, 5.0, 6.0, 6.5, 6.8, 6.9]
        for s in below_scores:
            s_int = canonical_scale(s)
            assert s_int < policy_threshold_int, f"Expected {s} ({s_int}) < {policy_threshold_int}"
            # Circuit constraint: assert(scores[i] <= policy_max_cvss)
            assert s_int <= policy_threshold_int

    def test_scores_equal_to_threshold(self):
        """Scores exactly equal to threshold 7.0 must satisfy boundary (70 <= 70)."""
        policy_threshold_int = canonical_scale(7.0)
        score_int = canonical_scale(7.0)
        assert score_int == 70
        assert policy_threshold_int == 70
        # Circuit constraint: assert(scores[i] <= policy_max_cvss)
        assert score_int <= policy_threshold_int

    def test_scores_above_threshold(self):
        """Scores strictly above threshold 7.0 must fail circuit constraint (score_int <= 70)."""
        policy_threshold_int = canonical_scale(7.0)
        above_scores = [7.1, 7.2, 7.5, 8.0, 8.5, 9.0, 9.8, 10.0]
        for s in above_scores:
            s_int = canonical_scale(s)
            assert s_int > policy_threshold_int, f"Expected {s} ({s_int}) > {policy_threshold_int}"
            # Circuit constraint: assert(scores[i] <= policy_max_cvss) fails
            is_compliant = (s_int <= policy_threshold_int)
            assert is_compliant is False, f"Score {s} unexpectedly passed threshold {policy_threshold_int}"

    def test_log4shell_cvss_10_against_policy_7(self):
        """
        Verify that Apache Log4j 2.14.1 (CVE-2021-44228, CVSS 10.0 = 100)
        strictly exceeds a policy threshold of 7.0 (70).
        """
        log4j_cvss = 10.0
        policy_threshold = 7.0

        log4j_int = canonical_scale(log4j_cvss)
        policy_int = canonical_scale(policy_threshold)

        assert log4j_int == 100
        assert policy_int == 70
        assert log4j_int > policy_int
        # Constraint failure
        assert not (log4j_int <= policy_int)

    def test_invalid_and_out_of_bounds_inputs(self):
        """Negative scores and scores > 10.0 must be rejected by Pydantic schemas."""
        invalid_scores = [-1.0, -0.1, 10.1, 15.0, 100.0]
        for s in invalid_scores:
            with pytest.raises(ValidationError):
                VulnerabilityIngestionItem(purl="pkg:npm/test@1.0", cvss_score=s)

            with pytest.raises(ValidationError):
                PolicyCreateRequest(max_cvss_score=s)

    def test_nan_and_infinity_rejected(self):
        """NaN and Infinity must be rejected."""
        for bad_val in [float("nan"), float("inf"), float("-inf")]:
            with pytest.raises(ValidationError):
                VulnerabilityIngestionItem(purl="pkg:npm/test@1.0", cvss_score=bad_val)

            with pytest.raises(ValidationError):
                PolicyCreateRequest(max_cvss_score=bad_val)

    def test_legacy_scale_anomaly_analysis(self):
        """
        Formal regression analysis:
        When a legacy baseline policy stores max_allowed_cvss_int = 700 (100x scale),
        while vulnerability ingestion stores max_cvss = 100 (10x scale for CVSS 10.0),
        the circuit constraint assert(scores[i] <= policy_max_cvss) evaluates
        100 <= 700 (True), which fails to reject Log4Shell without policy scale alignment.
        """
        legacy_policy_int = 700  # Mistaken 100x scale
        log4j_int = canonical_scale(10.0)  # Canonical 10x scale = 100

        # Anomaly demonstration:
        # Constraint evaluates True instead of False!
        evaluates_to_true_anomaly = (log4j_int <= legacy_policy_int)
        assert evaluates_to_true_anomaly is True, "Legacy scale anomaly: 100 <= 700 passes"

        # Corrected scale alignment:
        # Both on 10x scale:
        aligned_policy_int = canonical_scale(7.0)  # 70
        assert (log4j_int <= aligned_policy_int) is False, "Aligned scale correctly rejects: 100 <= 70 fails"

    def test_poseidon_hash_policy_binding(self):
        """
        Verify that policy_hash cryptographically binds the exact integer threshold.
        poseidon_hash([70]) != poseidon_hash([700]).
        """
        hash_70 = f"0x{poseidon_hash([70]):064x}"
        hash_700 = f"0x{poseidon_hash([700]):064x}"

        assert hash_70 != hash_700
        # Hash of 700 matches baseline Stage 21L Policy hash
        assert hash_700 == "0x0628b30da1be08030f8d6d03a88cc029595ca9c43cf6d5bf1122d3491fa35c0a"

    def test_historical_policy_binding_preserves_independent_verification(self):
        """
        Verify Approach B: When a new presentation policy is activated (is_active=1),
        historical proofs and certificates bound to previous policies (is_active=0)
        remain verifiable against authoritative registered policy records.
        """
        from unittest.mock import MagicMock
        from verification_service.app.repositories.verification_repository import VerificationRepository
        from policy_service.app.models.policy_models import SecurityPolicy
        from sbom_service.app.models.sbom_models import SBOMUpload
        from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot

        session = MagicMock()
        repo = VerificationRepository(session)

        # Baseline legacy policy (historical version with is_active=0)
        legacy_pol = MagicMock(
            policy_hash="0x0628b30da1be08030f8d6d03a88cc029595ca9c43cf6d5bf1122d3491fa35c0a",
            is_active=0,
        )
        mock_sbom = MagicMock(sbom_root="0xsbom", status="committed")
        mock_snap = MagicMock(authoritative_smt_root="0xsnap", status="frozen", expires_at=None)

        def query_side_effect(model):
            q = MagicMock()
            if model == SBOMUpload:
                q.filter.return_value.first.return_value = mock_sbom
            elif model == VulnerabilitySnapshot:
                q.filter.return_value.first.return_value = mock_snap
            elif model == SecurityPolicy:
                q.filter.return_value.first.return_value = legacy_pol
            return q

        session.query.side_effect = query_side_effect

        # 1. Historical proof verification against superseded policy must SUCCEED (Approach B)
        assert repo.validate_authoritative_records("0xsbom", "0xsnap", legacy_pol.policy_hash) is True

        # 2. Tampered/fake policy hash must FAIL closed
        def query_tampered(model):
            q = MagicMock()
            if model == SBOMUpload:
                q.filter.return_value.first.return_value = mock_sbom
            elif model == VulnerabilitySnapshot:
                q.filter.return_value.first.return_value = mock_snap
            elif model == SecurityPolicy:
                q.filter.return_value.first.return_value = None
            return q

        session.query.side_effect = query_tampered
        assert repo.validate_authoritative_records("0xsbom", "0xsnap", "0xdeadbeef") is False



class TestNoirCircuitCVSSConstraint:
    """
    Dedicated Circuit-Level Test Suite:
    Executes the actual Noir ACIR circuit (segment_init_32) via Nargo toolchain in WSL.
    Proves that the circuit assertion assert(scores[i] <= policy_max_cvss) is genuinely
    enforced by the zero-knowledge constraint system.
    """

    @classmethod
    def setup_class(cls):
        import shutil, subprocess, tempfile, os, re
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[3]
        src_dir = repo_root / "segment_init_32"
        if not (src_dir / "src" / "main.nr").exists():
            pytest.skip("segment_init_32 circuit directory not found")

        # Verify WSL + nargo availability
        try:
            chk = subprocess.run(["wsl", "bash", "-c", "~/.nargo/bin/nargo --version"], capture_output=True, text=True, timeout=10)
            if chk.returncode != 0:
                pytest.skip("WSL nargo 0.32.0 not available")
        except Exception as e:
            pytest.skip(f"WSL unavailable: {e}")

        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.tmp_path = Path(cls.tmp_dir.name)
        shutil.copy(src_dir / "Nargo.toml", cls.tmp_path)
        shutil.copytree(src_dir / "src", cls.tmp_path / "src")

        # Pre-copy compiled target artifact so Nargo executes witness solver directly without re-compiling 38MB ACIR
        target_src = src_dir / "target" / "segment_init_32.json"
        if target_src.exists():
            os.makedirs(cls.tmp_path / "target", exist_ok=True)
            shutil.copy(target_src, cls.tmp_path / "target" / "segment_init_32.json")

        # Configure Prover.toml with policy threshold = 70 (CVSS 7.0)
        prover_text = (src_dir / "Prover.toml").read_text(encoding="utf-8")
        hash_70 = f"0x{poseidon_hash([70]):064x}"
        prover_text = re.sub(r'policy_hash = "[^"]+"', f'policy_hash = "{hash_70}"', prover_text)
        prover_text = re.sub(r'policy_max_cvss = "[^"]+"', 'policy_max_cvss = "70"', prover_text)
        cls.base_prover_text = prover_text

        norm_path = str(cls.tmp_path).replace("\\", "/")
        cls.wsl_tmp = subprocess.check_output(["wsl", "wslpath", "-u", norm_path], text=True).strip()

    @classmethod
    def teardown_class(cls):
        if hasattr(cls, "tmp_dir"):
            cls.tmp_dir.cleanup()

    def _execute_circuit_with_score(self, test_score: int) -> subprocess.CompletedProcess:
        import re, subprocess
        # Component 1 has presence=0, which isolates assert(scores[i] <= policy_max_cvss) from SMT verification
        new_scores = re.sub(r"scores = \[4, [0-9]+,", f"scores = [4, {test_score},", self.base_prover_text)
        (self.tmp_path / "Prover.toml").write_text(new_scores, encoding="utf-8")
        cmd = ["wsl", "bash", "-c", f"cd '{self.wsl_tmp}' && ~/.nargo/bin/nargo execute -p Prover test_witness_{test_score}"]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    def test_circuit_level_cvss_6_9_accepted(self):
        """Circuit-Level: CVSS 6.9 (score 69) against policy 7.0 (70) must satisfy constraint and solve witness."""
        res = self._execute_circuit_with_score(69)
        assert res.returncode == 0, f"Expected circuit success for score 69 <= 70, got: {res.stderr}"

    def test_circuit_level_cvss_7_0_accepted(self):
        """Circuit-Level: CVSS 7.0 (score 70) against policy 7.0 (70) must satisfy <= boundary and solve witness."""
        res = self._execute_circuit_with_score(70)
        assert res.returncode == 0, f"Expected circuit success for score 70 <= 70, got: {res.stderr}"

    def test_circuit_level_cvss_7_1_rejected(self):
        """Circuit-Level: CVSS 7.1 (score 71) against policy 7.0 (70) must fail circuit constraint."""
        res = self._execute_circuit_with_score(71)
        assert res.returncode != 0, "Expected circuit failure for score 71 > 70"
        assert "Failed constraint" in res.stderr
        assert "scores[i] <= policy_ma" in res.stderr

    def test_circuit_level_cvss_10_0_log4shell_rejected(self):
        """Circuit-Level: CVSS 10.0 (score 100, Log4Shell) against policy 7.0 (70) must fail circuit constraint."""
        res = self._execute_circuit_with_score(100)
        assert res.returncode != 0, "Expected circuit failure for Log4j score 100 > 70"
        assert "Failed constraint" in res.stderr
        assert "scores[i] <= policy_ma" in res.stderr


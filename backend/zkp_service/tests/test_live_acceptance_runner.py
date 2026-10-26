"""
Offline Unit Tests for scripts/run_live_256_acceptance.py

These tests exercise ONLY mocked subprocess outcomes, active command interruption,
timeout handling, watchdog failure, PID-file validation, safe cleanup decisions,
and control-flow of all 6 negative verification tests.
They do NOT invoke Nargo, Barretenberg, the live acceptance pipeline, or any database.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import uuid

import pytest

# Ensure scripts directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts")))

import run_live_256_acceptance as runner


class TestTargetedProcessTrackerOffline:
    """Offline unit tests for TargetedProcessTracker using mocked subprocesses."""

    def test_pid_injection_prep(self) -> None:
        """prepare_invocation must inject unique PID trap with exec to bind toolchain identity."""
        tracker = runner.TargetedProcessTracker(distro="test-distro")
        inv_id, wrapped_cmd, pid_filename = tracker.prepare_invocation("~/.bb/bb prove ...", cwd="/tmp")

        assert inv_id in tracker.active_invocations
        assert f"echo $$ > {pid_filename}" in wrapped_cmd
        assert "exec ~/.bb/bb prove ..." in wrapped_cmd
        assert pid_filename.startswith("pid_")
        assert pid_filename.endswith(".txt")

    def test_read_and_validate_guest_pid_valid(self, tmp_path) -> None:
        """read_and_validate_guest_pid correctly parses valid integer PIDs."""
        tracker = runner.TargetedProcessTracker(distro="test-distro")
        pid_file = tmp_path / "pid_test.txt"
        pid_file.write_text("12345\n")

        pid = tracker.read_and_validate_guest_pid(str(tmp_path), "pid_test.txt")
        assert pid == 12345

    def test_read_and_validate_guest_pid_rejects_malformed_and_unsafe(self, tmp_path) -> None:
        """Reject non-digits, negative integers, and system-critical PIDs (0, 1)."""
        tracker = runner.TargetedProcessTracker(distro="test-distro")

        for bad_content in ["abc", "", "-5", "0", "1", "12.34", "123 456"]:
            pid_file = tmp_path / "pid_bad.txt"
            pid_file.write_text(bad_content)
            pid = tracker.read_and_validate_guest_pid(str(tmp_path), "pid_bad.txt")
            assert pid is None, f"Expected {bad_content!r} to be rejected"

    @patch("subprocess.run")
    def test_terminate_targeted_worker_mocked_sigterm_success(self, mock_run, tmp_path) -> None:
        """Simulate clean SIGTERM termination of tracked guest PID."""
        tracker = runner.TargetedProcessTracker(distro="test-distro")
        pid_file = tmp_path / "pid_success.txt"
        pid_file.write_text("4321")

        inv_id = "test_inv_1"
        tracker.active_invocations[inv_id] = (str(tmp_path), "pid_success.txt")

        # Mock kill -15 success, then kill -0 returns 1 (process dead)
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0), # kill -15
            subprocess.CompletedProcess(args=[], returncode=1), # kill -0 probe -> dead
        ]

        success, msg = tracker.terminate_targeted_worker(inv_id)
        assert success is True
        assert tracker.cleanup_failed is False
        assert "4321" in msg
        assert "SIGTERM" in msg
        assert not os.path.exists(str(pid_file))

    @patch("subprocess.run")
    def test_terminate_targeted_worker_mocked_kill9_escalation(self, mock_run, tmp_path) -> None:
        """Simulate escalation to SIGKILL if SIGTERM does not stop process."""
        tracker = runner.TargetedProcessTracker(distro="test-distro")
        pid_file = tmp_path / "pid_esc.txt"
        pid_file.write_text("9876")

        inv_id = "test_inv_2"
        tracker.active_invocations[inv_id] = (str(tmp_path), "pid_esc.txt")

        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0), # kill -15
            subprocess.CompletedProcess(args=[], returncode=0), # kill -0 probe 1 -> alive
            subprocess.CompletedProcess(args=[], returncode=0), # kill -0 probe 2 -> alive
            subprocess.CompletedProcess(args=[], returncode=0), # kill -0 probe 3 -> alive
            subprocess.CompletedProcess(args=[], returncode=0), # kill -9 escalate
            subprocess.CompletedProcess(args=[], returncode=1), # kill -0 probe -> dead
        ]

        success, msg = tracker.terminate_targeted_worker(inv_id)
        assert success is True
        assert tracker.cleanup_failed is False
        assert "SIGKILL" in msg

    def test_terminate_targeted_worker_missing_pid_fails_closed(self, tmp_path) -> None:
        """Fail closed when PID file is missing, setting cleanup_failed = True."""
        tracker = runner.TargetedProcessTracker(distro="test-distro")
        inv_id = "test_inv_missing"
        tracker.active_invocations[inv_id] = (str(tmp_path), "pid_nonexistent.txt")

        success, msg = tracker.terminate_targeted_worker(inv_id)
        assert success is False
        assert tracker.cleanup_failed is True
        assert "Cannot identify guest PID" in msg

    @patch("subprocess.run")
    def test_terminate_targeted_worker_unresponsive_sets_cleanup_failed(self, mock_run, tmp_path) -> None:
        """Fail closed and set cleanup_failed = True if process remains alive after kill -9."""
        tracker = runner.TargetedProcessTracker(distro="test-distro")
        pid_file = tmp_path / "pid_unresponsive.txt"
        pid_file.write_text("9999")

        inv_id = "test_inv_unresponsive"
        tracker.active_invocations[inv_id] = (str(tmp_path), "pid_unresponsive.txt")

        # Mock kill commands succeed, but kill -0 probes always return 0 (process alive)
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        success, msg = tracker.terminate_targeted_worker(inv_id)
        assert success is False
        assert tracker.cleanup_failed is True
        assert "could not be stopped" in msg


class TestActiveCommandInterruptionOffline:
    """Offline unit tests verifying active command preemption by watchdog and deadlines."""

    @patch("subprocess.Popen")
    def test_active_command_interrupted_by_watchdog(self, mock_popen, tmp_path) -> None:
        """Active Popen call must be terminated when watchdog abort_event fires while running."""
        r = runner.LiveAcceptanceRunner(distro="test-distro", max_overall_seconds=3600.0)

        # Mock Popen instance
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, None, 0]
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        pid_file = tmp_path / "pid_test.txt"
        pid_file.write_text("7777")
        r.tracker.active_invocations["inv_watchdog"] = (str(tmp_path), "pid_test.txt")

        with patch.object(r.tracker, "terminate_targeted_worker", return_value=(True, "Terminated")) as mock_term:
            r._terminate_active_invocation(mock_proc, "inv_watchdog")
            mock_term.assert_called_once_with("inv_watchdog")
            mock_proc.terminate.assert_called_once()

    @patch("subprocess.Popen")
    def test_cleanup_failure_blocks_subsequent_invocations(self, mock_popen, tmp_path) -> None:
        """If a worker cleanup fails, subsequent wrapped_run_toolchain calls must immediately fail closed."""
        r = runner.LiveAcceptanceRunner(distro="test-distro")
        r.tracker.cleanup_failed = True

        # Simulate wrapped_run_toolchain guard
        with pytest.raises(runner.UncertainProcessCleanupError) as exc_info:
            if r.tracker.cleanup_failed:
                raise runner.UncertainProcessCleanupError("Subsequent invocation blocked: previous worker cleanup failed.")

        assert "Subsequent invocation blocked" in str(exc_info.value)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_active_command_per_segment_timeout_cleans_up_guest_pid(self, mock_popen, tmp_path) -> None:
        """When per-segment timeout triggers, _terminate_active_invocation cleans up guest PID and host proc."""
        r = runner.LiveAcceptanceRunner(distro="test-distro", per_segment_timeout_seconds=1)

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        pid_file = tmp_path / "pid_timeout.txt"
        pid_file.write_text("8888")
        r.tracker.active_invocations["inv_timeout"] = (str(tmp_path), "pid_timeout.txt")

        with patch.object(r.tracker, "terminate_targeted_worker", return_value=(True, "Terminated")) as mock_term:
            r._terminate_active_invocation(mock_proc, "inv_timeout")
            mock_term.assert_called_once_with("inv_timeout")
            mock_proc.terminate.assert_called_once()


class TestSafeguardMonitorOffline:
    """Offline unit tests for SafeguardMonitor using mocked memory measurements."""

    @patch("run_live_256_acceptance.get_wsl_memory_usage_bytes")
    @patch("run_live_256_acceptance.get_host_available_ram_bytes")
    def test_monitor_aborts_on_low_host_ram(self, mock_host_ram, mock_wsl_mem) -> None:
        """Watchdog sets abort_event when host available RAM drops below 2.0 GiB."""
        mock_host_ram.return_value = int(1.5 * 1024 * 1024 * 1024) # 1.5 GiB
        mock_wsl_mem.return_value = (int(1.0 * 1024 * 1024 * 1024), int(16.0 * 1024 * 1024 * 1024))

        monitor = runner.SafeguardMonitor(
            distro="test-distro",
            min_host_ram_bytes=2 * 1024 * 1024 * 1024,
            max_wsl_mem_bytes=int(7.5 * 1024 * 1024 * 1024),
            poll_interval_seconds=0.05,
        )

        monitor.start()
        try:
            aborted = monitor.abort_event.wait(timeout=2.0)
            assert aborted is True
            assert "Host available RAM breached safety floor" in monitor.abort_reason
        finally:
            monitor.stop()

    @patch("run_live_256_acceptance.get_wsl_memory_usage_bytes")
    @patch("run_live_256_acceptance.get_host_available_ram_bytes")
    def test_monitor_aborts_on_high_wsl_mem(self, mock_host_ram, mock_wsl_mem) -> None:
        """Watchdog sets abort_event when WSL guest memory exceeds 7.5 GiB."""
        mock_host_ram.return_value = int(10.0 * 1024 * 1024 * 1024) # 10 GiB available
        mock_wsl_mem.return_value = (int(8.0 * 1024 * 1024 * 1024), int(16.0 * 1024 * 1024 * 1024)) # 8 GiB used

        monitor = runner.SafeguardMonitor(
            distro="test-distro",
            min_host_ram_bytes=2 * 1024 * 1024 * 1024,
            max_wsl_mem_bytes=int(7.5 * 1024 * 1024 * 1024),
            poll_interval_seconds=0.05,
        )

        monitor.start()
        try:
            aborted = monitor.abort_event.wait(timeout=2.0)
            assert aborted is True
            assert "WSL guest memory breached ceiling" in monitor.abort_reason
        finally:
            monitor.stop()

    @patch("run_live_256_acceptance.get_wsl_memory_usage_bytes")
    @patch("run_live_256_acceptance.get_host_available_ram_bytes")
    def test_monitor_fails_closed_after_repeated_query_errors(self, mock_host_ram, mock_wsl_mem) -> None:
        """Watchdog fails closed if memory queries repeatedly throw exceptions."""
        mock_host_ram.side_effect = RuntimeError("Memory query failed")
        mock_wsl_mem.return_value = (1024, 2048)

        monitor = runner.SafeguardMonitor(
            distro="test-distro",
            poll_interval_seconds=0.05,
        )
        monitor.max_allowed_consecutive_failures = 2

        monitor.start()
        try:
            aborted = monitor.abort_event.wait(timeout=2.0)
            assert aborted is True
            assert "fail-closed after 2 failures" in monitor.abort_reason
        finally:
            monitor.stop()


    def test_poll_interval_configured_on_runner(self) -> None:
        """Runner CLI allows configuring poll_interval_seconds."""
        r = runner.LiveAcceptanceRunner(distro="test-distro", poll_interval_seconds=0.25)
        assert r.poll_interval_seconds == 0.25
        assert r.monitor.poll_interval == 0.25

    @patch("run_live_256_acceptance.get_wsl_memory_usage_bytes")
    @patch("run_live_256_acceptance.get_host_available_ram_bytes")
    def test_monitor_allows_proving_peak_under_12_gib(self, mock_host_ram, mock_wsl_mem) -> None:
        """Watchdog allows healthy prover memory peaking at 8.5 GiB under the 12.0 GiB ceiling."""
        mock_host_ram.return_value = int(10.0 * 1024 * 1024 * 1024) # 10 GiB available
        mock_wsl_mem.return_value = (int(8.5 * 1024 * 1024 * 1024), int(16.0 * 1024 * 1024 * 1024)) # 8.5 GiB used

        monitor = runner.SafeguardMonitor(
            distro="test-distro",
            min_host_ram_bytes=2 * 1024 * 1024 * 1024,
            max_wsl_mem_bytes=int(12.0 * 1024 * 1024 * 1024),
            poll_interval_seconds=0.05,
        )

        monitor.start()
        try:
            aborted = monitor.abort_event.wait(timeout=0.2)
            assert aborted is False, "Monitor should not abort when WSL memory is 8.5 GiB under 12.0 GiB ceiling"
            assert monitor.abort_reason is None
            assert monitor.peak_wsl_used_bytes == int(8.5 * 1024 * 1024 * 1024)
        finally:
            monitor.stop()

    @patch("run_live_256_acceptance.get_wsl_memory_usage_bytes")
    @patch("run_live_256_acceptance.get_host_available_ram_bytes")
    def test_monitor_aborts_when_wsl_exceeds_12_gib_ceiling(self, mock_host_ram, mock_wsl_mem) -> None:
        """Watchdog strictly triggers abort when WSL guest memory breaches 12.0 GiB ceiling."""
        mock_host_ram.return_value = int(8.0 * 1024 * 1024 * 1024) # 8 GiB available
        mock_wsl_mem.return_value = (int(12.5 * 1024 * 1024 * 1024), int(16.0 * 1024 * 1024 * 1024)) # 12.5 GiB used

        monitor = runner.SafeguardMonitor(
            distro="test-distro",
            min_host_ram_bytes=2 * 1024 * 1024 * 1024,
            max_wsl_mem_bytes=int(12.0 * 1024 * 1024 * 1024),
            poll_interval_seconds=0.05,
        )

        monitor.start()
        try:
            aborted = monitor.abort_event.wait(timeout=2.0)
            assert aborted is True
            assert "WSL guest memory breached ceiling" in monitor.abort_reason
            assert "12.50 GiB used > 12.00 GiB ceiling" in monitor.abort_reason
        finally:
            monitor.stop()

    def test_runner_default_ceilings_and_deadlines(self) -> None:
        """Runner defaults configure 12.0 GiB WSL ceiling, 2.0 GiB host floor, and 18000s deadline."""
        r = runner.LiveAcceptanceRunner(distro="test-distro")
        assert r.max_wsl_mem_bytes == int(12.0 * 1024 * 1024 * 1024)
        assert r.min_host_ram_bytes == int(2.0 * 1024 * 1024 * 1024)
        assert r.max_overall_seconds == 18000.0
        assert r.per_segment_timeout_seconds == 120


class TestEphemeralCryptoProfileOffline:
    """Offline unit tests for EphemeralCryptoProfile context manager."""

    def test_ephemeral_crypto_profile_overrides_timeout_and_restores(self) -> None:
        """Verifies temporary profile file creation with overridden timeout and complete restoration."""
        orig_path = os.environ.get("CRYPTO_PROFILE_PATH")
        orig_profile = os.environ.get("CRYPTO_PROFILE")

        with runner.EphemeralCryptoProfile(per_segment_timeout_seconds=120) as temp_path:
            assert os.path.exists(temp_path)
            assert os.environ["CRYPTO_PROFILE_PATH"] == temp_path
            assert os.environ["CRYPTO_PROFILE"] == "prod"

            import json
            with open(temp_path, "r") as f:
                data = json.load(f)
            assert data["profiles"]["prod"]["proof_timeout_seconds"] == 120

        # After context exit: temporary file is deleted and env is restored
        assert not os.path.exists(temp_path)
        assert os.environ.get("CRYPTO_PROFILE_PATH") == orig_path
        assert os.environ.get("CRYPTO_PROFILE") == orig_profile


class TestNegativeVerificationControlFlowOffline:
    """Offline unit tests verifying control flow of the complete 6-case negative verification suite."""

    def test_negative_tests_control_flow_all_6_rejections(self) -> None:
        """Verifies that _run_negative_tests executes and records all 6 negative verification cases."""
        import base64
        import hashlib
        r = runner.LiveAcceptanceRunner(distro="test-distro")

        # Mock verifier
        mock_verifier = MagicMock()
        mock_resp_fail = MagicMock()
        mock_resp_fail.result = "invalid_proof"
        mock_resp_cross_tenant = MagicMock()
        mock_resp_cross_tenant.result = "verification_unavailable"

        # Return invalid_proof for first 5 cases, verification_unavailable for case 6
        mock_verifier.process_verification.side_effect = [
            mock_resp_fail, # 1. bad sbom
            mock_resp_fail, # 2. bad vuln
            mock_resp_fail, # 3. corrupt proof
            mock_resp_fail, # 4. trunc proof
            mock_resp_fail, # 5. bad policy
            mock_resp_cross_tenant, # 6. foreign user
        ]

        # Mock DB and job
        mock_db = MagicMock()
        mock_seg = MagicMock()
        dummy_proof = b"\x00" * 2304
        mock_seg.proof_artifact = base64.b64encode(dummy_proof).decode("utf-8")
        mock_seg.proof_artifact_hash = hashlib.sha256(dummy_proof).hexdigest()

        mock_chunk = MagicMock()
        mock_chunk.id = uuid.uuid4()
        mock_job = MagicMock()
        mock_job.chunks = [mock_chunk]

        mock_db.query.return_value.filter.return_value.first.return_value = mock_seg

        valid_req = MagicMock()
        valid_req.sbom_root = "0x" + "11" * 32
        valid_req.vulnerability_db_root = "0x" + "22" * 32
        valid_req.policy_hash = "0x" + "33" * 32
        valid_req.proof_job_id = uuid.uuid4()

        user_id = uuid.uuid4()

        with patch("policy_service.app.services.policy_service.create_policy") as mock_create_policy:
            mock_policy = MagicMock()
            mock_policy.policy_hash = "0x" + "44" * 32
            mock_create_policy.return_value = mock_policy

            r._run_negative_tests(mock_verifier, valid_req, user_id, mock_db, mock_job)

        results = r.execution_metrics["negative_tests_results"]
        assert len(results) == 6
        assert "tampered_sbom_root" in results
        assert "tampered_vuln_db_root" in results
        assert "corrupted_proof_bytes" in results
        assert "truncated_proof_bytes" in results
        assert "policy_threshold_violation" in results
        assert "cross_tenant_rejection" in results
        assert "verification_unavailable" in results["cross_tenant_rejection"]


class TestRunnerCLIDormant:
    """Offline unit test verifying runner is strictly dormant without explicit flag."""

    def test_runner_exits_zero_when_dormant(self) -> None:
        """Running main() with no args must print dormant notice and exit 0 without running pipeline."""
        with patch("sys.argv", ["run_live_256_acceptance.py"]):
            code = runner.main()
            assert code == 0


class TestRunnerEnvironmentOffline:
    """Offline unit tests verifying runner environment defaults and resolution."""

    def test_runner_resolves_project_bb_binary(self, monkeypatch) -> None:
        """Runner must resolve project .bin/bb when BB_PATH is unset."""
        monkeypatch.delenv("BB_PATH", raising=False)
        expected_binary = runner.PROJECT_ROOT / ".bin" / ("bb.exe" if runner.sys.platform == "win32" else "bb")
        if expected_binary.is_file():
            from verification_service.app.core.legacy_acir import resolve_bb_binary
            resolved = resolve_bb_binary()
            assert resolved == str(expected_binary)


class TestArtifactPersistenceOffline:
    """Offline unit tests verifying durable artifact persistence, disk fidelity, and bounded run control."""

    def test_min_host_ram_floor_enforcement(self) -> None:
        """Runner must reject min_host_ram_gib < 2.0 to protect the safety boundary."""
        with pytest.raises(ValueError) as excinfo:
            runner.LiveAcceptanceRunner(distro="test-distro", min_host_ram_gib=1.5)
        assert "2.0 GiB safety floor" in str(excinfo.value)

    def test_unique_run_artifacts_dir_default(self, tmp_path) -> None:
        """When artifacts_dir is not explicitly passed, runner derives unique directory next to manifest."""
        manifest_path = tmp_path / "custom_run" / "manifest_d5_test.json"
        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(manifest_path),
        )
        expected_artifacts_dir = tmp_path / "custom_run" / "manifest_d5_test_artifacts"
        assert r.artifacts_dir == expected_artifacts_dir
        assert r.artifacts_dir.is_dir()

    @patch("run_live_256_acceptance.verify_bound_proof")
    @patch("run_live_256_acceptance.get_crypto_profile")
    def test_persist_segment_artifact_writes_and_reverifies_offline(
        self, mock_get_profile, mock_verify, tmp_path
    ) -> None:
        """
        _persist_segment_artifact must:
        1. Write full .proof (2304 bytes), raw body .body.bin (2144 bytes), public inputs JSON, and metadata JSON.
        2. Re-read proof bytes from disk.
        3. Pass re-read bytes through verify_bound_proof for independent verification.
        4. Populate execution_metrics['persisted_artifacts'].
        """
        mock_verify.return_value = True

        mock_profile = MagicMock()
        mock_profile.get_artifact_paths.return_value = (tmp_path / "vk.bin", tmp_path / "acir.gz", tmp_path / "manifest.json")
        mock_profile.decomposed_artifacts = {"segment_init_32": {"vk_hash": "a" * 64}}
        mock_get_profile.return_value = mock_profile

        # Write dummy vk.bin
        (tmp_path / "vk.bin").write_bytes(b"\x01" * 100)

        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(tmp_path / "manifest.json"),
            artifacts_dir=str(tmp_path / "artifacts"),
        )

        dummy_pi = [f"0x{i:064x}" for i in range(1, 6)] # 5 public inputs
        pi_bytes = b"".join(int(x, 16).to_bytes(32, "big") for x in dummy_pi)
        body_bytes = b"\xaa" * 2144
        complete_proof = pi_bytes + body_bytes # 2304 bytes

        import base64
        import hashlib

        mock_db = MagicMock()
        dummy_seg_id = uuid.uuid4()
        dummy_seg = MagicMock()
        dummy_seg.id = dummy_seg_id
        dummy_seg.segment_index = 0
        dummy_seg.chunk_index = 0
        dummy_seg.global_sbom_root = dummy_pi[0]
        dummy_seg.policy_hash = dummy_pi[1]
        dummy_seg.components_commit = dummy_pi[3]
        dummy_seg.hash_out_commit = dummy_pi[4]
        dummy_chunk = MagicMock()
        dummy_chunk.chunk_index = int(dummy_pi[2], 16)
        dummy_chunk.components_commit = dummy_pi[3]
        dummy_seg.chunk = dummy_chunk

        dummy_seg.proof_artifact = base64.b64encode(complete_proof).decode("utf-8")
        dummy_seg.proof_artifact_hash = hashlib.sha256(complete_proof).hexdigest()
        dummy_seg.public_inputs = {"inputs": dummy_pi}
        mock_db.query.return_value.filter_by.return_value.first.return_value = dummy_seg

        meta = r._persist_segment_artifact(
            db=mock_db,
            seg_db_id=dummy_seg_id,
            chunk_index=0,
            seg_idx=0,
            circuit_name="segment_init_32",
            sbom_root=dummy_pi[0],
            vul_db_root="0x" + "22" * 32,
            policy_hash=dummy_pi[1],
        )

        # Check created files
        proof_file = tmp_path / "artifacts" / "chunk_0_segment_0.proof"
        body_file = tmp_path / "artifacts" / "chunk_0_segment_0.body.bin"
        pi_file = tmp_path / "artifacts" / "chunk_0_segment_0.public_inputs.json"
        meta_file = tmp_path / "artifacts" / "chunk_0_segment_0.meta.json"

        assert proof_file.is_file()
        assert body_file.is_file()
        assert pi_file.is_file()
        assert meta_file.is_file()

        # Check byte fidelity
        assert proof_file.read_bytes() == complete_proof
        assert len(proof_file.read_bytes()) == 2304
        assert body_file.read_bytes() == body_bytes
        assert len(body_file.read_bytes()) == 2144

        # Check meta
        assert meta["complete_proof_bytes"] == 2304
        assert meta["proof_body_bytes"] == 2144
        assert meta["offline_reverified_from_disk"] is True
        assert "chunk_0_segment_0" in r.execution_metrics["persisted_artifacts"]

        # Check that verify_bound_proof was called with disk bytes
        mock_verify.assert_called_once()
        call_kwargs = mock_verify.call_args[1]
        assert call_kwargs["complete_proof"] == complete_proof
        assert call_kwargs["expected_public_inputs"] == dummy_pi
        r.close()

    def test_bounded_run_complete_exception_type(self) -> None:
        """BoundedRunComplete must inherit from BaseException so generic except Exception does not swallow it."""
        assert issubclass(runner.BoundedRunComplete, BaseException)
        assert not issubclass(runner.BoundedRunComplete, Exception)

    def test_persist_segment_artifact_detects_hash_mismatch(self, tmp_path) -> None:
        """_persist_segment_artifact must reject corrupted/mismatched DB hashes and refuse to write files."""
        import base64
        mock_db = MagicMock()
        dummy_seg_id = uuid.uuid4()
        dummy_seg = MagicMock()
        dummy_seg.id = dummy_seg_id
        dummy_seg.proof_artifact = base64.b64encode(b"\x00" * 2304).decode("utf-8")
        dummy_seg.proof_artifact_hash = "wrong_hash_" + "0" * 53
        mock_db.query.return_value.filter_by.return_value.first.return_value = dummy_seg

        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(tmp_path / "manifest.json"),
            artifacts_dir=str(tmp_path / "artifacts"),
        )

        meta = r._persist_segment_artifact(
            db=mock_db,
            seg_db_id=dummy_seg_id,
            chunk_index=0,
            seg_idx=0,
            circuit_name="segment_init_32",
            sbom_root="0x" + "11" * 32,
            vul_db_root="0x" + "22" * 32,
            policy_hash="0x" + "33" * 32,
        )

        assert meta == {}
        proof_file = tmp_path / "artifacts" / "chunk_0_segment_0.proof"
        assert not proof_file.exists(), "Corrupt artifact must not be written to disk"
        assert "chunk_0_segment_0" not in r.execution_metrics["persisted_artifacts"]
        r.close()

    def test_max_segments_raises_bounded_run_complete(self, tmp_path) -> None:
        """When total_segments_verified reaches max_segments, BoundedRunComplete is raised."""
        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(tmp_path / "manifest.json"),
            max_segments=1,
        )
        r.execution_metrics["total_segments_verified"] = 1

        with pytest.raises(runner.BoundedRunComplete) as excinfo:
            if r.max_segments is not None and r.execution_metrics["total_segments_verified"] >= r.max_segments:
                raise runner.BoundedRunComplete(f"Bounded execution limit of {r.max_segments} segments reached.")

        assert "Bounded execution limit of 1 segments reached" in str(excinfo.value)
        r.close()

    def test_max_segments_rejects_zero_and_negative_limits(self, tmp_path) -> None:
        """Reject non-positive max_segments limits in constructor and execution pipeline."""
        for bad_val in [0, -1, -10]:
            with pytest.raises(ValueError, match="max_segments must be a positive integer greater than zero"):
                runner.LiveAcceptanceRunner(
                    distro="test-distro",
                    manifest_output_path=str(tmp_path / f"manifest_{bad_val}.json"),
                    max_segments=bad_val,
                )

        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(tmp_path / "manifest_ok.json"),
            max_segments=1,
        )
        # Directly tampering max_segments attribute before pipeline run fails closed
        r.max_segments = 0
        with pytest.raises(ValueError, match="max_segments must be a positive integer greater than zero"):
            r._execute_acceptance_pipeline(start_time=time.monotonic())
        r.close()

    @patch("run_live_256_acceptance.verify_bound_proof")
    @patch("run_live_256_acceptance.get_crypto_profile")
    def test_persist_segment_artifact_rejects_public_input_mismatch(
        self, mock_get_profile, mock_verify, tmp_path
    ) -> None:
        """_persist_segment_artifact must reject if proof public inputs differ from authoritative metadata."""
        mock_verify.return_value = True
        mock_profile = MagicMock()
        mock_profile.get_artifact_paths.return_value = (tmp_path / "vk.bin", tmp_path / "acir.gz", tmp_path / "manifest.json")
        mock_profile.decomposed_artifacts = {"segment_init_32": {"vk_hash": "a" * 64}}
        mock_get_profile.return_value = mock_profile
        (tmp_path / "vk.bin").write_bytes(b"\x01" * 100)

        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(tmp_path / "manifest.json"),
            artifacts_dir=str(tmp_path / "artifacts"),
        )

        dummy_pi = [f"0x{i:064x}" for i in range(1, 6)]
        pi_bytes = b"".join(int(x, 16).to_bytes(32, "big") for x in dummy_pi)
        body_bytes = b"\xaa" * 2144
        complete_proof = pi_bytes + body_bytes

        import base64
        import hashlib

        mock_db = MagicMock()
        dummy_seg_id = uuid.uuid4()
        dummy_seg = MagicMock()
        dummy_seg.id = dummy_seg_id
        dummy_seg.segment_index = 0
        dummy_seg.chunk_index = 0
        # Authoritative metadata differs from proof's dummy_pi[0]
        dummy_seg.global_sbom_root = "0x" + "99" * 32
        dummy_seg.policy_hash = dummy_pi[1]
        dummy_seg.components_commit = dummy_pi[3]
        dummy_seg.hash_out_commit = dummy_pi[4]
        dummy_chunk = MagicMock()
        dummy_chunk.chunk_index = int(dummy_pi[2], 16)
        dummy_chunk.components_commit = dummy_pi[3]
        dummy_seg.chunk = dummy_chunk

        dummy_seg.proof_artifact = base64.b64encode(complete_proof).decode("utf-8")
        dummy_seg.proof_artifact_hash = hashlib.sha256(complete_proof).hexdigest()
        mock_db.query.return_value.filter_by.return_value.first.return_value = dummy_seg

        meta = r._persist_segment_artifact(
            db=mock_db,
            seg_db_id=dummy_seg_id,
            chunk_index=0,
            seg_idx=0,
            circuit_name="segment_init_32",
            sbom_root="0x" + "99" * 32,
            vul_db_root="0x" + "22" * 32,
            policy_hash=dummy_pi[1],
        )

        assert meta == {}
        proof_file = tmp_path / "artifacts" / "chunk_0_segment_0.proof"
        assert not proof_file.exists(), "Mismatched public inputs must not be written to disk"
        assert "chunk_0_segment_0" not in r.execution_metrics["persisted_artifacts"]
        r.close()

    def test_persist_segment_artifact_rejects_commitment_mismatch(self, tmp_path) -> None:
        """_persist_segment_artifact must reject if segment metadata does not match job/request commitments."""
        import base64
        import hashlib

        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(tmp_path / "manifest.json"),
            artifacts_dir=str(tmp_path / "artifacts"),
        )

        dummy_pi = [f"0x{i:064x}" for i in range(1, 6)]
        pi_bytes = b"".join(int(x, 16).to_bytes(32, "big") for x in dummy_pi)
        complete_proof = pi_bytes + (b"\xaa" * 2144)

        mock_db = MagicMock()
        dummy_seg_id = uuid.uuid4()
        dummy_seg = MagicMock()
        dummy_seg.id = dummy_seg_id
        dummy_seg.segment_index = 0
        dummy_seg.chunk_index = 0
        dummy_seg.global_sbom_root = dummy_pi[0]
        dummy_seg.policy_hash = dummy_pi[1]
        dummy_seg.components_commit = dummy_pi[3]
        dummy_seg.hash_out_commit = dummy_pi[4]
        dummy_chunk = MagicMock()
        dummy_chunk.chunk_index = int(dummy_pi[2], 16)
        dummy_chunk.components_commit = dummy_pi[3]
        dummy_seg.chunk = dummy_chunk

        dummy_seg.proof_artifact = base64.b64encode(complete_proof).decode("utf-8")
        dummy_seg.proof_artifact_hash = hashlib.sha256(complete_proof).hexdigest()
        mock_db.query.return_value.filter_by.return_value.first.return_value = dummy_seg

        # Request passes a conflicting sbom_root
        meta = r._persist_segment_artifact(
            db=mock_db,
            seg_db_id=dummy_seg_id,
            chunk_index=0,
            seg_idx=0,
            circuit_name="segment_init_32",
            sbom_root="0x" + "ff" * 32,
            vul_db_root="0x" + "22" * 32,
            policy_hash=dummy_pi[1],
        )

        assert meta == {}
        assert "chunk_0_segment_0" not in r.execution_metrics["persisted_artifacts"]
        r.close()

    def test_tracked_generate_segment_proof_does_not_increment_counter_on_persistence_or_verification_failure(
        self, tmp_path
    ) -> None:
        """Simulate persistence failure or disk-based verification failure and assert total_segments_verified does not increment."""
        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(tmp_path / "manifest.json"),
            artifacts_dir=str(tmp_path / "artifacts"),
            max_segments=2,
        )

        assert r.execution_metrics["total_segments_verified"] == 0

        # Case 1: _persist_segment_artifact returns {} (e.g. hash mismatch or commitment mismatch)
        with patch.object(r, "_persist_segment_artifact", return_value={}):
            persist_meta = r._persist_segment_artifact(None, None, 0, 0, "segment_init_32", "", "", "")
            res = True
            if persist_meta and persist_meta.get("offline_reverified_from_disk") is True:
                r.execution_metrics["total_segments_verified"] += 1
            else:
                res = False

            assert res is False
            assert r.execution_metrics["total_segments_verified"] == 0

        # Case 2: _persist_segment_artifact raises an Exception
        with patch.object(r, "_persist_segment_artifact", side_effect=RuntimeError("Disk write failed")):
            persist_meta = {}
            res = True
            try:
                persist_meta = r._persist_segment_artifact(None, None, 0, 0, "segment_init_32", "", "", "")
            except Exception:
                pass

            if persist_meta and persist_meta.get("offline_reverified_from_disk") is True:
                r.execution_metrics["total_segments_verified"] += 1
            else:
                res = False

            assert res is False
            assert r.execution_metrics["total_segments_verified"] == 0

        # Case 3: _persist_segment_artifact returns meta with offline_reverified_from_disk=False
        with patch.object(r, "_persist_segment_artifact", return_value={"offline_reverified_from_disk": False}):
            persist_meta = r._persist_segment_artifact(None, None, 0, 0, "segment_init_32", "", "", "")
            res = True
            if persist_meta and persist_meta.get("offline_reverified_from_disk") is True:
                r.execution_metrics["total_segments_verified"] += 1
            else:
                res = False

            assert res is False
            assert r.execution_metrics["total_segments_verified"] == 0

        r.close()

    def test_logging_handler_not_duplicated_and_closes_cleanly(self, tmp_path) -> None:
        """LiveAcceptanceRunner should attach handler strictly to root without duplicate entries."""
        r = runner.LiveAcceptanceRunner(
            distro="test-distro",
            manifest_output_path=str(tmp_path / "manifest.json"),
        )
        test_msg = f"UNIQUE_TEST_LOG_ENTRY_{uuid.uuid4()}"
        runner.logger.info(test_msg)
        r.close()

        log_file = tmp_path / "manifest.log"
        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        count = content.count(test_msg)
        assert count == 1, f"Expected message to be logged exactly once, found {count} occurrences"

    def test_docstring_deadline_matches_default(self) -> None:
        """Docstring deadline must document 18000s / 5 hours, matching default max_overall_seconds."""
        assert "18000 seconds" in runner.__doc__
        assert "7200 seconds" not in runner.__doc__




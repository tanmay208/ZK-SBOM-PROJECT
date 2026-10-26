"""
Offline Unit Tests for scripts/run_live_256_acceptance_linux.py (Linux Cloud Runner)

These tests exercise ONLY mocked subprocess outcomes, /proc/meminfo parsing,
watchdog thresholds, monitor fail-closed behavior, process timeout, targeted
termination, cleanup guarantees, toolchain resolution, and preflight safeguards.
They do NOT invoke live Nargo, live Barretenberg, or write to any persistent database.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts directory is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import run_live_256_acceptance_linux as linux_runner

# Cross-platform signal definitions
SIGTERM = getattr(signal, "SIGTERM", 15)
SIGKILL = getattr(signal, "SIGKILL", 9)


class TestLinuxHostMemoryParsing:
    """Tests parsing and validation of Linux /proc/meminfo interface."""

    def test_parse_meminfo_with_memavailable(self, tmp_path) -> None:
        """Parse standard modern Linux /proc/meminfo with MemAvailable."""
        meminfo = tmp_path / "meminfo"
        meminfo.write_text(
            "MemTotal:       32768000 kB\n"
            "MemFree:         4096000 kB\n"
            "MemAvailable:    8388608 kB\n"  # Exactly 8.0 GiB
            "Buffers:          500000 kB\n"
            "Cached:          4000000 kB\n"
        )
        avail_bytes = linux_runner.get_linux_host_available_ram_bytes(str(meminfo))
        assert avail_bytes == 8388608 * 1024
        assert avail_bytes / (1024**3) == 8.0

        total_bytes = linux_runner.get_linux_host_total_ram_bytes(str(meminfo))
        assert total_bytes == 32768000 * 1024

    def test_parse_meminfo_fallback_calculation(self, tmp_path) -> None:
        """Fallback to MemFree + Buffers + Cached when MemAvailable is absent."""
        meminfo = tmp_path / "meminfo_legacy"
        meminfo.write_text(
            "MemTotal:       16384000 kB\n"
            "MemFree:         2000000 kB\n"
            "Buffers:         1000000 kB\n"
            "Cached:          3000000 kB\n"
        )
        avail_bytes = linux_runner.get_linux_host_available_ram_bytes(str(meminfo))
        expected_kb = 2000000 + 1000000 + 3000000
        assert avail_bytes == expected_kb * 1024

    def test_parse_meminfo_missing_file_raises_runtime_error(self, tmp_path) -> None:
        """Missing meminfo file must fail closed with RuntimeError."""
        nonexistent = str(tmp_path / "nonexistent_meminfo")
        with pytest.raises(RuntimeError) as exc_info:
            linux_runner.get_linux_host_available_ram_bytes(nonexistent)
        assert "not found" in str(exc_info.value)

    def test_parse_meminfo_malformed_raises_runtime_error(self, tmp_path) -> None:
        """Malformed meminfo file missing memory lines must fail closed."""
        meminfo = tmp_path / "meminfo_bad"
        meminfo.write_text("SwapTotal: 100000 kB\nSwapFree: 50000 kB\n")
        with pytest.raises(RuntimeError) as exc_info:
            linux_runner.get_linux_host_available_ram_bytes(str(meminfo))
        assert "Could not determine available memory" in str(exc_info.value)


class TestLinuxSafeguardMonitorOffline:
    """Tests watchdog behavior under low memory, query errors, and safety floors."""

    def test_monitor_aborts_on_low_host_ram(self, tmp_path) -> None:
        """Watchdog sets abort_event when host available RAM drops below 2.0 GiB."""
        meminfo = tmp_path / "meminfo_low"
        # 1.5 GiB available < 2.0 GiB floor
        meminfo.write_text(
            "MemTotal:       16384000 kB\n"
            "MemAvailable:    1572864 kB\n"  # 1.5 GiB
        )

        monitor = linux_runner.LinuxSafeguardMonitor(
            min_host_ram_bytes=2 * 1024 * 1024 * 1024,
            poll_interval_seconds=0.05,
            meminfo_path=str(meminfo),
        )
        monitor.start()
        try:
            aborted = monitor.abort_event.wait(timeout=2.0)
            assert aborted is True
            assert "Host available RAM breached safety floor" in monitor.abort_reason
            assert "1.50 GiB available" in monitor.abort_reason
        finally:
            monitor.stop()

    def test_monitor_fails_closed_after_repeated_query_errors(self, tmp_path) -> None:
        """Watchdog fails closed if memory queries repeatedly throw exceptions."""
        nonexistent = str(tmp_path / "no_meminfo")
        monitor = linux_runner.LinuxSafeguardMonitor(
            min_host_ram_bytes=2 * 1024 * 1024 * 1024,
            poll_interval_seconds=0.05,
            meminfo_path=nonexistent,
        )
        monitor.start()
        try:
            aborted = monitor.abort_event.wait(timeout=2.0)
            assert aborted is True
            assert "Memory monitoring unavailable (fail-closed" in monitor.abort_reason
        finally:
            monitor.stop()

    def test_runner_rejects_sub_2gib_safety_floor(self) -> None:
        """Runner must reject min_host_ram_gib < 2.0 with ValueError."""
        with pytest.raises(ValueError) as exc_info:
            linux_runner.LiveAcceptanceRunnerLinux(min_host_ram_gib=1.9)
        assert "cannot be set below the 2.0 GiB safety floor" in str(exc_info.value)

    def test_runner_default_ceilings_and_deadlines(self) -> None:
        """Validate runner defaults: 18000s overall, 120s per segment, 2.0 GiB floor."""
        r = linux_runner.LiveAcceptanceRunnerLinux()
        assert r.max_overall_seconds == 18000.0
        assert r.per_segment_timeout_seconds == 120
        assert r.min_host_ram_bytes == 2 * 1024 * 1024 * 1024


class TestLinuxTargetedProcessTrackerOffline:
    """Tests targeted process tracking, invocation wrapping, and termination."""

    def test_prepare_invocation_bash_exec_wrapping(self) -> None:
        """prepare_invocation must wrap toolchain command with bash exec and unique PID trap."""
        tracker = linux_runner.LinuxTargetedProcessTracker()
        inv_id, wrapped_cmd, pid_filename = tracker.prepare_invocation(["bb", "prove", "--test"], cwd="/tmp")

        assert inv_id in tracker.active_invocations
        assert wrapped_cmd[0] == "bash"
        assert wrapped_cmd[1] == "-c"
        assert f'echo $$ > "{pid_filename}" && exec "$@"' in wrapped_cmd[2]
        assert wrapped_cmd[3] == "--"
        assert wrapped_cmd[4:] == ["bb", "prove", "--test"]
        assert pid_filename.startswith("pid_")
        assert pid_filename.endswith(".txt")

    def test_read_and_validate_pid_valid(self, tmp_path) -> None:
        """read_and_validate_pid correctly parses valid integer PIDs."""
        tracker = linux_runner.LinuxTargetedProcessTracker()
        pid_file = tmp_path / "pid_test.txt"
        pid_file.write_text("54321\n")

        pid = tracker.read_and_validate_pid(str(tmp_path), "pid_test.txt")
        assert pid == 54321

    def test_read_and_validate_pid_rejects_malformed_and_unsafe(self, tmp_path) -> None:
        """Reject non-digits, negative integers, and system-critical PIDs (0, 1)."""
        tracker = linux_runner.LinuxTargetedProcessTracker()
        for bad_content in ["abc", "", "-1", "0", "1", "12.34", "999 888"]:
            pid_file = tmp_path / "pid_bad.txt"
            pid_file.write_text(bad_content)
            pid = tracker.read_and_validate_pid(str(tmp_path), "pid_bad.txt")
            assert pid is None, f"Expected {bad_content!r} to be rejected"

    @patch("os.kill")
    def test_terminate_targeted_worker_sigterm_clean_exit(self, mock_kill, tmp_path) -> None:
        """Clean termination sends SIGTERM and polls until process exits."""
        tracker = linux_runner.LinuxTargetedProcessTracker()
        pid_file = tmp_path / "pid_clean.txt"
        pid_file.write_text("11223")

        inv_id = "test_inv_clean"
        tracker.active_invocations[inv_id] = (str(tmp_path), "pid_clean.txt")

        # Mock: os.kill(pid, SIGTERM) succeeds.
        # Next: is_pid_alive probes os.kill(pid, 0) -> raises ProcessLookupError (dead).
        def kill_side_effect(pid, sig):
            if sig == 0:
                raise ProcessLookupError("No such process")
            return None

        mock_kill.side_effect = kill_side_effect

        success, msg = tracker.terminate_targeted_worker(inv_id)
        assert success is True
        assert tracker.cleanup_failed is False
        assert "11223" in msg
        assert "SIGTERM" in msg
        assert not os.path.exists(str(pid_file))

    @patch("os.kill")
    def test_terminate_targeted_worker_sigkill_escalation(self, mock_kill, tmp_path) -> None:
        """Escalate to SIGKILL if worker process remains alive after SIGTERM."""
        tracker = linux_runner.LinuxTargetedProcessTracker()
        pid_file = tmp_path / "pid_esc.txt"
        pid_file.write_text("33445")

        inv_id = "test_inv_esc"
        tracker.active_invocations[inv_id] = (str(tmp_path), "pid_esc.txt")

        # Call sequence:
        # 1. os.kill(pid, SIGTERM) -> None
        # 2. os.kill(pid, 0) probe 1 -> None (alive)
        # 3. os.kill(pid, 0) probe 2 -> None (alive)
        # 4. os.kill(pid, 0) probe 3 -> None (alive)
        # 5. os.kill(pid, SIGKILL) -> None
        # 6. os.kill(pid, 0) probe -> ProcessLookupError (dead)
        calls = []

        def kill_side_effect(pid, sig):
            calls.append((pid, sig))
            if sig == SIGKILL:
                return None
            if sig == 0 and any(c[1] == SIGKILL for c in calls):
                raise ProcessLookupError("Dead after SIGKILL")
            return None

        mock_kill.side_effect = kill_side_effect

        success, msg = tracker.terminate_targeted_worker(inv_id)
        assert success is True
        assert tracker.cleanup_failed is False
        assert "SIGKILL" in msg

    def test_terminate_targeted_worker_missing_pid_fails_closed(self, tmp_path) -> None:
        """Fail closed when PID file is missing, setting cleanup_failed = True."""
        tracker = linux_runner.LinuxTargetedProcessTracker()
        inv_id = "test_inv_missing"
        tracker.active_invocations[inv_id] = (str(tmp_path), "pid_nonexistent.txt")

        success, msg = tracker.terminate_targeted_worker(inv_id)
        assert success is False
        assert tracker.cleanup_failed is True
        assert "Cannot identify worker PID" in msg

    @patch("os.kill")
    def test_terminate_targeted_worker_unresponsive_fails_closed(self, mock_kill, tmp_path) -> None:
        """Fail closed if process remains alive even after SIGKILL."""
        tracker = linux_runner.LinuxTargetedProcessTracker()
        pid_file = tmp_path / "pid_stuck.txt"
        pid_file.write_text("77777")

        inv_id = "test_inv_stuck"
        tracker.active_invocations[inv_id] = (str(tmp_path), "pid_stuck.txt")

        # Process never dies: os.kill always returns None
        mock_kill.return_value = None

        success, msg = tracker.terminate_targeted_worker(inv_id)
        assert success is False
        assert tracker.cleanup_failed is True
        assert "could not be stopped" in msg


class TestLinuxActiveCommandInterruptionOffline:
    """Tests active command preemption by watchdog and deadlines on Linux."""

    @patch("subprocess.Popen")
    def test_active_command_interrupted_by_watchdog(self, mock_popen, tmp_path) -> None:
        """Active Popen call must be terminated when watchdog abort_event fires."""
        r = linux_runner.LiveAcceptanceRunnerLinux(max_overall_seconds=3600.0)

        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, None, 0]
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        pid_file = tmp_path / "pid_watchdog.txt"
        pid_file.write_text("6666")
        r.tracker.active_invocations["inv_watchdog"] = (str(tmp_path), "pid_watchdog.txt")

        with patch.object(r.tracker, "terminate_targeted_worker", return_value=(True, "Terminated")) as mock_term:
            r._terminate_active_invocation(mock_proc, "inv_watchdog")
            mock_term.assert_called_once_with("inv_watchdog")
            mock_proc.terminate.assert_called_once()

    def test_cleanup_failure_blocks_subsequent_invocations(self) -> None:
        """If worker cleanup fails, subsequent invocations must raise UncertainProcessCleanupError."""
        r = linux_runner.LiveAcceptanceRunnerLinux()
        r.tracker.cleanup_failed = True

        with pytest.raises(linux_runner.UncertainProcessCleanupError) as exc_info:
            if r.tracker.cleanup_failed:
                raise linux_runner.UncertainProcessCleanupError(
                    "Subsequent invocation blocked: previous worker cleanup failed."
                )
        assert "Subsequent invocation blocked" in str(exc_info.value)

    @patch("subprocess.Popen")
    def test_active_command_per_segment_timeout_cleans_up_pid(self, mock_popen, tmp_path) -> None:
        """When per-segment timeout triggers, _terminate_active_invocation cleans up worker PID."""
        r = linux_runner.LiveAcceptanceRunnerLinux(per_segment_timeout_seconds=1)

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


class TestLinuxToolchainResolution:
    """Tests resolution of pinned Nargo and Barretenberg toolchains on Linux."""

    def test_resolve_toolchain_unsupported_tool_raises_value_error(self) -> None:
        """Unsupported tool names must raise ValueError."""
        with pytest.raises(ValueError):
            linux_runner.resolve_linux_toolchain("solc")

    def test_resolve_toolchain_respects_env_vars(self, tmp_path) -> None:
        """Explicit NARGO_PATH and BB_PATH must take highest precedence."""
        fake_nargo = tmp_path / "nargo"
        fake_nargo.write_text("#!/bin/sh\n")
        fake_bb = tmp_path / "bb"
        fake_bb.write_text("#!/bin/sh\n")

        with patch.dict(os.environ, {"NARGO_PATH": str(fake_nargo), "BB_PATH": str(fake_bb)}):
            assert linux_runner.resolve_linux_toolchain("nargo") == str(fake_nargo)
            assert linux_runner.resolve_linux_toolchain("bb") == str(fake_bb)

    def test_resolve_toolchain_local_bin_wrapper(self) -> None:
        """.bin/bb wrapper in workspace is resolvable."""
        local_bb = PROJECT_ROOT / ".bin" / "bb"
        if local_bb.exists():
            resolved = linux_runner.resolve_linux_toolchain("bb")
            assert os.path.exists(resolved)


class TestLinuxRunnerCLIDormant:
    """Tests dormant-by-default CLI behavior on Linux runner."""

    def test_runner_exits_zero_when_dormant(self) -> None:
        """Executing runner without opt-in flags exits with returncode 0."""
        with patch("sys.argv", ["run_live_256_acceptance_linux.py"]):
            exit_code = linux_runner.main()
            assert exit_code == 0

    def test_max_segments_rejects_zero_and_negative(self) -> None:
        """--max-segments <= 0 must be rejected with returncode 2."""
        with patch("sys.argv", ["run_live_256_acceptance_linux.py", "--max-segments", "0"]):
            assert linux_runner.main() == 2

        with patch("sys.argv", ["run_live_256_acceptance_linux.py", "--max-segments", "-5"]):
            assert linux_runner.main() == 2


class TestLinuxPreflightCheckOffline:
    """Tests Linux preflight safeguards audit mode (--check-safeguards-only)."""

    def test_preflight_fails_when_ram_below_floor(self, tmp_path) -> None:
        """Preflight fails cleanly if host available RAM is below the 2.0 GiB floor."""
        meminfo = tmp_path / "meminfo_low"
        meminfo.write_text(
            "MemTotal:       16384000 kB\n"
            "MemAvailable:    1048576 kB\n"  # 1.0 GiB < 2.0 GiB
        )
        r = linux_runner.LiveAcceptanceRunnerLinux(meminfo_path=str(meminfo))
        assert r.check_safeguards_preflight() is False

    def test_preflight_verifies_fixtures_and_artifacts(self, tmp_path) -> None:
        """Preflight passes when RAM >= 2.0 GiB, fixtures exist, and circuits are configured."""
        meminfo = tmp_path / "meminfo_ok"
        meminfo.write_text(
            "MemTotal:       32768000 kB\n"
            "MemAvailable:   16777216 kB\n"  # 16.0 GiB
        )
        fake_nargo = tmp_path / "nargo"
        fake_nargo.write_text("#!/bin/sh\n")
        fake_bb = tmp_path / "bb"
        fake_bb.write_text("#!/bin/sh\n")

        with patch.dict(os.environ, {"NARGO_PATH": str(fake_nargo), "BB_PATH": str(fake_bb)}):
            r = linux_runner.LiveAcceptanceRunnerLinux(meminfo_path=str(meminfo))
            ok = r.check_safeguards_preflight()
            assert ok is True

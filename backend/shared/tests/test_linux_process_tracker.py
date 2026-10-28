import os
import signal
import subprocess
import time
import unittest

from scripts.run_live_256_acceptance_linux import (
    LinuxTargetedProcessTracker,
    check_process_state,
    UncertainProcessCleanupError,
)


class TestLinuxProcessTracker(unittest.TestCase):
    def test_check_process_state_running_and_dead(self):
        # Spawn a sleeping child
        proc = subprocess.Popen(["sleep", "10"])
        try:
            self.assertEqual(check_process_state(proc.pid), "alive")
        finally:
            proc.kill()
            proc.wait()

        self.assertEqual(check_process_state(proc.pid), "dead")
        self.assertEqual(check_process_state(999999), "dead")

    def test_is_pid_alive_detects_and_reaps_zombie(self):
        proc = subprocess.Popen(["sleep", "60"])
        pid = proc.pid
        tracker = LinuxTargetedProcessTracker()

        self.assertTrue(tracker.is_pid_alive(pid))

        # Send SIGKILL directly without calling proc.wait() or proc.poll()
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.1)

        # In old implementation, os.kill(pid, 0) returned True because pid was a zombie.
        # With the fix, is_pid_alive reaps the child with waitpid / checks /proc and returns False.
        self.assertFalse(tracker.is_pid_alive(pid))
        proc.poll()

    def test_tracker_terminate_worker_clean_sigterm(self):
        tracker = LinuxTargetedProcessTracker()
        cwd = os.getcwd()
        inv_id, cmd, pid_file = tracker.prepare_invocation(["sleep", "60"], cwd=cwd)

        proc = subprocess.Popen(cmd, cwd=cwd)
        try:
            # Wait until pid file is written and process starts
            pid_path = os.path.join(cwd, pid_file)
            for _ in range(20):
                if os.path.exists(pid_path):
                    break
                time.sleep(0.05)
            self.assertTrue(os.path.exists(pid_path))

            success, msg = tracker.terminate_targeted_worker(inv_id)
            self.assertTrue(success)
            self.assertFalse(tracker.cleanup_failed)
            self.assertFalse(os.path.exists(pid_path))
        finally:
            try:
                proc.kill()
                proc.wait(timeout=1.0)
            except Exception:
                pass

    def test_tracker_terminate_worker_escalates_to_sigkill(self):
        tracker = LinuxTargetedProcessTracker()
        cwd = os.getcwd()
        # Trap SIGTERM so it ignores SIGTERM and requires SIGKILL
        inv_id, cmd, pid_file = tracker.prepare_invocation(
            ["bash", "-c", "trap '' TERM; while true; do sleep 0.1; done"], cwd=cwd
        )

        proc = subprocess.Popen(cmd, cwd=cwd)
        try:
            pid_path = os.path.join(cwd, pid_file)
            for _ in range(20):
                if os.path.exists(pid_path):
                    break
                time.sleep(0.05)
            self.assertTrue(os.path.exists(pid_path))

            success, msg = tracker.terminate_targeted_worker(inv_id)
            self.assertTrue(success)
            self.assertFalse(tracker.cleanup_failed)
            self.assertFalse(os.path.exists(pid_path))
        finally:
            try:
                proc.kill()
                proc.wait(timeout=1.0)
            except Exception:
                pass


    def test_tracker_terminate_worker_already_exited(self):
        tracker = LinuxTargetedProcessTracker()
        cwd = os.getcwd()
        inv_id, cmd, pid_file = tracker.prepare_invocation(["true"], cwd=cwd)

        proc = subprocess.Popen(cmd, cwd=cwd)
        proc.wait(timeout=5.0)

        # Process already exited
        success, msg = tracker.terminate_targeted_worker(inv_id)
        self.assertTrue(success)
        self.assertFalse(tracker.cleanup_failed)

    def test_tracker_missing_pid_file_fails_closed(self):
        tracker = LinuxTargetedProcessTracker()
        cwd = os.getcwd()
        inv_id, cmd, pid_file = tracker.prepare_invocation(["sleep", "1"], cwd=cwd)

        # Do not run the command, pid file does not exist
        success, msg = tracker.terminate_targeted_worker(inv_id)
        self.assertFalse(success)
        self.assertTrue(tracker.cleanup_failed)
        self.assertIn("pid file missing/malformed", msg)


if __name__ == "__main__":
    unittest.main()


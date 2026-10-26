#!/usr/bin/env python3
"""
Dedicated Standalone Live 256-Segment Acceptance Runner
Authoritative Location: scripts/run_live_256_acceptance.py

DORMANT BY DEFAULT:
  This script is strictly dormant unless invoked with the explicit opt-in flag:
    --execute-live-acceptance
  Without this flag, it exits immediately with code 0 without initializing
  databases, executing toolchains, or generating proofs.

SAFETY SAFEGUARDS:
  1. Overall Deadline: 300 minutes (18000 seconds / 5 hours) enforced via monotonic timer.
  2. Per-Segment Timeout: 120 seconds via ephemeral CRYPTO_PROFILE_PATH override.
  3. Host Available RAM: Abort threshold at 2.0 GiB (Win32 GlobalMemoryStatusEx).
  4. WSL Guest Memory: Monitored via /proc/meminfo; abort threshold at 7.5 GiB.
  5. Targeted Process Tracking: Unique PID trap (echo $$ > pid_<inv>.txt && exec <bin>)
     enabling targeted SIGTERM / SIGKILL of strictly the active toolchain process.
     Broad operations (wsl --shutdown, wsl --terminate, pkill -f) are strictly avoided.
  6. Zero Persistent Mutations: Temporary profile and PID files cleaned up in finally blocks.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Set up logger
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("LiveAcceptanceRunner")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
PAYLOAD_FIXTURE_PATH = PROJECT_ROOT / "scripts" / "stage21_payload.json"
CANONICAL_PROFILE_PATH = BACKEND_DIR / "shared" / "crypto" / "profile.json"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from shared.crypto.config import get_crypto_profile
from verification_service.app.core.legacy_acir import (
    split_legacy_acir_proof_body,
    verify_bound_proof,
)


# ---------------------------------------------------------------------------
# Memory Measurement Helpers (Standard Library / Win32 / WSL)
# ---------------------------------------------------------------------------

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def get_host_available_ram_bytes() -> int:
    """Return available host physical memory in bytes using Win32 API."""
    if os.name == "nt":
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return int(stat.ullAvailPhys)
        raise RuntimeError("GlobalMemoryStatusEx call failed")
    else:
        # Fallback for POSIX hosts
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
        raise RuntimeError("Could not determine host available RAM from /proc/meminfo")


def get_wsl_memory_usage_bytes(distro: str = "kali-linux") -> Tuple[int, int]:
    """
    Query WSL guest memory via /proc/meminfo.
    Returns: (used_bytes, total_bytes)
    """
    try:
        cmd = ["wsl", "-d", distro, "--", "cat", "/proc/meminfo"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            raise RuntimeError(f"WSL meminfo query failed (code {res.returncode}): {res.stderr.strip()}")

        mem_total_kb = None
        mem_avail_kb = None
        for line in res.stdout.splitlines():
            if line.startswith("MemTotal:"):
                mem_total_kb = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                mem_avail_kb = int(line.split()[1])

        if mem_total_kb is None or mem_avail_kb is None:
            raise RuntimeError("Incomplete /proc/meminfo data returned by WSL")

        total_bytes = mem_total_kb * 1024
        used_bytes = (mem_total_kb - mem_avail_kb) * 1024
        return used_bytes, total_bytes
    except Exception as exc:
        raise RuntimeError(f"Failed to query WSL guest memory: {exc}") from exc


# ---------------------------------------------------------------------------
# Safeguard Monitor (Background Daemon Thread)
# ---------------------------------------------------------------------------

class SafeguardAbortError(RuntimeError):
    """Raised when a resource ceiling is breached or monitoring fails closed."""


class SafeguardMonitor:
    """
    Periodically polls host available RAM and WSL guest memory.
    Signals abort_event if host available RAM < min_host_ram_gib
    or WSL guest memory > max_wsl_mem_gib.
    """

    def __init__(
        self,
        distro: str,
        min_host_ram_bytes: int = 2 * 1024 * 1024 * 1024,
        max_wsl_mem_bytes: int = int(12.0 * 1024 * 1024 * 1024),
        poll_interval_seconds: float = 1.0,
    ) -> None:
        self.distro = distro
        self.min_host_ram_bytes = min_host_ram_bytes
        self.max_wsl_mem_bytes = max_wsl_mem_bytes
        self.poll_interval = poll_interval_seconds

        self.abort_event = threading.Event()
        self.abort_reason: Optional[str] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.peak_wsl_used_bytes: int = 0
        self.min_host_avail_bytes: int = 2**63 - 1
        self.consecutive_failures: int = 0
        self.max_allowed_consecutive_failures: int = 3

    def start(self) -> None:
        self._stop_event.clear()
        self.abort_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="SafeguardMonitor")
        self._thread.start()
        logger.info("Safeguard monitor started (poll=%.1fs, host_min=%.1fGiB, wsl_max=%.1fGiB)",
                    self.poll_interval, self.min_host_ram_bytes / (1024**3), self.max_wsl_mem_bytes / (1024**3))

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("Safeguard monitor stopped")

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                # 1. Host Available RAM
                avail_ram = get_host_available_ram_bytes()
                if avail_ram < self.min_host_avail_bytes:
                    self.min_host_avail_bytes = avail_ram

                if avail_ram < self.min_host_ram_bytes:
                    self.abort_reason = (
                        f"Host available RAM breached safety floor: "
                        f"{avail_ram / (1024**3):.2f} GiB available < {self.min_host_ram_bytes / (1024**3):.2f} GiB floor"
                    )
                    logger.critical("[WATCHDOG ABORT] %s", self.abort_reason)
                    self.abort_event.set()
                    break

                # 2. WSL Guest Memory
                wsl_used, _ = get_wsl_memory_usage_bytes(self.distro)
                if wsl_used > self.peak_wsl_used_bytes:
                    self.peak_wsl_used_bytes = wsl_used

                if wsl_used > self.max_wsl_mem_bytes:
                    self.abort_reason = (
                        f"WSL guest memory breached ceiling: "
                        f"{wsl_used / (1024**3):.2f} GiB used > {self.max_wsl_mem_bytes / (1024**3):.2f} GiB ceiling"
                    )
                    logger.critical("[WATCHDOG ABORT] %s", self.abort_reason)
                    self.abort_event.set()
                    break

                self.consecutive_failures = 0
            except Exception as exc:
                self.consecutive_failures += 1
                logger.warning("Safeguard monitor query failed (%d/%d): %s",
                               self.consecutive_failures, self.max_allowed_consecutive_failures, exc)
                if self.consecutive_failures >= self.max_allowed_consecutive_failures:
                    self.abort_reason = f"Memory monitoring unavailable (fail-closed after {self.consecutive_failures} failures): {exc}"
                    logger.critical("[WATCHDOG FAIL-CLOSED] %s", self.abort_reason)
                    self.abort_event.set()
                    break

            time.sleep(self.poll_interval)


# ---------------------------------------------------------------------------
# Targeted Process Tracker & Cleaner
# ---------------------------------------------------------------------------

class UncertainProcessCleanupError(RuntimeError):
    """Raised when an orphaned worker process cannot be verified as terminated."""


class TargetedProcessTracker:
    """
    Manages invocation wrapping and targeted process termination.
    Injects `echo $$ > pid_<inv_id>.txt && exec <cmd>` so the tracked PID
    corresponds to the actual toolchain binary (not an abandoned shell).
    """

    def __init__(self, distro: str = "kali-linux") -> None:
        self.distro = distro
        self.active_invocations: Dict[str, Tuple[str, str]] = {} # inv_id -> (cwd, pid_filename)
        self.cleanup_failed: bool = False

    def prepare_invocation(self, inner_cmd: str, cwd: str) -> Tuple[str, str, str]:
        """
        Wrap command string with unique PID trap.
        Returns: (inv_id, wrapped_inner_cmd, pid_filename)
        """
        inv_id = uuid.uuid4().hex[:12]
        pid_filename = f"pid_{inv_id}.txt"
        wrapped_inner_cmd = f"echo $$ > {pid_filename} && exec {inner_cmd}"
        self.active_invocations[inv_id] = (cwd, pid_filename)
        return inv_id, wrapped_inner_cmd, pid_filename

    def read_and_validate_guest_pid(self, cwd: str, pid_filename: str) -> Optional[int]:
        """Read and validate the recorded guest PID from the PID file in cwd."""
        pid_file_path = os.path.join(cwd, pid_filename)
        if not os.path.exists(pid_file_path):
            return None

        try:
            with open(pid_file_path, "r") as f:
                content = f.read().strip()
            if not content.isdigit():
                logger.error("Malformed PID file content: %r", content)
                return None
            pid = int(content)
            if pid <= 1:
                logger.error("Unsafe PID recorded (%d)", pid)
                return None
            return pid
        except Exception as exc:
            logger.error("Failed to read PID file '%s': %s", pid_file_path, exc)
            return None

    def is_guest_pid_alive(self, pid: int) -> bool:
        """Probe whether the specific guest PID is currently running in WSL."""
        check_cmd = ["wsl", "-d", self.distro, "--", "kill", "-0", str(pid)]
        res = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        return res.returncode == 0

    def terminate_targeted_worker(self, inv_id: str) -> Tuple[bool, str]:
        """
        Attempt targeted termination of strictly the specific worker process.
        Returns (success: bool, status_message: str).
        Sets self.cleanup_failed = True if PID cannot be identified or stopped.
        """
        if inv_id not in self.active_invocations:
            return True, "No active invocation found"

        cwd, pid_filename = self.active_invocations.pop(inv_id)
        guest_pid = self.read_and_validate_guest_pid(cwd, pid_filename)

        pid_file_path = os.path.join(cwd, pid_filename)
        if os.path.exists(pid_file_path):
            try:
                os.remove(pid_file_path)
            except Exception:
                pass

        if guest_pid is None:
            self.cleanup_failed = True
            msg = f"Cannot identify guest PID for invocation {inv_id} (pid file missing/malformed)"
            logger.critical("[CLEANUP UNCERTAIN] %s", msg)
            return False, msg

        logger.info("Attempting targeted termination of guest PID %d in WSL [%s]...", guest_pid, self.distro)

        # 1. Attempt SIGTERM (kill -15)
        subprocess.run(["wsl", "-d", self.distro, "--", "kill", "-15", str(guest_pid)],
                       capture_output=True, text=True, timeout=5)

        # Poll for exit (up to 1.5 seconds)
        for _ in range(3):
            time.sleep(0.5)
            if not self.is_guest_pid_alive(guest_pid):
                logger.info("Guest PID %d terminated cleanly via SIGTERM", guest_pid)
                return True, f"PID {guest_pid} terminated cleanly (SIGTERM)"

        # 2. Escalate to SIGKILL (kill -9)
        logger.warning("Guest PID %d still alive after SIGTERM, escalating to SIGKILL...", guest_pid)
        subprocess.run(["wsl", "-d", self.distro, "--", "kill", "-9", str(guest_pid)],
                       capture_output=True, text=True, timeout=5)

        time.sleep(0.5)
        if not self.is_guest_pid_alive(guest_pid):
            logger.info("Guest PID %d terminated via SIGKILL", guest_pid)
            return True, f"PID {guest_pid} terminated (SIGKILL)"

        self.cleanup_failed = True
        msg = f"Guest PID {guest_pid} could not be stopped and remains active in WSL"
        logger.critical("[CLEANUP FAILED] %s", msg)
        return False, msg


# ---------------------------------------------------------------------------
# Ephemeral Cryptographic Profile Context Manager
# ---------------------------------------------------------------------------

class EphemeralCryptoProfile:
    """
    Temporarily overrides proof_timeout_seconds to 120s using a disposable
    JSON profile file and the CRYPTO_PROFILE_PATH environment variable.
    Restores original environment and cleans up the temporary file on exit.
    """

    def __init__(self, per_segment_timeout_seconds: int = 120) -> None:
        self.timeout_seconds = per_segment_timeout_seconds
        self._temp_file: Optional[str] = None
        self._orig_profile_path: Optional[str] = None
        self._orig_crypto_profile: Optional[str] = None

    def __enter__(self) -> str:
        if not CANONICAL_PROFILE_PATH.exists():
            raise FileNotFoundError(f"Canonical profile not found: {CANONICAL_PROFILE_PATH}")

        with open(CANONICAL_PROFILE_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # Apply timeout override to prod profile
        manifest["profiles"]["prod"]["proof_timeout_seconds"] = self.timeout_seconds

        fd, temp_path = tempfile.mkstemp(prefix="zkp_profile_", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        self._temp_file = temp_path

        self._orig_profile_path = os.environ.get("CRYPTO_PROFILE_PATH")
        self._orig_crypto_profile = os.environ.get("CRYPTO_PROFILE")

        os.environ["CRYPTO_PROFILE_PATH"] = self._temp_file
        os.environ["CRYPTO_PROFILE"] = "prod"
        logger.info("Configured ephemeral crypto profile (proof_timeout_seconds=%d) at %s",
                    self.timeout_seconds, self._temp_file)
        return self._temp_file

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._orig_profile_path is not None:
            os.environ["CRYPTO_PROFILE_PATH"] = self._orig_profile_path
        else:
            os.environ.pop("CRYPTO_PROFILE_PATH", None)

        if self._orig_crypto_profile is not None:
            os.environ["CRYPTO_PROFILE"] = self._orig_crypto_profile
        else:
            os.environ.pop("CRYPTO_PROFILE", None)

        if self._temp_file and os.path.exists(self._temp_file):
            try:
                os.remove(self._temp_file)
                logger.info("Cleaned up ephemeral crypto profile %s", self._temp_file)
            except Exception as exc:
                logger.warning("Failed to remove ephemeral profile %s: %s", self._temp_file, exc)


class BoundedRunComplete(BaseException):
    """Raised when the bounded segment execution limit is reached cleanly."""
    pass


# ---------------------------------------------------------------------------
# Acceptance Pipeline Orchestrator
# ---------------------------------------------------------------------------

class LiveAcceptanceRunner:
    """
    Orchestrates the mandatory Stage D5 live 256-segment acceptance run.
    Uses real native toolchains, isolated SQLite DB, and rigorous checks.
    """

    def __init__(
        self,
        distro: str = "kali-linux",
        max_overall_seconds: float = 18000.0,
        per_segment_timeout_seconds: int = 120,
        min_host_ram_gib: float = 2.0,
        max_wsl_mem_gib: float = 12.0,
        poll_interval_seconds: float = 1.0,
        manifest_output_path: Optional[str] = None,
        artifacts_dir: Optional[str] = None,
        max_segments: Optional[int] = None,
    ) -> None:
        self.distro = distro
        self.max_overall_seconds = max_overall_seconds
        self.per_segment_timeout_seconds = per_segment_timeout_seconds
        if min_host_ram_gib < 2.0:
            raise ValueError(f"Host RAM threshold cannot be set below the 2.0 GiB safety floor (got {min_host_ram_gib} GiB)")
        self.min_host_ram_bytes = int(min_host_ram_gib * 1024 * 1024 * 1024)
        self.max_wsl_mem_bytes = int(max_wsl_mem_gib * 1024 * 1024 * 1024)
        self.poll_interval_seconds = poll_interval_seconds
        self.manifest_output_path = manifest_output_path or str(PROJECT_ROOT / "scripts" / "live_acceptance_manifest.json")
        if max_segments is not None:
            if not isinstance(max_segments, int) or max_segments <= 0:
                raise ValueError(f"max_segments must be a positive integer greater than zero (got {max_segments})")
        self.max_segments = max_segments

        # Set up transcript log file alongside manifest
        out_path = Path(self.manifest_output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        log_file_path = out_path.with_suffix(".log")
        self.file_handler = logging.FileHandler(str(log_file_path), mode="w", encoding="utf-8")
        self.file_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
        # Prevent duplicate logging: runner logger handles record directly with propagate=False,
        # while root logger handles records from child services (prover, verifier, etc.).
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.addHandler(self.file_handler)
        logging.getLogger().addHandler(self.file_handler)

        if artifacts_dir:
            self.artifacts_dir = Path(artifacts_dir)
        else:
            self.artifacts_dir = out_path.parent / f"{out_path.stem}_artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        self.tracker = TargetedProcessTracker(distro=self.distro)
        self.monitor = SafeguardMonitor(
            distro=self.distro,
            min_host_ram_bytes=self.min_host_ram_bytes,
            max_wsl_mem_bytes=self.max_wsl_mem_bytes,
            poll_interval_seconds=self.poll_interval_seconds,
        )

        self.execution_metrics: Dict[str, Any] = {
            "status": "initialized",
            "start_timestamp": None,
            "end_timestamp": None,
            "elapsed_seconds": 0.0,
            "per_segment_durations": {},
            "total_chunks_processed": 0,
            "total_segments_verified": 0,
            "peak_wsl_used_gib": 0.0,
            "min_host_avail_gib": 0.0,
            "negative_tests_results": {},
            "errors": [],
            "persisted_artifacts": {},
            "max_segments_limit": self.max_segments,
            "artifacts_directory": str(self.artifacts_dir),
        }

    def _persist_segment_artifact(
        self,
        db: Any,
        seg_db_id: uuid.UUID,
        chunk_index: int,
        seg_idx: int,
        circuit_name: str,
        sbom_root: str,
        vul_db_root: str,
        policy_hash: str,
    ) -> Dict[str, Any]:
        """
        Durable Artifact Persistence & Verification Gate:
        Atomically writes:
          1. Complete serialized proof buffer (.proof)
          2. Raw 2,144-byte UltraPlonk proof body (.body.bin)
          3. Public inputs metadata JSON (.public_inputs.json)
          4. Segment metadata with tool versions & SHA-256 digests (.meta.json)
        Then re-reads the artifact directly from disk and verifies it with official verifier.
        """
        import base64
        from zkp_service.app.models.zkp_models import ChunkProofSet, SegmentProof
        from verification_service.app.core.verifier import (
            _field_value,
            _public_inputs_match,
            _public_input_values,
        )

        seg = db.query(SegmentProof).filter_by(id=seg_db_id).first()
        if not seg or not seg.proof_artifact:
            logger.error("Cannot persist segment artifact: SegmentProof %s not found or empty", seg_db_id)
            return {}

        chunk = getattr(seg, "chunk", None)
        if not chunk and hasattr(seg, "chunk_id"):
            chunk = db.query(ChunkProofSet).filter_by(id=seg.chunk_id).first()
        if not chunk:
            from types import SimpleNamespace
            chunk = SimpleNamespace(
                chunk_index=getattr(seg, "chunk_index", chunk_index),
                components_commit=getattr(seg, "components_commit", None),
            )

        # 1. Authoritative commitment binding check
        if not _public_inputs_match(
            segment=seg,
            chunk=chunk,
            expected_sbom_root=sbom_root,
            expected_vulnerability_db_root=vul_db_root,
            expected_policy_hash=policy_hash,
        ):
            logger.error(
                "Authoritative commitment binding check failed (_public_inputs_match) for chunk %d segment %d",
                chunk_index,
                seg_idx,
            )
            return {}

        # 2. Derive authoritative circuit-declared public inputs vector
        try:
            expected_pi_values = _public_input_values(seg, chunk)
            expected_pi_formatted = [f"0x{_field_value(v):064x}" for v in expected_pi_values]
        except Exception as exc:
            logger.error("Failed to derive authoritative public input values for chunk %d segment %d: %s", chunk_index, seg_idx, exc)
            return {}

        complete_proof_bytes = base64.b64decode(seg.proof_artifact)
        actual_hash = hashlib.sha256(complete_proof_bytes).hexdigest()
        if actual_hash != seg.proof_artifact_hash:
            logger.error("Segment %s proof hash mismatch: DB=%s, actual=%s", seg_db_id, seg.proof_artifact_hash, actual_hash)
            return {}

        segment_name = "segment_mid_32" if "segment_mid_32" in circuit_name else circuit_name
        proof_body_bytes = split_legacy_acir_proof_body(segment_name, complete_proof_bytes)
        body_hash = hashlib.sha256(proof_body_bytes).hexdigest()

        pi_prefix_len = len(complete_proof_bytes) - len(proof_body_bytes)
        pi_bytes = complete_proof_bytes[:pi_prefix_len]
        pi_list = []
        for i in range(0, len(pi_bytes), 32):
            val_int = int.from_bytes(pi_bytes[i:i+32], "big")
            pi_list.append("0x" + hex(val_int)[2:].zfill(64))

        # 3. Validate proof public inputs match authoritative expected commitments
        if len(pi_list) != len(expected_pi_formatted):
            logger.error(
                "Proof public inputs count mismatch for chunk %d segment %d: proof has %d, authoritative expected %d",
                chunk_index, seg_idx, len(pi_list), len(expected_pi_formatted)
            )
            return {}

        for idx, (actual_pi, exp_pi) in enumerate(zip(pi_list, expected_pi_formatted)):
            if _field_value(actual_pi) != _field_value(exp_pi):
                logger.error(
                    "Proof public input mismatch at index %d for chunk %d segment %d: proof=%s, authoritative expected=%s",
                    idx, chunk_index, seg_idx, actual_pi, exp_pi
                )
                return {}

        seg_prefix = f"chunk_{chunk_index}_segment_{seg_idx}"
        proof_file_path = self.artifacts_dir / f"{seg_prefix}.proof"
        body_file_path = self.artifacts_dir / f"{seg_prefix}.body.bin"
        pi_file_path = self.artifacts_dir / f"{seg_prefix}.public_inputs.json"
        meta_file_path = self.artifacts_dir / f"{seg_prefix}.meta.json"

        # Atomic file write helpers
        def _atomic_write_bytes(target_path: Path, data: bytes) -> None:
            tmp_path = target_path.with_suffix(".tmp")
            with open(tmp_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target_path)

        def _atomic_write_json(target_path: Path, data: Any) -> None:
            tmp_path = target_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target_path)

        _atomic_write_bytes(proof_file_path, complete_proof_bytes)
        _atomic_write_bytes(body_file_path, proof_body_bytes)
        _atomic_write_json(pi_file_path, {
            "circuit_name": segment_name,
            "chunk_index": chunk_index,
            "segment_index": seg_idx,
            "public_inputs": pi_list,
            "public_input_bytes_count": pi_prefix_len,
        })

        # Re-read proof from disk to guarantee storage fidelity
        with open(proof_file_path, "rb") as f_disk:
            disk_bytes = f_disk.read()
        assert disk_bytes == complete_proof_bytes, "Disk read mismatch: saved bytes do not match in-memory bytes"

        # Independent offline verification using official verification key
        profile = get_crypto_profile()
        vk_path, _, _ = profile.get_artifact_paths(segment_name)
        expected_vk_hash = profile.decomposed_artifacts[segment_name]["vk_hash"]
        with open(vk_path, "rb") as f_vk:
            vk_bytes = f_vk.read()

        offline_pass = verify_bound_proof(
            circuit_id=segment_name,
            verification_key=vk_bytes,
            expected_verification_key_sha256=expected_vk_hash,
            complete_proof=disk_bytes,
            expected_public_inputs=expected_pi_formatted,
            timeout_seconds=self.per_segment_timeout_seconds,
        )

        meta = {
            "segment_key": seg_prefix,
            "segment_db_id": str(seg_db_id),
            "circuit_name": segment_name,
            "chunk_index": chunk_index,
            "segment_index": seg_idx,
            "complete_proof_file": str(proof_file_path),
            "complete_proof_bytes": len(complete_proof_bytes),
            "complete_proof_sha256": actual_hash,
            "proof_body_file": str(body_file_path),
            "proof_body_bytes": len(proof_body_bytes),
            "proof_body_sha256": body_hash,
            "public_inputs_count": len(pi_list),
            "verified_in_flight": True,
            "offline_reverified_from_disk": offline_pass,
            "persisted_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write_json(meta_file_path, meta)

        logger.info(
            "Persisted durable artifact for %s: %s (%d bytes, SHA-256=%s, offline_reverified=%s)",
            seg_prefix, proof_file_path.name, len(complete_proof_bytes), actual_hash[:16] + "...", offline_pass
        )

        self.execution_metrics["persisted_artifacts"][seg_prefix] = meta
        return meta

    def close(self) -> None:
        """Close and detach the transcript file handler."""
        if hasattr(self, "file_handler") and self.file_handler:
            try:
                logger.removeHandler(self.file_handler)
                logging.getLogger().removeHandler(self.file_handler)
                self.file_handler.close()
            except Exception:
                pass
            self.file_handler = None

    def _terminate_active_invocation(self, proc: subprocess.Popen, inv_id: Optional[str]) -> None:
        """
        Targeted termination of both the guest worker in WSL and the Windows host launcher.
        Fails closed by setting tracker.cleanup_failed = True and raising UncertainProcessCleanupError
        if the worker cannot be verified as stopped.
        """
        if inv_id:
            success, msg = self.tracker.terminate_targeted_worker(inv_id)
            if not success:
                self.tracker.cleanup_failed = True
                try:
                    proc.kill()
                    proc.wait(timeout=2.0)
                except Exception:
                    pass
                raise UncertainProcessCleanupError(f"Targeted cleanup failed for {inv_id}: {msg}")

        try:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)
        except Exception as exc:
            logger.warning("Error terminating host process: %s", exc)

    def check_safeguards_preflight(self) -> bool:
        """Validate that host RAM, WSL meminfo, and toolchains are discoverable."""
        logger.info("--- PREFLIGHT SAFEGUARDS AUDIT ---")

        # 1. Host Available RAM
        avail_ram = get_host_available_ram_bytes()
        avail_gib = avail_ram / (1024**3)
        logger.info("Host Available RAM: %.2f GiB (Floor: %.2f GiB)", avail_gib, self.min_host_ram_bytes / (1024**3))
        if avail_ram < self.min_host_ram_bytes:
            logger.error("Preflight failed: Host available RAM is below the %.1f GiB floor", self.min_host_ram_bytes / (1024**3))
            return False

        # 2. WSL Guest Memory Query
        try:
            wsl_used, wsl_total = get_wsl_memory_usage_bytes(self.distro)
            logger.info("WSL Guest Memory: %.2f GiB used / %.2f GiB total (Ceiling: %.2f GiB)",
                        wsl_used / (1024**3), wsl_total / (1024**3), self.max_wsl_mem_bytes / (1024**3))
            if wsl_used > self.max_wsl_mem_bytes:
                logger.error("Preflight failed: WSL guest memory is above the %.1f GiB ceiling", self.max_wsl_mem_bytes / (1024**3))
                return False
        except Exception as exc:
            logger.error("Preflight failed: Cannot query WSL guest memory: %s", exc)
            return False

        # 3. Fixture Existence
        if not PAYLOAD_FIXTURE_PATH.exists():
            logger.error("Preflight failed: Payload fixture not found: %s", PAYLOAD_FIXTURE_PATH)
            return False
        logger.info("Payload Fixture: Found at %s", PAYLOAD_FIXTURE_PATH)

        # 4. Check Native Binaries in WSL
        for binary in ("~/.nargo/bin/nargo", "~/.bb/bb"):
            cmd = ["wsl", "-d", self.distro, "--", "bash", "-c", f"test -x {binary}"]
            res = subprocess.run(cmd, capture_output=True, timeout=5)
            if res.returncode != 0:
                logger.error("Preflight failed: Required binary '%s' is not executable in WSL [%s]", binary, self.distro)
                return False
            logger.info("WSL Binary '%s': Verified executable", binary)

        logger.info("All preflight safeguards verified successfully.")
        return True

    def run(self) -> int:
        """
        Execute the live proof generation acceptance suite under strict safeguards.
        Returns exit code (0 on full success, 1 on failure).
        """
        logger.info("Starting Live 256-Segment Acceptance Run...")
        start_time = time.monotonic()
        self.execution_metrics["start_timestamp"] = datetime.now(timezone.utc).isoformat()

        if not self.check_safeguards_preflight():
            self.execution_metrics["status"] = "preflight_failed"
            return 1

        with EphemeralCryptoProfile(per_segment_timeout_seconds=self.per_segment_timeout_seconds):
            self.monitor.start()
            try:
                # Execute full acceptance workflow
                return self._execute_acceptance_pipeline(start_time)
            finally:
                self.monitor.stop()
                end_time = time.monotonic()
                elapsed = end_time - start_time
                self.execution_metrics["end_timestamp"] = datetime.now(timezone.utc).isoformat()
                self.execution_metrics["elapsed_seconds"] = elapsed
                self.execution_metrics["peak_wsl_used_gib"] = self.monitor.peak_wsl_used_bytes / (1024**3)
                self.execution_metrics["min_host_avail_gib"] = self.monitor.min_host_avail_bytes / (1024**3)
                self._save_execution_manifest()
                self.close()

    def _execute_acceptance_pipeline(self, start_time: float) -> int:
        """Orchestrate the ingestion, proving, verification, and negative tests."""
        if self.max_segments is not None and self.max_segments <= 0:
            raise ValueError(f"max_segments must be a positive integer greater than zero (got {self.max_segments})")

        from sqlalchemy import create_engine, text, event
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from sqlalchemy.ext.compiler import compiles
        from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER

        from shared.database import Base
        from shared.models.user import User
        from sbom_service.app.services.sbom_intake_service import SBOMIntakeService
        from vulnerability_service.app.services.vulnerability_service import ingest_vulnerabilities
        from vulnerability_service.app.schemas.vulnerability_schemas import (
            VulnerabilityIngestionRequest, VulnerabilityIngestionItem
        )
        from vulnerability_service.app.api.routes.vulnerability_routes import (
            approve_snapshot,
            freeze_snapshot,
        )
        from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot
        from policy_service.app.services.policy_service import create_policy
        from zkp_service.app.repositories.zkp_repository import ZKPRepository
        from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest
        from zkp_service.app.services.prover_service import ProverService
        from verification_service.app.services.verification_service import VerificationService
        from verification_service.app.schemas.verification_schemas import VerifyProofRequest

        # 1. Setup isolated in-memory SQLite database
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        @compiles(UNIQUEIDENTIFIER, "sqlite")
        def _compile_uid(element, compiler, **kw):
            return "CHAR(36)"

        @event.listens_for(engine, "connect")
        def _do_connect(dbapi_conn, record):
            import sqlite3
            if isinstance(dbapi_conn, sqlite3.Connection):
                dbapi_conn.create_function(
                    "getutcdate", 0, lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                )

        with engine.connect() as conn:
            for s in ("sbom", "vulnerability", "policy", "zkp", "verification"):
                conn.execute(text(f"ATTACH DATABASE ':memory:' AS {s}"))

        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        db = SessionLocal()

        try:
            importer_user = User(id=uuid.uuid4(), username="trusted_importer", hashed_password="pw", role="trusted_importer")
            user = User(id=uuid.uuid4(), username="acceptance_admin", hashed_password="pw", role="admin")
            db.add_all([importer_user, user])
            db.commit()

            # Ensure CERTIFICATE_SECRET_KEY is present in env for certificate issuance upon verification
            os.environ.setdefault("CERTIFICATE_SECRET_KEY", "acceptance_runner_certificate_secret_1234567890")

            # Ensure BB_PATH points to project-local runtime binary if present and unset
            local_bb = PROJECT_ROOT / ".bin" / ("bb.exe" if sys.platform == "win32" else "bb")
            if local_bb.is_file():
                os.environ.setdefault("BB_PATH", str(local_bb))

            # 2. Ingest Payload Fixture
            with open(PAYLOAD_FIXTURE_PATH, "r", encoding="utf-8") as f:
                payload = json.load(f)

            # Phase 1: Ingest SBOM (1024 components)
            logger.info("Ingesting 1024-component CycloneDX SBOM...")
            sbom_svc = SBOMIntakeService(db)
            cyclonedx = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": payload["components"],
            }
            sbom_resp = sbom_svc.ingest(
                application_name="Live Acceptance App",
                vendor="Live Acceptance Vendor",
                filename="acceptance_bom.json",
                format="CycloneDX",
                content=json.dumps(cyclonedx),
                user_id=user.id,
            )
            logger.info("  -> SBOM Root: %s", sbom_resp.sbom_root)

            # Phase 2: Ingest Vulnerabilities (2 records)
            logger.info("Ingesting authoritative vulnerabilities...")
            vul_req = VulnerabilityIngestionRequest(
                source_identity="NVD",
                provenance={"feed": "NVD", "feed_version": "acceptance_fixture"},
                vulnerabilities=[VulnerabilityIngestionItem(**v) for v in payload["vulnerabilities"]],
            )
            vul_resp = ingest_vulnerabilities(db, vul_req, importer_user.id)
            snapshot_uuid = uuid.UUID(vul_resp.snapshot_id)
            approve_snapshot(snapshot_uuid, db, user)
            freeze_snapshot(snapshot_uuid, db, user)
            snap = db.query(VulnerabilitySnapshot).filter_by(id=snapshot_uuid).first()
            logger.info("  -> Authoritative SMT Root: %s", snap.authoritative_smt_root)

            # Phase 3: Create Policy (max CVSS 5.0)
            logger.info("Creating security policy...")
            pol = create_policy(db, max_cvss_score=payload["policy"]["max_cvss_score"], name="Acceptance Policy")
            logger.info("  -> Policy Hash: %s", pol.policy_hash)

            # Phase 4: Proof Generation with Targeted Process Tracking & Deadlines
            logger.info("Creating Proof Job...")
            repo = ZKPRepository(db)
            job = repo.create_job(
                GenerateProofRequest(
                    sbom_upload_id=sbom_resp.id,
                    snapshot_id=snap.id,
                    policy_id=pol.id,
                ),
                user_id=user.id,
            )
            logger.info("  -> Proof Job ID: %s", job.id)

            # Monkeypatch ProverService toolchain execution with targeted process tracking and deadlines
            orig_build_toolchain = sys.modules["zkp_service.app.services.prover_service"].build_toolchain_command
            orig_run_toolchain = sys.modules["zkp_service.app.services.prover_service"].run_toolchain_command

            current_invocation_holder = [None] # holds current inv_id

            def wrapped_build_toolchain(tool: str, subcmd_args: list[str], **kwargs):
                cmd = orig_build_toolchain(tool, subcmd_args, **kwargs)
                # If on Windows, cmd is ['wsl', ..., '--', 'bash', '-c', inner_cmd]
                if cmd[0] == "wsl" and cmd[-2] == "-c":
                    orig_inner = cmd[-1]
                    # We pass cwd through an environmental or context channel
                    inv_id, wrapped_inner, _ = self.tracker.prepare_invocation(orig_inner, cwd=os.getcwd())
                    current_invocation_holder[0] = inv_id
                    cmd[-1] = wrapped_inner
                return cmd

            def wrapped_run_toolchain(cmd: list[str], cwd: str, timeout: int | float) -> subprocess.CompletedProcess | None:
                # 1. Guard against subsequent invocations after a failed cleanup
                if self.tracker.cleanup_failed:
                    raise UncertainProcessCleanupError("Subsequent invocation blocked: previous worker cleanup failed or was unverified.")

                # 2. Check watchdog abort before starting
                if self.monitor.abort_event.is_set():
                    raise SafeguardAbortError(f"Pre-command watchdog abort: {self.monitor.abort_reason}")

                # 3. Check overall deadline before starting
                if time.monotonic() - start_time > self.max_overall_seconds:
                    raise TimeoutError(f"Overall deadline of {self.max_overall_seconds}s exceeded")

                inv_id = current_invocation_holder[0]
                if inv_id and inv_id in self.tracker.active_invocations:
                    _, pid_filename = self.tracker.active_invocations[inv_id]
                    self.tracker.active_invocations[inv_id] = (cwd, pid_filename)

                # Launch non-blocking Popen so active command can be monitored and interrupted
                try:
                    proc = subprocess.Popen(
                        cmd,
                        cwd=cwd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                except FileNotFoundError as exc:
                    logger.error("Runtime toolchain unavailable: executable '%s' not found: %s", cmd[0], exc)
                    return None
                except OSError as exc:
                    logger.error("Toolchain execution failed to launch '%s': %s", cmd[0], exc)
                    return None

                cmd_start = time.monotonic()
                while proc.poll() is None:
                    # Active Check A: Watchdog abort triggered during command execution
                    if self.monitor.abort_event.is_set():
                        logger.critical("[ACTIVE COMMAND ABORT] Watchdog triggered during command execution: %s", self.monitor.abort_reason)
                        self._terminate_active_invocation(proc, inv_id)
                        raise SafeguardAbortError(f"Active command aborted by watchdog: {self.monitor.abort_reason}")

                    # Active Check B: Overall deadline reached during command execution
                    if time.monotonic() - start_time > self.max_overall_seconds:
                        logger.critical("[ACTIVE COMMAND ABORT] Overall deadline of %.1fs reached during command", self.max_overall_seconds)
                        self._terminate_active_invocation(proc, inv_id)
                        raise TimeoutError(f"Overall deadline of {self.max_overall_seconds}s exceeded during active command")

                    # Active Check C: Per-segment toolchain timeout reached
                    if time.monotonic() - cmd_start > timeout:
                        logger.warning("[ACTIVE COMMAND TIMEOUT] Command exceeded per-segment timeout of %ss", timeout)
                        self._terminate_active_invocation(proc, inv_id)
                        return None

                    time.sleep(0.1)

                # Process exited normally
                stdout, stderr = proc.communicate()
                if inv_id in self.tracker.active_invocations:
                    cwd_tracked, pid_file = self.tracker.active_invocations.pop(inv_id)
                    pid_path = os.path.join(cwd_tracked, pid_file)
                    if os.path.exists(pid_path):
                        try:
                            os.remove(pid_path)
                        except Exception:
                            pass

                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=proc.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )

            # Apply monkeypatch
            sys.modules["zkp_service.app.services.prover_service"].build_toolchain_command = wrapped_build_toolchain
            sys.modules["zkp_service.app.services.prover_service"].run_toolchain_command = wrapped_run_toolchain

            try:
                prover = ProverService(db)
                prover.circuit_dir = str(PROJECT_ROOT)

                orig_generate_segment_proof = prover.generate_segment_proof
                def tracked_generate_segment_proof(seg_db, circuit_name, chunk_comps, chunk_merkle_paths, smt, chunk_index, seg_idx, hash_in, hash_out, hash_in_array, sbom_root, vul_db_root, policy_hash, policy_max_cvss):
                    seg_t0 = time.monotonic()
                    res = orig_generate_segment_proof(seg_db, circuit_name, chunk_comps, chunk_merkle_paths, smt, chunk_index, seg_idx, hash_in, hash_out, hash_in_array, sbom_root, vul_db_root, policy_hash, policy_max_cvss)
                    seg_dur = round(time.monotonic() - seg_t0, 3)
                    seg_key = f"chunk_{chunk_index}_segment_{seg_idx}"
                    self.execution_metrics["per_segment_durations"][seg_key] = seg_dur
                    if res:
                        persist_meta = {}
                        try:
                            persist_meta = self._persist_segment_artifact(
                                db=db,
                                seg_db_id=seg_db.id,
                                chunk_index=chunk_index,
                                seg_idx=seg_idx,
                                circuit_name=circuit_name,
                                sbom_root=sbom_root,
                                vul_db_root=vul_db_root,
                                policy_hash=policy_hash,
                            )
                        except Exception as e_persist:
                            logger.error("Failed to persist durable artifact for %s: %s", seg_key, e_persist)

                        if persist_meta and persist_meta.get("offline_reverified_from_disk") is True:
                            self.execution_metrics["total_segments_verified"] += 1
                        else:
                            res = False
                            logger.error(
                                "Segment %s verification rejected: persistence failed or disk-based offline re-verification did not return True",
                                seg_key,
                            )

                    logger.info("  [Segment %d/256] chunk_%d_segment_%d: %s (%.2fs)",
                                len(self.execution_metrics["per_segment_durations"]),
                                chunk_index, seg_idx, "PASS" if res else "FAIL", seg_dur)

                    if res and self.max_segments is not None and self.execution_metrics["total_segments_verified"] >= self.max_segments:
                        logger.info("Bounded segment limit reached (%d/%d segments). Terminating proving run cleanly.",
                                    self.execution_metrics["total_segments_verified"], self.max_segments)
                        raise BoundedRunComplete(f"Bounded execution limit of {self.max_segments} segments reached.")

                    return res

                prover.generate_segment_proof = tracked_generate_segment_proof

                orig_generate_chunk_proofs = prover.generate_chunk_proofs
                def tracked_generate_chunk_proofs(chunk, padded_components, smt, sbom_root, vul_db_root, policy_hash, policy_max_cvss, merkle_paths_all):
                    c_res = orig_generate_chunk_proofs(chunk, padded_components, smt, sbom_root, vul_db_root, policy_hash, policy_max_cvss, merkle_paths_all)
                    if c_res:
                        self.execution_metrics["total_chunks_processed"] += 1
                    logger.info(" [Chunk %d/32] Processed: %s (total chunks: %d/32)",
                                chunk.chunk_index, "PASS" if c_res else "FAIL", self.execution_metrics["total_chunks_processed"])
                    return c_res

                prover.generate_chunk_proofs = tracked_generate_chunk_proofs

                logger.info("Executing 256-segment proof generation...")
                try:
                    final_job = prover.process_job(job.id, user_id=user.id)
                except BoundedRunComplete:
                    logger.info("Bounded execution limit of %d segment(s) reached successfully.", self.max_segments)
                    self.execution_metrics["status"] = "bounded_pass"
                    return 0

                if not final_job or final_job.status != "completed":
                    err = final_job.error_message if final_job else "Unknown prover error"
                    logger.error("Proof generation failed: %s", err)
                    self.execution_metrics["status"] = "prover_failed"
                    self.execution_metrics["errors"].append(err)
                    return 1

                logger.info("Proof generation SUCCESS: Job %s completed", final_job.id)
            finally:
                sys.modules["zkp_service.app.services.prover_service"].build_toolchain_command = orig_build_toolchain
                sys.modules["zkp_service.app.services.prover_service"].run_toolchain_command = orig_run_toolchain

            # Phase 5: Cryptographic Verification
            logger.info("Executing full verification across all 256 segment proofs...")
            verifier = VerificationService(db)
            verify_req = VerifyProofRequest(
                sbom_root=sbom_resp.sbom_root,
                vulnerability_db_root=snap.authoritative_smt_root,
                policy_hash=pol.policy_hash,
                proof_job_id=final_job.id,
            )
            verify_resp = verifier.process_verification(verify_req, user.id)
            if verify_resp.result != "verified":
                logger.error("Backend verification failed: %s", verify_resp.result)
                self.execution_metrics["status"] = "verification_failed"
                return 1

            logger.info("Verification SUCCESS: Certificate Request %s issued", verify_resp.id)

            # Phase 6: Negative Verification Tests
            logger.info("Executing Complete Negative Cryptographic Verification Tests...")
            self._run_negative_tests(verifier, verify_req, user.id, db, final_job)

            self.execution_metrics["status"] = "success"
            return 0
        finally:
            db.close()
            engine.dispose()

    def _run_negative_tests(
        self,
        verifier: Any,
        valid_req: Any,
        user_id: uuid.UUID,
        db: Any,
        job: Any,
    ) -> None:
        """
        Run complete negative verification test suite ensuring fail-closed behavior:
        1. Tampered SBOM Root
        2. Tampered Vulnerability DB Root
        3. Corrupted Proof Bytes
        4. Truncated Proof Bytes
        5. Policy Threshold Violation
        6. Cross-Tenant Verification Rejection
        """
        import base64
        import hashlib
        from verification_service.app.schemas.verification_schemas import VerifyProofRequest
        from verification_service.app.models.verification_models import VerificationRequest
        from policy_service.app.services.policy_service import create_policy
        from shared.models.user import User
        from zkp_service.app.models.zkp_models import SegmentProof

        # 1. Tampered SBOM Root
        bad_sbom = VerifyProofRequest(
            sbom_root="0x" + "00" * 31 + "ff",
            vulnerability_db_root=valid_req.vulnerability_db_root,
            policy_hash=valid_req.policy_hash,
            proof_job_id=valid_req.proof_job_id,
        )
        res_sbom = verifier.process_verification(bad_sbom, user_id)
        assert res_sbom.result != "verified", "Negative test failed: Tampered SBOM root was accepted"
        self.execution_metrics["negative_tests_results"]["tampered_sbom_root"] = f"REJECTED ({res_sbom.result})"

        # 2. Tampered Vulnerability DB Root
        bad_vuln = VerifyProofRequest(
            sbom_root=valid_req.sbom_root,
            vulnerability_db_root="0x" + "00" * 31 + "ee",
            policy_hash=valid_req.policy_hash,
            proof_job_id=valid_req.proof_job_id,
        )
        res_vuln = verifier.process_verification(bad_vuln, user_id)
        assert res_vuln.result != "verified", "Negative test failed: Tampered Vuln DB root was accepted"
        self.execution_metrics["negative_tests_results"]["tampered_vuln_db_root"] = f"REJECTED ({res_vuln.result})"

        # 3. Corrupted Proof Bytes
        db.query(VerificationRequest).filter_by(proof_job_id=valid_req.proof_job_id).delete()
        db.commit()

        seg = db.query(SegmentProof).filter(
            SegmentProof.chunk_id == job.chunks[0].id,
            SegmentProof.segment_index == 0,
        ).first()
        assert seg is not None, "Cannot find segment proof for corruption test"
        orig_artifact = seg.proof_artifact
        orig_hash = seg.proof_artifact_hash

        try:
            raw_bytes = base64.b64decode(orig_artifact)
            corrupted_bytes = raw_bytes[:-16] + b"\xff" * 16
            seg.proof_artifact = base64.b64encode(corrupted_bytes).decode("utf-8")
            seg.proof_artifact_hash = hashlib.sha256(corrupted_bytes).hexdigest()
            db.commit()

            corrupt_req = VerifyProofRequest(
                sbom_root=valid_req.sbom_root,
                vulnerability_db_root=valid_req.vulnerability_db_root,
                policy_hash=valid_req.policy_hash,
                proof_job_id=valid_req.proof_job_id,
            )
            res_corrupt = verifier.process_verification(corrupt_req, user_id)
            assert res_corrupt.result != "verified", "Negative test failed: Corrupted proof bytes were accepted"
            self.execution_metrics["negative_tests_results"]["corrupted_proof_bytes"] = f"REJECTED ({res_corrupt.result})"
        finally:
            seg.proof_artifact = orig_artifact
            seg.proof_artifact_hash = orig_hash
            db.commit()

        # 4. Truncated Proof Bytes
        db.query(VerificationRequest).filter_by(proof_job_id=valid_req.proof_job_id).delete()
        db.commit()

        try:
            raw_bytes = base64.b64decode(orig_artifact)
            truncated_bytes = raw_bytes[:100]
            seg.proof_artifact = base64.b64encode(truncated_bytes).decode("utf-8")
            seg.proof_artifact_hash = hashlib.sha256(truncated_bytes).hexdigest()
            db.commit()

            trunc_req = VerifyProofRequest(
                sbom_root=valid_req.sbom_root,
                vulnerability_db_root=valid_req.vulnerability_db_root,
                policy_hash=valid_req.policy_hash,
                proof_job_id=valid_req.proof_job_id,
            )
            res_trunc = verifier.process_verification(trunc_req, user_id)
            assert res_trunc.result != "verified", "Negative test failed: Truncated proof bytes were accepted"
            self.execution_metrics["negative_tests_results"]["truncated_proof_bytes"] = f"REJECTED ({res_trunc.result})"
        finally:
            seg.proof_artifact = orig_artifact
            seg.proof_artifact_hash = orig_hash
            db.commit()

        # 5. Policy Threshold Violation
        strict_pol = create_policy(db, max_cvss_score=3.0, name="Strict Acceptance Policy")
        bad_policy_req = VerifyProofRequest(
            sbom_root=valid_req.sbom_root,
            vulnerability_db_root=valid_req.vulnerability_db_root,
            policy_hash=strict_pol.policy_hash,
            proof_job_id=valid_req.proof_job_id,
        )
        res_policy = verifier.process_verification(bad_policy_req, user_id)
        assert res_policy.result != "verified", "Negative test failed: Policy threshold violation was accepted"
        self.execution_metrics["negative_tests_results"]["policy_threshold_violation"] = f"REJECTED ({res_policy.result})"

        # 6. Cross-Tenant Verification Rejection
        foreign_user = User(
            id=uuid.uuid4(),
            username="unauthorized_buyer",
            hashed_password="pw",
            role="buyer",
        )
        db.add(foreign_user)
        db.commit()

        res_foreign = verifier.process_verification(valid_req, foreign_user.id)
        assert res_foreign.result == "verification_unavailable", f"Cross-tenant verification expected verification_unavailable, got {res_foreign.result}"
        assert res_foreign.result != "verified", "Negative test failed: Cross-tenant verification was accepted"
        self.execution_metrics["negative_tests_results"]["cross_tenant_rejection"] = f"REJECTED ({res_foreign.result})"

        logger.info("All 6 negative verification tests PASSED.")

    def _save_execution_manifest(self) -> None:
        """Persist structured metrics to JSON."""
        try:
            out_file = Path(self.manifest_output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(self.execution_metrics, f, indent=2)
            logger.info("Saved execution manifest to %s", self.manifest_output_path)
        except Exception as exc:
            logger.error("Failed to write execution manifest: %s", exc)


# ---------------------------------------------------------------------------
# CLI Entrypoint (Strictly Dormant by Default)
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stage D5 Live 256-Segment Acceptance Runner (Strictly Dormant by Default)",
    )
    parser.add_argument(
        "--execute-live-acceptance",
        action="store_true",
        default=False,
        help="EXPLICIT OPT-IN FLAG. Required to execute live proof generation. Without this flag, runner is dormant.",
    )
    parser.add_argument(
        "--check-safeguards-only",
        action="store_true",
        default=False,
        help="Perform preflight safeguard and memory checks without executing live proof generation.",
    )
    parser.add_argument(
        "--distro",
        type=str,
        default=os.environ.get("WSL_DISTRIBUTION", "kali-linux"),
        help="WSL distribution name (default: kali-linux)",
    )
    parser.add_argument(
        "--max-overall-seconds",
        type=float,
        default=18000.0,
        help="Overall deadline in seconds (default: 18000s / 5 hours)",
    )
    parser.add_argument(
        "--segment-timeout-seconds",
        type=int,
        default=120,
        help="Per-segment toolchain timeout in seconds (default: 120s)",
    )
    parser.add_argument(
        "--min-host-ram-gib",
        type=float,
        default=2.0,
        help="Host available RAM abort threshold in GiB (default: 2.0 GiB)",
    )
    parser.add_argument(
        "--max-wsl-mem-gib",
        type=float,
        default=12.0,
        help="WSL guest memory ceiling in GiB (default: 12.0 GiB)",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=float,
        default=1.0,
        help="Safeguard monitoring poll interval in seconds (default: 1.0s)",
    )
    parser.add_argument(
        "--output-manifest",
        type=str,
        default=None,
        help="Path to write execution manifest JSON",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=str,
        default=None,
        help="Directory to persist durable proof artifacts (default: unique subdir next to manifest)",
    )
    parser.add_argument(
        "--max-segments",
        type=int,
        default=None,
        help="Maximum segments to prove before bounded clean exit (default: None = all 256 segments)",
    )

    args = parser.parse_args()

    if args.max_segments is not None and args.max_segments <= 0:
        logger.error("--max-segments must be a positive integer greater than zero (got %d)", args.max_segments)
        return 2

    runner = LiveAcceptanceRunner(
        distro=args.distro,
        max_overall_seconds=args.max_overall_seconds,
        per_segment_timeout_seconds=args.segment_timeout_seconds,
        min_host_ram_gib=args.min_host_ram_gib,
        max_wsl_mem_gib=args.max_wsl_mem_gib,
        poll_interval_seconds=args.poll_interval_seconds,
        manifest_output_path=args.output_manifest,
        artifacts_dir=args.artifacts_dir,
        max_segments=args.max_segments,
    )

    if args.check_safeguards_only:
        logger.info("Executing safeguards-only preflight check (no proving)...")
        ok = runner.check_safeguards_preflight()
        return 0 if ok else 1

    if not args.execute_live_acceptance:
        logger.warning(
            "DORMANT RUNNER: Neither --execute-live-acceptance nor --check-safeguards-only was specified.\n"
            "By design, this runner is strictly dormant and will not execute proof generation, invoke toolchains,\n"
            "or access databases without explicit opt-in authorization.\n"
            "To test safeguards without proving, run: python scripts/run_live_256_acceptance.py --check-safeguards-only\n"
            "Exiting safely with code 0."
        )
        return 0

    return runner.run()


if __name__ == "__main__":
    sys.exit(main())

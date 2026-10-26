"""
Job Ownership and Recovery Module for ZKP Proof Jobs (AUD-A-003).

Provides safe distributed job ownership using PostgreSQL session-level
advisory locks, with deterministic 64-bit key derivation and connection
isolation to avoid connection pool lock retention.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof

logger = logging.getLogger(__name__)

# Fallback lock registry for non-PostgreSQL dialects (e.g., SQLite in unit tests)
_mock_held_locks: set[int] = set()
_mock_lock = threading.Lock()


def job_lock_key(job_id: UUID) -> int:
    """
    Derive a deterministic signed 64-bit integer from a 128-bit UUID.
    PostgreSQL pg_advisory_lock(bigint) expects a signed 64-bit integer
    ranging from -2^63 to 2^63 - 1.
    """
    val = job_id.int
    # XOR upper 64 bits and lower 64 bits so all 128 bits contribute
    key64 = ((val >> 64) ^ (val & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    if key64 >= (1 << 63):
        key64 -= (1 << 64)
    return key64


class WorkerJobLock:
    """
    Encapsulates ownership of a proof job via a dedicated database connection.
    Holding this object means the worker holds the session-level advisory lock
    in PostgreSQL.
    """

    def __init__(
        self,
        job_id: UUID,
        conn: Connection | None,
        key: int,
        is_postgresql: bool,
    ) -> None:
        self.job_id = job_id
        self._conn = conn
        self.key = key
        self.is_postgresql = is_postgresql
        self._released = False

    def release(self) -> None:
        """
        Safely release the advisory lock and close the underlying connection.
        Ensures the connection cannot retain or transfer locks in connection pools.
        """
        if self._released:
            return
        self._released = True

        if self.is_postgresql and self._conn is not None:
            try:
                self._conn.execute(
                    text("SELECT pg_advisory_unlock(:k)"),
                    {"k": self.key},
                )
            except Exception as exc:
                logger.warning(
                    "Error executing pg_advisory_unlock for job %s: %s",
                    self.job_id,
                    exc,
                )
            finally:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
        else:
            with _mock_lock:
                _mock_held_locks.discard(self.key)
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None


class JobLockManager:
    """
    Manages lock acquisition and active-job probing across workers.
    """

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._is_postgresql = (engine.dialect.name == "postgresql")

    def acquire_worker_lock(self, job_id: UUID) -> WorkerJobLock:
        """
        Acquire ownership lock for job_id on a dedicated connection.
        Must be acquired before or during job creation to protect the
        initial persistence-to-background-scheduling window.
        """
        key = job_lock_key(job_id)
        if self._is_postgresql:
            conn = self._engine.connect()
            try:
                acquired = conn.execute(
                    text("SELECT pg_try_advisory_lock(:k)"),
                    {"k": key},
                ).scalar()
                if not acquired:
                    conn.close()
                    raise RuntimeError(
                        f"Failed to acquire advisory lock for job {job_id}: already held"
                    )
                return WorkerJobLock(job_id, conn, key, is_postgresql=True)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                raise
        else:
            with _mock_lock:
                if key in _mock_held_locks:
                    raise RuntimeError(
                        f"Failed to acquire lock for job {job_id}: already held"
                    )
                _mock_held_locks.add(key)
            return WorkerJobLock(job_id, None, key, is_postgresql=False)

    def is_job_active(self, job_id: UUID) -> bool:
        """
        Probe whether a live worker holds the lock for job_id.
        Returns True if a live worker holds the lock (job is actively running).
        Returns False if the lock is free (worker is dead, crashed, or terminated).
        """
        key = job_lock_key(job_id)
        if self._is_postgresql:
            with self._engine.connect() as probe_conn:
                acquired = probe_conn.execute(
                    text("SELECT pg_try_advisory_lock(:k)"),
                    {"k": key},
                ).scalar()
                if acquired:
                    # Successfully acquired probe lock -> no worker held it!
                    # Release probe lock immediately and report inactive.
                    try:
                        probe_conn.execute(
                            text("SELECT pg_advisory_unlock(:k)"),
                            {"k": key},
                        )
                    except Exception:
                        pass
                    return False
                # Lock could not be acquired -> live worker currently holds it.
                return True
        else:
            with _mock_lock:
                return key in _mock_held_locks


def get_job_lock_manager(engine: Engine) -> JobLockManager:
    """Return a JobLockManager instance for the given engine."""
    return JobLockManager(engine)


def reconcile_abandoned_job(db: Session, job: ProofJob) -> bool:
    """
    If a job is in an active status ('pending', 'assembling_witness', 'running')
    and its worker lock is NOT held, mark the job and its incomplete
    chunks and segments as 'failed'.

    Acquires the advisory/mock lock for the job during reconciliation so that:
    1. If a live worker holds the lock, reconciliation aborts immediately.
    2. If no worker holds the lock, recovery acquires it exclusively across
       the entire database transaction, preventing any concurrent worker
       or recovery probe from racing until the transaction is committed.

    Returns True if the job was reconciled, False if it was live or not active.
    """
    if job.status not in ("pending", "assembling_witness", "running"):
        return False

    engine = db.get_bind()
    mgr = get_job_lock_manager(engine)
    try:
        recovery_lock = mgr.acquire_worker_lock(job.id)
    except RuntimeError:
        # Genuinely live worker is executing this job (or another reconciler is actively holding it)
        return False

    try:
        try:
            db.refresh(job)
        except Exception:
            pass

        if job.status not in ("pending", "assembling_witness", "running"):
            return False

        # Definitively abandoned: reconcile job
        job.status = "failed"
        job.error_message = "Proof generation worker terminated unexpectedly"
        job.completed_at = datetime.now(timezone.utc)

        # Reconcile incomplete chunks and segments
        for chunk in job.chunks:
            if chunk.status in ("pending", "running"):
                chunk.status = "failed"
            for seg in chunk.segments:
                if seg.status in ("pending", "running"):
                    seg.status = "failed"
                    seg.completed_at = datetime.now(timezone.utc)

        db.commit()
        logger.info("Reconciled abandoned proof job %s to failed", job.id)
        return True
    finally:
        recovery_lock.release()


def reconcile_all_abandoned_jobs(db: Session, engine: Engine) -> int:
    """
    Reconcile all active proof jobs across the database whose worker lock is free.
    Safe on startup: live workers holding locks are never touched.
    Returns the count of reconciled jobs.
    """
    active_jobs = (
        db.query(ProofJob)
        .filter(ProofJob.status.in_(("pending", "assembling_witness", "running")))
        .all()
    )
    reconciled_count = 0
    for job in active_jobs:
        if reconcile_abandoned_job(db, job):
            reconciled_count += 1
    return reconciled_count

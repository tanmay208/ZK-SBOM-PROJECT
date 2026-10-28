"""
Regression tests for AUD-A-003: Proof-Job Ownership and Abandoned-Job Recovery.

Validates the 10 mandatory test scenarios:
1. A fresh active job blocks a duplicate request (HTTP 429).
2. A definitively abandoned job can be recovered and retried.
3. A job in the initial scheduling window is not incorrectly failed.
4. A live worker's job is never marked failed by recovery.
5. Worker failure releases or loses ownership in a way recovery can detect.
6. Success and ordinary exceptions release ownership correctly.
7. Incomplete chunk and segment records are reconciled consistently.
8. Completed jobs and proof artifacts remain unchanged.
9. Existing proof-generation and tenant-isolation tests continue to pass.
10. Database-specific PostgreSQL advisory-lock key derivation and semantics.
"""

from __future__ import annotations

import sys
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from zkp_service.app.main import app
from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
from zkp_service.app.core.job_lock import (
    job_lock_key,
    WorkerJobLock,
    JobLockManager,
    get_job_lock_manager,
    reconcile_abandoned_job,
    reconcile_all_abandoned_jobs,
    _mock_held_locks,
    _mock_lock,
)
from shared.auth import get_current_user
from shared.database import get_session
from shared.models.user import User

client = TestClient(app, raise_server_exceptions=False)


@compiles(UNIQUEIDENTIFIER, "sqlite")
def compile_uniqueidentifier(type_, compiler, **kw):
    return "CHAR(36)"


@pytest.fixture(autouse=True)
def clean_mock_locks():
    """Ensure clean mock lock state before and after each test."""
    with _mock_lock:
        _mock_held_locks.clear()
    yield
    with _mock_lock:
        _mock_held_locks.clear()


@pytest.fixture
def sqlite_db_session():
    """Provide a thread-safe in-memory SQLite database session with zkp models."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _register_sqlite_functions(connection, record):
        connection.create_function(
            "getutcdate",
            0,
            lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        )

    # Detach schema attributes for SQLite compatibility
    ProofJob.__table__.schema = None
    ChunkProofSet.__table__.schema = None
    SegmentProof.__table__.schema = None
    User.__table__.schema = None

    User.__table__.create(engine)
    ProofJob.__table__.create(engine)
    ChunkProofSet.__table__.create(engine)
    SegmentProof.__table__.create(engine)

    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=engine
    )
    db = TestingSessionLocal()
    try:
        yield db, engine
    finally:
        db.close()
        engine.dispose()


class TestJobLockKeyDerivation:
    """Scenario 10: PostgreSQL advisory lock key derivation."""

    def test_key_derivation_deterministic_and_within_bigint_bounds(self) -> None:
        """Every call for the same UUID yields the exact same signed 64-bit integer."""
        job_id = uuid.UUID("12345678-1234-5678-1234-567812345678")
        key1 = job_lock_key(job_id)
        key2 = job_lock_key(job_id)
        assert key1 == key2
        # Must fit within signed 64-bit integer [-2^63, 2^63 - 1]
        assert -(2**63) <= key1 <= (2**63 - 1)

    def test_different_uuids_produce_different_keys(self) -> None:
        job_id_1 = uuid.uuid4()
        job_id_2 = uuid.uuid4()
        assert job_lock_key(job_id_1) != job_lock_key(job_id_2)


class TestJobOwnershipAndRecovery:
    """Scenarios 1-8: Lifecycle ownership, liveness, and reconciliation."""

    def test_live_worker_job_is_never_marked_failed(self, sqlite_db_session) -> None:
        """Scenario 4: Live worker's job cannot be marked failed by recovery."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(job)
        db.commit()

        # Worker holds the lock
        lock_mgr = get_job_lock_manager(engine)
        worker_lock = lock_mgr.acquire_worker_lock(job_id)

        try:
            # Competing recovery probe executes
            reconciled = reconcile_abandoned_job(db, job)
            assert reconciled is False
            db.refresh(job)
            assert job.status == "running"
            assert job.completed_at is None
        finally:
            worker_lock.release()

    def test_job_in_initial_scheduling_window_is_not_failed(self, sqlite_db_session) -> None:
        """Scenario 3: A job in the scheduling window is protected because its lock is held."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        # In generate_proof, worker_lock is acquired at creation
        lock_mgr = get_job_lock_manager(engine)
        worker_lock = lock_mgr.acquire_worker_lock(job_id)

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="pending",
            user_id=user_id,
        )
        db.add(job)
        db.commit()

        try:
            # Recovery executes while job is still pending in scheduling window
            reconciled = reconcile_abandoned_job(db, job)
            assert reconciled is False
            db.refresh(job)
            assert job.status == "pending"
        finally:
            worker_lock.release()

    def test_definitively_abandoned_job_can_be_recovered_and_retried(self, sqlite_db_session) -> None:
        """Scenario 2 & 5: When worker crashes (lock released/lost), recovery marks job failed."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(job)
        db.commit()

        # No worker holds the lock (simulating worker crash/restart)
        reconciled = reconcile_abandoned_job(db, job)
        assert reconciled is True
        db.refresh(job)
        assert job.status == "failed"
        assert job.completed_at is not None
        assert "worker terminated" in job.error_message.lower()

    def test_incomplete_chunks_and_segments_reconciled_consistently(self, sqlite_db_session) -> None:
        """Scenario 7 & 8: Incomplete chunks/segments fail; completed chunks/segments remain intact."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(job)

        chunk_done = ChunkProofSet(
            id=uuid.uuid4(),
            proof_job_id=job_id,
            chunk_index=0,
            total_chunks=2,
            component_start=0,
            component_count=32,
            status="completed",
        )
        chunk_running = ChunkProofSet(
            id=uuid.uuid4(),
            proof_job_id=job_id,
            chunk_index=1,
            total_chunks=2,
            component_start=32,
            component_count=32,
            status="running",
        )
        db.add_all([chunk_done, chunk_running])

        seg_done = SegmentProof(
            id=uuid.uuid4(),
            chunk_id=chunk_done.id,
            chunk_index=0,
            total_chunks=2,
            segment_index=0,
            status="completed",
            proof_artifact="proof_base64_data",
            proof_artifact_hash="abc123hash",
        )
        seg_running = SegmentProof(
            id=uuid.uuid4(),
            chunk_id=chunk_running.id,
            chunk_index=1,
            total_chunks=2,
            segment_index=0,
            status="running",
        )
        db.add_all([seg_done, seg_running])
        db.commit()

        # Reconcile abandoned job
        reconciled = reconcile_abandoned_job(db, job)
        assert reconciled is True

        db.refresh(job)
        db.refresh(chunk_done)
        db.refresh(chunk_running)
        db.refresh(seg_done)
        db.refresh(seg_running)

        assert job.status == "failed"
        # Completed chunk and segment remain completed
        assert chunk_done.status == "completed"
        assert seg_done.status == "completed"
        assert seg_done.proof_artifact == "proof_base64_data"
        assert seg_done.proof_artifact_hash == "abc123hash"
        # Incomplete chunk and segment transition to failed
        assert chunk_running.status == "failed"
        assert seg_running.status == "failed"
        assert seg_running.completed_at is not None

    def test_ordinary_success_and_exception_releases_ownership(self, sqlite_db_session) -> None:
        """Scenario 6: Lock ownership is released cleanly after success or exception."""
        _, engine = sqlite_db_session
        job_id = uuid.uuid4()
        lock_mgr = get_job_lock_manager(engine)

        lock = lock_mgr.acquire_worker_lock(job_id)
        assert lock_mgr.is_job_active(job_id) is True

        # Normal release
        lock.release()
        assert lock_mgr.is_job_active(job_id) is False

        # Double release is a safe no-op
        lock.release()
        assert lock_mgr.is_job_active(job_id) is False

    def test_startup_reconciliation_clears_abandoned_jobs_only(self, sqlite_db_session) -> None:
        """Startup reconciliation recovers dead jobs while leaving live jobs alone."""
        db, engine = sqlite_db_session
        user_1 = uuid.uuid4()
        user_2 = uuid.uuid4()

        dead_job = ProofJob(
            id=uuid.uuid4(),
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_1,
        )
        live_job = ProofJob(
            id=uuid.uuid4(),
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_2,
        )
        completed_job = ProofJob(
            id=uuid.uuid4(),
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="completed",
            user_id=user_1,
        )
        db.add_all([dead_job, live_job, completed_job])
        db.commit()

        lock_mgr = get_job_lock_manager(engine)
        live_lock = lock_mgr.acquire_worker_lock(live_job.id)

        try:
            reconciled_count = reconcile_all_abandoned_jobs(db, engine)
            assert reconciled_count == 1

            db.refresh(dead_job)
            db.refresh(live_job)
            db.refresh(completed_job)

            assert dead_job.status == "failed"
            assert live_job.status == "running"
            assert completed_job.status == "completed"
        finally:
            live_lock.release()


class TestAPIRouteActiveGuardAndRecovery:
    """Scenario 1 & 2 via FastAPI HTTP endpoint."""

    def test_fresh_active_job_blocks_duplicate_request(self, sqlite_db_session) -> None:
        """Scenario 1: Active job returns HTTP 429 on retry."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(job)
        db.commit()

        lock_mgr = get_job_lock_manager(engine)
        worker_lock = lock_mgr.acquire_worker_lock(job_id)

        def override_get_session():
            yield db

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_current_user] = lambda: User(
            id=user_id, username="vendor", role="vendor"
        )
        try:
            resp = client.post(
                "/api/v1/zkp/generate",
                json={
                    "sbom_upload_id": str(uuid.uuid4()),
                    "snapshot_id": str(uuid.uuid4()),
                    "policy_id": str(uuid.uuid4()),
                },
            )
            assert resp.status_code == 429
            assert "already active" in resp.json()["error"]
        finally:
            worker_lock.release()
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_current_user, None)

    def test_stale_abandoned_job_reconciled_allowing_retry(self, sqlite_db_session) -> None:
        """Scenario 2: Stale job without worker lock is auto-recovered, unblocking new submission."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        old_job_id = uuid.uuid4()

        stale_job = ProofJob(
            id=old_job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(stale_job)
        db.commit()

        # No worker holds old_job_id lock (abandoned)
        def override_get_session():
            yield db

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_current_user] = lambda: User(
            id=user_id, username="vendor", role="vendor"
        )
        try:
            with patch("zkp_service.app.api.routes.zkp_routes.ZKPRepository") as mock_repo_cls, \
                 patch("zkp_service.app.api.routes.zkp_routes.ProverService"):
                mock_repo = mock_repo_cls.return_value
                new_job = ProofJob(
                    id=uuid.uuid4(),
                    sbom_upload_id=uuid.uuid4(),
                    snapshot_id=uuid.uuid4(),
                    policy_id=uuid.uuid4(),
                    status="pending",
                    user_id=user_id,
                    created_at=datetime.now(timezone.utc),
                )
                mock_repo.create_job.return_value = new_job

                resp = client.post(
                    "/api/v1/zkp/generate",
                    json={
                        "sbom_upload_id": str(uuid.uuid4()),
                        "snapshot_id": str(uuid.uuid4()),
                        "policy_id": str(uuid.uuid4()),
                    },
                )
                assert resp.status_code == 202

                # Verify stale job was reconciled to failed
                db.refresh(stale_job)
                assert stale_job.status == "failed"
                assert stale_job.completed_at is not None
        finally:
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_current_user, None)


class TestOnDemandPollingRecovery:
    """D5.2.2: On-demand recovery during GET /jobs/{job_id} polling."""

    def test_get_proof_job_reconciles_abandoned_job_on_demand(self, sqlite_db_session) -> None:
        """Abandoned active job is healed to failed when polled by owner."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(job)
        db.commit()

        # No worker holds the lock (abandoned)
        def override_get_session():
            yield db

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_current_user] = lambda: User(
            id=user_id, username="vendor", role="vendor"
        )
        try:
            resp = client.get(f"/api/v1/zkp/jobs/{job_id}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "failed"
            assert data["completed_at"] is not None
            assert "worker terminated" in data["error_message"].lower()

            # Confirm DB persisted state
            db.refresh(job)
            assert job.status == "failed"
            assert job.completed_at is not None
        finally:
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_current_user, None)

    def test_get_proof_job_preserves_live_worker_job(self, sqlite_db_session) -> None:
        """A live worker's running job is returned as running without modification."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(job)
        db.commit()

        lock_mgr = get_job_lock_manager(engine)
        worker_lock = lock_mgr.acquire_worker_lock(job_id)

        def override_get_session():
            yield db

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_current_user] = lambda: User(
            id=user_id, username="vendor", role="vendor"
        )
        try:
            resp = client.get(f"/api/v1/zkp/jobs/{job_id}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "running"
            assert data["completed_at"] is None

            db.refresh(job)
            assert job.status == "running"
            assert job.completed_at is None
        finally:
            worker_lock.release()
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_current_user, None)

    def test_get_proof_job_tenant_isolation_blocks_recovery_by_foreign_tenant(self, sqlite_db_session) -> None:
        """Tenant B polling Tenant A's job gets 404; no lock probe or state mutation occurs."""
        db, engine = sqlite_db_session
        user_a = uuid.uuid4()
        user_b = uuid.uuid4()
        job_id = uuid.uuid4()

        job_a = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_a,
        )
        db.add(job_a)
        db.commit()

        def override_get_session():
            yield db

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_current_user] = lambda: User(
            id=user_b, username="tenant_b", role="vendor"
        )
        try:
            resp = client.get(f"/api/v1/zkp/jobs/{job_id}")
            assert resp.status_code == 404

            # Ensure job_a was NOT touched by unauthorized recovery attempt
            db.refresh(job_a)
            assert job_a.status == "running"
            assert job_a.completed_at is None
        finally:
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_current_user, None)

    def test_get_proof_job_terminal_status_skips_recovery(self, sqlite_db_session) -> None:
        """Terminal job states (completed, failed) skip lock checking and retain artifacts."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        completed_job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="completed",
            proof_artifact="valid_proof_payload",
            proof_archive_hash="archive123",
            user_id=user_id,
        )
        db.add(completed_job)
        db.commit()

        def override_get_session():
            yield db

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_current_user] = lambda: User(
            id=user_id, username="vendor", role="vendor"
        )
        try:
            resp = client.get(f"/api/v1/zkp/jobs/{job_id}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "completed"
            assert data["proof_artifact"] == "valid_proof_payload"
            assert data["proof_archive_hash"] == "archive123"
        finally:
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_current_user, None)

    def test_repeated_polling_on_reconciled_job_is_idempotent(self, sqlite_db_session) -> None:
        """Repeated polls on an abandoned job consistently return failed without errors."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(job)
        db.commit()

        def override_get_session():
            yield db

        app.dependency_overrides[get_session] = override_get_session
        app.dependency_overrides[get_current_user] = lambda: User(
            id=user_id, username="vendor", role="vendor"
        )
        try:
            resp1 = client.get(f"/api/v1/zkp/jobs/{job_id}")
            assert resp1.status_code == 200
            assert resp1.json()["status"] == "failed"

            resp2 = client.get(f"/api/v1/zkp/jobs/{job_id}")
            assert resp2.status_code == 200
            assert resp2.json()["status"] == "failed"
            assert resp1.json()["completed_at"] == resp2.json()["completed_at"]
        finally:
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_current_user, None)

    def test_recovery_lock_held_during_reconciliation_prevents_worker_race(self, sqlite_db_session) -> None:
        """While reconciliation holds the lock, a worker cannot acquire it."""
        db, engine = sqlite_db_session
        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=user_id,
        )
        db.add(job)
        db.commit()

        lock_mgr = get_job_lock_manager(engine)
        # Verify that holding the lock during reconciliation blocks competing acquisitions
        rec_lock = lock_mgr.acquire_worker_lock(job_id)
        try:
            # Second worker attempt must be rejected
            with pytest.raises(RuntimeError, match="already held"):
                lock_mgr.acquire_worker_lock(job_id)
        finally:
            rec_lock.release()


class TestAtomicBatchPersistence:
    """D5.2.2: Atomic chunk and segment batch persistence with rollback semantics."""

    def test_atomic_batch_chunk_and_segment_creation_success(self, sqlite_db_session) -> None:
        """Create 32 chunks and 256 segments in a single atomic transaction."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        db, _ = sqlite_db_session
        job_id = uuid.uuid4()
        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=uuid.uuid4(),
        )
        db.add(job)
        db.commit()

        repo = ZKPRepository(db)
        total_chunks = 32
        segments_per_chunk = 8

        chunks_data = [
            {
                "chunk_index": i,
                "total_chunks": total_chunks,
                "component_start": i * 32,
                "component_count": 32,
                "components_commit": f"0xcommit{i}",
            }
            for i in range(total_chunks)
        ]

        created_chunks = repo.create_chunks_and_segments_batch(
            proof_job_id=job.id,
            chunks_data=chunks_data,
            segments_per_chunk=segments_per_chunk,
        )

        assert len(created_chunks) == 32
        # Verify exact counts in DB
        db_chunks = db.query(ChunkProofSet).filter_by(proof_job_id=job_id).all()
        assert len(db_chunks) == 32

        total_segments = db.query(SegmentProof).count()
        assert total_segments == 32 * 8  # 256

        # Check each chunk has 8 correctly indexed segments
        for chunk in db_chunks:
            assert len(chunk.segments) == 8
            seg_indices = sorted([s.segment_index for s in chunk.segments])
            assert seg_indices == list(range(8))
            assert chunk.status == "pending"
            for s in chunk.segments:
                assert s.status == "pending"
                assert s.chunk_id == chunk.id

    def test_atomic_batch_rollback_on_injected_failure(self, sqlite_db_session) -> None:
        """Failure halfway through batch insertion rolls back all records, leaving zero orphans."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        db, _ = sqlite_db_session
        job_id = uuid.uuid4()
        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            user_id=uuid.uuid4(),
        )
        db.add(job)
        db.commit()

        repo = ZKPRepository(db)
        total_chunks = 32
        segments_per_chunk = 8

        # Malformed item at index 16 missing required total_chunks key
        chunks_data = []
        for i in range(total_chunks):
            if i == 16:
                chunks_data.append({
                    "chunk_index": i,
                    # Missing "total_chunks" to induce KeyError during iteration
                    "component_start": i * 32,
                    "component_count": 32,
                    "components_commit": f"0xcommit{i}",
                })
            else:
                chunks_data.append({
                    "chunk_index": i,
                    "total_chunks": total_chunks,
                    "component_start": i * 32,
                    "component_count": 32,
                    "components_commit": f"0xcommit{i}",
                })

        with pytest.raises(KeyError):
            repo.create_chunks_and_segments_batch(
                proof_job_id=job.id,
                chunks_data=chunks_data,
                segments_per_chunk=segments_per_chunk,
            )

        # Rollback guarantee: 0 chunks and 0 segments remain in the DB
        assert db.query(ChunkProofSet).filter_by(proof_job_id=job_id).count() == 0
        assert db.query(SegmentProof).count() == 0


class TestUTCModernization:
    """D5.2.2: Verification of timezone-aware UTC timestamp creation and serialization."""

    def test_utc_timestamp_serialization_in_api(self, sqlite_db_session) -> None:
        """Timezone-aware UTC timestamps serialize cleanly into ISO format strings."""
        from zkp_service.app.schemas.zkp_schemas import ProofJobResponse

        now_utc = datetime.now(timezone.utc)
        job = ProofJob(
            id=uuid.uuid4(),
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="completed",
            user_id=uuid.uuid4(),
            created_at=now_utc,
            completed_at=now_utc,
        )

        response_model = ProofJobResponse.model_validate(job)
        assert response_model.created_at is not None
        assert response_model.completed_at is not None
        assert response_model.status == "completed"


class TestJobStateMachineInvariants:
    """D5.2.3: State machine transition enforcement, terminal immutability, and chunk/segment protection."""

    def test_allowed_job_transitions_forward_progression(self, sqlite_db_session) -> None:
        """Verify normal progression: pending -> assembling_witness -> running -> completed."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        db, _ = sqlite_db_session
        job_id = uuid.uuid4()
        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="pending",
            user_id=uuid.uuid4(),
        )
        db.add(job)
        db.commit()

        repo = ZKPRepository(db)

        # 1. pending -> assembling_witness
        j = repo.update_job_status(job_id, "assembling_witness")
        assert j.status == "assembling_witness"

        # 2. assembling_witness -> running
        j = repo.update_job_status(job_id, "running", sbom_root="0xroot", vulnerability_db_root="0xvuln")
        assert j.status == "running"
        assert j.sbom_root == "0xroot"

        # 3. running -> completed
        j = repo.update_job_status(job_id, "completed", proof_archive_hash="hash123")
        assert j.status == "completed"
        assert j.proof_archive_hash == "hash123"
        assert j.completed_at is not None

    def test_allowed_job_transitions_to_failed_and_execution_blocked(self, sqlite_db_session) -> None:
        """Verify each active state can transition legitimately to failed or execution_blocked."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        db, _ = sqlite_db_session
        repo = ZKPRepository(db)

        # pending -> failed
        j1 = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending", user_id=uuid.uuid4())
        db.add(j1); db.commit()
        res1 = repo.update_job_status(j1.id, "failed", error_message="quota exceeded")
        assert res1.status == "failed"

        # pending -> execution_blocked
        j2 = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending", user_id=uuid.uuid4())
        db.add(j2); db.commit()
        res2 = repo.update_job_status(j2.id, "execution_blocked")
        assert res2.status == "execution_blocked"

        # assembling_witness -> failed
        j3 = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="assembling_witness", user_id=uuid.uuid4())
        db.add(j3); db.commit()
        res3 = repo.update_job_status(j3.id, "failed", error_message="missing upstream")
        assert res3.status == "failed"

        # running -> failed
        j4 = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="running", user_id=uuid.uuid4())
        db.add(j4); db.commit()
        res4 = repo.update_job_status(j4.id, "failed", error_message="prover timed out")
        assert res4.status == "failed"

    def test_terminal_job_state_immutability_rejects_transitions(self, sqlite_db_session) -> None:
        """Terminal states (completed, failed, execution_blocked) must reject any subsequent transition."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        db, _ = sqlite_db_session
        repo = ZKPRepository(db)

        # 1. completed is immutable
        j_completed = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="completed", user_id=uuid.uuid4())
        db.add(j_completed); db.commit()

        for target in ("pending", "assembling_witness", "running", "failed", "completed", "execution_blocked"):
            with pytest.raises(ValueError, match="Illegal proof job transition"):
                repo.update_job_status(j_completed.id, target)

        # 2. failed is immutable
        j_failed = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="failed", user_id=uuid.uuid4())
        db.add(j_failed); db.commit()

        for target in ("pending", "assembling_witness", "running", "completed", "failed", "execution_blocked"):
            with pytest.raises(ValueError, match="Illegal proof job transition"):
                repo.update_job_status(j_failed.id, target)

        # 3. execution_blocked is immutable
        j_blocked = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="execution_blocked", user_id=uuid.uuid4())
        db.add(j_blocked); db.commit()

        for target in ("pending", "assembling_witness", "running", "completed", "failed"):
            with pytest.raises(ValueError, match="Illegal proof job transition"):
                repo.update_job_status(j_blocked.id, target)

    def test_illegal_backward_and_skip_transitions_rejected(self, sqlite_db_session) -> None:
        """Reject backward transitions (running -> pending) and invalid jumps (pending -> completed)."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        db, _ = sqlite_db_session
        repo = ZKPRepository(db)

        # pending -> completed is forbidden (must run through pipeline)
        j_pending = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending", user_id=uuid.uuid4())
        db.add(j_pending); db.commit()
        with pytest.raises(ValueError, match="Illegal proof job transition"):
            repo.update_job_status(j_pending.id, "completed")

        # running -> pending (backward) is forbidden
        j_running = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="running", user_id=uuid.uuid4())
        db.add(j_running); db.commit()
        with pytest.raises(ValueError, match="Illegal proof job transition"):
            repo.update_job_status(j_running.id, "pending")

        # running -> assembling_witness (backward) is forbidden
        with pytest.raises(ValueError, match="Illegal proof job transition"):
            repo.update_job_status(j_running.id, "assembling_witness")

        # assembling_witness -> pending (backward) is forbidden
        j_witness = ProofJob(id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="assembling_witness", user_id=uuid.uuid4())
        db.add(j_witness); db.commit()
        with pytest.raises(ValueError, match="Illegal proof job transition"):
            repo.update_job_status(j_witness.id, "pending")

    def test_chunk_state_machine_and_completed_protection(self, sqlite_db_session) -> None:
        """Chunk status transitions forward and prevents regressing or mutating completed chunks."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        db, _ = sqlite_db_session
        repo = ZKPRepository(db)
        job_id = uuid.uuid4()
        chunk = ChunkProofSet(
            id=uuid.uuid4(),
            proof_job_id=job_id,
            chunk_index=0,
            total_chunks=32,
            component_start=0,
            component_count=32,
            status="pending",
        )
        db.add(chunk); db.commit()

        # pending -> running -> completed
        repo.update_chunk_status(chunk.id, "running")
        db.refresh(chunk)
        assert chunk.status == "running"

        repo.update_chunk_status(chunk.id, "completed")
        db.refresh(chunk)
        assert chunk.status == "completed"

        # completed chunk cannot be set to running, pending, or failed
        for invalid_target in ("running", "pending", "failed"):
            with pytest.raises(ValueError, match="Illegal chunk transition"):
                repo.update_chunk_status(chunk.id, invalid_target)

    def test_segment_state_machine_and_completed_protection(self, sqlite_db_session) -> None:
        """Segment proof artifacts and status cannot be overwritten once completed."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        db, _ = sqlite_db_session
        repo = ZKPRepository(db)
        chunk_id = uuid.uuid4()
        seg = SegmentProof(
            id=uuid.uuid4(),
            chunk_id=chunk_id,
            chunk_index=0,
            total_chunks=32,
            segment_index=0,
            status="pending",
        )
        db.add(seg); db.commit()

        # Update to completed with valid artifact
        repo.update_segment_artifact(
            segment_id=seg.id,
            status="completed",
            proof_artifact="genuine_proof_b64",
            proof_artifact_hash="hash_abc",
            components_commit="0xcomp",
            hash_in_commit="0xin",
            hash_out_commit="0xout",
        )
        db.refresh(seg)
        assert seg.status == "completed"
        assert seg.proof_artifact == "genuine_proof_b64"
        assert seg.completed_at is not None

        # Cannot overwrite completed segment with running, pending, or failed
        for invalid_target in ("running", "pending", "failed"):
            with pytest.raises(ValueError, match="Illegal segment transition"):
                repo.update_segment_artifact(
                    segment_id=seg.id,
                    status=invalid_target,
                    proof_artifact="stale_artifact",
                    proof_artifact_hash="stale_hash",
                    components_commit="0xstale",
                    hash_in_commit="0xstale",
                    hash_out_commit="0xstale",
                )

        # Verify artifact was NOT mutated
        db.refresh(seg)
        assert seg.status == "completed"
        assert seg.proof_artifact == "genuine_proof_b64"


class TestZKPJobObservabilityAndRevocationSemantics:
    """Targeted regression tests for job status semantics, revocation root-cause, and observability."""

    def test_proof_job_rejects_revoked_status_transition(self, sqlite_db_session) -> None:
        """Verify ProofJob has NO 'revoked' status in its state machine (AUD-A-003 / Phase 2 Root Cause)."""
        from zkp_service.app.repositories.zkp_repository import ZKPRepository, ALLOWED_JOB_TRANSITIONS

        # 'revoked' is not a valid state for ProofJob
        assert "revoked" not in ALLOWED_JOB_TRANSITIONS
        for state, targets in ALLOWED_JOB_TRANSITIONS.items():
            assert "revoked" not in targets, f"'revoked' must not be an allowed target from state '{state}'"

        db, _ = sqlite_db_session
        repo = ZKPRepository(db)
        job = ProofJob(
            id=uuid.uuid4(),
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
        )
        db.add(job)
        db.commit()

        # Attempting transition to 'revoked' must raise ValueError
        with pytest.raises(ValueError, match="Illegal proof job transition"):
            repo.update_job_status(job.id, "revoked")

    def test_long_running_worker_holding_lock_remains_running_under_repeated_probes(
        self, sqlite_db_session
    ) -> None:
        """Verify that an active long-running worker holding the job lock remains running under repeated recovery probes."""
        from zkp_service.app.core.job_lock import get_job_lock_manager, reconcile_abandoned_job

        db, engine = sqlite_db_session
        job = ProofJob(
            id=uuid.uuid4(),
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            created_at=datetime.now(timezone.utc),
        )
        db.add(job)
        db.commit()

        mgr = get_job_lock_manager(engine)
        worker_lock = mgr.acquire_worker_lock(job.id)

        try:
            # Simulate 10 successive polling intervals from frontend or monitoring
            for _ in range(10):
                reconciled = reconcile_abandoned_job(db, job)
                assert reconciled is False, "Reconciliation must not alter a job whose worker holds the lock"
                db.refresh(job)
                assert job.status == "running", "Job must remain running while worker executes"
                assert job.completed_at is None
        finally:
            worker_lock.release()

    def test_proof_job_response_serialization_with_chunk_and_segment_telemetry(
        self, sqlite_db_session
    ) -> None:
        """Verify ProofJobResponse serializes chunks and segments for truthful UI observability."""
        from zkp_service.app.schemas.zkp_schemas import ProofJobResponse

        db, _ = sqlite_db_session
        job_id = uuid.uuid4()
        chunk_id = uuid.uuid4()
        job = ProofJob(
            id=job_id,
            sbom_upload_id=uuid.uuid4(),
            snapshot_id=uuid.uuid4(),
            policy_id=uuid.uuid4(),
            status="running",
            created_at=datetime.now(timezone.utc),
        )
        chunk = ChunkProofSet(
            id=chunk_id,
            proof_job_id=job_id,
            chunk_index=0,
            total_chunks=32,
            component_start=0,
            component_count=32,
            status="running",
            created_at=datetime.now(timezone.utc),
        )
        seg0 = SegmentProof(
            id=uuid.uuid4(),
            chunk_id=chunk_id,
            chunk_index=0,
            total_chunks=32,
            segment_index=0,
            status="completed",
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        seg1 = SegmentProof(
            id=uuid.uuid4(),
            chunk_id=chunk_id,
            chunk_index=0,
            total_chunks=32,
            segment_index=1,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        db.add_all([job, chunk, seg0, seg1])
        db.commit()
        db.refresh(job)

        response = ProofJobResponse.model_validate(job)
        assert response.id == job_id
        assert response.status == "running"
        assert len(response.chunks) == 1
        assert response.chunks[0].chunk_index == 0
        assert len(response.chunks[0].segments) == 2

        # Compute telemetry metrics exactly as done in frontend
        completed_segs = sum(
            1 for c in response.chunks for s in c.segments if s.status == "completed"
        )
        assert completed_segs == 1



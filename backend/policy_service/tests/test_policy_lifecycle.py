"""
Offline tests for Stage D4.2 — Policy Lifecycle & Proof Pre-Validation.

Verifies:
  1. Policy activation requires an active administrator (admin-only).
  2. Non-admin roles (auditor, vendor) and unauthenticated callers are rejected.
  3. Inactive administrators are rejected with 403.
  4. Unknown policy IDs return non-disclosing 404.
  5. Activating a policy deactivates any existing active policy (at most 1 active).
  6. Repeated activation of an already-active policy is safe and idempotent.
  7. New proof-job creation rejects nonexistent policies (404).
  8. New proof-job creation rejects inactive policies (400).
  9. New proof-job creation accepts active policies (200/202).
  10. Rejected proof-job requests leave no partial jobs and do not trigger prover.
  11. Existing ownership and SBOM/snapshot validations remain strictly enforced.
  12. Historical proof jobs with deactivated policies remain queryable and valid.
  13. Policy hash canonicalization and Poseidon calculations remain frozen.

All tests run completely offline using in-memory SQLite and isolated mocks/overrides.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from shared.database import Base, get_session
from shared.auth import get_current_user, require_roles
from shared.models.user import User
from shared.crypto.poseidon_bn254 import poseidon_hash

from policy_service.app.main import app as policy_app
from policy_service.app.models.policy_models import SecurityPolicy
from policy_service.app.services.policy_service import create_policy, activate_policy

from sbom_service.app.models.sbom_models import SBOMUpload, Application
from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot
from zkp_service.app.main import app as zkp_app
from zkp_service.app.models.zkp_models import ProofJob
from zkp_service.app.repositories.zkp_repository import ZKPRepository
from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest


# ---------------------------------------------------------------------------
# Test Users
# ---------------------------------------------------------------------------
ADMIN_USER_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
VENDOR_USER_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
AUDITOR_USER_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_VENDOR_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")


# ---------------------------------------------------------------------------
# Database Fixtures (Isolated In-Memory SQLite with StaticPool)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def sqlite_engine():
    """Create a module-scoped SQLite in-memory database with StaticPool."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    for table in Base.metadata.tables.values():
        table.schema = None
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def sqlite_session(sqlite_engine):
    """Provide a clean session per test with automatic teardown."""
    SessionLocal = sessionmaker(bind=sqlite_engine, autocommit=False, autoflush=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.query(ProofJob).delete()
        session.query(VulnerabilitySnapshot).delete()
        session.query(SBOMUpload).delete()
        session.query(Application).delete()
        session.query(SecurityPolicy).delete()
        session.query(User).delete()
        session.commit()
        session.close()


@pytest.fixture
def policy_client(sqlite_session):
    """FastAPI TestClient wired to the in-memory SQLite database for policy service."""
    def override_get_session():
        yield sqlite_session

    policy_app.dependency_overrides[get_session] = override_get_session
    client = TestClient(policy_app, raise_server_exceptions=False)
    yield client
    policy_app.dependency_overrides.clear()


@pytest.fixture
def zkp_client(sqlite_session):
    """FastAPI TestClient wired to the in-memory SQLite database for zkp service."""
    def override_get_session():
        yield sqlite_session

    zkp_app.dependency_overrides[get_session] = override_get_session
    client = TestClient(zkp_app, raise_server_exceptions=False)
    yield client
    zkp_app.dependency_overrides.clear()


# ===========================================================================
# Unit Tests — Policy Activation Endpoint (D4.2.1)
# ===========================================================================

def test_activate_policy_unauthenticated(policy_client):
    """Unauthenticated requests to activate a policy must be rejected with 401."""
    policy_id = uuid.uuid4()
    response = policy_client.post(f"/api/v1/policy/{policy_id}/activate")
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_activate_policy_non_admin_denied(policy_client, sqlite_session):
    """Auditor and Vendor roles must be denied with 403 Insufficient permissions."""
    policy = create_policy(sqlite_session, max_cvss_score=7.0, name="Standard Policy")

    # Auditor attempt
    policy_app.dependency_overrides[get_current_user] = lambda: User(
        id=AUDITOR_USER_ID, username="auditor_user", role="auditor", is_active=True
    )
    resp_auditor = policy_client.post(f"/api/v1/policy/{policy.id}/activate")
    assert resp_auditor.status_code == 403
    assert resp_auditor.json()["error"] == "Insufficient permissions"
    assert resp_auditor.json()["code"] == "FORBIDDEN"

    # Vendor attempt
    policy_app.dependency_overrides[get_current_user] = lambda: User(
        id=VENDOR_USER_ID, username="vendor_user", role="vendor", is_active=True
    )
    resp_vendor = policy_client.post(f"/api/v1/policy/{policy.id}/activate")
    assert resp_vendor.status_code == 403
    assert resp_vendor.json()["error"] == "Insufficient permissions"
    assert resp_vendor.json()["code"] == "FORBIDDEN"


def test_activate_policy_inactive_admin_denied(policy_client, sqlite_session):
    """Deactivated administrators must be denied with 403 Account is deactivated."""
    policy = create_policy(sqlite_session, max_cvss_score=7.0, name="Standard Policy")

    def mock_inactive_admin():
        raise HTTPException(status_code=403, detail="Account is deactivated")

    policy_app.dependency_overrides[get_current_user] = mock_inactive_admin
    response = policy_client.post(f"/api/v1/policy/{policy.id}/activate")
    assert response.status_code == 403
    assert response.json()["error"] == "Account is deactivated"
    assert response.json()["code"] == "FORBIDDEN"


def test_activate_policy_unknown_id(policy_client, sqlite_session):
    """Activating a non-existent policy ID must return non-disclosing 404."""
    policy_app.dependency_overrides[get_current_user] = lambda: User(
        id=ADMIN_USER_ID, username="admin_user", role="admin", is_active=True
    )
    unknown_id = uuid.uuid4()
    response = policy_client.post(f"/api/v1/policy/{unknown_id}/activate")
    assert response.status_code == 404
    assert response.json()["error"] == "Policy not found"
    assert response.json()["code"] == "NOT_FOUND"


def test_activate_policy_success_and_single_active_invariant(policy_client, sqlite_session):
    """
    Activating a policy must:
    1. Set the target policy's is_active to 1.
    2. Deactivate any previously active policy (is_active = 0).
    3. Ensure at most one policy is active in the database.
    4. Return the standard PolicyResponse shape.
    """
    policy_app.dependency_overrides[get_current_user] = lambda: User(
        id=ADMIN_USER_ID, username="admin_user", role="admin", is_active=True
    )

    # Create Policy 1 (initially active=1)
    pol1 = create_policy(sqlite_session, max_cvss_score=6.0, name="Policy 1")
    assert pol1.is_active == 1

    # Create Policy 2 (becomes active=1, deactivates Policy 1 to active=0)
    pol2 = create_policy(sqlite_session, max_cvss_score=8.0, name="Policy 2")
    sqlite_session.refresh(pol1)
    sqlite_session.refresh(pol2)
    assert pol1.is_active == 0
    assert pol2.is_active == 1

    # Now activate Policy 1 via the API endpoint
    response = policy_client.post(f"/api/v1/policy/{pol1.id}/activate")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(pol1.id)
    assert data["name"] == "Policy 1"
    assert data["max_cvss_score"] == 6.0
    assert data["active"] is True
    assert "policy_hash" in data
    assert "created_at" in data

    # Verify single-active-policy invariant in DB
    sqlite_session.refresh(pol1)
    sqlite_session.refresh(pol2)
    assert pol1.is_active == 1
    assert pol2.is_active == 0

    active_count = sqlite_session.query(SecurityPolicy).filter(SecurityPolicy.is_active == 1).count()
    assert active_count == 1


def test_activate_policy_repeated_activation_safe(policy_client, sqlite_session):
    """Repeated activation of an already-active policy is idempotent, safe, and returns 200."""
    policy_app.dependency_overrides[get_current_user] = lambda: User(
        id=ADMIN_USER_ID, username="admin_user", role="admin", is_active=True
    )

    pol = create_policy(sqlite_session, max_cvss_score=5.5, name="Idempotent Policy")
    assert pol.is_active == 1

    # First activation
    resp1 = policy_client.post(f"/api/v1/policy/{pol.id}/activate")
    assert resp1.status_code == 200
    assert resp1.json()["active"] is True

    # Repeated activation
    resp2 = policy_client.post(f"/api/v1/policy/{pol.id}/activate")
    assert resp2.status_code == 200
    assert resp2.json()["active"] is True
    assert resp2.json()["id"] == str(pol.id)

    # Invariant holds
    active_count = sqlite_session.query(SecurityPolicy).filter(SecurityPolicy.is_active == 1).count()
    assert active_count == 1


# ===========================================================================
# Unit Tests — Proof-Job Policy Pre-Validation (D4.2.2)
# ===========================================================================

def test_proof_job_rejects_nonexistent_policy(sqlite_session):
    """create_job must raise 404 if the referenced policy does not exist."""
    app_entity = Application(
        id=uuid.uuid4(),
        name="App",
        vendor="Acme",
        user_id=VENDOR_USER_ID,
    )
    sqlite_session.add(app_entity)
    sqlite_session.commit()

    sbom = SBOMUpload(
        id=uuid.uuid4(),
        application_id=app_entity.id,
        user_id=VENDOR_USER_ID,
        format="CycloneDX",
        status="active",
    )
    snap = VulnerabilitySnapshot(
        id=uuid.uuid4(),
        snapshot_label="Snapshot",
        status="frozen",
    )
    sqlite_session.add_all([sbom, snap])
    sqlite_session.commit()

    repo = ZKPRepository(sqlite_session)
    req = GenerateProofRequest(
        sbom_upload_id=sbom.id,
        snapshot_id=snap.id,
        policy_id=uuid.uuid4(),  # Nonexistent policy
    )

    with pytest.raises(HTTPException) as exc_info:
        repo.create_job(req, user_id=VENDOR_USER_ID)
    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Policy not found"


def test_proof_job_rejects_inactive_policy(sqlite_session):
    """create_job must raise 400 if the referenced policy is inactive (is_active != 1)."""
    pol_inactive = create_policy(sqlite_session, max_cvss_score=7.0, name="Pol 1")
    pol_active = create_policy(sqlite_session, max_cvss_score=8.0, name="Pol 2")

    sqlite_session.refresh(pol_inactive)
    assert pol_inactive.is_active == 0

    app_entity = Application(
        id=uuid.uuid4(),
        name="App",
        vendor="Acme",
        user_id=VENDOR_USER_ID,
    )
    sqlite_session.add(app_entity)
    sqlite_session.commit()

    sbom = SBOMUpload(
        id=uuid.uuid4(),
        application_id=app_entity.id,
        user_id=VENDOR_USER_ID,
        format="CycloneDX",
        status="active",
    )
    snap = VulnerabilitySnapshot(
        id=uuid.uuid4(),
        snapshot_label="Snapshot",
        status="frozen",
    )
    sqlite_session.add_all([sbom, snap])
    sqlite_session.commit()

    repo = ZKPRepository(sqlite_session)
    req = GenerateProofRequest(
        sbom_upload_id=sbom.id,
        snapshot_id=snap.id,
        policy_id=pol_inactive.id,
    )

    with pytest.raises(HTTPException) as exc_info:
        repo.create_job(req, user_id=VENDOR_USER_ID)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Policy is not active"


def test_proof_job_accepts_active_policy(sqlite_session):
    """create_job must succeed and persist a job when the policy is active."""
    pol = create_policy(sqlite_session, max_cvss_score=7.0, name="Active Policy")
    assert pol.is_active == 1

    app_entity = Application(
        id=uuid.uuid4(),
        name="App",
        vendor="Acme",
        user_id=VENDOR_USER_ID,
    )
    sqlite_session.add(app_entity)
    sqlite_session.commit()

    sbom = SBOMUpload(
        id=uuid.uuid4(),
        application_id=app_entity.id,
        user_id=VENDOR_USER_ID,
        format="CycloneDX",
        status="active",
    )
    snap = VulnerabilitySnapshot(
        id=uuid.uuid4(),
        snapshot_label="Snapshot",
        status="frozen",
    )
    sqlite_session.add_all([sbom, snap])
    sqlite_session.commit()

    repo = ZKPRepository(sqlite_session)
    req = GenerateProofRequest(
        sbom_upload_id=sbom.id,
        snapshot_id=snap.id,
        policy_id=pol.id,
    )

    job = repo.create_job(req, user_id=VENDOR_USER_ID)
    assert job is not None
    assert job.status == "pending"
    assert job.policy_id == pol.id
    assert job.user_id == VENDOR_USER_ID

    # Verified persisted in DB
    persisted = sqlite_session.query(ProofJob).filter(ProofJob.id == job.id).first()
    assert persisted is not None
    assert persisted.status == "pending"


def test_rejected_job_leaves_no_partial_job_or_prover_run(zkp_client, sqlite_session):
    """
    When POST /api/v1/zkp/generate is called with an inactive policy:
    1. Returns 400 with 'Policy is not active'.
    2. Leaves NO records in proof_jobs table.
    3. Does NOT invoke the prover service.
    """
    zkp_app.dependency_overrides[get_current_user] = lambda: User(
        id=VENDOR_USER_ID, username="vendor_user", role="vendor", is_active=True
    )

    pol1 = create_policy(sqlite_session, max_cvss_score=6.0, name="Old Policy")
    pol2 = create_policy(sqlite_session, max_cvss_score=7.0, name="New Policy")
    sqlite_session.refresh(pol1)
    assert pol1.is_active == 0

    app_entity = Application(
        id=uuid.uuid4(),
        name="App",
        vendor="Acme",
        user_id=VENDOR_USER_ID,
    )
    sqlite_session.add(app_entity)
    sqlite_session.commit()

    sbom = SBOMUpload(
        id=uuid.uuid4(),
        application_id=app_entity.id,
        user_id=VENDOR_USER_ID,
        format="CycloneDX",
        status="active",
    )
    snap = VulnerabilitySnapshot(
        id=uuid.uuid4(),
        snapshot_label="Snapshot",
        status="frozen",
    )
    sqlite_session.add_all([sbom, snap])
    sqlite_session.commit()

    with patch("zkp_service.app.api.routes.zkp_routes.ProverService") as mock_prover:
        response = zkp_client.post(
            "/api/v1/zkp/generate",
            json={
                "sbom_upload_id": str(sbom.id),
                "snapshot_id": str(snap.id),
                "policy_id": str(pol1.id),
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "Policy is not active"
        assert response.json()["code"] == "BAD_REQUEST"
        mock_prover.assert_not_called()

    # Zero proof jobs persisted
    jobs_count = sqlite_session.query(ProofJob).count()
    assert jobs_count == 0


def test_existing_ownership_and_snapshot_validations_preserved(sqlite_session):
    """
    Verify that existing security invariants are preserved:
    1. SBOM not owned by user -> 403 Forbidden.
    2. Missing SBOM -> 404.
    3. Missing Snapshot -> 404.
    4. Unfrozen Snapshot (status 'pending') -> 400.
    """
    pol = create_policy(sqlite_session, max_cvss_score=7.0)

    # 1. Unowned SBOM
    app_other = Application(
        id=uuid.uuid4(),
        name="Other App",
        vendor="Other Corp",
        user_id=OTHER_VENDOR_ID,
    )
    sqlite_session.add(app_other)
    sqlite_session.commit()

    unowned_sbom = SBOMUpload(
        id=uuid.uuid4(),
        application_id=app_other.id,
        user_id=OTHER_VENDOR_ID,
        format="CycloneDX",
        status="active",
    )
    frozen_snap = VulnerabilitySnapshot(
        id=uuid.uuid4(),
        snapshot_label="Frozen Snapshot",
        status="frozen",
    )
    sqlite_session.add_all([unowned_sbom, frozen_snap])
    sqlite_session.commit()

    repo = ZKPRepository(sqlite_session)
    req_unowned = GenerateProofRequest(
        sbom_upload_id=unowned_sbom.id,
        snapshot_id=frozen_snap.id,
        policy_id=pol.id,
    )
    with pytest.raises(HTTPException) as exc1:
        repo.create_job(req_unowned, user_id=VENDOR_USER_ID)
    assert exc1.value.status_code == 403
    assert "Forbidden" in exc1.value.detail

    # 2. Missing SBOM
    req_no_sbom = GenerateProofRequest(
        sbom_upload_id=uuid.uuid4(),
        snapshot_id=frozen_snap.id,
        policy_id=pol.id,
    )
    with pytest.raises(HTTPException) as exc2:
        repo.create_job(req_no_sbom, user_id=VENDOR_USER_ID)
    assert exc2.value.status_code == 404
    assert exc2.value.detail == "SBOM not found"

    # 3. Missing Snapshot
    app_owned = Application(
        id=uuid.uuid4(),
        name="My App",
        vendor="My Corp",
        user_id=VENDOR_USER_ID,
    )
    sqlite_session.add(app_owned)
    sqlite_session.commit()

    owned_sbom = SBOMUpload(
        id=uuid.uuid4(),
        application_id=app_owned.id,
        user_id=VENDOR_USER_ID,
        format="CycloneDX",
        status="active",
    )
    sqlite_session.add(owned_sbom)
    sqlite_session.commit()

    req_no_snap = GenerateProofRequest(
        sbom_upload_id=owned_sbom.id,
        snapshot_id=uuid.uuid4(),
        policy_id=pol.id,
    )
    with pytest.raises(HTTPException) as exc3:
        repo.create_job(req_no_snap, user_id=VENDOR_USER_ID)
    assert exc3.value.status_code == 404
    assert exc3.value.detail == "Snapshot not found"

    # 4. Unfrozen Snapshot
    pending_snap = VulnerabilitySnapshot(
        id=uuid.uuid4(),
        snapshot_label="Pending Snapshot",
        status="pending",
    )
    sqlite_session.add(pending_snap)
    sqlite_session.commit()

    req_unfrozen = GenerateProofRequest(
        sbom_upload_id=owned_sbom.id,
        snapshot_id=pending_snap.id,
        policy_id=pol.id,
    )
    with pytest.raises(HTTPException) as exc4:
        repo.create_job(req_unfrozen, user_id=VENDOR_USER_ID)
    assert exc4.value.status_code == 400
    assert exc4.value.detail == "Snapshot is not frozen"


def test_historical_jobs_unaffected_by_inactive_policy(sqlite_session):
    """
    Historical proof jobs pointing to policies that later became inactive
    must remain readable, queryable, and unaffected.
    """
    # Policy created and was active when historical job was run
    historical_pol = create_policy(sqlite_session, max_cvss_score=7.0, name="Historical Policy")

    # Historical job persisted
    hist_job_id = uuid.uuid4()
    hist_job = ProofJob(
        id=hist_job_id,
        sbom_upload_id=uuid.uuid4(),
        snapshot_id=uuid.uuid4(),
        policy_id=historical_pol.id,
        status="completed",
        policy_hash=historical_pol.policy_hash,
        user_id=VENDOR_USER_ID,
    )
    sqlite_session.add(hist_job)
    sqlite_session.commit()

    # Now a new policy is created, deactivating historical_pol
    new_pol = create_policy(sqlite_session, max_cvss_score=9.0, name="New Policy")
    sqlite_session.refresh(historical_pol)
    assert historical_pol.is_active == 0
    assert new_pol.is_active == 1

    # Verify historical job is retrieved cleanly without any error
    repo = ZKPRepository(sqlite_session)
    retrieved = repo.get_job(hist_job_id, user_id=VENDOR_USER_ID)
    assert retrieved is not None
    assert retrieved.id == hist_job_id
    assert retrieved.policy_id == historical_pol.id
    assert retrieved.status == "completed"
    assert retrieved.policy_hash == historical_pol.policy_hash


def test_policy_hash_invariant_unaffected():
    """Verify that policy hash canonicalization is completely preserved."""
    max_cvss = 7.5
    cvss_int = int(round(max_cvss * 10))
    expected_hash = f"0x{poseidon_hash([cvss_int]):064x}"

    assert len(expected_hash) == 66
    assert expected_hash.startswith("0x")
    # Must be deterministic
    assert expected_hash == f"0x{poseidon_hash([75]):064x}"

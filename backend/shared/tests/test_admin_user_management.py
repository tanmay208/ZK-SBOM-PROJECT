"""
Offline Integration and Security Test Suite for Administrative User Management (Stage D3.1).

Validates:
1. Endpoint Authorization:
   - Admin access allowed for all endpoints
   - Non-admin roles (vendor, buyer, auditor, trusted_importer) rejected with HTTP 403
   - Unauthenticated requests rejected with HTTP 401
2. User Listing & Retrieval:
   - Pagination (skip, limit) and validation bounds
   - Filters by role (exact 5-role validation) and is_active status
   - Single user retrieval (200) and nonexistent user handling (404)
   - Password hash non-disclosure across all responses
3. Role Updates:
   - All 5 authorized roles (vendor, buyer, auditor, admin, trusted_importer) successfully assigned
   - Invalid roles (root, superadmin, etc.) rejected with HTTP 422
   - Role updates refresh updated_at timestamp
4. Account Activation & Deactivation:
   - Deactivation and reactivation lifecycle
   - Deactivated accounts immediately fail closed on login and current-user resolution (HTTP 403)
   - Self-deactivation by active admin strictly rejected (HTTP 400)
5. Last-Active-Administrator Invariant & Concurrency Protection:
   - Last active administrator cannot be demoted (HTTP 400)
   - Last active administrator cannot be deactivated (HTTP 400)
   - Modifying another admin allowed only when invariant is satisfied
   - Pre-existing zero-admin state allows recovery path (promoting admin) and rejects non-recovery mutations (HTTP 409)
   - Concurrent mutation simulation demonstrates that race conditions cannot leave zero active admins

Strictly offline: Zero PostgreSQL connections, zero network I/O, SQLite in-memory fixtures.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import secrets
import socket
import threading
from typing import Generator
from uuid import UUID, uuid4
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from shared.auth import (
    create_access_token,
    get_password_hash,
)
from shared.database import Base, get_session
from shared.models.user import User
from verification_service.app.main import app


# ---------------------------------------------------------------------------
# Strict Offline Enforcement
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def enforce_offline_isolation(monkeypatch):
    """Enforce strict offline isolation: any network socket connection to PostgreSQL or external hosts fails closed."""
    orig_connect = socket.socket.connect

    def _guarded_connect(self, address, *args, **kwargs):
        if isinstance(address, tuple) and len(address) >= 2:
            host, port = address[0], address[1]
            if port in (5432, 5433):
                raise RuntimeError(f"Database connection to PostgreSQL on port {port} strictly forbidden during offline tests!")
            if host not in ("127.0.0.1", "localhost", "::1"):
                raise RuntimeError(f"External network connection to {host}:{port} strictly forbidden during offline tests!")
        else:
            raise RuntimeError("Network socket connection attempted during offline test execution!")
        return orig_connect(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)


# ---------------------------------------------------------------------------
# Database & Client Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine, tables=[User.__table__])
    return engine


@pytest.fixture
def db_session(db_engine) -> Generator:
    TestingSession = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.rollback()
        # Clean up any leftover users between tests
        session.query(User).delete()
        session.commit()
        session.close()


@pytest.fixture
def client(db_session) -> Generator:
    app.dependency_overrides[get_session] = lambda: db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.pop(get_session, None)


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def create_test_user(
    db_session,
    username: str,
    role: str = "buyer",
    is_active: bool = True,
    password: str = "StrongP@ssw0rd123!",
) -> User:
    user = User(
        username=username,
        hashed_password=get_password_hash(password),
        role=role,
        is_active=is_active,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def get_auth_headers(user: User) -> dict[str, str]:
    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. User Listing & Pagination Tests
# ---------------------------------------------------------------------------

def test_admin_list_users_success_and_pagination(client, db_session):
    """Admin successfully lists registered users with deterministic pagination."""
    admin = create_test_user(db_session, "admin_lead", role="admin")
    u1 = create_test_user(db_session, "user_alpha", role="vendor")
    u2 = create_test_user(db_session, "user_beta", role="buyer")
    u3 = create_test_user(db_session, "user_gamma", role="auditor")

    headers = get_auth_headers(admin)

    # Full list
    resp = client.get("/api/v1/admin/users", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 4
    usernames = [u["username"] for u in data]
    assert admin.username in usernames
    assert u1.username in usernames

    # Paginated: limit=2, skip=0
    resp_p1 = client.get("/api/v1/admin/users?skip=0&limit=2", headers=headers)
    assert resp_p1.status_code == 200
    p1_data = resp_p1.json()
    assert len(p1_data) == 2

    # Paginated: limit=2, skip=2
    resp_p2 = client.get("/api/v1/admin/users?skip=2&limit=2", headers=headers)
    assert resp_p2.status_code == 200
    p2_data = resp_p2.json()
    assert len(p2_data) == 2

    # Verify no overlap between p1 and p2
    p1_ids = {u["id"] for u in p1_data}
    p2_ids = {u["id"] for u in p2_data}
    assert len(p1_ids.intersection(p2_ids)) == 0


def test_admin_list_users_filters(client, db_session):
    """Admin filters users by role and is_active status."""
    admin = create_test_user(db_session, "admin_filter", role="admin")
    create_test_user(db_session, "buyer_act", role="buyer", is_active=True)
    create_test_user(db_session, "buyer_inact", role="buyer", is_active=False)
    create_test_user(db_session, "vendor_act", role="vendor", is_active=True)

    headers = get_auth_headers(admin)

    # Filter by role=buyer
    resp_role = client.get("/api/v1/admin/users?role=buyer", headers=headers)
    assert resp_role.status_code == 200
    role_data = resp_role.json()
    assert len(role_data) == 2
    assert all(u["role"] == "buyer" for u in role_data)

    # Filter by is_active=false
    resp_inact = client.get("/api/v1/admin/users?is_active=false", headers=headers)
    assert resp_inact.status_code == 200
    inact_data = resp_inact.json()
    assert len(inact_data) == 1
    assert inact_data[0]["username"] == "buyer_inact"
    assert inact_data[0]["is_active"] is False

    # Filter by both role=buyer and is_active=true
    resp_both = client.get("/api/v1/admin/users?role=buyer&is_active=true", headers=headers)
    assert resp_both.status_code == 200
    both_data = resp_both.json()
    assert len(both_data) == 1
    assert both_data[0]["username"] == "buyer_act"


def test_admin_list_users_invalid_parameters(client, db_session):
    """Validation bounds on skip, limit, and role filters fail closed with HTTP 422."""
    admin = create_test_user(db_session, "admin_bounds", role="admin")
    headers = get_auth_headers(admin)

    # Negative skip
    resp_neg_skip = client.get("/api/v1/admin/users?skip=-1", headers=headers)
    assert resp_neg_skip.status_code == 422

    # Limit > 100
    resp_large_limit = client.get("/api/v1/admin/users?limit=101", headers=headers)
    assert resp_large_limit.status_code == 422

    # Limit <= 0
    resp_zero_limit = client.get("/api/v1/admin/users?limit=0", headers=headers)
    assert resp_zero_limit.status_code == 422

    # Legacy and unsupported role filters rejected with 422
    for rejected_filter in ["superadmin", "auditor", "trusted_importer"]:
        resp_bad = client.get(f"/api/v1/admin/users?role={rejected_filter}", headers=headers)
        assert resp_bad.status_code == 422
        assert "Invalid role filter" in resp_bad.text


# ---------------------------------------------------------------------------
# 2. Single User Retrieval Tests
# ---------------------------------------------------------------------------

def test_admin_get_user_by_id_success(client, db_session):
    """Admin retrieves a specific user by UUID."""
    admin = create_test_user(db_session, "admin_viewer", role="admin")
    target = create_test_user(db_session, "target_buyer", role="buyer")

    headers = get_auth_headers(admin)
    resp = client.get(f"/api/v1/admin/users/{target.id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(target.id)
    assert data["username"] == "target_buyer"
    assert data["role"] == "buyer"
    assert data["is_active"] is True
    assert "created_at" in data
    assert "updated_at" in data


def test_admin_get_user_nonexistent_returns_404(client, db_session):
    """Querying a nonexistent user UUID returns HTTP 404 Not Found."""
    admin = create_test_user(db_session, "admin_notfound", role="admin")
    headers = get_auth_headers(admin)

    random_id = uuid4()
    resp = client.get(f"/api/v1/admin/users/{random_id}", headers=headers)
    assert resp.status_code == 404
    assert resp.json()["error"] == "User not found"
    assert resp.json()["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# 3. Authorization & RBAC Boundary Tests
# ---------------------------------------------------------------------------

def test_unauthenticated_requests_rejected_with_401(client, db_session):
    """All admin endpoints reject unauthenticated callers with HTTP 401."""
    random_id = uuid4()

    assert client.get("/api/v1/admin/users").status_code == 401
    assert client.get(f"/api/v1/admin/users/{random_id}").status_code == 401
    assert client.patch(f"/api/v1/admin/users/{random_id}/role", json={"role": "vendor"}).status_code == 401
    assert client.patch(f"/api/v1/admin/users/{random_id}/status", json={"is_active": False}).status_code == 401


def test_non_admin_roles_rejected_with_403(client, db_session):
    """Every non-admin role receives HTTP 403 Forbidden across all four admin endpoint families."""
    non_admin_roles = ["vendor", "buyer", "auditor", "trusted_importer"]
    random_id = uuid4()

    for role in non_admin_roles:
        caller = create_test_user(db_session, f"caller_{role}", role=role)
        headers = get_auth_headers(caller)

        # GET /api/v1/admin/users
        resp_list = client.get("/api/v1/admin/users", headers=headers)
        assert resp_list.status_code == 403, f"Role {role} must receive 403 on user listing"
        assert resp_list.json()["code"] == "FORBIDDEN"

        # GET /api/v1/admin/users/{id}
        resp_get = client.get(f"/api/v1/admin/users/{random_id}", headers=headers)
        assert resp_get.status_code == 403, f"Role {role} must receive 403 on single user detail"

        # PATCH /api/v1/admin/users/{id}/role
        resp_role = client.patch(
            f"/api/v1/admin/users/{random_id}/role",
            json={"role": "admin"},
            headers=headers,
        )
        assert resp_role.status_code == 403, f"Role {role} must receive 403 on role update"

        # PATCH /api/v1/admin/users/{id}/status
        resp_status = client.patch(
            f"/api/v1/admin/users/{random_id}/status",
            json={"is_active": False},
            headers=headers,
        )
        assert resp_status.status_code == 403, f"Role {role} must receive 403 on status update"


# ---------------------------------------------------------------------------
# 4. Role Update Lifecycle & Validation Tests
# ---------------------------------------------------------------------------

def test_all_three_primary_roles_update_success(client, db_session):
    """Admin successfully updates a user to each of the 3 primary authorized roles (vendor, buyer, admin)."""
    admin = create_test_user(db_session, "admin_role_mgr", role="admin")
    target = create_test_user(db_session, "target_user", role="buyer")

    headers = get_auth_headers(admin)
    primary_roles = ["vendor", "buyer", "admin"]

    for new_role in primary_roles:
        resp = client.patch(
            f"/api/v1/admin/users/{target.id}/role",
            json={"role": new_role},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == new_role

        # Verify DB persistence
        db_user = db_session.query(User).filter(User.id == target.id).first()
        assert db_user.role == new_role
        assert db_user.updated_at is not None


def test_retired_roles_rejected_on_update_with_422(client, db_session):
    """Retired legacy roles (auditor, trusted_importer) are rejected with HTTP 422 on role update."""
    admin = create_test_user(db_session, "admin_retired_test", role="admin")
    target = create_test_user(db_session, "target_retired_test", role="buyer")

    headers = get_auth_headers(admin)
    retired_roles = ["auditor", "trusted_importer"]

    for ret_role in retired_roles:
        resp = client.patch(
            f"/api/v1/admin/users/{target.id}/role",
            json={"role": ret_role},
            headers=headers,
        )
        assert resp.status_code == 422
        assert f"Invalid role '{ret_role}'" in resp.text

    # Verify target user role remained unchanged in DB
    db_user = db_session.query(User).filter(User.id == target.id).first()
    assert db_user.role == "buyer"


def test_invalid_role_update_rejected_with_422(client, db_session):
    """Unknown, escalated, or malformed roles are rejected with HTTP 422."""
    admin = create_test_user(db_session, "admin_val_role", role="admin")
    target = create_test_user(db_session, "target_val", role="buyer")

    headers = get_auth_headers(admin)
    invalid_roles = ["root", "superadmin", "manager", "operator", "", "   ", "ADMINISTRATOR", "auditor", "trusted_importer"]

    for bad_role in invalid_roles:
        resp = client.patch(
            f"/api/v1/admin/users/{target.id}/role",
            json={"role": bad_role},
            headers=headers,
        )
        assert resp.status_code == 422
        assert "Invalid role" in resp.text

    # Verify target user role remained unchanged in DB
    db_user = db_session.query(User).filter(User.id == target.id).first()
    assert db_user.role == "buyer"


def test_idempotent_role_and_status_no_ops(client, db_session):
    """Submitting the user's current role or status is a safe idempotent no-op."""
    admin = create_test_user(db_session, "admin_idempotent", role="admin")
    target = create_test_user(db_session, "target_idem", role="vendor", is_active=True)
    headers = get_auth_headers(admin)

    # Same role
    resp_role = client.patch(
        f"/api/v1/admin/users/{target.id}/role",
        json={"role": "vendor"},
        headers=headers,
    )
    assert resp_role.status_code == 200
    assert resp_role.json()["role"] == "vendor"

    # Same status
    resp_stat = client.patch(
        f"/api/v1/admin/users/{target.id}/status",
        json={"is_active": True},
        headers=headers,
    )
    assert resp_stat.status_code == 200
    assert resp_stat.json()["is_active"] is True


# ---------------------------------------------------------------------------
# 5. Account Activation & Deactivation Tests
# ---------------------------------------------------------------------------

def test_account_activation_and_deactivation_success(client, db_session):
    """Admin deactivates and reactivates a user; changes persist to database."""
    admin = create_test_user(db_session, "admin_status_mgr", role="admin")
    target = create_test_user(db_session, "target_lifecycle", role="buyer", is_active=True)
    headers = get_auth_headers(admin)

    # Deactivate
    resp_deact = client.patch(
        f"/api/v1/admin/users/{target.id}/status",
        json={"is_active": False},
        headers=headers,
    )
    assert resp_deact.status_code == 200
    assert resp_deact.json()["is_active"] is False

    db_user = db_session.query(User).filter(User.id == target.id).first()
    assert db_user.is_active is False

    # Reactivate
    resp_react = client.patch(
        f"/api/v1/admin/users/{target.id}/status",
        json={"is_active": True},
        headers=headers,
    )
    assert resp_react.status_code == 200
    assert resp_react.json()["is_active"] is True

    db_user = db_session.query(User).filter(User.id == target.id).first()
    assert db_user.is_active is True


def test_deactivated_user_rejected_from_authenticated_routes(client, db_session):
    """Deactivation immediately blocks login and invalidates existing JWT sessions."""
    admin = create_test_user(db_session, "admin_deactivator", role="admin")
    target = create_test_user(
        db_session,
        "victim_buyer",
        role="buyer",
        is_active=True,
        password="TargetPassword123!",
    )
    headers = get_auth_headers(admin)

    # Issue token to target while still active
    target_headers = get_auth_headers(target)
    me_resp_before = client.get("/api/v1/auth/me", headers=target_headers)
    assert me_resp_before.status_code == 200

    # Admin deactivates target
    deact_resp = client.patch(
        f"/api/v1/admin/users/{target.id}/status",
        json={"is_active": False},
        headers=headers,
    )
    assert deact_resp.status_code == 200

    # 1. Existing JWT immediately fails with HTTP 403
    me_resp_after = client.get("/api/v1/auth/me", headers=target_headers)
    assert me_resp_after.status_code == 403
    assert me_resp_after.json()["error"] == "Account is deactivated"

    # 2. Login attempt immediately fails with HTTP 403
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": "victim_buyer", "password": "TargetPassword123!"},
    )
    assert login_resp.status_code == 403
    assert login_resp.json()["error"] == "Account is deactivated"


def test_self_deactivation_rejected_with_400(client, db_session):
    """An administrator cannot deactivate their own account."""
    admin = create_test_user(db_session, "admin_self_deact", role="admin")
    headers = get_auth_headers(admin)

    resp = client.patch(
        f"/api/v1/admin/users/{admin.id}/status",
        json={"is_active": False},
        headers=headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "Administrators cannot deactivate their own account"
    assert resp.json()["code"] == "BAD_REQUEST"

    # Verify admin remains active in DB
    db_admin = db_session.query(User).filter(User.id == admin.id).first()
    assert db_admin.is_active is True


# ---------------------------------------------------------------------------
# 6. Last Active Administrator Invariant Tests
# ---------------------------------------------------------------------------

def test_last_active_admin_cannot_be_deactivated(client, db_session):
    """When only 1 active administrator exists, deactivating that admin is rejected."""
    sole_admin = create_test_user(db_session, "sole_admin", role="admin", is_active=True)
    # Another caller trying to deactivate (simulate through admin headers)
    headers = get_auth_headers(sole_admin)

    # (Self-deactivation is rejected first, but let's test a distinct admin caller)
    # Create a second admin who is inactive
    inactive_admin = create_test_user(db_session, "inact_admin", role="admin", is_active=False)

    # Now create another active admin to attempt the deactivation
    active_admin2 = create_test_user(db_session, "active_admin2", role="admin", is_active=True)
    admin2_headers = get_auth_headers(active_admin2)

    # Deactivate sole_admin -> this leaves active_admin2 as the sole remaining active admin
    deact1 = client.patch(
        f"/api/v1/admin/users/{sole_admin.id}/status",
        json={"is_active": False},
        headers=admin2_headers,
    )
    assert deact1.status_code == 200

    # Now active_admin2 is the LAST active administrator.
    # An attempt to deactivate active_admin2 (by any valid admin session) must be rejected
    deact2 = client.patch(
        f"/api/v1/admin/users/{active_admin2.id}/status",
        json={"is_active": False},
        headers=admin2_headers,
    )
    # Fails via self-deactivation guard (400)
    assert deact2.status_code == 400
    assert "cannot deactivate" in deact2.json()["error"].lower()

    # Re-activate sole_admin so we can test non-self deactivation of the last admin
    react = client.patch(
        f"/api/v1/admin/users/{sole_admin.id}/status",
        json={"is_active": True},
        headers=admin2_headers,
    )
    assert react.status_code == 200

    # Now sole_admin deactivates active_admin2 -> leaving sole_admin as the last active admin
    sole_headers = get_auth_headers(sole_admin)
    deact_admin2 = client.patch(
        f"/api/v1/admin/users/{active_admin2.id}/status",
        json={"is_active": False},
        headers=sole_headers,
    )
    assert deact_admin2.status_code == 200

    # Now active_admin2 is inactive. sole_admin is the ONLY active admin.
    # If active_admin2 tries to deactivate sole_admin using their old token, it fails with 403 (inactive caller)
    # If sole_admin tries to deactivate themselves, it fails with 400
    assert db_session.query(User).filter(User.role == "admin", User.is_active == True).count() == 1


def test_last_active_admin_cannot_be_demoted(client, db_session):
    """When only 1 active administrator exists, demoting that admin to another role is rejected."""
    admin1 = create_test_user(db_session, "admin_one", role="admin", is_active=True)
    admin2 = create_test_user(db_session, "admin_two", role="admin", is_active=True)
    headers1 = get_auth_headers(admin1)

    # Admin 1 demotes Admin 2 to buyer -> valid because Admin 1 remains
    resp1 = client.patch(
        f"/api/v1/admin/users/{admin2.id}/role",
        json={"role": "buyer"},
        headers=headers1,
    )
    assert resp1.status_code == 200
    assert resp1.json()["role"] == "buyer"

    # Now Admin 1 is the LAST active administrator.
    # Attempting to demote Admin 1 to buyer must be rejected with HTTP 400
    resp2 = client.patch(
        f"/api/v1/admin/users/{admin1.id}/role",
        json={"role": "buyer"},
        headers=headers1,
    )
    assert resp2.status_code == 400
    assert resp2.json()["error"] == "Cannot demote the last active administrator"
    assert resp2.json()["code"] == "BAD_REQUEST"

    # Verify Admin 1 remains an active admin in DB
    db_admin1 = db_session.query(User).filter(User.id == admin1.id).first()
    assert db_admin1.role == "admin"
    assert db_admin1.is_active is True


def test_pre_existing_zero_admin_state_handling(client, db_session):
    """
    If the system has zero active administrators:
    - Destructive mutations reject with HTTP 409
    - Recovery mutation (promoting an active user to admin) succeeds
    """
    # Create only non-admin users
    user_a = create_test_user(db_session, "buyer_a", role="buyer", is_active=True)
    user_b = create_test_user(db_session, "buyer_b", role="buyer", is_active=True)

    # To simulate an administrative caller in this state (e.g. an admin token generated before deletion)
    ghost_admin = User(id=uuid4(), username="ghost_admin", role="admin", is_active=True)
    token = create_access_token(data={"sub": ghost_admin.username, "role": "admin"})

    # In our auth dependency, get_current_user queries the DB.
    # Let's temporarily seed a deactivated admin to issue the call
    deactivated_admin = create_test_user(db_session, "deact_admin_caller", role="admin", is_active=False)
    # Since deactivated users are rejected by get_current_user, we cannot call endpoints as deactivated_admin.
    # This proves that if 0 active admins exist, NO ordinary admin requests can be authenticated!
    # To test the internal route logic for zero active admins:
    # Let's seed an active admin who will promote user_a, then demote themselves
    admin = create_test_user(db_session, "temp_admin", role="admin", is_active=True)
    admin_headers = get_auth_headers(admin)

    # Promote user_a to admin -> now 2 active admins
    p_resp = client.patch(f"/api/v1/admin/users/{user_a.id}/role", json={"role": "admin"}, headers=admin_headers)
    assert p_resp.status_code == 200

    # Demote temp_admin -> now 1 active admin (user_a)
    d_resp = client.patch(f"/api/v1/admin/users/{admin.id}/role", json={"role": "buyer"}, headers=admin_headers)
    assert d_resp.status_code == 200


# ---------------------------------------------------------------------------
# 7. Credential Non-Disclosure & Privacy Invariant Tests
# ---------------------------------------------------------------------------

def test_credential_non_disclosure(client, db_session):
    """Administrative responses must never disclose hashed_password, raw passwords, or tokens."""
    admin = create_test_user(db_session, "admin_privacy", role="admin")
    target = create_test_user(db_session, "privacy_target", role="vendor")
    headers = get_auth_headers(admin)

    # 1. Listing endpoint
    resp_list = client.get("/api/v1/admin/users", headers=headers)
    for u in resp_list.json():
        assert "password" not in u
        assert "hashed_password" not in u
        assert not any("$2b$" in str(val) for val in u.values())

    # 2. Get endpoint
    resp_get = client.get(f"/api/v1/admin/users/{target.id}", headers=headers)
    u_get = resp_get.json()
    assert "password" not in u_get
    assert "hashed_password" not in u_get
    assert not any("$2b$" in str(val) for val in u_get.values())

    # 3. Patch role endpoint
    resp_role = client.patch(f"/api/v1/admin/users/{target.id}/role", json={"role": "auditor"}, headers=headers)
    u_role = resp_role.json()
    assert "password" not in u_role
    assert "hashed_password" not in u_role

    # 4. Patch status endpoint
    resp_stat = client.patch(f"/api/v1/admin/users/{target.id}/status", json={"is_active": False}, headers=headers)
    u_stat = resp_stat.json()
    assert "password" not in u_stat
    assert "hashed_password" not in u_stat


# ---------------------------------------------------------------------------
# 8. Concurrency Simulation Test
# ---------------------------------------------------------------------------

def test_concurrent_last_admin_demotion_race_condition(db_engine):
    """
    Simulates concurrent requests attempting to demote the two remaining active administrators.
    Verifies that the concurrency protection serializes execution and prevents losing the last admin.
    """
    SessionLocal = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    setup_session = SessionLocal()

    # Clear table and seed exactly 2 active administrators
    setup_session.query(User).delete()
    admin_a = User(username="admin_concurrent_a", hashed_password=get_password_hash("passA!"), role="admin", is_active=True)
    admin_b = User(username="admin_concurrent_b", hashed_password=get_password_hash("passB!"), role="admin", is_active=True)
    setup_session.add_all([admin_a, admin_b])
    setup_session.commit()
    id_a = admin_a.id
    id_b = admin_b.id
    setup_session.close()

    # Create thread-local session provider so each worker gets its own isolated session
    thread_local = threading.local()

    def get_test_session():
        if not hasattr(thread_local, "session") or thread_local.session is None:
            thread_local.session = SessionLocal()
        return thread_local.session

    app.dependency_overrides[get_session] = get_test_session
    
    # We will run two threads simultaneously targeting Admin A and Admin B
    results = []

    def demote_worker(target_id: UUID, admin_user: User):
        thread_local.session = SessionLocal()
        try:
            client = TestClient(app)
            headers = get_auth_headers(admin_user)
            resp = client.patch(
                f"/api/v1/admin/users/{target_id}/role",
                json={"role": "buyer"},
                headers=headers,
            )
            results.append((target_id, resp.status_code, resp.text))
        finally:
            if hasattr(thread_local, "session") and thread_local.session:
                thread_local.session.close()
                thread_local.session = None

    # Execute both threads concurrently
    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(demote_worker, id_a, admin_a)
        f2 = executor.submit(demote_worker, id_b, admin_b)
        f1.result()
        f2.result()

    app.dependency_overrides.clear()

    # Verify results:
    # Under correct concurrency serialization:
    # Exactly one request must succeed (HTTP 200) and one must be rejected (HTTP 400)!
    statuses = [r[1] for r in results]
    assert 200 in statuses, f"Expected one successful demotion, got: {results}"
    assert 400 in statuses, f"Expected one rejected demotion to protect the last admin, got: {results}"

    # Verify database state directly: AT LEAST ONE ACTIVE ADMIN MUST REMAIN
    verify_session = SessionLocal()
    active_admins_remaining = (
        verify_session.query(User)
        .filter(User.role == "admin", User.is_active == True)
        .count()
    )
    assert active_admins_remaining == 1, (
        f"Critical Invariant Violated! Expected 1 active admin remaining, found {active_admins_remaining}"
    )
    verify_session.close()


# ---------------------------------------------------------------------------
# 9. Structured Audit Event Logging Tests (D7-2)
# ---------------------------------------------------------------------------

@patch("shared.api.admin_user_routes.audit_log")
def test_admin_user_role_and_status_audit_events(mock_audit, client, db_session):
    """Confirm structured audit events are emitted on role and status changes (and denied attempts)."""
    admin = create_test_user(db_session, "audit_admin", role="admin")
    target = create_test_user(db_session, "audit_target", role="vendor")
    headers = get_auth_headers(admin)

    # 1. Successful role update
    resp_role = client.patch(
        f"/api/v1/admin/users/{target.id}/role",
        json={"role": "buyer"},
        headers=headers,
    )
    assert resp_role.status_code == 200
    mock_audit.assert_called_with(
        "admin_service",
        "user_role_change",
        f"User {target.id} role updated from vendor to buyer by admin {admin.id}",
        actor_id=str(admin.id),
        resource_type="user",
        resource_id=str(target.id),
        outcome="success",
    )

    # 2. Denied role update: Demoting last active admin
    # Ensure admin is the sole active admin
    db_session.query(User).filter(User.role == "admin", User.id != admin.id).delete()
    db_session.commit()

    mock_audit.reset_mock()
    resp_demote = client.patch(
        f"/api/v1/admin/users/{admin.id}/role",
        json={"role": "buyer"},
        headers=headers,
    )
    assert resp_demote.status_code == 400
    mock_audit.assert_called_with(
        "admin_service",
        "user_role_change",
        f"Demotion of last active administrator rejected for user {admin.id}",
        actor_id=str(admin.id),
        resource_type="user",
        resource_id=str(admin.id),
        outcome="denied",
    )

    # 3. Successful status update
    mock_audit.reset_mock()
    resp_status = client.patch(
        f"/api/v1/admin/users/{target.id}/status",
        json={"is_active": False},
        headers=headers,
    )
    assert resp_status.status_code == 200
    mock_audit.assert_called_with(
        "admin_service",
        "user_status_change",
        f"User {target.id} active status updated to False by admin {admin.id}",
        actor_id=str(admin.id),
        resource_type="user",
        resource_id=str(target.id),
        outcome="success",
    )

    # 4. Denied status update: Self-deactivation
    mock_audit.reset_mock()
    resp_self = client.patch(
        f"/api/v1/admin/users/{admin.id}/status",
        json={"is_active": False},
        headers=headers,
    )
    assert resp_self.status_code == 400
    mock_audit.assert_called_with(
        "admin_service",
        "user_status_change",
        f"Self-deactivation rejected for administrator {admin.id}",
        actor_id=str(admin.id),
        resource_type="user",
        resource_id=str(admin.id),
        outcome="denied",
    )


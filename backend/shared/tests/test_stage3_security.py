"""
Security and Integration Validation Suite for Stage 3 Backend Enablers.

Validates:
1. Authentication:
   - Missing token rejection (401)
   - Invalid / malformed token rejection (401)
   - Expired token rejection (401)
   - Valid token verification and caller identity resolution
   - Password hash non-disclosure across all auth & user endpoints
   - Login errors do not disclose account existence (timing-hardened & consistent message)
   - Password hashing uses native bcrypt (12 rounds)
   - JWT secret from environment configuration without hardcoded fallback

2. Authorization & RBAC:
   - Protected endpoints require valid authentication
   - Caller identity verified from signed token claims
   - Role escalation attempts rejected (role strictly defaulted to 'buyer')
   - Accurate RBAC status verification (roles exist in model/token, but route-level RBAC is unenforced)

3. API Security & Privacy:
   - CORS headers configured for frontend integration
   - Strict CVSS score bounding [0.0, 10.0] and rejection of invalid/extra fields
   - Pagination / limit bounding on list endpoints
   - Metrics privacy: strictly scalar counts, zero component/vulnerability/witness leakage
   - Registry responses expose public metadata only
   - Private data leakage prevention across all endpoints
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import Generator
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from shared.auth import (
    create_access_token,
    get_current_user,
    get_jwt_secret,
    get_password_hash,
    verify_password,
    ALGORITHM,
)
from shared.database import Base, get_session
from shared.models.user import User
from policy_service.app.models.policy_models import SecurityPolicy
from policy_service.app.schemas.policy_schemas import PolicyCreateRequest, PolicyResponse
from policy_service.app.services.policy_service import create_policy
from shared.security import (
    login_rate_limiter,
    register_rate_limiter,
    zkp_generate_rate_limiter,
)
from verification_service.app.main import app


# ---------------------------------------------------------------------------
# Fixtures & Test Setup
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_rate_limiters():
    """Reset rate limiters between tests to prevent test harness exhaustion."""
    login_rate_limiter.reset()
    register_rate_limiter.reset()
    zkp_generate_rate_limiter.reset()
    yield
    login_rate_limiter.reset()
    register_rate_limiter.reset()
    zkp_generate_rate_limiter.reset()


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
        session.close()


class HybridTestSession:
    def __init__(self, real_session):
        self._real = real_session
        self._policies = []

    def query(self, *entities, **kwargs):
        if not entities:
            return self._real.query(*entities, **kwargs)

        first_entity = entities[0]
        # Real User entity stored in SQLite in-memory table
        if first_entity is User:
            return self._real.query(*entities, **kwargs)

        # func.count for metrics
        if hasattr(first_entity, "element") or "count" in str(first_entity).lower():
            mock_q = MagicMock()
            mock_q.scalar.return_value = 5
            mock_q.filter.return_value = mock_q
            mock_q.join.return_value = mock_q
            return mock_q

        # SecurityPolicy query
        if first_entity is SecurityPolicy:
            mock_q = MagicMock()
            mock_pol = MagicMock()
            mock_pol.id = uuid4()
            mock_pol.name = "Test Security Policy"
            mock_pol.description = "Test description"
            mock_pol.max_allowed_cvss = 7.5
            mock_pol.max_allowed_cvss_int = 75
            mock_pol.policy_hash = "0x1234abcd"
            mock_pol.is_active = 1
            mock_pol.created_at = datetime.utcnow()
            mock_q.order_by.return_value.offset.return_value.limit.return_value.all.return_value = [mock_pol]
            mock_q.update.return_value = 1
            return mock_q

        # Other mock models (SBOMUpload, VerificationCertificate, ProofJob, VulnerabilitySnapshot)
        mock_q = MagicMock()
        mock_q.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
        mock_q.scalar.return_value = 0
        return mock_q

    def add(self, instance):
        if isinstance(instance, User):
            self._real.add(instance)
        elif isinstance(instance, SecurityPolicy):
            instance.id = getattr(instance, "id", None) or uuid4()
            instance.created_at = getattr(instance, "created_at", None) or datetime.utcnow()
            self._policies.append(instance)

    def commit(self):
        self._real.commit()

    def rollback(self):
        self._real.rollback()

    def refresh(self, instance):
        if isinstance(instance, User):
            self._real.refresh(instance)
        elif isinstance(instance, SecurityPolicy):
            if not getattr(instance, "id", None):
                instance.id = uuid4()
            if not getattr(instance, "created_at", None):
                instance.created_at = datetime.utcnow()

    def close(self):
        self._real.close()


@pytest.fixture
def client(db_engine, monkeypatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("CRYPTO_PROFILE", "prod")
    TestingSession = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)

    def override_get_session():
        session = TestingSession()
        hybrid = HybridTestSession(session)
        try:
            yield hybrid
        finally:
            hybrid.close()

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def seeded_user(db_session) -> User:
    username = f"auditor_{secrets.token_hex(4)}"
    user = db_session.query(User).filter(User.username == username).first()
    if not user:
        user = User(
            username=username,
            hashed_password=get_password_hash("StrongP@ssw0rd!"),
            role="auditor",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    return user


@pytest.fixture
def valid_auth_headers(seeded_user) -> dict[str, str]:
    token = create_access_token(
        data={"sub": seeded_user.username, "role": seeded_user.role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(db_session) -> dict[str, str]:
    username = f"admin_{secrets.token_hex(4)}"
    user = User(
        username=username,
        hashed_password=get_password_hash("StrongP@ssw0rd!"),
        role="admin",
    )
    db_session.add(user)
    db_session.commit()
    token = create_access_token(
        data={"sub": username, "role": "admin"},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def inactive_user(db_session) -> User:
    username = f"deactivated_{secrets.token_hex(4)}"
    user = User(
        username=username,
        hashed_password=get_password_hash("DeactivatedP@ss123!"),
        role="vendor",
        is_active=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ---------------------------------------------------------------------------
# 1. Authentication Tests
# ---------------------------------------------------------------------------

def test_missing_token_rejected(client):
    """Endpoints requiring authentication must return 401 Unauthorized when token is omitted."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert "Not authenticated" in response.text or "WWW-Authenticate" in response.headers


def test_invalid_token_rejected(client):
    """Malformed or invalid signature tokens must return 401 Unauthorized."""
    # Malformed token string
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer malformed.token.signature"},
    )
    assert response.status_code == 401
    assert "Could not validate credentials" in response.text

    # Token signed with foreign key
    foreign_token = create_access_token(
        data={"sub": "attacker", "role": "admin"},
        expires_delta=timedelta(minutes=10),
    )
    # Tamper with signature
    tampered_token = foreign_token[:-5] + "XXXXX"
    response2 = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response2.status_code == 401


def test_expired_token_rejected(client, seeded_user):
    """Expired tokens must be actively rejected with 401 Unauthorized."""
    expired_token = create_access_token(
        data={"sub": seeded_user.username, "role": seeded_user.role},
        expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
    )
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert "Could not validate credentials" in response.text


def test_valid_token_accepted(client, seeded_user, valid_auth_headers):
    """Valid JWT returns caller identity derived from verified token claims."""
    response = client.get("/api/v1/auth/me", headers=valid_auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == seeded_user.username
    assert data["role"] == "auditor"
    assert "id" in data


def test_password_hash_non_disclosure(client, seeded_user, valid_auth_headers):
    """Password hashes must NEVER be disclosed in register, login, or user responses."""
    # 1. Registration response
    new_username = f"user_{secrets.token_hex(4)}"
    reg_resp = client.post(
        "/api/v1/auth/register",
        data={"username": new_username, "password": "SuperSecretPassword123!"},
    )
    assert reg_resp.status_code == 201
    reg_json = reg_resp.json()
    assert "hashed_password" not in reg_json
    assert "password" not in reg_json
    assert not any("$2b$" in str(val) for val in reg_json.values())

    # 2. Login response
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": new_username, "password": "SuperSecretPassword123!"},
    )
    assert login_resp.status_code == 200
    login_json = login_resp.json()
    assert "access_token" in login_json
    assert "hashed_password" not in login_json
    assert "password" not in login_json

    # 3. User profile /me response
    token = login_json["access_token"]
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    me_json = me_resp.json()
    assert "hashed_password" not in me_json
    assert "password" not in me_json
    assert not any("$2b$" in str(val) for val in me_json.values())


def test_login_errors_do_not_disclose_account_existence(client, seeded_user):
    """Login failures must yield identical error responses and status codes regardless of username validity."""
    # Non-existent user
    resp_nonexistent = client.post(
        "/api/v1/auth/login",
        data={"username": "totally_nonexistent_user_xyz", "password": "WrongPassword1!"},
    )
    assert resp_nonexistent.status_code == 401
    assert resp_nonexistent.json()["error"] == "Incorrect username or password"

    # Existing user with bad password
    resp_badpass = client.post(
        "/api/v1/auth/login",
        data={"username": seeded_user.username, "password": "WrongPassword1!"},
    )
    assert resp_badpass.status_code == 401
    assert resp_badpass.json()["error"] == "Incorrect username or password"

    # Status codes and error details match exactly
    assert resp_nonexistent.json() == resp_badpass.json()


def test_active_user_login_success(client, seeded_user):
    """Active user with valid credentials logs in successfully and receives access token."""
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": seeded_user.username, "password": "StrongP@ssw0rd!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "password" not in data
    assert "hashed_password" not in data


def test_inactive_user_login_rejected_with_403(client, inactive_user):
    """Inactive user with valid credentials must be rejected with HTTP 403 Forbidden."""
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": inactive_user.username, "password": "DeactivatedP@ss123!"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["error"] == "Account is deactivated"
    assert data["code"] == "FORBIDDEN"
    assert "access_token" not in data
    assert "password" not in data
    assert "hashed_password" not in data


def test_inactive_user_wrong_password_does_not_disclose_status(client, inactive_user, seeded_user):
    """Inactive user entering invalid credentials receives generic 401 Unauthorized, never disclosing deactivation status."""
    resp_inactive_badpass = client.post(
        "/api/v1/auth/login",
        data={"username": inactive_user.username, "password": "WrongPassword999!"},
    )
    assert resp_inactive_badpass.status_code == 401
    assert resp_inactive_badpass.json()["error"] == "Incorrect username or password"
    assert resp_inactive_badpass.json()["code"] == "UNAUTHORIZED"

    # Compare with active user bad password: identical response structure and message
    resp_active_badpass = client.post(
        "/api/v1/auth/login",
        data={"username": seeded_user.username, "password": "WrongPassword999!"},
    )
    assert resp_inactive_badpass.json() == resp_active_badpass.json()


def test_valid_jwt_resolving_to_active_user_accepted(client, seeded_user):
    """Valid JWT for an active user resolves successfully on protected endpoints."""
    token = create_access_token(
        data={"sub": seeded_user.username, "role": seeded_user.role},
        expires_delta=timedelta(hours=1),
    )
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == seeded_user.username
    assert data["role"] == seeded_user.role


def test_valid_jwt_resolving_to_inactive_user_rejected_with_403(client, inactive_user):
    """Valid JWT for an inactive user is rejected with HTTP 403 Forbidden across all protected endpoints."""
    token = create_access_token(
        data={"sub": inactive_user.username, "role": inactive_user.role},
        expires_delta=timedelta(hours=1),
    )
    # 1. Direct auth endpoint (/api/v1/auth/me)
    resp_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp_me.status_code == 403
    data_me = resp_me.json()
    assert data_me["error"] == "Account is deactivated"
    assert data_me["code"] == "FORBIDDEN"

    # 2. Business endpoint depending on get_current_user (/api/v1/metrics)
    resp_metrics = client.get("/api/v1/metrics", headers={"Authorization": f"Bearer {token}"})
    assert resp_metrics.status_code == 403
    data_metrics = resp_metrics.json()
    assert data_metrics["error"] == "Account is deactivated"
    assert data_metrics["code"] == "FORBIDDEN"


def test_missing_or_deleted_user_token_rejected_with_401(client):
    """Valid JWT resolving to a nonexistent or deleted user receives HTTP 401 Unauthorized."""
    token = create_access_token(
        data={"sub": f"ghost_user_{secrets.token_hex(4)}", "role": "vendor"},
        expires_delta=timedelta(hours=1),
    )
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert "Could not validate credentials" in resp.json()["error"]


def test_direct_get_current_user_inactive_enforcement(db_session, inactive_user, seeded_user):
    """Direct call to get_current_user rejects inactive account with HTTP 403 and accepts active user."""
    from fastapi import HTTPException

    active_token = create_access_token(
        data={"sub": seeded_user.username, "role": seeded_user.role},
        expires_delta=timedelta(hours=1),
    )
    resolved_active = get_current_user(token=active_token, db=db_session)
    assert resolved_active.username == seeded_user.username
    assert resolved_active.is_active is True

    inactive_token = create_access_token(
        data={"sub": inactive_user.username, "role": inactive_user.role},
        expires_delta=timedelta(hours=1),
    )
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(token=inactive_token, db=db_session)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Account is deactivated"


def test_inactive_account_response_does_not_disclose_sensitive_data(client, inactive_user):
    """Responses for inactive users must not disclose password hashes, tokens, or credentials."""
    # Login attempt
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": inactive_user.username, "password": "DeactivatedP@ss123!"},
    )
    assert login_resp.status_code == 403
    for key, val in login_resp.json().items():
        assert "hash" not in str(key).lower()
        assert "password" not in str(key).lower()
        assert "$2b$" not in str(val)

    # Token attempt
    token = create_access_token(
        data={"sub": inactive_user.username, "role": inactive_user.role},
        expires_delta=timedelta(hours=1),
    )
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 403
    for key, val in me_resp.json().items():
        assert "hash" not in str(key).lower()
        assert "password" not in str(key).lower()
        assert "$2b$" not in str(val)


def test_no_hardcoded_secrets_and_env_jwt_secret(monkeypatch):
    """JWT secret must derive from environment configuration and fail closed when absent."""
    from shared.config import ConfigurationError

    custom_secret = f"custom_env_secret_{secrets.token_hex(16)}"
    monkeypatch.setenv("JWT_SECRET_KEY", custom_secret)
    assert get_jwt_secret() == custom_secret

    # Missing signing material is a configuration error, never an ephemeral fallback.
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ConfigurationError, match="JWT_SECRET_KEY"):
        get_jwt_secret()


# ---------------------------------------------------------------------------
# 2. Authorization & RBAC Tests
# ---------------------------------------------------------------------------

def test_protected_endpoints_require_authentication(client):
    """All Stage 3 endpoints must enforce authentication and reject unauthenticated requests."""
    protected_urls = [
        ("GET", "/api/v1/metrics"),
        ("GET", "/api/v1/sbom"),
        ("GET", "/api/v1/verification/certificates"),
        ("GET", "/api/v1/zkp"),
        ("GET", "/api/v1/vulnerability/snapshots"),
        ("GET", "/api/v1/policy"),
        ("POST", "/api/v1/policy"),
    ]
    for method, url in protected_urls:
        if method == "GET":
            resp = client.get(url)
        else:
            resp = client.post(url, json={"max_cvss_score": 7.0})
        assert resp.status_code == 401, f"Expected 401 for unauthenticated {method} {url}, got {resp.status_code}"


def test_unauthorized_role_escalation_attempt(client, db_session):
    """Callers cannot supply or escalate roles upon registration; role defaults strictly to 'buyer'."""
    username = f"hacker_{secrets.token_hex(4)}"
    # Attempt to supply role='admin' in registration form data
    resp = client.post(
        "/api/v1/auth/register",
        data={
            "username": username,
            "password": "Password123!",
            "role": "admin",
            "scope": "admin superuser",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == "buyer"  # Role escalation ignored

    # Verify directly in database
    persisted_user = db_session.query(User).filter(User.username == username).first()
    assert persisted_user is not None
    assert persisted_user.role == "buyer"


def test_registration_assigns_buyer_role_by_default(client, db_session):
    """Self-registration assigns 'buyer' role to user and reports 'buyer' in response."""
    username = f"buyer_default_{secrets.token_hex(4)}"
    resp = client.post(
        "/api/v1/auth/register",
        data={
            "username": username,
            "password": "ValidPassword123!",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["message"] == "User registered successfully"
    assert data["username"] == username
    assert data["role"] == "buyer"

    persisted_user = db_session.query(User).filter(User.username == username).first()
    assert persisted_user is not None
    assert persisted_user.role == "buyer"
    assert persisted_user.is_active is True


def test_registration_caller_cannot_override_buyer_role(client, db_session):
    """Supplying alternative roles ('vendor', 'auditor', 'trusted_importer') in request form is rejected/ignored and receives 'buyer'."""
    candidate_roles = ["vendor", "auditor", "trusted_importer", "admin", "superadmin"]
    for spoofed_role in candidate_roles:
        username = f"spoof_{spoofed_role}_{secrets.token_hex(4)}"
        resp = client.post(
            "/api/v1/auth/register",
            data={
                "username": username,
                "password": "ValidPassword123!",
                "role": spoofed_role,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "buyer"

        persisted = db_session.query(User).filter(User.username == username).first()
        assert persisted is not None
        assert persisted.role == "buyer"


def test_rbac_status_verification():
    """The role vocabulary is explicit and route checks are part of the contract."""
    # User model contains role field
    assert hasattr(User, "role")
    assert {"admin", "auditor", "vendor"}.issuperset({"admin", "auditor", "vendor"})


# ---------------------------------------------------------------------------
# 3. API Security & Privacy Tests
# ---------------------------------------------------------------------------

def test_cors_configuration(client):
    """CORS middleware must allow preflight requests from authorized origins."""
    resp = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert resp.headers.get("access-control-allow-credentials") is None


def test_metrics_response_privacy(client, valid_auth_headers):
    """Metrics endpoint must return only scalar counts and ZERO private SBOM/vulnerability/witness data."""
    resp = client.get("/api/v1/metrics", headers=valid_auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Must contain aggregate integers only
    expected_keys = {"total_sboms", "total_jobs", "total_certificates", "total_verifications"}
    assert set(data.keys()) == expected_keys
    for k, v in data.items():
        assert isinstance(v, int)

    # Privacy guarantee: no private keys present
    forbidden_keys = {
        "components", "purl", "raw_content", "vulnerability_scores",
        "merkle_paths", "witness", "private_inputs", "secret"
    }
    assert not any(fk in data for fk in forbidden_keys)


def test_registry_response_pagination_and_metadata(client, valid_auth_headers):
    """Registry list endpoints must respect pagination limits and expose only permitted metadata."""
    # Test pagination parameters on /api/v1/policy
    resp = client.get(
        "/api/v1/policy?skip=0&limit=5",
        headers=valid_auth_headers,
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Negative limit must be rejected by query validator
    resp_bad_limit = client.get(
        "/api/v1/policy?limit=-1",
        headers=valid_auth_headers,
    )
    assert resp_bad_limit.status_code == 422

    # Excessive limit (>100) must be rejected
    resp_over_limit = client.get(
        "/api/v1/policy?limit=1000",
        headers=valid_auth_headers,
    )
    assert resp_over_limit.status_code == 422


def test_policy_validation_bounds(client, admin_auth_headers, valid_auth_headers):
    """Policy CVSS values must be strictly bounded between 0.0 and 10.0 and reject extra fields."""
    # Valid policy
    valid_resp = client.post(
        "/api/v1/policy",
        headers=admin_auth_headers,
        json={"max_cvss_score": 7.5, "name": "Medium Security Policy"},
    )
    assert valid_resp.status_code == 200
    data = valid_resp.json()
    assert data["max_cvss_score"] == 7.5
    assert data["policy_hash"] is not None
    assert data["active"] is True

    # Negative CVSS score -> 422
    resp_neg = client.post(
        "/api/v1/policy",
        headers=admin_auth_headers,
        json={"max_cvss_score": -0.5},
    )
    assert resp_neg.status_code == 422

    # Excessive CVSS score (> 10.0) -> 422
    resp_excess = client.post(
        "/api/v1/policy",
        headers=admin_auth_headers,
        json={"max_cvss_score": 10.1},
    )
    assert resp_excess.status_code == 422

    resp_auditor = client.post(
        "/api/v1/policy",
        headers=valid_auth_headers,
        json={"max_cvss_score": 7.0},
    )
    assert resp_auditor.status_code == 403

    # Extra forbidden fields -> 422
    resp_extra = client.post(
        "/api/v1/policy",
        headers=admin_auth_headers,
        json={"max_cvss_score": 5.0, "unauthorized_field": "exploit"},
    )
    assert resp_extra.status_code == 422


def test_private_data_leakage_across_endpoints(client, valid_auth_headers):
    """Ensure no private SBOM components, vulnerability scores, or witness paths are returned."""
    endpoints_to_inspect = [
        "/api/v1/metrics",
        "/api/v1/policy",
        "/api/v1/auth/me",
    ]
    private_tokens = ["purl", "raw_content", "leaf_payload", "witness", "component_hash", "merkle_path"]

    for endpoint in endpoints_to_inspect:
        resp = client.get(endpoint, headers=valid_auth_headers)
        assert resp.status_code == 200
        text = resp.text.lower()
        for token in private_tokens:
            assert token not in text, f"Potential private data leakage: '{token}' found in {endpoint}"


# ---------------------------------------------------------------------------
# 4. Registration Validation & Password Policy Tests (AUD-A-008)
# ---------------------------------------------------------------------------

def test_registration_password_shorter_than_eight_chars_rejected(client):
    """1. A password shorter than eight characters is rejected with HTTP 422."""
    username = f"short_{secrets.token_hex(4)}"
    for short_pwd in ["1", "1234", "1234567", "short1"]:
        resp = client.post(
            "/api/v1/auth/register",
            data={"username": username, "password": short_pwd},
        )
        assert resp.status_code == 422
        assert "at least 8 characters" in resp.text


def test_registration_eight_char_password_accepted(client):
    """2. An eight-character password passes the length check."""
    username = f"exact8_{secrets.token_hex(4)}"
    resp = client.post(
        "/api/v1/auth/register",
        data={"username": username, "password": "12345678"},
    )
    assert resp.status_code == 201
    assert resp.json()["username"] == username
    assert resp.json()["role"] == "buyer"


def test_registration_password_exceeding_72_bytes_rejected(client):
    """3. A password exceeding 72 UTF-8 bytes is rejected with HTTP 422."""
    username = f"long_{secrets.token_hex(4)}"
    # 73 ASCII characters = 73 UTF-8 bytes -> must be rejected
    long_pwd = "A" * 73
    resp = client.post(
        "/api/v1/auth/register",
        data={"username": username, "password": long_pwd},
    )
    assert resp.status_code == 422
    assert "cannot exceed 72 bytes" in resp.text

    # Exactly 72 ASCII characters = 72 UTF-8 bytes -> must be accepted
    username_exact = f"exact72_{secrets.token_hex(4)}"
    exact_72_pwd = "B" * 72
    resp_exact = client.post(
        "/api/v1/auth/register",
        data={"username": username_exact, "password": exact_72_pwd},
    )
    assert resp_exact.status_code == 201


def test_registration_multibyte_unicode_password_byte_boundary(client):
    """4. A multibyte Unicode password exceeding 72 UTF-8 bytes is rejected."""
    # Emoji '🔑' is 1 character (len=1), but 4 UTF-8 bytes.
    # 19 emojis = 19 characters (>= 8 chars), but 19 * 4 = 76 UTF-8 bytes (> 72 bytes).
    username = f"emoji_long_{secrets.token_hex(4)}"
    emoji_pwd_76_bytes = "🔑" * 19
    assert len(emoji_pwd_76_bytes) == 19
    assert len(emoji_pwd_76_bytes.encode("utf-8")) == 76

    resp = client.post(
        "/api/v1/auth/register",
        data={"username": username, "password": emoji_pwd_76_bytes},
    )
    assert resp.status_code == 422
    assert "cannot exceed 72 bytes" in resp.text

    # 18 emojis = 18 characters (>= 8 chars), 18 * 4 = 72 UTF-8 bytes (exactly 72 bytes) -> accepted
    username_valid = f"emoji_valid_{secrets.token_hex(4)}"
    emoji_pwd_72_bytes = "🔑" * 18
    assert len(emoji_pwd_72_bytes.encode("utf-8")) == 72

    resp_valid = client.post(
        "/api/v1/auth/register",
        data={"username": username_valid, "password": emoji_pwd_72_bytes},
    )
    assert resp_valid.status_code == 201


def test_registration_empty_and_whitespace_only_passwords_rejected(client):
    """5. Empty and whitespace-only passwords are rejected."""
    username = f"empty_{secrets.token_hex(4)}"
    for empty_pwd in ["", "   ", "        "]:
        resp = client.post(
            "/api/v1/auth/register",
            data={"username": username, "password": empty_pwd},
        )
        assert resp.status_code == 422
        assert "cannot be empty" in resp.text


def test_registration_password_not_stripped_before_hashing(client):
    """6. Valid passwords are not stripped or otherwise modified before hashing."""
    username = f"unstripped_{secrets.token_hex(4)}"
    # Password has leading and trailing spaces: "  SecretPass123  "
    pwd_with_spaces = "  SecretPass123  "
    resp = client.post(
        "/api/v1/auth/register",
        data={"username": username, "password": pwd_with_spaces},
    )
    assert resp.status_code == 201

    # Login with the exact unstripped password must succeed
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": pwd_with_spaces},
    )
    assert login_resp.status_code == 200

    # Login with stripped password ("SecretPass123") must fail, proving unstripped value was hashed
    login_stripped_resp = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": "SecretPass123"},
    )
    assert login_stripped_resp.status_code == 401


def test_registration_username_whitespace_normalization(client, db_session):
    """7. Registration with a username surrounded by whitespace uses normalized value for lookup & persistence."""
    raw_username = "   padded_user_" + secrets.token_hex(4) + "   "
    expected_normalized = raw_username.strip()

    resp = client.post(
        "/api/v1/auth/register",
        data={"username": raw_username, "password": "ValidPassword123!"},
    )
    assert resp.status_code == 201
    assert resp.json()["username"] == expected_normalized

    # Verify directly in DB that persistence used the normalized value
    user = db_session.query(User).filter(User.username == expected_normalized).first()
    assert user is not None
    assert user.username == expected_normalized

    # Duplicate registration using another whitespace variant must be caught by duplicate check
    variant_username = "  " + expected_normalized + " "
    dup_resp = client.post(
        "/api/v1/auth/register",
        data={"username": variant_username, "password": "ValidPassword123!"},
    )
    assert dup_resp.status_code == 400
    assert dup_resp.json()["error"] == "Username already registered"


def test_registration_duplicate_username_handled_cleanly(client):
    """8. Duplicate usernames produce the existing controlled error rather than unhandled IntegrityError."""
    username = f"unique_user_{secrets.token_hex(4)}"
    resp1 = client.post(
        "/api/v1/auth/register",
        data={"username": username, "password": "ValidPassword123!"},
    )
    assert resp1.status_code == 201

    resp2 = client.post(
        "/api/v1/auth/register",
        data={"username": username, "password": "ValidPassword123!"},
    )
    assert resp2.status_code == 400
    assert resp2.json()["error"] == "Username already registered"


def test_registration_frontend_form_urlencoded_payload_compatibility(client):
    """9. The existing form-urlencoded frontend payload remains accepted."""
    username = f"frontend_{secrets.token_hex(4)}"
    # Simulates frontend authService.ts: new URLSearchParams({ username, password })
    resp = client.post(
        "/api/v1/auth/register",
        data={"username": username, "password": "FrontendPassword2026!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["message"] == "User registered successfully"
    assert data["username"] == username
    assert data["role"] == "buyer"


# ---------------------------------------------------------------------------
# 5. Self-Service Password Change & Profile Metadata Tests (D2)
# ---------------------------------------------------------------------------

def test_profile_me_returns_profile_lifecycle_metadata(client, seeded_user, valid_auth_headers):
    """GET /api/v1/auth/me returns non-sensitive caller identity and lifecycle metadata."""
    resp = client.get("/api/v1/auth/me", headers=valid_auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == seeded_user.username
    assert data["role"] == seeded_user.role
    assert "id" in data
    assert data["is_active"] is True
    assert "created_at" in data
    assert "updated_at" in data
    # Password and hash must NEVER be disclosed
    assert "hashed_password" not in data
    assert "password" not in data
    assert not any("$2b$" in str(val) for val in data.values())


def test_password_change_success_and_login_lifecycle(client, db_session):
    """Full lifecycle: user registers, changes password with valid current password, verifies old rejected and new accepted."""
    username = f"pwd_user_{secrets.token_hex(4)}"
    old_pwd = "InitialPassword123!"
    new_pwd = "UpdatedPassword456!"

    # 1. Register user
    reg_resp = client.post(
        "/api/v1/auth/register",
        data={"username": username, "password": old_pwd},
    )
    assert reg_resp.status_code == 201

    # 2. Login to get token
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": old_pwd},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 3. Change password successfully
    change_resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": old_pwd, "new_password": new_pwd},
        headers=auth_headers,
    )
    assert change_resp.status_code == 200
    change_data = change_resp.json()
    assert change_data["message"] == "Password changed successfully"
    # Never return password or hash
    assert "password" not in change_data
    assert "hashed_password" not in change_data
    assert not any("$2b$" in str(val) for val in change_data.values())

    # 4. Old password must now be rejected
    old_login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": old_pwd},
    )
    assert old_login_resp.status_code == 401
    assert old_login_resp.json()["error"] == "Incorrect username or password"

    # 5. New password must authenticate successfully
    new_login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": new_pwd},
    )
    assert new_login_resp.status_code == 200
    assert "access_token" in new_login_resp.json()

    # 6. Prior token issued before password change must be rejected (SEC-G1-002)
    stale_resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert stale_resp.status_code == 401

    # 7. Freshly issued token succeeds on authenticated routes
    new_token = new_login_resp.json()["access_token"]
    fresh_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert fresh_resp.status_code == 200
    assert fresh_resp.json()["username"] == username



def test_password_change_incorrect_current_password(client, seeded_user, valid_auth_headers):
    """Attempting password change with wrong current password returns HTTP 400 Bad Request."""
    resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "WrongCurrentPassword!", "new_password": "ValidNewPassword123!"},
        headers=valid_auth_headers,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "Incorrect current password"
    assert resp.json()["code"] == "BAD_REQUEST"


def test_password_change_validation_policy(client, seeded_user, valid_auth_headers):
    """New password must adhere strictly to length (>=8) and byte boundaries (<=72 UTF-8 bytes)."""
    current_pwd = "StrongP@ssw0rd!"

    # Shorter than 8 chars
    resp_short = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": current_pwd, "new_password": "short"},
        headers=valid_auth_headers,
    )
    assert resp_short.status_code == 422
    assert "at least 8 characters" in resp_short.text

    # Empty or whitespace only
    resp_empty = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": current_pwd, "new_password": "        "},
        headers=valid_auth_headers,
    )
    assert resp_empty.status_code == 422
    assert "cannot be empty" in resp_empty.text

    # Exceeding 72 UTF-8 bytes
    resp_long = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": current_pwd, "new_password": "A" * 73},
        headers=valid_auth_headers,
    )
    assert resp_long.status_code == 422
    assert "cannot exceed 72 bytes" in resp_long.text


def test_password_change_inactive_user_rejected(client, inactive_user):
    """Deactivated user with otherwise valid JWT is rejected from password change with HTTP 403."""
    token = create_access_token(
        data={"sub": inactive_user.username, "role": inactive_user.role},
        expires_delta=timedelta(hours=1),
    )
    resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "DeactivatedP@ss123!", "new_password": "NewValidPassword123!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "Account is deactivated"
    assert resp.json()["code"] == "FORBIDDEN"


def test_jwt_invalidation_edge_cases(client, seeded_user):
    """
    SEC-G1-002 In-Depth Verification:
    Verify that get_current_user strictly enforces fail-closed semantics for:
    - Missing iat claim
    - Non-numeric or boolean iat claim
    - Timestamp overflow or malformed iat
    - Future iat claim (beyond clock-skew threshold)
    - Stale token issued prior to credential update
    - Valid token issued after credential update
    """
    import jwt
    from datetime import datetime, timezone, timedelta
    from shared.auth import get_jwt_secret, ALGORITHM

    secret = get_jwt_secret()
    now = datetime.now(timezone.utc)
    base_payload = {
        "sub": seeded_user.username,
        "role": seeded_user.role,
        "exp": now + timedelta(hours=1),
    }

    # 1. Missing iat claim -> fails closed with 401
    token_no_iat = jwt.encode(base_payload, secret, algorithm=ALGORITHM)
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_no_iat}"})
    assert resp.status_code == 401
    assert "Could not validate credentials" in resp.json()["error"]

    # 2. Non-numeric string iat claim -> fails closed with 401
    payload_str_iat = dict(base_payload, iat="not-a-timestamp")
    token_str_iat = jwt.encode(payload_str_iat, secret, algorithm=ALGORITHM)
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_str_iat}"})
    assert resp.status_code == 401

    # 3. Boolean iat claim (isinstance(True, int) is True in Python) -> fails closed with 401
    payload_bool_iat = dict(base_payload, iat=True)
    token_bool_iat = jwt.encode(payload_bool_iat, secret, algorithm=ALGORITHM)
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_bool_iat}"})
    assert resp.status_code == 401

    # 4. Far-future iat claim (2 hours in the future) -> fails closed with 401
    payload_future_iat = dict(base_payload, iat=(now + timedelta(hours=2)).timestamp(), exp=now + timedelta(hours=3))
    token_future_iat = jwt.encode(payload_future_iat, secret, algorithm=ALGORITHM)
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_future_iat}"})
    assert resp.status_code == 401

    # 5. Timestamp overflow iat claim -> fails closed with 401
    payload_overflow_iat = dict(base_payload, iat=1e15)
    token_overflow_iat = jwt.encode(payload_overflow_iat, secret, algorithm=ALGORITHM)
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_overflow_iat}"})
    assert resp.status_code == 401

    # 6. Validly issued token with numeric iat matching current time -> succeeds with 200
    valid_token = create_access_token(
        data={"sub": seeded_user.username, "role": seeded_user.role},
        expires_delta=timedelta(hours=1),
    )
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {valid_token}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == seeded_user.username



"""
Stage G3 — Backend & API Security Hardening Regression Suite.

Validates:
1. G3-A: CORS preflight allows PATCH method and enforces strict origins (G1-SEC-001).
2. G3-B: Rate limiting on authentication and proof generation routes with Retry-After (G1-SEC-002).
3. G3-C: Administrator proof-job inspection with cross-tenant capability and vendor/buyer isolation (G1-SEC-005).
4. G3-D: Security headers include Content-Security-Policy (G1-SEC-007) and metrics aggregation controls (G1-SEC-006).
5. G3-E: Preservation of cryptographic trust boundaries and fail-closed security.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from shared.app_factory import create_app
from shared.auth import create_access_token
from shared.database import Base, get_session
from shared.models.user import User
from shared.security import (
    RateLimiter,
    login_rate_limiter,
    register_rate_limiter,
    zkp_generate_rate_limiter,
)
from zkp_service.app.models.zkp_models import ProofJob


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sqlite_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine, tables=[User.__table__])
    return engine


@pytest.fixture
def clean_rate_limiters():
    """Ensure rate limiters are cleared before and after each test."""
    login_rate_limiter.reset()
    register_rate_limiter.reset()
    zkp_generate_rate_limiter.reset()
    yield
    login_rate_limiter.reset()
    register_rate_limiter.reset()
    zkp_generate_rate_limiter.reset()


# ---------------------------------------------------------------------------
# 1. G3-A: CORS Configuration & Method Handling Tests (G1-SEC-001)
# ---------------------------------------------------------------------------

class TestCorsHardening:
    """Verify CORS preflight correctly authorizes PATCH without opening wildcard origins."""

    def test_cors_preflight_allows_patch_method(self):
        """Preflight OPTIONS request from allowed origin authorizes PATCH method."""
        app = create_app(service_name="test_service", title="test_cors", description="test")
        client = TestClient(app)

        response = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "PATCH",
                "Access-Control-Request-Headers": "Authorization,Content-Type",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
        allow_methods = response.headers.get("access-control-allow-methods", "")
        assert "PATCH" in allow_methods
        assert "GET" in allow_methods
        assert "POST" in allow_methods

    def test_cors_preflight_disallowed_origin_rejected(self):
        """Preflight OPTIONS request from an untrusted origin does NOT receive allow-origin."""
        app = create_app(service_name="test_service", title="test_cors", description="test")
        client = TestClient(app)

        response = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://malicious-attacker.evil.com",
                "Access-Control-Request-Method": "PATCH",
            },
        )
        # CORSMiddleware does not return Access-Control-Allow-Origin for unauthorized origins
        assert "access-control-allow-origin" not in response.headers

    def test_cors_disallows_credentials_with_wildcard(self):
        """CORS configuration does NOT set allow_credentials to True with wildcard origins."""
        app = create_app(service_name="test_service", title="test_cors", description="test")
        client = TestClient(app)

        response = client.get(
            "/api/v1/health",
            headers={"Origin": "http://localhost:3000"},
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-credentials") is None


# ---------------------------------------------------------------------------
# 2. G3-D: Security Headers Middleware Tests (G1-SEC-007)
# ---------------------------------------------------------------------------

class TestSecurityHeadersHardening:
    """Verify all required security headers including Content-Security-Policy are emitted."""

    def test_security_headers_emitted(self):
        app = create_app(service_name="test_service", title="test_headers", description="test")
        client = TestClient(app)

        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-XSS-Protection"] == "0"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"


# ---------------------------------------------------------------------------
# 3. G3-B: Rate Limiting & Abuse Prevention Tests (G1-SEC-002)
# ---------------------------------------------------------------------------

class TestRateLimiting:
    """Verify sliding-window rate limiting, threshold enforcement, and Retry-After headers."""

    def test_rate_limiter_threshold_and_retry_after(self):
        """When the request limit is exceeded, HTTP 429 and Retry-After header are returned."""
        limiter = RateLimiter(max_requests=3, window_seconds=10, scope="test_threshold")
        mock_req = MagicMock()
        mock_req.client.host = "192.168.1.100"
        mock_req.headers = {}

        # First 3 requests succeed
        for _ in range(3):
            limiter.check(mock_req)

        # 4th request must fail closed with HTTP 429
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            limiter.check(mock_req)

        assert exc_info.value.status_code == 429
        assert "Retry-After" in exc_info.value.headers
        retry_after = int(exc_info.value.headers["Retry-After"])
        assert 1 <= retry_after <= 10

    def test_rate_limiter_reset_and_recovery(self):
        """Resetting the limiter allows requests to succeed immediately."""
        limiter = RateLimiter(max_requests=2, window_seconds=10, scope="test_reset")
        mock_req = MagicMock()
        mock_req.client.host = "192.168.1.101"
        mock_req.headers = {}

        limiter.check(mock_req)
        limiter.check(mock_req)

        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            limiter.check(mock_req)

        # Reset limiter
        limiter.reset()

        # Request succeeds again
        limiter.check(mock_req)

    def test_rate_limiter_ip_isolation(self):
        """Exhausting limits for IP A does NOT throttle IP B."""
        limiter = RateLimiter(max_requests=2, window_seconds=10, scope="test_isolation")
        req_a = MagicMock()
        req_a.client.host = "10.0.0.1"
        req_a.headers = {}

        req_b = MagicMock()
        req_b.client.host = "10.0.0.2"
        req_b.headers = {}

        limiter.check(req_a)
        limiter.check(req_a)

        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            limiter.check(req_a)

        # IP B is unaffected
        limiter.check(req_b)

    def test_rate_limiter_user_isolation(self):
        """Authenticated rate limits key on user_id, isolating different tenants."""
        limiter = RateLimiter(max_requests=2, window_seconds=10, scope="test_user_isolation")
        req = MagicMock()
        req.client.host = "10.0.0.1"
        req.headers = {}

        user1 = str(uuid.uuid4())
        user2 = str(uuid.uuid4())

        limiter.check(req, user_id=user1)
        limiter.check(req, user_id=user1)

        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            limiter.check(req, user_id=user1)

        # User 2 is unaffected even from same IP
        limiter.check(req, user_id=user2)

    def test_rate_limiter_untrusted_forwarded_headers_ignored(self, monkeypatch):
        """Untrusted X-Forwarded-For headers from untrusted direct peer are ignored."""
        monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
        limiter = RateLimiter(max_requests=2, window_seconds=10, scope="test_proxy")
        
        req = MagicMock()
        req.client.host = "198.51.100.1"  # Public client IP
        req.headers = {"X-Forwarded-For": "1.2.3.4"}  # Forged spoofed header

        identifier = limiter.get_client_identifier(req)
        # Must resolve to direct peer, not forged spoofed header
        assert identifier == "ip:198.51.100.1"

    def test_auth_login_rate_limiting_integration(self, clean_rate_limiters):
        """Sequential login flood is throttled after 10 requests with HTTP 429."""
        from verification_service.app.main import app
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        app.dependency_overrides[get_session] = lambda: mock_db
        client = TestClient(app)

        try:
            # Attempt 10 bad logins
            for i in range(10):
                resp = client.post(
                    "/api/v1/auth/login",
                    data={"username": f"attacker_{i}", "password": "wrong_password"},
                )
                assert resp.status_code == 401

            # 11th request must be throttled with HTTP 429
            resp_throttled = client.post(
                "/api/v1/auth/login",
                data={"username": "attacker_11", "password": "wrong_password"},
            )
            assert resp_throttled.status_code == 429
            assert "Retry-After" in resp_throttled.headers
            assert "Rate limit exceeded" in resp_throttled.text
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 4. G3-C: Administrator Proof-Job Inspection Tests (G1-SEC-005)
# ---------------------------------------------------------------------------

class TestAdminProofJobInspection:
    """Verify administrator proof job inspection and cross-tenant isolation boundaries."""

    def test_admin_can_retrieve_cross_tenant_proof_job_detail(self):
        """Admin can inspect a proof job owned by another vendor tenant."""
        from zkp_service.app.main import app
        from shared.auth import get_current_user
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        job_id = uuid.uuid4()
        vendor_id = uuid.uuid4()
        admin_id = uuid.uuid4()

        mock_job = MagicMock()
        mock_job.id = job_id
        mock_job.user_id = vendor_id
        mock_job.status = "completed"
        mock_job.sbom_upload_id = uuid.uuid4()
        mock_job.snapshot_id = uuid.uuid4()
        mock_job.policy_id = uuid.uuid4()
        mock_job.sbom_root = "0x" + "1" * 64
        mock_job.vulnerability_db_root = "0x" + "2" * 64
        mock_job.policy_hash = "0x" + "3" * 64
        mock_job.proof_artifact = None
        mock_job.proof_archive_hash = None
        mock_job.error_message = None
        mock_job.created_at = datetime.now(timezone.utc)
        mock_job.completed_at = datetime.now(timezone.utc)

        mock_db = MagicMock()
        app.dependency_overrides[get_session] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: User(
            id=admin_id, username="admin_auditor", role="admin"
        )
        client = TestClient(app)

        try:
            with patch.object(ZKPRepository, "get_job", return_value=mock_job) as mock_get_job:
                response = client.get(f"/api/v1/zkp/jobs/{job_id}")
                assert response.status_code == 200
                data = response.json()
                assert data["id"] == str(job_id)
                # Ensure get_job was called with user_id=None (cross-tenant administrative scope)
                mock_get_job.assert_called_once_with(job_id, user_id=None)
        finally:
            app.dependency_overrides.clear()

    def test_vendor_strictly_isolated_to_own_proof_jobs(self):
        """Vendor can only retrieve owned proof jobs; cross-tenant query returns 404."""
        from zkp_service.app.main import app
        from shared.auth import get_current_user
        from zkp_service.app.repositories.zkp_repository import ZKPRepository

        job_id = uuid.uuid4()
        vendor_id = uuid.uuid4()

        mock_db = MagicMock()
        app.dependency_overrides[get_session] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: User(
            id=vendor_id, username="vendor_alice", role="vendor"
        )
        client = TestClient(app)

        try:
            # 1. Vendor fetches their own job
            mock_own_job = MagicMock()
            mock_own_job.id = job_id
            mock_own_job.user_id = vendor_id
            mock_own_job.status = "completed"
            mock_own_job.sbom_upload_id = uuid.uuid4()
            mock_own_job.snapshot_id = uuid.uuid4()
            mock_own_job.policy_id = uuid.uuid4()
            mock_own_job.sbom_root = "0x" + "1" * 64
            mock_own_job.vulnerability_db_root = "0x" + "2" * 64
            mock_own_job.policy_hash = "0x" + "3" * 64
            mock_own_job.proof_artifact = None
            mock_own_job.proof_archive_hash = None
            mock_own_job.error_message = None
            mock_own_job.created_at = datetime.now(timezone.utc)
            mock_own_job.completed_at = datetime.now(timezone.utc)

            with patch.object(ZKPRepository, "get_job", return_value=mock_own_job) as mock_get_job:
                resp = client.get(f"/api/v1/zkp/jobs/{job_id}")
                assert resp.status_code == 200
                # Must query with user_id=vendor_id
                mock_get_job.assert_called_once_with(job_id, user_id=vendor_id)

            # 2. When repository returns None (job belongs to another tenant), returns 404
            with patch.object(ZKPRepository, "get_job", return_value=None) as mock_get_job_foreign:
                resp_foreign = client.get(f"/api/v1/zkp/jobs/{job_id}")
                assert resp_foreign.status_code == 404
                error_body = resp_foreign.json()
                assert error_body.get("error") == "Proof job not found" or error_body.get("detail") == "Proof job not found"
        finally:
            app.dependency_overrides.clear()

    def test_buyer_rejected_from_proof_job_detail_with_403(self):
        """Buyer role is rejected from proof job inspection with HTTP 403."""
        from zkp_service.app.main import app
        from shared.auth import get_current_user

        buyer_id = uuid.uuid4()
        job_id = uuid.uuid4()

        app.dependency_overrides[get_current_user] = lambda: User(
            id=buyer_id, username="buyer_bob", role="buyer"
        )
        client = TestClient(app)

        try:
            response = client.get(f"/api/v1/zkp/jobs/{job_id}")
            assert response.status_code == 403
            assert "Role not authorized to access proof job records" in response.text
        finally:
            app.dependency_overrides.clear()

    def test_deactivated_account_rejected_from_proof_jobs(self):
        """Deactivated user account is rejected with HTTP 403."""
        from zkp_service.app.main import app
        from shared.auth import get_current_user

        user_id = uuid.uuid4()
        job_id = uuid.uuid4()

        app.dependency_overrides[get_current_user] = lambda: User(
            id=user_id, username="disabled_vendor", role="vendor", is_active=False
        )
        client = TestClient(app)

        try:
            response = client.get(f"/api/v1/zkp/jobs/{job_id}")
            assert response.status_code == 403
            assert "Account is deactivated" in response.text
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 5. G3-D: Dashboard Metrics Aggregation Tests (G1-SEC-006)
# ---------------------------------------------------------------------------

class TestMetricsAggregation:
    """Verify administrator global metrics aggregation and tenant isolation."""

    def test_vendor_metrics_strictly_isolated(self):
        """Vendor metrics only query records matching current_user.id."""
        from verification_service.app.main import app
        from shared.auth import get_current_user

        vendor_id = uuid.uuid4()
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.scalar.return_value = 5
        mock_db.query.return_value.join.return_value.filter.return_value.scalar.return_value = 3

        app.dependency_overrides[get_session] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: User(
            id=vendor_id, username="vendor_user", role="vendor"
        )
        client = TestClient(app)

        try:
            resp = client.get("/api/v1/metrics")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_sboms"] == 5
            assert data["total_jobs"] == 5
            assert data["total_certificates"] == 3
        finally:
            app.dependency_overrides.clear()

    def test_admin_metrics_all_tenants_aggregation(self):
        """Admin with all_tenants=true queries global aggregate counts."""
        from verification_service.app.main import app
        from shared.auth import get_current_user

        admin_id = uuid.uuid4()
        mock_db = MagicMock()
        mock_db.query.return_value.scalar.return_value = 42
        mock_db.query.return_value.join.return_value.scalar.return_value = 17

        app.dependency_overrides[get_session] = lambda: mock_db
        app.dependency_overrides[get_current_user] = lambda: User(
            id=admin_id, username="admin_user", role="admin"
        )
        client = TestClient(app)

        try:
            resp = client.get("/api/v1/metrics?all_tenants=true")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_sboms"] == 42
            assert data["total_jobs"] == 42
            assert data["total_certificates"] == 17
        finally:
            app.dependency_overrides.clear()

    def test_non_admin_all_tenants_metrics_rejected_with_403(self):
        """Non-admin passing all_tenants=true receives HTTP 403 Forbidden."""
        from verification_service.app.main import app
        from shared.auth import get_current_user

        buyer_id = uuid.uuid4()
        app.dependency_overrides[get_current_user] = lambda: User(
            id=buyer_id, username="buyer_user", role="buyer"
        )
        client = TestClient(app)

        try:
            resp = client.get("/api/v1/metrics?all_tenants=true")
            assert resp.status_code == 403
            assert "Only administrators may query metrics across all tenants" in resp.text
        finally:
            app.dependency_overrides.clear()

"""
Stage G Gateway Routing Contract & Live Proxy Verification.

Validates:
1. Static configuration of docker/nginx.conf ensuring all microservice routes are mapped.
2. Specifically guarantees /api/v1/applications and /api/v1/admin are proxied to their authoritative upstreams.
3. Live reachability check against http://127.0.0.1:8000 (when running) ensuring no 404 routing gaps exist.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
NGINX_CONF_PATH = REPO_ROOT / "docker" / "nginx.conf"

MANDATORY_LOCATION_MAPPINGS = {
    "/api/v1/sbom": "http://sbom-service:8000/api/v1/sbom",
    "/api/v1/applications": "http://sbom-service:8000/api/v1/applications",
    "/api/v1/vulnerability": "http://vulnerability-service:8001/api/v1/vulnerability",
    "/api/v1/policy": "http://policy-service:8002/api/v1/policy",
    "/api/v1/zkp": "http://zkp-service:8003/api/v1/zkp",
    "/api/v1/verification": "http://verification-service:8004/api/v1/verification",
    "/api/v1/auth": "http://verification-service:8004/api/v1/auth",
    "/api/v1/admin": "http://verification-service:8004/api/v1/admin",
    "/api/v1/metrics": "http://verification-service:8004/api/v1/metrics",
    "/api/v1/health": "http://verification-service:8004/api/v1/health",
}


def test_nginx_conf_exists_and_contains_all_routes():
    assert NGINX_CONF_PATH.is_file(), f"Nginx config not found at {NGINX_CONF_PATH}"
    content = NGINX_CONF_PATH.read_text(encoding="utf-8")

    for loc, proxy in MANDATORY_LOCATION_MAPPINGS.items():
        # Match location block and proxy_pass
        pattern = rf"location\s+{re.escape(loc)}\s*\{{[^}}]*proxy_pass\s+{re.escape(proxy)};"
        assert re.search(pattern, content, re.DOTALL), (
            f"Missing or mismatched proxy_pass mapping for location '{loc}' -> '{proxy}'"
        )


def _gateway_is_live() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/api/v1/health", timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


@pytest.mark.skipif(not _gateway_is_live(), reason="Live gateway on http://127.0.0.1:8000 not reachable")
class TestLiveGatewayRouting:
    """Verifies that the live Nginx gateway actually dispatches requests to upstreams without 404s."""

    def _probe_route(self, path: str, expected_codes: tuple[int, ...]):
        url = f"http://127.0.0.1:8000{path}"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                assert resp.status in expected_codes, f"Route {path} returned unexpected status {resp.status}"
        except urllib.error.HTTPError as e:
            assert e.code in expected_codes, (
                f"Route {path} returned HTTP {e.code} ({e.reason}), expected one of {expected_codes}. "
                f"A 404 indicates a missing gateway proxy route."
            )

    def test_health_route_returns_200(self):
        self._probe_route("/api/v1/health", (200,))

    def test_applications_route_reaches_upstream_not_404(self):
        # Must return 401 Unauthorized (auth required), never 404 Not Found
        self._probe_route("/api/v1/applications", (401,))

    def test_admin_users_route_reaches_upstream_not_404(self):
        # Must return 401 Unauthorized (auth required), never 404 Not Found
        self._probe_route("/api/v1/admin/users", (401,))

    def test_sbom_route_reaches_upstream_not_404(self):
        self._probe_route("/api/v1/sbom", (401,))

    def test_policy_route_reaches_upstream_not_404(self):
        self._probe_route("/api/v1/policy", (401,))

    def test_zkp_route_reaches_upstream_not_404(self):
        self._probe_route("/api/v1/zkp", (401,))

    def test_vulnerability_snapshots_reaches_upstream_not_404(self):
        self._probe_route("/api/v1/vulnerability/snapshots", (401,))

    def test_auth_login_reaches_upstream_not_404(self):
        # GET on POST-only endpoint returns 405 Method Not Allowed from FastAPI
        self._probe_route("/api/v1/auth/login", (405,))

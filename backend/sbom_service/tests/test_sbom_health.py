"""
Tests for the SBOM Service health endpoint.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from fastapi.testclient import TestClient
from sbom_service.app.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "sbom_service"
    assert data["status"] == "healthy"
    assert "version" in data


def test_health_no_secrets():
    """Health response must not leak secrets or internal paths."""
    response = client.get("/api/v1/health")
    body = response.text.lower()
    for forbidden in ["password", "secret", "credential", "token", ":\\\\", "c:/"]:
        assert forbidden not in body

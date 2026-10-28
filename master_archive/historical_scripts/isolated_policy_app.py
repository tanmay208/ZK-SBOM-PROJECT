"""
Isolated D9 Policy Acceptance Service Entrypoint.
Authoritative Location: scripts/isolated_policy_app.py

Provides the dedicated FastAPI ASGI application instance for isolated D9 acceptance.
Mounts strictly:
  - shared.api.auth_routes (POST /api/v1/auth/login, GET /api/v1/auth/me)
  - policy_service.app.api.routes.policy_routes (POST /api/v1/policy, GET /api/v1/policy, etc.)
  - shared /api/v1/health endpoint

Does NOT mount sbom, zkp, verification, or vulnerability platform routes.
Does NOT load root .env file.
"""

from __future__ import annotations

import os
import sys

_scripts_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.abspath(os.path.join(_scripts_dir, ".."))
_backend_dir = os.path.join(_repo_root, "backend")

if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from shared.app_factory import create_app
from shared.api.auth_routes import router as auth_router
from policy_service.app.api.routes.policy_routes import router as policy_router

app = create_app(
    service_name="policy_service",
    title="Isolated D9 Policy Acceptance Service",
    description="Dedicated isolated policy and authentication service for Stage D9 live acceptance.",
)

# Core authentication and policy routes strictly required for acceptance testing
app.include_router(auth_router)
app.include_router(policy_router)

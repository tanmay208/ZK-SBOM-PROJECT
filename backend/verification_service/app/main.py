"""
Verification Service — application entry point.

SERVICE_CONTRACTS.md §5:
  Allows buyers to independently verify ZK proofs.
  Privacy Classification: Public.
  MUST NEVER require or process private SBOM data.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from shared.app_factory import create_app  # noqa: E402
from verification_service.app.api.routes.verification_routes import router as verification_router  # noqa: E402
from shared.api.auth_routes import router as auth_router  # noqa: E402
from shared.api.metrics_routes import router as metrics_router  # noqa: E402
from policy_service.app.api.routes.policy_routes import router as policy_router  # noqa: E402
from sbom_service.app.api.routes.sbom_routes import router as sbom_router  # noqa: E402
from zkp_service.app.api.routes.zkp_routes import router as zkp_router  # noqa: E402
from vulnerability_service.app.api.routes.vulnerability_routes import router as vulnerability_router  # noqa: E402

app = create_app(
    service_name="verification_service",
    title="Verification & Platform API Service",
    description="ZK proof verification, public-input validation, certificates, and platform management APIs.",
)

# Core Verification & Auth routes
app.include_router(verification_router)
app.include_router(auth_router)
app.include_router(metrics_router)
app.include_router(policy_router)

# Unified platform routes for single-port frontend development
app.include_router(sbom_router)
app.include_router(zkp_router)
app.include_router(vulnerability_router, prefix="/api/v1/vulnerability", tags=["vulnerability"])

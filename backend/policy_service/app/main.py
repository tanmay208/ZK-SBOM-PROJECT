"""
Policy Service — application entry point.

SERVICE_CONTRACTS.md §3:
  Manages, canonicalizes, and commits security policies.
  Privacy Classification: Public / Transparent.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from shared.app_factory import create_app  # noqa: E402
from policy_service.app.api.routes.policy_routes import router as policy_router  # noqa: E402

app = create_app(
    service_name="policy_service",
    title="Policy Service",
    description="Security policy management, canonicalization, and POLICY_HASH generation.",
)

app.include_router(policy_router)

"""
ZKP Service — application entry point.

SERVICE_CONTRACTS.md §4:
  Executes Noir circuits to generate zero-knowledge proofs.
  Privacy Classification: Mixed (processes private data to produce public proof).
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from shared.app_factory import create_app  # noqa: E402
from zkp_service.app.api.routes.zkp_routes import router as zkp_router

app = create_app(
    service_name="zkp_service",
    title="ZKP Service",
    description="Witness preparation, Noir circuit execution, and proof generation.",
)

app.include_router(zkp_router)

"""
SBOM Service — application entry point.

SERVICE_CONTRACTS.md §1:
  Handles generation, parsing, validation, and commitment of SBOMs.
  Privacy Classification: Strictly Confidential / Private.
"""

import sys
import os

# Allow imports from the backend root so `shared` is resolvable.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from shared.app_factory import create_app  # noqa: E402
from sbom_service.app.api.routes.sbom_routes import router as sbom_router  # noqa: E402
from sbom_service.app.api.routes.application_routes import router as application_router  # noqa: E402

app = create_app(
    service_name="sbom_service",
    title="SBOM Service",
    description="SBOM upload, generation, parsing, canonicalization, and commitment.",
    domain_router=sbom_router,
)
app.include_router(application_router)


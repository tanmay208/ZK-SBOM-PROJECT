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


@app.on_event("startup")
def startup_reconciliation() -> None:
    """Reconcile any orphaned proof jobs from previous process terminations."""
    from shared.database import get_engine, get_session
    from zkp_service.app.core.job_lock import reconcile_all_abandoned_jobs
    try:
        engine = get_engine()
        db_gen = get_session()
        db = next(db_gen)
        try:
            reconcile_all_abandoned_jobs(db, engine)
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
    except Exception:
        # Fail safe if database is not yet ready or during lightweight unit tests
        pass

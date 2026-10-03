"""
Tests for the shared backend library.
"""

import sys
import os

# Ensure shared is importable from the test runner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_config_defaults():
    """ServiceSettings can be created with just a name."""
    from shared.config import get_settings

    settings = get_settings("test_service")
    assert settings.service_name == "test_service"
    assert settings.log_level == "INFO"


def test_db_settings_url_format():
    """DatabaseSettings.url produces a valid postgresql+psycopg2 connection string."""
    from shared.config import DatabaseSettings

    db = DatabaseSettings()
    assert db.url.startswith("postgresql+psycopg2://")
    assert db.name in db.url


def test_health_response_schema():
    """HealthResponse accepts expected fields."""
    from shared.schemas import HealthResponse

    resp = HealthResponse(service="test", status="healthy", version="0.1.0")
    assert resp.service == "test"
    assert resp.status == "healthy"


def test_exception_classes():
    """ServiceError hierarchy has correct status codes."""
    from shared.exceptions import NotFoundError, ConflictError, ServiceError

    assert ServiceError("x").status_code == 400
    assert NotFoundError().status_code == 404
    assert ConflictError().status_code == 409

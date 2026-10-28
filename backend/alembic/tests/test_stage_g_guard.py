"""
Unit tests for PostgreSQL 17 Stage G guard preflight (verify_stage_g_target_preflight).
Enforces fail-closed target validation, PostgreSQL 16 prohibition, and catalog verification.
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.engine import Connection

_backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

_alembic_dir = os.path.join(_backend_root, "alembic")
if _alembic_dir not in sys.path:
    sys.path.insert(0, _alembic_dir)

from staging_guard import (
    StagingConfigError,
    verify_stage_g_target_preflight,
)


class TestVerifyStageGTargetPreflight:
    """Validate Stage G preflight fail-closed boundaries."""

    def test_staging_mode_active_aborts_preflight(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "true")
        mock_conn = MagicMock(spec=Connection)
        with pytest.raises(StagingConfigError, match="STAGING_MODE=true is active"):
            verify_stage_g_target_preflight(mock_conn)

    def test_local_dev_environment_aborts_preflight(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.setenv("ENVIRONMENT", "local_dev")
        mock_conn = MagicMock(spec=Connection)
        with pytest.raises(StagingConfigError, match="ENVIRONMENT=local_dev is active"):
            verify_stage_g_target_preflight(mock_conn)

    def test_settings_prohibited_port_5433_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5433,
            name="postgres",
            password="secret_password",
        )
        with pytest.raises(StagingConfigError, match="Target client port 5433 is strictly prohibited"):
            verify_stage_g_target_preflight(mock_conn, settings=settings)

    def test_settings_prohibited_db_name_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5432,
            name="ZKP_SBOM_LOCAL_DEV",
            password="secret_password",
        )
        with pytest.raises(StagingConfigError, match="Target database 'ZKP_SBOM_LOCAL_DEV' is strictly prohibited"):
            verify_stage_g_target_preflight(mock_conn, settings=settings)

    def test_settings_empty_password_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5432,
            name="postgres",
            password="",
        )
        with pytest.raises(StagingConfigError, match="DB_PASSWORD must be configured"):
            verify_stage_g_target_preflight(mock_conn, settings=settings)

    def test_settings_remote_insecure_ssl_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="aws-0-ap-southeast-2.pooler.supabase.com",
            port=5432,
            name="postgres",
            password="secret_password",
            ssl_mode="disable",
        )
        with pytest.raises(StagingConfigError, match="Insecure SSL mode 'disable' is prohibited"):
            verify_stage_g_target_preflight(mock_conn, settings=settings)

    def test_connection_url_port_5433_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.engine = SimpleNamespace(url=SimpleNamespace(port=5433, host="127.0.0.1", database="postgres"))
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        with pytest.raises(StagingConfigError, match="Connection URL specifies port 5433"):
            verify_stage_g_target_preflight(mock_conn)

    def test_connection_url_pg16_database_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.engine = SimpleNamespace(url=SimpleNamespace(port=5432, host="127.0.0.1", database="ZKP_SBOM_LOCAL_DEV"))
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        with pytest.raises(StagingConfigError, match="Targeting PostgreSQL 16 development database is forbidden"):
            verify_stage_g_target_preflight(mock_conn)

    def test_server_reported_pg16_engine_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.execute.return_value.fetchone.return_value = ("postgres", "PostgreSQL 16.15 on x86_64-pc-linux-gnu")
        with pytest.raises(StagingConfigError, match="Targeting PostgreSQL 16 is strictly prohibited"):
            verify_stage_g_target_preflight(mock_conn)

    def test_server_reported_non_pg17_engine_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.execute.return_value.fetchone.return_value = ("postgres", "PostgreSQL 15.4 on x86_64-pc-linux-gnu")
        with pytest.raises(StagingConfigError, match="Expected major engine 'PostgreSQL 17'"):
            verify_stage_g_target_preflight(mock_conn)

    def test_server_version_num_under_170000_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.execute.return_value.fetchone.return_value = ("postgres", "PostgreSQL 17.0 on x86_64-pc-linux-gnu")
        mock_conn.execute.return_value.scalar.return_value = 160005
        with pytest.raises(StagingConfigError, match="indicates PostgreSQL older than 17"):
            verify_stage_g_target_preflight(mock_conn)

    def test_revision_mismatch_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.execute.return_value.fetchone.return_value = ("postgres", "PostgreSQL 17.11 on x86_64-pc-linux-gnu")
        mock_conn.execute.return_value.scalar.return_value = 170011

        with patch("staging_guard.get_recorded_alembic_revision") as mock_rev:
            from staging_guard import MigrationStateResult
            mock_rev.return_value = MigrationStateResult(is_known=True, revision="012", status="RECORDED")
            with pytest.raises(StagingConfigError, match="expected strictly '013'"):
                verify_stage_g_target_preflight(mock_conn, expected_revision="013")

    def test_valid_pg17_preflight_succeeds_and_rolls_back(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.execute.return_value.fetchone.return_value = ("postgres", "PostgreSQL 17.11 on x86_64-pc-linux-gnu")
        mock_conn.execute.return_value.scalar.return_value = 170011

        settings = SimpleNamespace(
            host="aws-0-ap-southeast-2.pooler.supabase.com",
            port=5432,
            name="postgres",
            password="secret_password",
            ssl_mode="require",
        )

        with patch("staging_guard.get_recorded_alembic_revision") as mock_rev:
            from staging_guard import MigrationStateResult
            mock_rev.return_value = MigrationStateResult(is_known=True, revision="013", status="RECORDED")
            verify_stage_g_target_preflight(mock_conn, settings=settings, expected_revision="013")

        mock_conn.rollback.assert_called_once()

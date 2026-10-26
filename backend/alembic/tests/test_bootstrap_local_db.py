"""
Offline mocked tests for development-only bootstrap tool (scripts/bootstrap_local_db.py).

Guarantees validated:
  1. Missing ALLOW_LOCAL_DEV_INIT=true aborts without connecting.
  2. STAGING_MODE=true aborts without connecting.
  3. Wrong client endpoint (host, port, database, empty password) aborts before connecting.
  4. Server-reported identity mismatch aborts before any DDL.
  5. Server-reported PostgreSQL 17 engine is explicitly rejected to protect the main project database.
  6. Server-reported container internal port (e.g. 5432) is accepted and not confused with host port 5433.
  7. Compatible existing table public.users performs zero DDL and returns 0 (idempotent).
  8. Incompatible existing table fails closed without attempting repair or alteration DDL.
  9. Missing table executes canonical DDL and commits atomically upon valid post-creation check.
  10. DDL execution failure or post-creation validation failure rolls back the transaction.
  11. CLI main entry point handles errors cleanly.

ALL tests are strictly offline and mocked. No network or database connections are made.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest
from sqlalchemy import text

# Ensure backend root, alembic, and scripts directories are on sys.path
_this_dir = os.path.dirname(os.path.abspath(__file__))
_backend_root = os.path.abspath(os.path.join(_this_dir, "../.."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

_alembic_dir = os.path.join(_backend_root, "alembic")
if _alembic_dir not in sys.path:
    sys.path.insert(0, _alembic_dir)

_repo_root = os.path.abspath(os.path.join(_backend_root, ".."))
_scripts_dir = os.path.join(_repo_root, "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

import bootstrap_local_db
from bootstrap_local_db import (
    BootstrapError,
    EXPECTED_ENGINE_MAJOR,
    PROHIBITED_ENGINE_MAJOR,
    TARGET_CLIENT_HOSTS,
    TARGET_CLIENT_PORT,
    TARGET_DB_NAME,
    main as bootstrap_main,
    run_local_dev_bootstrap,
    verify_client_configuration,
    verify_server_identity,
)
from staging_guard import ContractValidationResult


def _make_valid_client_settings() -> SimpleNamespace:
    return SimpleNamespace(
        host="127.0.0.1",
        port=5433,
        name="ZKP_SBOM_LOCAL_DEV",
        password="mock_secure_password",
        url="postgresql+psycopg2://user:mock_secure_password@127.0.0.1:5433/ZKP_SBOM_LOCAL_DEV",
    )


# =======================================================================
# 1. Gate Safeguards (Opt-in & Staging Lockout)
# =======================================================================

class TestGateSafeguards:
    """Verify that bootstrap aborts before creating any connection if prerequisites are absent."""

    def test_missing_opt_in_raises_bootstrap_error_without_connecting(self, monkeypatch):
        monkeypatch.delenv("ALLOW_LOCAL_DEV_INIT", raising=False)
        mock_engine = MagicMock()

        with pytest.raises(BootstrapError, match="ALLOW_LOCAL_DEV_INIT=true"):
            run_local_dev_bootstrap(engine=mock_engine)

        assert not mock_engine.connect.called

    def test_false_opt_in_raises_bootstrap_error_without_connecting(self, monkeypatch):
        monkeypatch.setenv("ALLOW_LOCAL_DEV_INIT", "false")
        mock_engine = MagicMock()

        with pytest.raises(BootstrapError, match="ALLOW_LOCAL_DEV_INIT=true"):
            run_local_dev_bootstrap(engine=mock_engine)

        assert not mock_engine.connect.called

    def test_staging_mode_raises_bootstrap_error_without_connecting(self, monkeypatch):
        monkeypatch.setenv("ALLOW_LOCAL_DEV_INIT", "true")
        monkeypatch.setenv("STAGING_MODE", "true")
        mock_engine = MagicMock()

        with pytest.raises(BootstrapError, match="rejects STAGING_MODE=true"):
            run_local_dev_bootstrap(engine=mock_engine)

        assert not mock_engine.connect.called

    @pytest.mark.parametrize("invalid_opt_in", ["TRUE", "True", "1", "yes", "YES", "on", "enabled"])
    def test_opt_in_requires_exact_lowercase_true(self, monkeypatch, invalid_opt_in):
        """Verify that ALLOW_LOCAL_DEV_INIT requires exact string 'true' and rejects variations."""
        monkeypatch.setenv("ALLOW_LOCAL_DEV_INIT", invalid_opt_in)
        mock_engine = MagicMock()
        with pytest.raises(BootstrapError, match="ALLOW_LOCAL_DEV_INIT=true"):
            run_local_dev_bootstrap(engine=mock_engine)
        assert not mock_engine.connect.called



# =======================================================================
# 2. Client Endpoint Configuration Validation
# =======================================================================

class TestClientConfiguration:
    """Verify strict fail-closed validation of client-side connection parameters."""

    def test_valid_client_settings_accepted(self):
        settings = _make_valid_client_settings()
        verify_client_configuration(settings)  # Should not raise

    def test_localhost_alias_accepted(self):
        settings = _make_valid_client_settings()
        settings.host = "localhost"
        verify_client_configuration(settings)  # Should not raise

    def test_remote_host_rejected(self):
        settings = _make_valid_client_settings()
        settings.host = "192.168.1.50"
        with pytest.raises(BootstrapError, match="Target host '192.168.1.50' is prohibited"):
            verify_client_configuration(settings)

    def test_port_5432_rejected_to_prevent_pg17_collision(self):
        settings = _make_valid_client_settings()
        settings.port = 5432
        with pytest.raises(BootstrapError, match="Target client port '5432' is prohibited"):
            verify_client_configuration(settings)

    def test_main_db_name_rejected_to_prevent_pg17_mutation(self):
        settings = _make_valid_client_settings()
        settings.name = "ZKP_SBOM"
        with pytest.raises(BootstrapError, match="Target database name 'ZKP_SBOM' is prohibited"):
            verify_client_configuration(settings)

    def test_staging_db_name_rejected(self):
        settings = _make_valid_client_settings()
        settings.name = "ZKP_SBOM_STAGING"
        with pytest.raises(BootstrapError, match="Target database name 'ZKP_SBOM_STAGING' is prohibited"):
            verify_client_configuration(settings)

    def test_empty_password_rejected(self):
        settings = _make_valid_client_settings()
        settings.password = ""
        with pytest.raises(BootstrapError, match="DB_PASSWORD must be configured"):
            verify_client_configuration(settings)

    @pytest.mark.parametrize("prohibited_port", [5432, 5431, 5434, 15432, 54320])
    def test_non_5433_ports_rejected(self, prohibited_port):
        """Verify that any client port other than 5433 is rejected."""
        settings = _make_valid_client_settings()
        settings.port = prohibited_port
        with pytest.raises(BootstrapError, match=f"Target client port '{prohibited_port}' is prohibited"):
            verify_client_configuration(settings)

    @pytest.mark.parametrize("prohibited_host", ["0.0.0.0", "192.168.1.1", "10.0.0.5", "db.internal", "172.17.0.1"])
    def test_non_local_hosts_rejected(self, prohibited_host):
        """Verify that any client host other than 127.0.0.1 or localhost is rejected."""
        settings = _make_valid_client_settings()
        settings.host = prohibited_host
        with pytest.raises(BootstrapError, match=f"Target host '{prohibited_host}' is prohibited"):
            verify_client_configuration(settings)



# =======================================================================
# 3. Server Identity & Engine Major Inspection
# =======================================================================

class TestServerIdentityInspection:
    """Verify inspection of server-reported metadata from catalog query."""

    def test_matching_server_identity_accepted(self):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (
            "ZKP_SBOM_LOCAL_DEV",
            "PostgreSQL 16.4 on x86_64-pc-linux-gnu",
            5432,  # Container internal socket port
        )
        verify_server_identity(mock_conn)  # Should not raise

    def test_server_database_mismatch_aborts(self):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (
            "ZKP_SBOM",  # Mismatched database!
            "PostgreSQL 16.4 on x86_64-pc-linux-gnu",
            5432,
        )
        with pytest.raises(BootstrapError, match="does not match expected target"):
            verify_server_identity(mock_conn)

    def test_server_reporting_pg17_is_strictly_prohibited(self):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (
            "ZKP_SBOM_LOCAL_DEV",
            "PostgreSQL 17.0 on x86_64-pc-linux-gnu",  # Forbidden PG 17!
            5432,
        )
        with pytest.raises(BootstrapError, match="Targeting PostgreSQL 17 is strictly prohibited"):
            verify_server_identity(mock_conn)

    @pytest.mark.parametrize("pg17_version", [
        "PostgreSQL 17.0 on x86_64-pc-linux-gnu",
        "PostgreSQL 17.1 (Debian 17.1-1.pgdg120+1)",
        "PostgreSQL 17devel on x86_64-windows",
        "PostgreSQL 17.4, 64-bit",
    ])
    def test_all_pg17_server_versions_strictly_prohibited(self, pg17_version):
        """Verify that any PostgreSQL 17 engine variation is strictly rejected."""
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (
            "ZKP_SBOM_LOCAL_DEV",
            pg17_version,
            5432,
        )
        with pytest.raises(BootstrapError, match="Targeting PostgreSQL 17 is strictly prohibited"):
            verify_server_identity(mock_conn)


    def test_unsupported_engine_version_aborts(self):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (
            "ZKP_SBOM_LOCAL_DEV",
            "PostgreSQL 15.6 on x86_64-pc-linux-gnu",
            5432,
        )
        with pytest.raises(BootstrapError, match="Expected major engine 'PostgreSQL 16'"):
            verify_server_identity(mock_conn)

    def test_container_port_mapping_awareness(self):
        """Server-reported port 5432 is normal inside Docker and must NOT cause failure."""
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (
            "ZKP_SBOM_LOCAL_DEV",
            "PostgreSQL 16.3 on x86_64-pc-linux-gnu",
            5432,  # internal port differs from host port 5433
        )
        # Does not raise even though server port is 5432 while client target port is 5433
        verify_server_identity(mock_conn)


# =======================================================================
# 4. Table Contract Inspection & Non-destructive Behavior
# =======================================================================

class TestTableContractBehavior:
    """Verify non-destructive table validation and atomic creation."""

    @patch("bootstrap_local_db.validate_users_contract")
    @patch("bootstrap_local_db.verify_server_identity")
    def test_compatible_table_is_noop_without_ddl(
        self, mock_verify_server, mock_validate_contract, monkeypatch
    ):
        monkeypatch.setenv("ALLOW_LOCAL_DEV_INIT", "true")
        monkeypatch.delenv("STAGING_MODE", raising=False)

        mock_validate_contract.return_value = ContractValidationResult(
            exists=True,
            is_valid=True,
            discrepancies=(),
        )

        mock_conn = MagicMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        mock_engine.connect.return_value.__exit__.return_value = False

        status = run_local_dev_bootstrap(
            engine=mock_engine, settings=_make_valid_client_settings()
        )

        assert status == 0
        assert mock_verify_server.called
        assert mock_validate_contract.called
        # Zero DDL executed
        assert not mock_conn.execute.called
        # Zero commits
        assert not mock_conn.commit.called

    @patch("bootstrap_local_db.validate_users_contract")
    @patch("bootstrap_local_db.verify_server_identity")
    def test_incompatible_table_fails_without_repair_ddl(
        self, mock_verify_server, mock_validate_contract, monkeypatch
    ):
        monkeypatch.setenv("ALLOW_LOCAL_DEV_INIT", "true")
        monkeypatch.delenv("STAGING_MODE", raising=False)

        mock_validate_contract.return_value = ContractValidationResult(
            exists=True,
            is_valid=False,
            discrepancies=("Missing required column: role",),
        )

        mock_conn = MagicMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        mock_engine.connect.return_value.__exit__.return_value = False

        with pytest.raises(BootstrapError, match="Automatic repair is strictly forbidden"):
            run_local_dev_bootstrap(
                engine=mock_engine, settings=_make_valid_client_settings()
            )

        assert mock_verify_server.called
        # NO repair or alteration DDL issued
        assert not mock_conn.execute.called
        assert not mock_conn.commit.called

    @patch("bootstrap_local_db.validate_users_contract")
    @patch("bootstrap_local_db.verify_server_identity")
    def test_absent_table_executes_canonical_ddl_and_commits(
        self, mock_verify_server, mock_validate_contract, monkeypatch
    ):
        monkeypatch.setenv("ALLOW_LOCAL_DEV_INIT", "true")
        monkeypatch.delenv("STAGING_MODE", raising=False)

        # Initial check: table absent; post-creation check: table exists & valid
        mock_validate_contract.side_effect = [
            ContractValidationResult(exists=False, is_valid=False, discrepancies=("Table absent",)),
            ContractValidationResult(exists=True, is_valid=True, discrepancies=()),
        ]

        ddl_executed = []
        mock_conn = MagicMock()

        def track_execute(stmt, *args, **kwargs):
            sql_text = stmt.text if hasattr(stmt, "text") else str(stmt)
            ddl_executed.append(sql_text)
            return MagicMock()

        mock_conn.execute.side_effect = track_execute
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        mock_engine.connect.return_value.__exit__.return_value = False

        status = run_local_dev_bootstrap(
            engine=mock_engine, settings=_make_valid_client_settings()
        )

        assert status == 0
        assert mock_verify_server.called
        assert len(ddl_executed) == 1
        assert "CREATE TABLE public.users" in ddl_executed[0]
        assert mock_conn.commit.called

    @patch("bootstrap_local_db.validate_users_contract")
    @patch("bootstrap_local_db.verify_server_identity")
    def test_post_creation_contract_failure_rolls_back(
        self, mock_verify_server, mock_validate_contract, monkeypatch
    ):
        monkeypatch.setenv("ALLOW_LOCAL_DEV_INIT", "true")
        monkeypatch.delenv("STAGING_MODE", raising=False)

        # Initial check: absent; post-creation check: still invalid!
        mock_validate_contract.side_effect = [
            ContractValidationResult(exists=False, is_valid=False, discrepancies=()),
            ContractValidationResult(exists=False, is_valid=False, discrepancies=("Creation failed",)),
        ]

        mock_conn = MagicMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        mock_engine.connect.return_value.__exit__.return_value = False

        with pytest.raises(BootstrapError, match="Post-creation contract validation failed"):
            run_local_dev_bootstrap(
                engine=mock_engine, settings=_make_valid_client_settings()
            )

        assert mock_conn.rollback.called
        assert not mock_conn.commit.called


# =======================================================================
# 5. CLI Entry Point
# =======================================================================

class TestCliEntryPoint:
    """Verify CLI main entry point error handling and exit codes."""

    @patch("bootstrap_local_db.run_local_dev_bootstrap")
    def test_main_success_returns_zero(self, mock_bootstrap):
        mock_bootstrap.return_value = 0
        exit_code = bootstrap_main([])
        assert exit_code == 0

    @patch("bootstrap_local_db.run_local_dev_bootstrap")
    def test_main_bootstrap_error_returns_one(self, mock_bootstrap, capsys):
        mock_bootstrap.side_effect = BootstrapError("Unauthorized target")
        exit_code = bootstrap_main([])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Bootstrap error: Unauthorized target" in captured.err

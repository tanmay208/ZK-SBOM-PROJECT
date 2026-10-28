"""
Unit and regression tests for Alembic caller-supplied verified connection support.

Stage D1.4.5 & D1.4.5.2:
  1. Mandatory target validation for supplied connections in local dev (FIND-D1451-01).
  2. Transaction ownership contract and active transaction fail-closed guard (FIND-D1451-02).
  3. A supplied connection is used by the orchestration path without creating a second engine.
  4. An invalid or active-transaction connection fails closed immediately and never falls back.
  5. The caller retains ownership of the supplied connection (never closed by Alembic).
  6. The existing CLI path remains compatible when no connection is supplied.
  7. Existing staging-target validation remains strictly enforced.
  8. Schema creation and migration transaction boundaries are explicitly managed.
  9. The tests use mocks or isolated fixtures and NEVER connect to PostgreSQL 16 or PostgreSQL 17.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Ensure backend root and alembic directory are on sys.path.
_backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

_alembic_dir = os.path.join(_backend_root, "alembic")
if _alembic_dir not in sys.path:
    sys.path.insert(0, _alembic_dir)

from sqlalchemy.engine import Connection, Engine

from staging_guard import (
    StagingConfigError,
    STAGING_DB_NAME,
    validate_supplied_connection,
    orchestrate_online_migrations,
    verify_pg16_target_preflight,
)


# ===========================================================================
# 1. validate_supplied_connection Unit Tests
# ===========================================================================

class TestValidateSuppliedConnection:
    """Validate connection checking rules and fail-closed policies."""

    def test_none_connection_raises_type_error(self):
        """None supplied as connection fails closed immediately."""
        with pytest.raises(TypeError, match="Supplied 'connection' attribute cannot be None"):
            validate_supplied_connection(None)

    def test_engine_as_connection_raises_type_error(self):
        """Supplying an Engine instead of a Connection raises TypeError."""
        mock_engine = MagicMock(spec=Engine)
        with pytest.raises(TypeError, match="must be an active SQLAlchemy Connection, not an Engine"):
            validate_supplied_connection(mock_engine)

    @pytest.mark.parametrize("invalid_val", [
        "postgresql://localhost/db",
        12345,
        ["not", "a", "connection"],
        {"connection": True},
        object(),
    ])
    def test_invalid_types_raise_type_error(self, invalid_val):
        """Non-connection objects fail closed with descriptive TypeError."""
        with pytest.raises(TypeError, match="not a valid SQLAlchemy Connection"):
            validate_supplied_connection(invalid_val)

    def test_closed_connection_raises_runtime_error(self):
        """A connection with closed=True fails closed."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = True
        with pytest.raises(RuntimeError, match="closed or unusable"):
            validate_supplied_connection(mock_conn)

    def test_invalidated_connection_raises_runtime_error(self):
        """A connection with invalidated=True fails closed."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = True
        with pytest.raises(RuntimeError, match="invalidated"):
            validate_supplied_connection(mock_conn)

    def test_active_transaction_raises_runtime_error(self):
        """A connection holding an active uncommitted transaction fails closed (FIND-D1451-02)."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = True

        with pytest.raises(RuntimeError, match="active uncommitted transaction"):
            validate_supplied_connection(mock_conn)

    def test_active_transaction_as_boolean_attribute_raises_runtime_error(self):
        """A connection with in_transaction attribute as True (non-callable) fails closed."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction = True

        with pytest.raises(RuntimeError, match="active uncommitted transaction"):
            validate_supplied_connection(mock_conn)

    def test_in_transaction_check_failure_raises_runtime_error(self):
        """If evaluating in_transaction raises an exception, validation fails closed."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.side_effect = Exception("DBAPI transaction inspection error")

        with pytest.raises(RuntimeError, match="Failed to verify transaction status"):
            validate_supplied_connection(mock_conn)

    def test_clean_connection_in_transaction_false_passes(self):
        """A clean connection outside any transaction block passes validation."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        result = validate_supplied_connection(mock_conn)
        assert result is mock_conn

    def test_valid_connection_passes(self):
        """A healthy active Connection object is returned unchanged."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        result = validate_supplied_connection(mock_conn)
        assert result is mock_conn

    def test_duck_typed_connection_passes(self):
        """A mock or wrapper with execute, dialect, and not closed passes validation."""
        mock_conn = MagicMock()
        del mock_conn.connect  # ensure not mistaken for Engine
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        result = validate_supplied_connection(mock_conn)
        assert result is mock_conn


# ===========================================================================
# 2. orchestrate_online_migrations with Supplied Connection
# ===========================================================================

class TestOrchestrateWithSuppliedConnection:
    """Verify orchestrate_online_migrations behavior when a Connection is supplied."""

    def test_supplied_connection_used_and_not_closed(self):
        """Supplied connection is passed to context.configure and NEVER closed on exit."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        def mock_execute(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.scalar.return_value = "ZKP_SBOM_LOCAL_DEV"
            return res

        mock_conn.execute.side_effect = mock_execute
        mock_context = MagicMock()

        orchestrate_online_migrations(
            connectable=mock_conn,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            target_database="ZKP_SBOM_LOCAL_DEV",
            is_connection=True,
        )

        # 1. Connection was configured in Alembic context
        mock_context.configure.assert_called_once()
        kwargs = mock_context.configure.call_args[1]
        assert kwargs["connection"] is mock_conn

        # 2. Migrations ran inside managed transaction
        mock_context.begin_transaction.assert_called_once()
        mock_context.run_migrations.assert_called_once()

        # 3. Connection was NOT closed (caller retains ownership)
        assert not mock_conn.close.called

    def test_missing_target_database_in_local_dev_aborts(self):
        """Omitting target_database fails closed in local dev mode (FIND-D1451-01)."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        with pytest.raises(StagingConfigError, match="Target database identity.*mandatory"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=False,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=MagicMock(),
                target_database=None,
                is_connection=True,
            )

    @pytest.mark.parametrize("empty_target", ["", "   ", "\t\n"])
    def test_empty_target_database_in_local_dev_aborts(self, empty_target):
        """Empty or whitespace target_database fails closed (FIND-D1451-01)."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        with pytest.raises(StagingConfigError, match="Target database identity.*mandatory"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=False,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=MagicMock(),
                target_database=empty_target,
                is_connection=True,
            )

    def test_mismatched_target_database_in_local_dev_aborts(self):
        """Target mismatch in local dev aborts before schema creation or migrations."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_context = MagicMock()

        def mock_execute(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.scalar.return_value = "ZKP_SBOM"  # wrong target (PostgreSQL 17!)
            return res

        mock_conn.execute.side_effect = mock_execute

        with pytest.raises(StagingConfigError, match="Target database mismatch"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=False,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=mock_context,
                target_database="ZKP_SBOM_LOCAL_DEV",
                is_connection=True,
            )

        # Migrations must NOT have run
        assert not mock_context.run_migrations.called
        assert not mock_conn.close.called

    def test_matching_target_database_in_local_dev_succeeds(self):
        """When expected and actual database match, migration proceeds."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_context = MagicMock()

        def mock_execute(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.scalar.return_value = "ZKP_SBOM_LOCAL_DEV"
            return res

        mock_conn.execute.side_effect = mock_execute

        orchestrate_online_migrations(
            connectable=mock_conn,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            target_database="ZKP_SBOM_LOCAL_DEV",
            is_connection=True,
        )

        mock_context.run_migrations.assert_called_once()
        assert not mock_conn.close.called

    def test_active_transaction_in_orchestrate_fails_closed(self):
        """Active transaction detected in orchestrate_online_migrations fails closed (FIND-D1451-02)."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = True  # dirty transaction!
        mock_context = MagicMock()

        with pytest.raises(StagingConfigError, match="active uncommitted transaction"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=False,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=mock_context,
                target_database="ZKP_SBOM_LOCAL_DEV",
                is_connection=True,
            )

        assert not mock_context.run_migrations.called
        assert not mock_conn.close.called

    def test_active_transaction_as_boolean_attribute_in_orchestrate_fails_closed(self):
        """Active transaction as boolean attribute in orchestrate_online_migrations fails closed."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction = True
        mock_context = MagicMock()

        with pytest.raises(StagingConfigError, match="active uncommitted transaction"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=False,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=mock_context,
                target_database="ZKP_SBOM_LOCAL_DEV",
                is_connection=True,
            )

        assert not mock_context.run_migrations.called
        assert not mock_conn.close.called

    def test_in_transaction_check_failure_in_orchestrate_fails_closed(self):
        """If evaluating in_transaction in orchestrate raises, it fails closed with StagingConfigError."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.side_effect = Exception("DBAPI error")
        mock_context = MagicMock()

        with pytest.raises(StagingConfigError, match="Failed to verify transaction status"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=False,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=mock_context,
                target_database="ZKP_SBOM_LOCAL_DEV",
                is_connection=True,
            )

        assert not mock_context.run_migrations.called
        assert not mock_conn.close.called

    def test_supplied_connection_in_staging_enforces_identity(self):
        """In staging mode, verify_connection_identity is strictly enforced on supplied connection."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        # Simulate returning wrong DB
        mock_result = MagicMock()
        mock_result.scalar.return_value = "ZKP_SBOM_PROD"
        mock_conn.execute.return_value = mock_result

        with pytest.raises(StagingConfigError, match="ZKP_SBOM_PROD"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=True,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=MagicMock(),
                is_connection=True,
            )

        assert not mock_conn.close.called

    def test_supplied_connection_in_staging_conflicting_target_aborts(self):
        """Passing a target_database that disagrees with STAGING_DB_NAME in staging fails closed."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        with pytest.raises(StagingConfigError, match="conflicts with staging expectation"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=True,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=MagicMock(),
                target_database="ZKP_SBOM_LOCAL_DEV",  # conflicting target
                is_connection=True,
            )

    def test_schema_creation_and_transaction_ownership(self):
        """Schema creation executes and commits on clean connection; migration transaction is isolated."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_context = MagicMock()

        executed_stmts = []

        def mock_execute(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            executed_stmts.append(sql)
            res = MagicMock()
            if "current_database" in sql:
                res.scalar.return_value = "ZKP_SBOM_LOCAL_DEV"
            return res

        mock_conn.execute.side_effect = mock_execute

        orchestrate_online_migrations(
            connectable=mock_conn,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            target_database="ZKP_SBOM_LOCAL_DEV",
            create_schemas=True,
            is_connection=True,
        )

        # 1. Identity query was executed first
        assert "SELECT current_database()" in executed_stmts[0]

        # 2. Schema DDL statements were executed
        schema_stmts = [s for s in executed_stmts if "CREATE SCHEMA IF NOT EXISTS" in s]
        assert len(schema_stmts) > 0

        # 3. Commit was called for schema DDL
        mock_conn.commit.assert_called_once()

        # 4. Migration ran inside managed transaction
        mock_context.begin_transaction.assert_called_once()
        mock_context.run_migrations.assert_called_once()

        # 5. Caller retains open connection
        assert not mock_conn.close.called

    def test_schema_creation_failure_rolls_back_and_raises(self):
        """Failure during schema creation triggers rollback on open transaction and re-raises."""
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        call_count = 0

        def mock_execute(stmt, *args, **kwargs):
            nonlocal call_count
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            if "current_database" in sql:
                res = MagicMock()
                res.scalar.return_value = "ZKP_SBOM_LOCAL_DEV"
                return res
            call_count += 1
            if call_count == 2:
                # Simulate schema creation failure
                mock_conn.in_transaction.return_value = True
                raise RuntimeError("Disk full / permission denied during CREATE SCHEMA")
            return MagicMock()

        mock_conn.execute.side_effect = mock_execute

        with pytest.raises(RuntimeError, match="permission denied during CREATE SCHEMA"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=False,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=MagicMock(),
                target_database="ZKP_SBOM_LOCAL_DEV",
                create_schemas=True,
                is_connection=True,
            )

        # Rollback was called to prevent leaving connection in aborted state
        mock_conn.rollback.assert_called_once()
        assert not mock_conn.close.called

    def test_engine_connectable_preserves_connect_and_close_lifecycle(self):
        """When an Engine is passed (CLI path), connect() is entered and connection is closed on exit."""
        mock_engine = MagicMock(spec=Engine)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_context = MagicMock()

        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            is_connection=False,
        )

        # Engine connect was called and context exited
        mock_engine.connect.assert_called_once()
        mock_engine.connect.return_value.__exit__.assert_called_once()

    def test_engine_cli_without_target_database_succeeds(self):
        """When an Engine is passed without target_database in non-staging, CLI path proceeds normally."""
        mock_engine = MagicMock(spec=Engine)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_context = MagicMock()

        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            target_database=None,
            is_connection=False,
        )

        mock_context.run_migrations.assert_called_once()


# ===========================================================================
# 3. env.py Integration & Regression Tests (Mocked)
# ===========================================================================

class TestEnvConnectionOrchestration:
    """Test env.py online/offline migration routing with supplied connection."""

    @pytest.fixture(autouse=True)
    def clean_env(self, monkeypatch):
        """Ensure clean environment flags for each test."""
        monkeypatch.delenv("STAGING_MODE", raising=False)
        monkeypatch.delenv("ENFORCE_USER_BASELINE", raising=False)

    def test_online_with_supplied_connection_does_not_create_engine(self):
        """When connection is in config.attributes, engine_from_config is NOT called."""
        import env

        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        mock_config = MagicMock()
        mock_config.attributes = {
            "connection": mock_conn,
            "target_database": "ZKP_SBOM_LOCAL_DEV",
        }

        mock_context = MagicMock()

        with patch("env.config", mock_config), \
             patch("env.context", mock_context), \
             patch("env.engine_from_config") as mock_engine_from_config, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            env.run_migrations_online()

            # 1. engine_from_config was NEVER called
            assert not mock_engine_from_config.called

            # 2. orchestrate_online_migrations was called with supplied connection and target_database
            mock_orchestrate.assert_called_once()
            call_kwargs = mock_orchestrate.call_args[1]
            assert call_kwargs["connectable"] is mock_conn
            assert call_kwargs["is_connection"] is True
            assert call_kwargs["target_database"] == "ZKP_SBOM_LOCAL_DEV"

    def test_online_with_supplied_connection_missing_target_database_fails_closed(self):
        """Omitting target_database in non-staging fails closed in env.py (FIND-D1451-01)."""
        import env

        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        mock_config = MagicMock()
        mock_config.attributes = {"connection": mock_conn}  # missing target_database

        with patch("env.config", mock_config), \
             patch("env._is_staging", False), \
             patch("env.engine_from_config") as mock_engine_from_config, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            with pytest.raises(StagingConfigError, match="Target database identity.*mandatory"):
                env.run_migrations_online()

            assert not mock_engine_from_config.called
            assert not mock_orchestrate.called

    @pytest.mark.parametrize("empty_target", ["", "   ", None])
    def test_online_with_supplied_connection_empty_target_database_fails_closed(self, empty_target):
        """Empty or None target_database fails closed without creating engine (FIND-D1451-01)."""
        import env

        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        mock_config = MagicMock()
        mock_config.attributes = {
            "connection": mock_conn,
            "target_database": empty_target,
        }

        with patch("env.config", mock_config), \
             patch("env._is_staging", False), \
             patch("env.engine_from_config") as mock_engine_from_config, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            with pytest.raises(StagingConfigError, match="Target database identity.*mandatory"):
                env.run_migrations_online()

            assert not mock_engine_from_config.called
            assert not mock_orchestrate.called

    def test_online_with_supplied_connection_active_transaction_fails_closed(self):
        """Supplied connection with active transaction fails closed immediately (FIND-D1451-02)."""
        import env

        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = True  # dirty!

        mock_config = MagicMock()
        mock_config.attributes = {
            "connection": mock_conn,
            "target_database": "ZKP_SBOM_LOCAL_DEV",
        }

        with patch("env.config", mock_config), \
             patch("env.engine_from_config") as mock_engine_from_config, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            with pytest.raises(RuntimeError, match="active uncommitted transaction"):
                env.run_migrations_online()

            assert not mock_engine_from_config.called
            assert not mock_orchestrate.called

    def test_online_with_invalid_connection_fails_closed_without_engine(self):
        """When an invalid connection is supplied, raises TypeError and NEVER creates engine."""
        import env

        mock_config = MagicMock()
        mock_config.attributes = {"connection": "not_a_valid_connection"}

        with patch("env.config", mock_config), \
             patch("env.engine_from_config") as mock_engine_from_config, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            with pytest.raises(TypeError, match="not a valid SQLAlchemy Connection"):
                env.run_migrations_online()

            assert not mock_engine_from_config.called
            assert not mock_orchestrate.called

    def test_online_with_none_connection_fails_closed_without_engine(self):
        """When connection attribute is None, raises TypeError and NEVER creates engine."""
        import env

        mock_config = MagicMock()
        mock_config.attributes = {"connection": None}

        with patch("env.config", mock_config), \
             patch("env.engine_from_config") as mock_engine_from_config, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            with pytest.raises(TypeError, match="cannot be None"):
                env.run_migrations_online()

            assert not mock_engine_from_config.called
            assert not mock_orchestrate.called

    def test_online_with_engine_as_connection_fails_closed(self):
        """When an Engine is mistakenly supplied as connection, raises TypeError."""
        import env

        mock_engine = MagicMock(spec=Engine)
        mock_config = MagicMock()
        mock_config.attributes = {"connection": mock_engine}

        with patch("env.config", mock_config), \
             patch("env.engine_from_config") as mock_engine_from_config, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            with pytest.raises(TypeError, match="must be an active SQLAlchemy Connection, not an Engine"):
                env.run_migrations_online()

            assert not mock_engine_from_config.called
            assert not mock_orchestrate.called

    def test_online_cli_path_calls_engine_from_config_when_no_connection(self):
        """When no connection is in config.attributes, existing CLI path calls engine_from_config."""
        import env

        mock_config = MagicMock()
        mock_config.attributes = {}
        mock_config.config_ini_section = "alembic"
        mock_config.get_section.return_value = {"sqlalchemy.url": "postgresql://mock/db"}

        mock_engine = MagicMock(spec=Engine)

        with patch("env.config", mock_config), \
             patch("env._is_staging", False), \
             patch("env.engine_from_config", return_value=mock_engine) as mock_engine_from_config, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            env.run_migrations_online()

            # engine_from_config was called
            mock_engine_from_config.assert_called_once()

            # orchestrate called with the created engine
            mock_orchestrate.assert_called_once()
            call_kwargs = mock_orchestrate.call_args[1]
            assert call_kwargs["connectable"] is mock_engine

    def test_offline_rejects_supplied_connection(self):
        """Offline mode aborts if a connection is present in config.attributes."""
        import env

        mock_config = MagicMock()
        mock_config.attributes = {"connection": MagicMock(spec=Connection)}

        with patch("env.config", mock_config):
            with pytest.raises(RuntimeError, match="Cannot run offline migrations with an externally supplied connection"):
                env.run_migrations_offline()

    def test_staging_enforcement_with_supplied_connection(self):
        """In staging mode, validate_staging_target and verify_connection_identity are called on connection."""
        import env

        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        mock_config = MagicMock()
        mock_config.attributes = {"connection": mock_conn}

        with patch("env.config", mock_config), \
             patch("env._is_staging", True), \
             patch("env.validate_staging_target") as mock_val_staging, \
             patch("env.verify_connection_identity") as mock_verify_conn, \
             patch("env.orchestrate_online_migrations") as mock_orchestrate:

            env.run_migrations_online()

            mock_val_staging.assert_called_once()
            mock_verify_conn.assert_called_once_with(mock_conn)
            mock_orchestrate.assert_called_once()


# ===========================================================================
# 4. verify_pg16_target_preflight Unit Tests (Physical Boundary Enforcement)
# ===========================================================================

class TestVerifyPg16TargetPreflight:
    """Validate physical endpoint verification, PG17 protection, and revision check."""

    def test_staging_mode_active_aborts_preflight(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "true")
        mock_conn = MagicMock(spec=Connection)
        with pytest.raises(StagingConfigError, match="STAGING_MODE=true is active"):
            verify_pg16_target_preflight(mock_conn)

    def test_settings_prohibited_port_5432_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5432,  # Prohibited PostgreSQL 17 port!
            name="ZKP_SBOM_LOCAL_DEV",
            password="secret_password",
        )
        with pytest.raises(StagingConfigError, match="Target client port 5432 is strictly prohibited"):
            verify_pg16_target_preflight(mock_conn, settings=settings)

    def test_settings_wrong_port_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5434,
            name="ZKP_SBOM_LOCAL_DEV",
            password="secret_password",
        )
        with pytest.raises(StagingConfigError, match="Target client port '5434' is prohibited"):
            verify_pg16_target_preflight(mock_conn, settings=settings)

    def test_settings_prohibited_pg17_database_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5433,
            name="ZKP_SBOM",  # Prohibited PostgreSQL 17 database!
            password="secret_password",
        )
        with pytest.raises(StagingConfigError, match="Target database 'ZKP_SBOM' is strictly prohibited"):
            verify_pg16_target_preflight(mock_conn, settings=settings)

    def test_settings_wrong_database_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5433,
            name="ZKP_SBOM_TEST",
            password="secret_password",
        )
        with pytest.raises(StagingConfigError, match="Target database 'ZKP_SBOM_TEST' is invalid"):
            verify_pg16_target_preflight(mock_conn, settings=settings)

    def test_settings_prohibited_host_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="192.168.1.50",
            port=5433,
            name="ZKP_SBOM_LOCAL_DEV",
            password="secret_password",
        )
        with pytest.raises(StagingConfigError, match="Target host '192.168.1.50' is prohibited"):
            verify_pg16_target_preflight(mock_conn, settings=settings)

    def test_settings_empty_password_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5433,
            name="ZKP_SBOM_LOCAL_DEV",
            password="",
        )
        with pytest.raises(StagingConfigError, match="DB_PASSWORD must be configured"):
            verify_pg16_target_preflight(mock_conn, settings=settings)

    def test_connection_url_port_5432_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock()
        del mock_conn.connect
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_url = MagicMock()
        mock_url.port = 5432
        mock_url.host = "127.0.0.1"
        mock_url.database = "ZKP_SBOM_LOCAL_DEV"
        mock_conn.engine.url = mock_url

        with pytest.raises(StagingConfigError, match="Connection URL specifies port 5432"):
            verify_pg16_target_preflight(mock_conn)

    def test_connection_url_pg17_database_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock()
        del mock_conn.connect
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_url = MagicMock()
        mock_url.port = 5433
        mock_url.host = "127.0.0.1"
        mock_url.database = "ZKP_SBOM"
        mock_conn.engine.url = mock_url

        with pytest.raises(StagingConfigError, match="Targeting PostgreSQL 17 database is forbidden"):
            verify_pg16_target_preflight(mock_conn)

    def test_server_reported_postgresql_17_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.fetchone.return_value = ("ZKP_SBOM_LOCAL_DEV", "PostgreSQL 17.0 on x86_64")
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(StagingConfigError, match="Targeting PostgreSQL 17 is strictly prohibited"):
            verify_pg16_target_preflight(mock_conn)

    def test_server_reported_not_postgresql_16_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.fetchone.return_value = ("ZKP_SBOM_LOCAL_DEV", "PostgreSQL 15.4 on x86_64")
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(StagingConfigError, match="Expected major engine 'PostgreSQL 16'"):
            verify_pg16_target_preflight(mock_conn)

    def test_server_reported_database_mismatch_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.fetchone.return_value = ("ZKP_SBOM", "PostgreSQL 16.2 on x86_64")
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(StagingConfigError, match="Targeting PostgreSQL 17 database is strictly forbidden"):
            verify_pg16_target_preflight(mock_conn)

    def test_revision_mismatch_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.fetchone.return_value = ("ZKP_SBOM_LOCAL_DEV", "PostgreSQL 16.4 on x86_64")
            elif "server_version_num" in sql:
                res.scalar.return_value = 160004
            elif "information_schema.tables" in sql:
                res.scalar.return_value = 1
            elif "version_num" in sql:
                res.fetchall.return_value = [("007",)]  # wrong revision!
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(StagingConfigError, match="Database current revision is '007', expected strictly '014'"):
            verify_pg16_target_preflight(mock_conn, expected_revision="014")

    def test_valid_pg16_preflight_succeeds_and_rolls_back_query_transaction(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock()
        del mock_conn.connect
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False

        mock_url = MagicMock()
        mock_url.port = 5433
        mock_url.host = "127.0.0.1"
        mock_url.database = "ZKP_SBOM_LOCAL_DEV"
        mock_conn.engine.url = mock_url

        settings = SimpleNamespace(
            host="127.0.0.1",
            port=5433,
            name="ZKP_SBOM_LOCAL_DEV",
            password="mock_password",
        )

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.fetchone.return_value = ("ZKP_SBOM_LOCAL_DEV", "PostgreSQL 16.3 on x86_64-pc-linux-gnu")
            elif "server_version_num" in sql:
                res.scalar.return_value = 160003
            elif "information_schema.tables" in sql:
                res.scalar.return_value = 1
            elif "version_num" in sql:
                res.fetchall.return_value = [("014",)]
            return res

        mock_conn.execute.side_effect = mock_exec

        # Execute preflight check
        verify_pg16_target_preflight(mock_conn, settings=settings, expected_revision="014")

        # Rollback was called to clean up autobegin transaction
        mock_conn.rollback.assert_called_once()

    def test_dbapi_socket_port_5432_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        mock_dbapi = MagicMock()
        mock_dbapi.info.port = 5432
        mock_conn.connection.connection = mock_dbapi

        with pytest.raises(StagingConfigError, match="DBAPI socket connection specifies port 5432"):
            verify_pg16_target_preflight(mock_conn)

    def test_dbapi_socket_wrong_port_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        mock_dbapi = MagicMock()
        mock_dbapi.info.port = 5434
        mock_conn.connection.connection = mock_dbapi

        with pytest.raises(StagingConfigError, match="DBAPI socket connection specifies port 5434.*Must be strictly 5433"):
            verify_pg16_target_preflight(mock_conn)

    def test_dbapi_socket_prohibited_host_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        mock_dbapi = MagicMock()
        mock_dbapi.info.port = 5433
        mock_dbapi.info.host = "unauthorized.remote.com"
        mock_conn.connection.connection = mock_dbapi

        with pytest.raises(StagingConfigError, match="DBAPI socket connection host 'unauthorized.remote.com' is prohibited"):
            verify_pg16_target_preflight(mock_conn)

    def test_dbapi_socket_pg17_database_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        mock_dbapi = MagicMock()
        mock_dbapi.info.port = 5433
        mock_dbapi.info.host = "127.0.0.1"
        mock_dbapi.info.dbname = "ZKP_SBOM"
        mock_conn.connection.connection = mock_dbapi

        with pytest.raises(StagingConfigError, match="DBAPI socket targets database 'ZKP_SBOM'.*Targeting PostgreSQL 17 database is forbidden"):
            verify_pg16_target_preflight(mock_conn)

    def test_incompatible_legacy_role_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.fetchone.return_value = ("ZKP_SBOM_LOCAL_DEV", "PostgreSQL 16.4 on x86_64")
            elif "server_version_num" in sql:
                res.scalar.return_value = 160004
            elif "information_schema.tables" in sql:
                res.scalar.return_value = 1
            elif "version_num" in sql:
                res.fetchall.return_value = [("014",)]
            elif "SELECT DISTINCT role" in sql:
                res.fetchall.return_value = [("superadmin",)]
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(StagingConfigError, match="unexpected legacy role.*superadmin"):
            verify_pg16_target_preflight(mock_conn)

    def test_preflight_schema_conflict_existing_column_aborts(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        mock_conn = MagicMock(spec=Connection)
        mock_conn.closed = False
        mock_conn.invalidated = False
        mock_conn.in_transaction.return_value = False
        mock_conn.engine = None

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "current_database" in sql:
                res.fetchone.return_value = ("ZKP_SBOM_LOCAL_DEV", "PostgreSQL 16.4 on x86_64")
            elif "server_version_num" in sql:
                res.scalar.return_value = 160004
            elif "information_schema.tables" in sql:
                res.scalar.return_value = 1
            elif "version_num" in sql:
                res.fetchall.return_value = [("014",)]
            elif "SELECT DISTINCT role" in sql:
                res.fetchall.return_value = []
            elif "information_schema.columns" in sql:
                res.fetchall.return_value = [("public", "users", "is_active")]
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(StagingConfigError, match="schema conflict detected.*public.users.is_active"):
            verify_pg16_target_preflight(mock_conn)


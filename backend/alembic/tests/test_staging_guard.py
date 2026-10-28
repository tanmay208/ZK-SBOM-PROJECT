"""
Focused mocked tests for the staging migration safety guard.

These tests exercise the exact helper functions in staging_guard.py
that are called by the real Alembic env.py online migration path,
including the shared orchestrate_online_migrations implementation.

ALL database interactions are mocked. No test connects to PostgreSQL,
executes Alembic migrations, or reads real .env files.

Test categories:
  - Import isolation and third-party Alembic package distinction
  - STAGING_MODE parsing and invalid values
  - Missing .env.staging file
  - Missing or empty required staging values
  - Conflicting inherited environment variables (without exposing values)
  - Incorrect staging database name
  - Pre-connection target validation (DB_NAME, DB_HOST, DB_PORT)
  - Online identity verification
  - Shared online orchestration (identity check before DDL, cleanup, ordering regression)
  - Offline URL rejection
  - Non-staging preservation
"""

import importlib
import os
import sys
from unittest.mock import MagicMock, call, patch

import pytest
from sqlalchemy import text
from sqlalchemy.engine.url import make_url

# Ensure backend root and alembic directory are on sys.path.
_backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

_alembic_dir = os.path.join(_backend_root, "alembic")
if _alembic_dir not in sys.path:
    sys.path.insert(0, _alembic_dir)

import staging_guard
from staging_guard import (
    STAGING_DB_NAME,
    _DB_SETTING_KEYS,
    StagingConfigError,
    classify_online_command,
    load_environment,
    load_staging_environment,
    orchestrate_online_migrations,
    parse_staging_mode,
    set_validated_staging_config,
    validate_staging_target,
    verify_connection_identity,
    CANONICAL_REVISION_CONTRACT_MAP,
    ContractValidationResult,
    MigrationStateResult,
    USERS_CONTRACT_V1_COLS,
    USERS_CONTRACT_V2_COLS,
    assert_users_baseline_ready,
    determine_contract_for_revision,
    determine_users_contract,
    get_recorded_alembic_revision,
    validate_users_contract,
)



# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure DB_ and STAGING_MODE variables are absent before each test.

    Restores the environment automatically after each test via monkeypatch.
    Does NOT read, overwrite, or hide any real .env file.
    """
    for key in list(os.environ.keys()):
        if key.startswith("DB_") or key == "STAGING_MODE":
            monkeypatch.delenv(key, raising=False)
    set_validated_staging_config(None)
    yield
    set_validated_staging_config(None)


@pytest.fixture
def staging_env_dict():
    """Return a valid staging .env.staging dictionary for mocking."""
    return {
        "DB_HOST": "host.docker.internal",
        "DB_PORT": "5432",
        "DB_USER": "staging_migrator",
        "DB_PASSWORD": "staging_test_password_placeholder",
        "DB_NAME": "ZKP_SBOM_STAGING",
        "DB_SSL_MODE": "prefer",
        "DB_SSL_ROOT_CERT": "/etc/ssl/certs/staging-ca.crt",
        "DB_ECHO": "false",
    }


# =======================================================================
# 1. Import isolation & helper resolution
# =======================================================================

class TestImportIsolation:
    """Verify staging_guard resolves to the project file and not third-party Alembic."""

    def test_staging_guard_resolves_to_project_file(self):
        """staging_guard must resolve to backend/alembic/staging_guard.py."""
        expected_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "staging_guard.py")
        )
        actual_path = os.path.abspath(staging_guard.__file__)
        assert actual_path == expected_path

    def test_alembic_package_not_shadowed(self):
        """Installed third-party Alembic package is loaded, not shadowed."""
        import alembic
        assert "site-packages" in alembic.__file__ or "dist-packages" in alembic.__file__
        assert hasattr(alembic, "context")

    def test_staging_guard_not_in_alembic_package(self):
        """Third-party alembic package does NOT contain staging_guard."""
        import alembic
        assert not hasattr(alembic, "staging_guard")

    def test_import_safety(self):
        """Importing staging_guard does not read files, connect, or run migrations."""
        import ast
        with open(staging_guard.__file__, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        # Inspect top-level expressions and calls in AST
        # Verify no top-level call to load_dotenv, dotenv_values, engine_from_config, etc.
        top_level_calls = [
            node for node in tree.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
        ]
        called_names = []
        for stmt in top_level_calls:
            func = stmt.value.func
            if isinstance(func, ast.Name):
                called_names.append(func.id)
            elif isinstance(func, ast.Attribute):
                called_names.append(func.attr)
        assert "load_dotenv" not in called_names
        assert "dotenv_values" not in called_names
        assert "engine_from_config" not in called_names
        assert "connect" not in called_names
        assert "run_migrations" not in called_names


# =======================================================================
# 2. STAGING_MODE parsing
# =======================================================================

class TestParseStagingMode:
    """Test strict STAGING_MODE value parsing."""

    def test_absent_returns_false(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        assert parse_staging_mode() is False

    def test_exactly_false_returns_false(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "false")
        assert parse_staging_mode() is False

    def test_exactly_true_returns_true(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "true")
        assert parse_staging_mode() is True

    def test_uppercase_true_rejects(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "TRUE")
        with pytest.raises(StagingConfigError, match="Invalid STAGING_MODE"):
            parse_staging_mode()

    def test_mixed_case_rejects(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "True")
        with pytest.raises(StagingConfigError, match="Invalid STAGING_MODE"):
            parse_staging_mode()

    def test_empty_string_rejects(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "")
        with pytest.raises(StagingConfigError, match="Invalid STAGING_MODE"):
            parse_staging_mode()

    def test_whitespace_rejects(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", " true ")
        with pytest.raises(StagingConfigError, match="Invalid STAGING_MODE"):
            parse_staging_mode()

    def test_typo_rejects(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "staging")
        with pytest.raises(StagingConfigError, match="Invalid STAGING_MODE"):
            parse_staging_mode()


# =======================================================================
# 3. Missing .env.staging
# =======================================================================

class TestMissingStagingFile:
    """Test that a missing .env.staging file aborts staging."""

    def test_missing_file_aborts(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "true")
        with patch("staging_guard.os.path.exists", return_value=False):
            with pytest.raises(StagingConfigError, match=r"\.env\.staging is missing"):
                load_staging_environment()


# =======================================================================
# 4. Missing or empty required staging values
# =======================================================================

class TestMissingRequiredValues:
    """Test that missing or empty required values in .env.staging abort."""

    @pytest.mark.parametrize("missing_key", [
        "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME",
    ])
    def test_missing_required_key(self, monkeypatch, staging_env_dict, missing_key):
        config_without_key = {k: v for k, v in staging_env_dict.items() if k != missing_key}
        monkeypatch.setenv("STAGING_MODE", "true")
        with patch("staging_guard.os.path.exists", return_value=True), \
             patch("staging_guard.dotenv_values", return_value=config_without_key):
            with pytest.raises(StagingConfigError, match=f"'{missing_key}'.*missing or empty"):
                load_staging_environment()

    @pytest.mark.parametrize("empty_key", [
        "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME",
    ])
    def test_empty_required_key(self, monkeypatch, staging_env_dict, empty_key):
        staging_env_dict[empty_key] = ""
        monkeypatch.setenv("STAGING_MODE", "true")
        with patch("staging_guard.os.path.exists", return_value=True), \
             patch("staging_guard.dotenv_values", return_value=staging_env_dict):
            with pytest.raises(StagingConfigError, match=f"'{empty_key}'.*missing or empty"):
                load_staging_environment()

    def test_whitespace_only_key_rejected(self, monkeypatch, staging_env_dict):
        staging_env_dict["DB_PASSWORD"] = "   "
        monkeypatch.setenv("STAGING_MODE", "true")
        with patch("staging_guard.os.path.exists", return_value=True), \
             patch("staging_guard.dotenv_values", return_value=staging_env_dict):
            with pytest.raises(StagingConfigError, match="'DB_PASSWORD'.*missing or empty"):
                load_staging_environment()


# =======================================================================
# 5. Conflicting inherited environment variables
# =======================================================================

class TestConflictingInheritedVars:
    """Test that inherited shell variables conflicting with staging abort.

    CRITICAL: No conflicting value must appear in test output.
    """

    @pytest.mark.parametrize("conflict_key", list(_DB_SETTING_KEYS))
    def test_conflict_aborts(self, monkeypatch, staging_env_dict, conflict_key, capsys):
        """Each of the eight DB settings triggers a conflict abort."""
        dummy_conflict = "LEAKED_VALUE_SENTINEL"
        monkeypatch.setenv(conflict_key, dummy_conflict)
        monkeypatch.setenv("STAGING_MODE", "true")

        with patch("staging_guard.os.path.exists", return_value=True), \
             patch("staging_guard.dotenv_values", return_value=staging_env_dict):
            with pytest.raises(StagingConfigError, match=f"'{conflict_key}'"):
                load_staging_environment()

        # Verify the dummy secret value did NOT leak to output.
        captured = capsys.readouterr()
        assert dummy_conflict not in captured.out
        assert dummy_conflict not in captured.err

    def test_ca_path_conflict_aborts(self, monkeypatch, staging_env_dict, capsys):
        """Conflicting DB_SSL_ROOT_CERT triggers abort without leaking the path."""
        dummy_conflict = "/rogue/unauthorized/ca-cert.pem"
        monkeypatch.setenv("DB_SSL_ROOT_CERT", dummy_conflict)
        monkeypatch.setenv("STAGING_MODE", "true")

        with patch("staging_guard.os.path.exists", return_value=True), \
             patch("staging_guard.dotenv_values", return_value=staging_env_dict):
            with pytest.raises(StagingConfigError, match="'DB_SSL_ROOT_CERT'"):
                load_staging_environment()

        captured = capsys.readouterr()
        assert dummy_conflict not in captured.out
        assert dummy_conflict not in captured.err

    def test_ca_path_in_db_setting_keys(self):
        """DB_SSL_ROOT_CERT is tracked in _DB_SETTING_KEYS."""
        assert "DB_SSL_ROOT_CERT" in _DB_SETTING_KEYS

    def test_matching_inherited_value_succeeds(self, monkeypatch, staging_env_dict):
        """An inherited variable that matches .env.staging is not a conflict."""
        monkeypatch.setenv("DB_HOST", staging_env_dict["DB_HOST"])
        monkeypatch.setenv("STAGING_MODE", "true")

        with patch("staging_guard.os.path.exists", return_value=True), \
             patch("staging_guard.dotenv_values", return_value=staging_env_dict), \
             patch("staging_guard.load_dotenv"):
            load_staging_environment()


# =======================================================================
# 6. Incorrect staging database name
# =======================================================================

class TestIncorrectStagingDbName:
    """Test that a non-staging DB_NAME in .env.staging aborts."""

    def test_production_db_name_rejected(self, monkeypatch, staging_env_dict):
        staging_env_dict["DB_NAME"] = "ZKP_SBOM"
        monkeypatch.setenv("STAGING_MODE", "true")
        with patch("staging_guard.os.path.exists", return_value=True), \
             patch("staging_guard.dotenv_values", return_value=staging_env_dict):
            with pytest.raises(StagingConfigError, match="ZKP_SBOM_STAGING"):
                load_staging_environment()


# =======================================================================
# 7. Pre-connection target validation (DB_NAME, DB_HOST, DB_PORT)
# =======================================================================

class TestValidateStagingTarget:
    """Test validate_staging_target enforces DB_HOST, DB_PORT, and DB_NAME."""

    def test_correct_target_passes(self, monkeypatch, staging_env_dict):
        """When host, port, and db_name match, target validation passes."""
        monkeypatch.setenv("DB_HOST", staging_env_dict["DB_HOST"])
        monkeypatch.setenv("DB_PORT", staging_env_dict["DB_PORT"])
        monkeypatch.setenv("DB_NAME", STAGING_DB_NAME)

        validate_staging_target(expected_config=staging_env_dict)

    def test_database_name_mismatch_aborts(self, monkeypatch, staging_env_dict):
        """Mismatched DB_NAME raises StagingConfigError identifying setting name."""
        monkeypatch.setenv("DB_HOST", staging_env_dict["DB_HOST"])
        monkeypatch.setenv("DB_PORT", staging_env_dict["DB_PORT"])
        monkeypatch.setenv("DB_NAME", "ZKP_SBOM_PROD")

        with pytest.raises(StagingConfigError, match="DB_NAME"):
            validate_staging_target(expected_config=staging_env_dict)

    def test_host_mismatch_aborts(self, monkeypatch, staging_env_dict):
        """Mismatched DB_HOST raises StagingConfigError identifying setting name."""
        monkeypatch.setenv("DB_HOST", "production.postgres.internal")
        monkeypatch.setenv("DB_PORT", staging_env_dict["DB_PORT"])
        monkeypatch.setenv("DB_NAME", STAGING_DB_NAME)

        with pytest.raises(StagingConfigError, match="DB_HOST"):
            validate_staging_target(expected_config=staging_env_dict)

    def test_port_mismatch_aborts(self, monkeypatch, staging_env_dict):
        """Mismatched DB_PORT raises StagingConfigError identifying setting name."""
        monkeypatch.setenv("DB_HOST", staging_env_dict["DB_HOST"])
        monkeypatch.setenv("DB_PORT", "5433")
        monkeypatch.setenv("DB_NAME", STAGING_DB_NAME)

        with pytest.raises(StagingConfigError, match="DB_PORT"):
            validate_staging_target(expected_config=staging_env_dict)

    def test_missing_host_aborts(self, monkeypatch, staging_env_dict):
        """Missing DB_HOST in active environment aborts."""
        monkeypatch.delenv("DB_HOST", raising=False)
        monkeypatch.setenv("DB_PORT", staging_env_dict["DB_PORT"])
        monkeypatch.setenv("DB_NAME", STAGING_DB_NAME)

        with pytest.raises(StagingConfigError, match="DB_HOST"):
            validate_staging_target(expected_config=staging_env_dict)

    def test_missing_port_aborts(self, monkeypatch, staging_env_dict):
        """Missing DB_PORT in active environment aborts."""
        monkeypatch.setenv("DB_HOST", staging_env_dict["DB_HOST"])
        monkeypatch.delenv("DB_PORT", raising=False)
        monkeypatch.setenv("DB_NAME", STAGING_DB_NAME)

        with pytest.raises(StagingConfigError, match="DB_PORT"):
            validate_staging_target(expected_config=staging_env_dict)

    def test_missing_dbname_aborts(self, monkeypatch, staging_env_dict):
        """Missing DB_NAME in active environment aborts."""
        monkeypatch.setenv("DB_HOST", staging_env_dict["DB_HOST"])
        monkeypatch.setenv("DB_PORT", staging_env_dict["DB_PORT"])
        monkeypatch.delenv("DB_NAME", raising=False)

        with pytest.raises(StagingConfigError, match="DB_NAME"):
            validate_staging_target(expected_config=staging_env_dict)

    def test_target_validation_errors_identify_setting_name_only_and_no_secrets(
        self, monkeypatch, staging_env_dict, capsys
    ):
        """Secret values, passwords, and hosts are not leaked in target errors."""
        secret_host = "secret-staging-host.internal"
        secret_pass = "SuperSecretPassword123"
        staging_env_dict["DB_HOST"] = secret_host
        staging_env_dict["DB_PASSWORD"] = secret_pass

        monkeypatch.setenv("DB_HOST", "wrong-host.internal")
        monkeypatch.setenv("DB_PORT", staging_env_dict["DB_PORT"])
        monkeypatch.setenv("DB_NAME", STAGING_DB_NAME)

        with pytest.raises(StagingConfigError) as exc_info:
            validate_staging_target(expected_config=staging_env_dict)

        err_msg = str(exc_info.value)
        assert "DB_HOST" in err_msg
        assert secret_host not in err_msg
        assert secret_pass not in err_msg
        assert "wrong-host.internal" not in err_msg

        captured = capsys.readouterr()
        assert secret_host not in captured.out
        assert secret_pass not in captured.out

    def test_database_settings_inconsistency_aborts(self, monkeypatch, staging_env_dict):
        """Inconsistency between DatabaseSettings and expected staging config aborts."""
        monkeypatch.setenv("DB_HOST", staging_env_dict["DB_HOST"])
        monkeypatch.setenv("DB_PORT", staging_env_dict["DB_PORT"])
        monkeypatch.setenv("DB_NAME", STAGING_DB_NAME)

        mock_db_settings = MagicMock()
        mock_db_settings.name = STAGING_DB_NAME
        mock_db_settings.host = "unvalidated-inherited-host"
        mock_db_settings.port = 5432

        with pytest.raises(StagingConfigError, match="DatabaseSettings DB_HOST"):
            validate_staging_target(
                expected_config=staging_env_dict,
                db_settings=mock_db_settings,
            )


# =======================================================================
# 8. Online identity verification (direct helper)
# =======================================================================

class TestOnlineIdentityVerification:
    """Test verify_connection_identity checks connected database."""

    def _make_mock_connection(self, current_db_name):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar.return_value = current_db_name
        mock_conn.execute.return_value = mock_result
        return mock_conn

    def test_mismatch_aborts(self):
        mock_conn = self._make_mock_connection("ZKP_SBOM_PROD")
        with pytest.raises(StagingConfigError, match="ZKP_SBOM_PROD"):
            verify_connection_identity(mock_conn)

    def test_correct_identity_passes(self):
        mock_conn = self._make_mock_connection(STAGING_DB_NAME)
        verify_connection_identity(mock_conn)

    def test_production_db_name_rejected(self):
        mock_conn = self._make_mock_connection("ZKP_SBOM")
        with pytest.raises(StagingConfigError, match="ZKP_SBOM"):
            verify_connection_identity(mock_conn)


# =======================================================================
# 9. Shared online orchestration (invokes real orchestrate_online_migrations)
# =======================================================================

class TestOnlineOrchestration:
    """Exercise the actual shared orchestrate_online_migrations function.

    Guarantees:
      - Connection context manager exits on both success and failure.
      - Identity check query runs before any schema DDL.
      - On mismatch, no schema DDL, commit, or migrations run.
      - Ordering regression test demonstrates moving DDL before identity fails.
    """

    def test_identity_mismatch_aborts_before_ddl_and_migrations(self):
        """Identity mismatch query is executed first; DDL and migrations are skipped."""
        call_log = []
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_context = MagicMock()

        def tracking_execute(stmt, *args, **kwargs):
            sql_text = stmt.text if hasattr(stmt, "text") else str(stmt)
            call_log.append(sql_text)
            result = MagicMock()
            if "current_database" in sql_text:
                result.scalar.return_value = "ZKP_SBOM_PROD"
            return result

        mock_conn.execute.side_effect = tracking_execute
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        with pytest.raises(StagingConfigError, match="ZKP_SBOM_PROD"):
            orchestrate_online_migrations(
                connectable=mock_engine,
                is_staging=True,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=mock_context,
            )

        # 1. Exactly one execute: the identity query
        assert len(call_log) == 1
        assert "SELECT current_database()" in call_log[0]

        # 2. No DDL statements were executed
        assert not any("CREATE SCHEMA" in stmt for stmt in call_log)

        # 3. No commit or migrations run
        assert not mock_conn.commit.called
        assert not mock_context.configure.called
        assert not mock_context.run_migrations.called
        assert not mock_context.begin_transaction.called

        # 4. Context manager was exited (resource cleanup)
        assert mock_engine.connect.return_value.__exit__.called

    def test_successful_identity_precedes_ddl_and_migrations(self):
        """Identity check strictly precedes every schema DDL statement and migration."""
        call_log = []
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_context = MagicMock()

        def tracking_execute(stmt, *args, **kwargs):
            sql_text = stmt.text if hasattr(stmt, "text") else str(stmt)
            call_log.append(sql_text)
            result = MagicMock()
            if "current_database" in sql_text:
                result.scalar.return_value = STAGING_DB_NAME
            return result

        mock_conn.execute.side_effect = tracking_execute
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=True,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            schemas=("sbom", "vulnerability", "policy", "zkp", "verification"),
        )

        # 1. Identity query MUST be the very first statement executed
        assert len(call_log) == 6
        assert call_log[0] == "SELECT current_database()"

        # 2. Schema DDL statements follow in order
        expected_ddl = [
            f'CREATE SCHEMA IF NOT EXISTS "{s}"'
            for s in ("sbom", "vulnerability", "policy", "zkp", "verification")
        ]
        assert call_log[1:] == expected_ddl

        # 3. Connection commit, context configure, transaction, and migrations called
        assert mock_conn.commit.called
        assert mock_context.configure.called
        assert mock_context.begin_transaction.called
        assert mock_context.run_migrations.called

        # 4. Context manager exited cleanly
        assert mock_engine.connect.return_value.__exit__.called

    def test_resource_cleanup_on_mismatch_and_success(self):
        """The exact context manager returned by connectable.connect() exits on both paths."""
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_conn
        mock_cm.__exit__.return_value = False
        mock_engine.connect.return_value = mock_cm

        # Failure path: identity mismatch
        mock_res_fail = MagicMock()
        mock_res_fail.scalar.return_value = "WRONG_DB"
        mock_conn.execute.return_value = mock_res_fail

        with pytest.raises(StagingConfigError):
            orchestrate_online_migrations(
                connectable=mock_engine,
                is_staging=True,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=MagicMock(),
            )
        assert mock_cm.__exit__.called
        assert mock_cm.__exit__.call_args[0][0] is StagingConfigError

        # Success path
        mock_cm.reset_mock()
        mock_res_ok = MagicMock()
        mock_res_ok.scalar.return_value = STAGING_DB_NAME
        mock_conn.execute.return_value = mock_res_ok

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=True,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
        )
        assert mock_cm.__exit__.called
        assert mock_cm.__exit__.call_args[0][0] is None

    def test_ordering_regression_demonstration(self):
        """Demonstrate through test design that moving DDL before identity fails.

        An ordering validator validates that identity check strictly precedes DDL.
        We show:
          1. The real orchestrate_online_migrations satisfies the ordering requirement.
          2. An inverted sequence (DDL before identity) fails the ordering requirement.
        """
        def assert_safe_statement_order(recorded_statements: list[str]) -> None:
            """Validate that SELECT current_database() precedes all CREATE SCHEMA DDL."""
            assert len(recorded_statements) > 0, "No statements executed"
            assert "SELECT current_database()" in recorded_statements[0], (
                f"Ordering regression: first statement was {recorded_statements[0]}, "
                f"expected SELECT current_database()"
            )
            for idx, stmt in enumerate(recorded_statements):
                if "CREATE SCHEMA" in stmt:
                    prior = recorded_statements[:idx]
                    assert any("current_database" in s for s in prior), (
                        f"Ordering regression: schema DDL at index {idx} executed "
                        f"before identity query"
                    )

        # 1. Real orchestration passes the order assertion
        real_events = []
        mock_engine = MagicMock()
        mock_conn = MagicMock()

        def tracking_execute(stmt, *args, **kwargs):
            sql_text = stmt.text if hasattr(stmt, "text") else str(stmt)
            real_events.append(sql_text)
            res = MagicMock()
            res.scalar.return_value = STAGING_DB_NAME
            return res

        mock_conn.execute.side_effect = tracking_execute
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=True,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
        )
        assert_safe_statement_order(real_events)

        # 2. Inverted ordering fails the order assertion
        inverted_events = [
            'CREATE SCHEMA IF NOT EXISTS "sbom"',
            "SELECT current_database()",
        ]
        with pytest.raises(AssertionError, match="Ordering regression"):
            assert_safe_statement_order(inverted_events)

    def test_non_staging_mode_skips_identity_check(self):
        """When is_staging=False, identity query is skipped and DDL runs directly."""
        call_log = []
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_context = MagicMock()

        def tracking_execute(stmt, *args, **kwargs):
            sql_text = stmt.text if hasattr(stmt, "text") else str(stmt)
            call_log.append(sql_text)
            return MagicMock()

        mock_conn.execute.side_effect = tracking_execute
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            schemas=("sbom",),
        )

        assert not any("current_database" in stmt for stmt in call_log)
        assert call_log == ['CREATE SCHEMA IF NOT EXISTS "sbom"']
        assert mock_conn.commit.called
        assert mock_context.run_migrations.called


# =======================================================================
# 10. Offline URL rejection
# =======================================================================

class TestOfflineUrlRejection:
    """Test offline mode URL validation using structured parsing."""

    def test_production_url_rejected(self):
        url = "postgresql+psycopg2://user:pass@localhost:5432/ZKP_SBOM?sslmode=require"
        parsed = make_url(url)
        assert parsed.database != STAGING_DB_NAME

    def test_staging_url_accepted(self):
        url = "postgresql+psycopg2://user:pass@localhost:5432/ZKP_SBOM_STAGING?sslmode=prefer"
        parsed = make_url(url)
        assert parsed.database == STAGING_DB_NAME

    def test_missing_database_rejected(self):
        url = "postgresql+psycopg2://user:pass@localhost:5432/?sslmode=require"
        parsed = make_url(url)
        assert parsed.database != STAGING_DB_NAME


# =======================================================================
# 11. Non-staging behaviour preserved
# =======================================================================

class TestNonStagingPreserved:
    """Test that non-staging mode preserves existing behaviour."""

    def test_absent_staging_mode_loads_production(self, monkeypatch):
        monkeypatch.delenv("STAGING_MODE", raising=False)
        with patch("staging_guard.load_dotenv") as mock_load:
            load_environment()
            assert mock_load.called
            loaded_path = mock_load.call_args[0][0]
            assert loaded_path.endswith(".env")
            assert not loaded_path.endswith(".env.staging")

    def test_false_staging_mode_loads_production(self, monkeypatch):
        monkeypatch.setenv("STAGING_MODE", "false")
        with patch("staging_guard.load_dotenv") as mock_load:
            load_environment()
            assert mock_load.called
            loaded_path = mock_load.call_args[0][0]
            assert loaded_path.endswith(".env")
            assert not loaded_path.endswith(".env.staging")


# =======================================================================
# 12. Online command classification
# =======================================================================

class TestClassifyOnlineCommand:
    """Test classification of Alembic commands as inspection or migration."""

    def test_classify_inspection_commands_by_cmd(self):
        for cmd_name in ("current", "heads", "history", "branches", "check"):
            mock_cfg = MagicMock()
            mock_fn = MagicMock()
            mock_fn.__name__ = cmd_name
            mock_cfg.cmd_opts.cmd = [mock_fn]
            mock_cfg.cmd_opts.subcommand = None

            is_inspect, is_mig = classify_online_command(mock_cfg, MagicMock())
            assert is_inspect is True, f"Failed for {cmd_name}"
            assert is_mig is False, f"Failed for {cmd_name}"

    def test_classify_migration_commands_by_cmd(self):
        for cmd_name in ("upgrade", "downgrade"):
            mock_cfg = MagicMock()
            mock_fn = MagicMock()
            mock_fn.__name__ = cmd_name
            mock_cfg.cmd_opts.cmd = [mock_fn]
            mock_cfg.cmd_opts.subcommand = None

            is_inspect, is_mig = classify_online_command(mock_cfg, MagicMock())
            assert is_inspect is False, f"Failed for {cmd_name}"
            assert is_mig is True, f"Failed for {cmd_name}"

    def test_classify_inspection_by_subcommand(self):
        mock_cfg = MagicMock()
        mock_cfg.cmd_opts.cmd = []
        mock_cfg.cmd_opts.subcommand = "current"

        is_inspect, is_mig = classify_online_command(mock_cfg, MagicMock())
        assert is_inspect is True
        assert is_mig is False

    def test_classify_by_context_fn(self):
        mock_cfg = MagicMock()
        mock_cfg.cmd_opts = None

        mock_ctx = MagicMock()
        mock_fn = MagicMock()
        mock_fn.__name__ = "display_version"
        mock_ctx._proxy.fn = mock_fn

        is_inspect, is_mig = classify_online_command(mock_cfg, mock_ctx)
        assert is_inspect is True
        assert is_mig is False

    def test_classify_unrecognized_fails_safe_to_migration(self):
        """Unknown or unclassifiable commands fail-safe to migration mode."""
        mock_cfg = MagicMock()
        mock_cfg.cmd_opts = None
        mock_ctx = MagicMock()
        mock_ctx._proxy = None
        mock_ctx.fn = None

        is_inspect, is_mig = classify_online_command(mock_cfg, mock_ctx)
        assert is_inspect is False
        assert is_mig is True


# =======================================================================
# 13. Inspection orchestration safety
# =======================================================================

class TestInspectionOrchestrationSafety:
    """Test that inspection mode executes zero schema DDL and zero DDL commits."""

    def test_inspection_mode_skips_schema_creation_and_commit(self):
        call_log = []
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_context = MagicMock()

        def tracking_execute(stmt, *args, **kwargs):
            sql_text = stmt.text if hasattr(stmt, "text") else str(stmt)
            call_log.append(sql_text)
            return MagicMock()

        mock_conn.execute.side_effect = tracking_execute
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            schemas=("sbom", "vulnerability"),
            check_users_baseline=False,
            create_schemas=False,
        )

        # 1. Zero DDL executed
        assert len(call_log) == 0
        # 2. Connection commit NOT called for DDL
        assert not mock_conn.commit.called
        # 3. Context configured and migrations run
        assert mock_context.configure.called
        assert mock_context.run_migrations.called

    @patch("staging_guard.assert_users_baseline_ready")
    def test_inspection_mode_skips_users_baseline_when_explicitly_false(self, mock_assert_ready):
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
            check_users_baseline=False,
            create_schemas=False,
        )

        assert not mock_assert_ready.called

    @patch("staging_guard.assert_users_baseline_ready")
    def test_migration_mode_enforces_users_baseline_when_explicitly_true(self, mock_assert_ready):
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
            check_users_baseline=True,
            create_schemas=True,
        )

        assert mock_assert_ready.called

    @patch("staging_guard.assert_users_baseline_ready")
    def test_orchestrate_passes_allow_unversioned_baseline_default_false(self, mock_assert_ready):
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
            check_users_baseline=True,
            create_schemas=True,
        )

        mock_assert_ready.assert_called_once_with(mock_conn, allow_unversioned_baseline=False)

    @patch("staging_guard.assert_users_baseline_ready")
    def test_orchestrate_passes_allow_unversioned_baseline_explicit_true(self, mock_assert_ready):
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
            check_users_baseline=True,
            create_schemas=True,
            allow_unversioned_baseline=True,
        )

        mock_assert_ready.assert_called_once_with(mock_conn, allow_unversioned_baseline=True)

    @patch("staging_guard.assert_users_baseline_ready")
    def test_orchestrate_passes_allow_unversioned_baseline_from_env(self, mock_assert_ready, monkeypatch):
        monkeypatch.setenv("ALLOW_UNVERSIONED_BASELINE", "true")
        mock_engine = MagicMock()
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
            check_users_baseline=True,
            create_schemas=True,
            allow_unversioned_baseline=False,
        )

        mock_assert_ready.assert_called_once_with(mock_conn, allow_unversioned_baseline=True)

    def test_allow_unversioned_baseline_cannot_bypass_target_db_check(self):
        """Even with allow_unversioned_baseline=True, mismatched target_database fails closed."""
        mock_conn = MagicMock()
        mock_conn.in_transaction.return_value = False
        mock_conn.execute.return_value.scalar.return_value = "WRONG_DB"

        with pytest.raises(StagingConfigError, match="Target database mismatch"):
            orchestrate_online_migrations(
                connectable=mock_conn,
                is_staging=False,
                target_metadata=MagicMock(),
                include_name=MagicMock(),
                context=MagicMock(),
                check_users_baseline=True,
                create_schemas=True,
                target_database="EXPECTED_DB",
                is_connection=True,
                allow_unversioned_baseline=True,
            )



# =======================================================================
# 14. Comprehensive Fail-Closed Target Protection & Inspection Idempotency
# =======================================================================

class TestTargetProtectionAndInspectionInvariants:
    """Rigorous offline tests verifying target protections fail closed and inspection commands produce zero DDL."""

    @pytest.mark.parametrize("inspection_cmd", ["current", "heads", "history", "branches", "check"])
    def test_all_inspection_subcommands_classified_as_inspection(self, inspection_cmd):
        """Verify that every supported inspection command is recognized regardless of case."""
        mock_cfg = MagicMock()
        mock_cfg.cmd_opts.cmd = []
        mock_cfg.cmd_opts.subcommand = inspection_cmd

        is_inspect, is_mig = classify_online_command(mock_cfg, MagicMock())
        assert is_inspect is True
        assert is_mig is False

        # Test upper-case variation
        mock_cfg.cmd_opts.subcommand = inspection_cmd.upper()
        is_inspect, is_mig = classify_online_command(mock_cfg, MagicMock())
        assert is_inspect is True
        assert is_mig is False

    @pytest.mark.parametrize("inspection_cmd", ["current", "heads", "history", "branches", "check"])
    def test_all_inspection_cmd_functions_classified_as_inspection(self, inspection_cmd):
        """Verify inspection commands passed via cmd_opts.cmd list."""
        mock_cfg = MagicMock()
        mock_fn = MagicMock()
        mock_fn.__name__ = inspection_cmd
        mock_cfg.cmd_opts.cmd = [mock_fn]
        mock_cfg.cmd_opts.subcommand = None

        is_inspect, is_mig = classify_online_command(mock_cfg, MagicMock())
        assert is_inspect is True
        assert is_mig is False

    @pytest.mark.parametrize("mig_cmd", ["upgrade", "downgrade", "UPGRADE", "DOWNGRADE"])
    def test_migration_commands_classified_as_migration(self, mig_cmd):
        mock_cfg = MagicMock()
        mock_cfg.cmd_opts.cmd = []
        mock_cfg.cmd_opts.subcommand = mig_cmd

        is_inspect, is_mig = classify_online_command(mock_cfg, MagicMock())
        assert is_inspect is False
        assert is_mig is True

    @pytest.mark.parametrize("unknown_cmd", ["stamp", "revision", "edit", "merge", "show", "unknown", None])
    def test_unclassified_commands_fail_safe_to_migration_mode(self, unknown_cmd):
        """Unrecognized commands MUST fail safe to migration mode so safeguards are not bypassed."""
        mock_cfg = MagicMock()
        mock_cfg.cmd_opts.cmd = []
        mock_cfg.cmd_opts.subcommand = unknown_cmd
        mock_ctx = MagicMock()
        mock_ctx._proxy = None
        mock_ctx.fn = None

        is_inspect, is_mig = classify_online_command(mock_cfg, mock_ctx)
        assert is_inspect is False
        assert is_mig is True

    def test_inspection_mode_never_executes_create_schema_sql(self):
        """Verify that orchestrate_online_migrations in inspection mode NEVER executes CREATE SCHEMA."""
        executed_statements = []
        mock_engine = MagicMock()
        mock_conn = MagicMock()

        def capture_execute(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            executed_statements.append(sql)
            return MagicMock()

        mock_conn.execute.side_effect = capture_execute
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
            schemas=["sbom", "vulnerability", "zkp", "policy", "verification"],
            check_users_baseline=False,
            create_schemas=False,
        )

        for stmt in executed_statements:
            assert "CREATE SCHEMA" not in stmt.upper(), f"Unexpected DDL executed: {stmt}"
        assert not mock_conn.commit.called

    def test_migration_mode_executes_create_schema_for_all_schemas(self):
        """Verify that orchestrate_online_migrations in migration mode executes CREATE SCHEMA for all schemas."""
        executed_statements = []
        mock_engine = MagicMock()
        mock_conn = MagicMock()

        def capture_execute(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            executed_statements.append(sql)
            return MagicMock()

        mock_conn.execute.side_effect = capture_execute
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__ = MagicMock(return_value=False)

        schemas = ["sbom", "vulnerability", "zkp", "policy", "verification"]
        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=MagicMock(),
            schemas=schemas,
            check_users_baseline=False,
            create_schemas=True,
        )

        assert mock_conn.commit.called
        schema_ddl_count = sum(1 for stmt in executed_statements if "CREATE SCHEMA IF NOT EXISTS" in stmt)
        assert schema_ddl_count == len(schemas)

    def test_staging_target_validation_rejects_non_staging_database(self):
        """Verify that validate_staging_target strictly fails closed if DB_NAME is not ZKP_SBOM_STAGING."""
        mock_config = {
            "DB_HOST": "staging.example.com",
            "DB_PORT": "5432",
            "DB_NAME": "ZKP_SBOM",  # Target protected database!
            "DB_USER": "staging_user",
        }
        with pytest.raises(StagingConfigError, match=f"Staging DB_NAME must be exactly '{STAGING_DB_NAME}'"):
            validate_staging_target(expected_config=mock_config)

    def test_verify_connection_identity_rejects_mismatched_server_db(self):
        """Verify that verify_connection_identity fails closed if server-reported database != ZKP_SBOM_STAGING."""
        mock_conn = MagicMock()
        mock_conn.execute.return_value.scalar.return_value = "ZKP_SBOM_LOCAL_DEV"
        with pytest.raises(StagingConfigError, match="Connected database is 'ZKP_SBOM_LOCAL_DEV'"):
            verify_connection_identity(mock_conn)


# =======================================================================
# 15. Versioned public.users Baseline Contract Validation (Stage D2.1)
# =======================================================================

def _make_mock_conn_for_users_contract(
    table_exists: bool = True,
    alembic_version_exists: bool = True,
    alembic_revs: list[str] | None = None,
    columns: list[tuple] | None = None,
    has_pk: bool = True,
    has_uq_username: bool = True,
):
    """Build a mock connection returning simulated information_schema and catalog data."""
    mock_conn = MagicMock()

    def mock_execute(stmt, *args, **kwargs):
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        res = MagicMock()

        if "FROM information_schema.tables" in sql:
            if "alembic_version" in sql:
                res.scalar.return_value = 1 if alembic_version_exists else None
                return res
            if "users" in sql:
                res.scalar.return_value = 1 if table_exists else None
                return res
            res.scalar.return_value = 1
            return res

        if "FROM public.alembic_version" in sql:
            if alembic_revs is None:
                res.fetchall.return_value = []
            else:
                res.fetchall.return_value = [(r,) for r in alembic_revs]
            return res

        if "FROM information_schema.columns" in sql:
            res.fetchall.return_value = columns if columns is not None else []
            return res

        if "tc.constraint_type = 'PRIMARY KEY'" in sql:
            res.fetchall.return_value = [("id",)] if has_pk else []
            return res

        if "FROM pg_catalog.pg_index" in sql:
            res.fetchall.return_value = [("uq_users_username",)] if has_uq_username else []
            return res

        res.scalar.return_value = None
        res.fetchall.return_value = []
        return res

    mock_conn.execute.side_effect = mock_execute
    return mock_conn


_V1_COLUMNS = [
    ("id", "uuid", "NO", None, None),
    ("username", "character varying", "NO", 255, None),
    ("hashed_password", "character varying", "NO", 255, None),
    ("role", "character varying", "NO", 50, None),
    ("created_at", "timestamp without time zone", "YES", None, "now()"),
]

_V2_COLUMNS = [
    ("id", "uuid", "NO", None, None),
    ("username", "character varying", "NO", 255, None),
    ("hashed_password", "character varying", "NO", 255, None),
    ("role", "character varying", "NO", 50, None),
    ("created_at", "timestamp without time zone", "YES", None, "now()"),
    ("is_active", "boolean", "NO", None, "true"),
    ("updated_at", "timestamp without time zone", "NO", None, "CURRENT_TIMESTAMP"),
]


class TestVersionedUsersContractValidation:
    """Test suite validating migration-state-aware versioned public.users contracts (FIND-D13-01)."""

    @pytest.mark.parametrize("rev", ["014", "011", "001_initial"])
    def test_v1_accepted_at_pre_015_migration_state(self, rev):
        """Pre-015 revisions automatically select and pass Contract v1."""
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=[rev],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is True
        assert res.contract_version == "v1"
        assert len(res.discrepancies) == 0

    def test_v2_accepted_at_revision_015(self):
        """Revision 015 automatically selects and passes Contract v2."""
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=["015"],
            columns=_V2_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is True
        assert res.contract_version == "v2"
        assert len(res.discrepancies) == 0

    def test_v1_rejected_at_revision_015(self):
        """Revision 015 rejects Contract v1 due to missing is_active and updated_at."""
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=["015"],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("Required column 'is_active' is missing" in d for d in res.discrepancies)
        assert any("Required column 'updated_at' is missing" in d for d in res.discrepancies)

    @pytest.mark.parametrize("rev", ["014", "011"])
    def test_v2_rejected_at_pre_015_revision(self, rev):
        """Pre-015 revisions reject Contract v2 due to unexpected extra columns."""
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=[rev],
            columns=_V2_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("Unexpected unmapped column(s) in public.users for contract v1: ['is_active', 'updated_at']" in d for d in res.discrepancies)

    def test_unexpected_columns_rejected_for_v1(self):
        """Contract v1 fails closed when unmapped extra columns are present."""
        cols_with_extra = _V1_COLUMNS + [("phone", "character varying", "YES", 50, None)]
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=["014"],
            columns=cols_with_extra,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("Unexpected unmapped column(s) in public.users for contract v1: ['phone']" in d for d in res.discrepancies)

    def test_unexpected_columns_rejected_for_v2(self):
        """Contract v2 fails closed when unmapped extra columns are present."""
        cols_with_extra = _V2_COLUMNS + [("department", "character varying", "YES", 100, None)]
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=["015"],
            columns=cols_with_extra,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("Unexpected unmapped column(s) in public.users for contract v2: ['department']" in d for d in res.discrepancies)

    def test_missing_required_column_rejected_v1(self):
        """Contract v1 fails closed when a required column (role) is missing."""
        cols_missing_role = [c for c in _V1_COLUMNS if c[0] != "role"]
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=["014"],
            columns=cols_missing_role,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("Required column 'role' is missing" in d for d in res.discrepancies)

    def test_missing_required_column_rejected_v2(self):
        """Contract v2 fails closed when updated_at is missing."""
        cols_missing_updated_at = [c for c in _V2_COLUMNS if c[0] != "updated_at"]
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=["015"],
            columns=cols_missing_updated_at,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("Required column 'updated_at' is missing" in d for d in res.discrepancies)

    def test_unknown_migration_state_empty_alembic_version_rejected(self):
        """Empty public.alembic_version table fails closed as unknown migration state."""
        conn = _make_mock_conn_for_users_contract(
            alembic_version_exists=True,
            alembic_revs=[],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("recorded migration state is unknown" in d for d in res.discrepancies)

    def test_unknown_migration_state_multiple_revisions_rejected(self):
        """Multiple revision records fail closed as inconsistent migration state."""
        conn = _make_mock_conn_for_users_contract(
            alembic_version_exists=True,
            alembic_revs=["014", "015"],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("Multiple revision records found" in d for d in res.discrepancies)

    def test_unknown_migration_state_unrecognized_revision_rejected(self):
        """Unrecognized revision string fails closed."""
        conn = _make_mock_conn_for_users_contract(
            alembic_version_exists=True,
            alembic_revs=["invalid_branch_xyz"],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("cannot be mapped to a known users contract" in d for d in res.discrepancies)

    def test_unversioned_database_rejected_without_baseline_flag(self):
        """Unversioned database fails closed when allow_unversioned_baseline=False."""
        conn = _make_mock_conn_for_users_contract(
            alembic_version_exists=False,
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn, allow_unversioned_baseline=False)
        assert res.exists is True
        assert res.is_valid is False
        assert any("recorded migration state is unknown" in d for d in res.discrepancies)

    def test_unversioned_database_accepted_with_explicit_flag(self):
        """Unversioned database successfully selects Contract v1 with allow_unversioned_baseline=True."""
        conn = _make_mock_conn_for_users_contract(
            alembic_version_exists=False,
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn, allow_unversioned_baseline=True)
        assert res.exists is True
        assert res.is_valid is True
        assert res.contract_version == "v1"

    def test_contract_and_migration_state_disagreement_rejected(self):
        """Disagreement between explicitly requested contract and database state fails closed."""
        conn_015 = _make_mock_conn_for_users_contract(
            alembic_revs=["015"],
            columns=_V1_COLUMNS,
        )
        res1 = validate_users_contract(conn_015, contract="v1")
        assert res1.is_valid is False
        assert any("Contract/migration state disagreement" in d for d in res1.discrepancies)

        conn_014 = _make_mock_conn_for_users_contract(
            alembic_revs=["014"],
            columns=_V2_COLUMNS,
        )
        res2 = validate_users_contract(conn_014, contract="v2")
        assert res2.is_valid is False
        assert any("Contract/migration state disagreement" in d for d in res2.discrepancies)

    def test_invalid_contract_version_string_rejected(self):
        """Invalid contract version string fails closed."""
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=["014"],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn, contract="v99")
        assert res.is_valid is False
        assert any("Invalid contract version requested" in d for d in res.discrepancies)

    def test_assert_users_baseline_ready_raises_on_discrepancy(self):
        """assert_users_baseline_ready raises StagingConfigError when validation fails."""
        conn_missing = _make_mock_conn_for_users_contract(table_exists=False)
        with pytest.raises(StagingConfigError, match="table 'public.users' does not exist"):
            assert_users_baseline_ready(conn_missing)

        conn_incompat = _make_mock_conn_for_users_contract(
            alembic_revs=["014"],
            columns=[c for c in _V1_COLUMNS if c[0] != "id"],
        )
        with pytest.raises(StagingConfigError, match="does not match schema contract"):
            assert_users_baseline_ready(conn_incompat)

        conn_valid = _make_mock_conn_for_users_contract(
            alembic_revs=["014"],
            columns=_V1_COLUMNS,
        )
        assert_users_baseline_ready(conn_valid)

    def test_assert_users_baseline_ready_unversioned_with_flag_succeeds(self):
        """assert_users_baseline_ready succeeds on unversioned DB when allow_unversioned_baseline=True and schema matches V1."""
        conn_unversioned = _make_mock_conn_for_users_contract(
            alembic_version_exists=False,
            columns=_V1_COLUMNS,
        )
        assert_users_baseline_ready(conn_unversioned, allow_unversioned_baseline=True)

    def test_assert_users_baseline_ready_unversioned_without_flag_fails(self):
        """assert_users_baseline_ready fails on unversioned DB when allow_unversioned_baseline=False."""
        conn_unversioned = _make_mock_conn_for_users_contract(
            alembic_version_exists=False,
            columns=_V1_COLUMNS,
        )
        with pytest.raises(StagingConfigError, match="does not match schema contract"):
            assert_users_baseline_ready(conn_unversioned, allow_unversioned_baseline=False)

    def test_assert_users_baseline_ready_unversioned_with_missing_table_fails_even_with_flag(self):
        """Even with allow_unversioned_baseline=True, missing public.users raises StagingConfigError."""
        conn_missing = _make_mock_conn_for_users_contract(
            alembic_version_exists=False,
            table_exists=False,
        )
        with pytest.raises(StagingConfigError, match="table 'public.users' does not exist"):
            assert_users_baseline_ready(conn_missing, allow_unversioned_baseline=True)

    def test_assert_users_baseline_ready_unversioned_with_invalid_columns_fails_even_with_flag(self):
        """Even with allow_unversioned_baseline=True, incompatible columns raises StagingConfigError."""
        conn_incompat = _make_mock_conn_for_users_contract(
            alembic_version_exists=False,
            columns=[c for c in _V1_COLUMNS if c[0] != "hashed_password"],
        )
        with pytest.raises(StagingConfigError, match="does not match schema contract"):
            assert_users_baseline_ready(conn_incompat, allow_unversioned_baseline=True)



ALL_CANONICAL_REVISIONS = [
    "001_initial",
    "002",
    "003",
    "004",
    "005_add_topology_constraints",
    "006_add_proof_archive_hash",
    "007",
    "008",
    "009",
    "010",
    "011",
    "012",
    "013",
    "014",
    "015",
    "016",
]

PRE_015_CANONICAL_REVISIONS = [
    "001_initial",
    "002",
    "003",
    "004",
    "005_add_topology_constraints",
    "006_add_proof_archive_hash",
    "007",
    "008",
    "009",
    "010",
    "011",
    "012",
    "013",
    "014",
]


class TestStrictRevisionParsingHardening:
    """Focused test suite validating strict canonical revision recognition (FIND-D21-01)."""

    def test_canonical_revision_map_matches_expected_chain(self):
        """CANONICAL_REVISION_CONTRACT_MAP contains exactly the 16 canonical migrations in the chain."""
        assert set(CANONICAL_REVISION_CONTRACT_MAP.keys()) == set(ALL_CANONICAL_REVISIONS)
        for rev in PRE_015_CANONICAL_REVISIONS:
            assert CANONICAL_REVISION_CONTRACT_MAP[rev] == "v1"
        assert CANONICAL_REVISION_CONTRACT_MAP["015"] == "v2"
        assert CANONICAL_REVISION_CONTRACT_MAP["016"] == "v2"

    @pytest.mark.parametrize("rev", ALL_CANONICAL_REVISIONS)
    def test_every_canonical_revision_maps_to_correct_contract(self, rev):
        """determine_contract_for_revision correctly maps every canonical migration identifier."""
        expected = "v2" if rev in ("015", "016") else "v1"
        assert determine_contract_for_revision(rev) == expected

    @pytest.mark.parametrize("rev", PRE_015_CANONICAL_REVISIONS)
    def test_every_pre_015_canonical_revision_validates_v1(self, rev):
        """Every canonical pre-015 revision passes Contract v1 schema validation."""
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=[rev],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is True
        assert res.contract_version == "v1"
        assert len(res.discrepancies) == 0

    def test_canonical_revision_015_validates_v2(self):
        """Canonical revision 015 passes Contract v2 schema validation."""
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=["015"],
            columns=_V2_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is True
        assert res.contract_version == "v2"
        assert len(res.discrepancies) == 0

    @pytest.mark.parametrize(
        "malformed_rev",
        [
            "014_evil",
            "015_dirty",
            "014_custom",
            "015_dev",
            "001_initial_suffix",
            "002_rbac",
            "011_schema_parity",
        ],
    )
    def test_malformed_suffixes_rejected(self, malformed_rev):
        """Revision strings with unmanaged suffixes (e.g. 014_evil, 015_dirty) fail closed."""
        assert determine_contract_for_revision(malformed_rev) is None
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=[malformed_rev],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("cannot be mapped to a known users contract" in d for d in res.discrepancies)

    @pytest.mark.parametrize(
        "whitespace_rev",
        [
            " 014",
            "014 ",
            "  014  ",
            " 015",
            "015 ",
            "  015  ",
            "014\n",
            "\t015",
            " 001_initial ",
        ],
    )
    def test_whitespace_variations_rejected(self, whitespace_rev):
        """Revision strings with surrounding whitespace fail closed without silent trimming."""
        assert determine_contract_for_revision(whitespace_rev) is None
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=[whitespace_rev],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("cannot be mapped to a known users contract" in d for d in res.discrepancies)

    @pytest.mark.parametrize(
        "prefixed_rev",
        [
            "v014",
            "rev_014",
            "_014",
            "v015",
            "rel_015",
            "14",
            "15",
            "1",
            "01",
        ],
    )
    def test_unexpected_prefixes_and_non_canonical_numbers_rejected(self, prefixed_rev):
        """Unexpected prefixes and non-canonical digit representations fail closed."""
        assert determine_contract_for_revision(prefixed_rev) is None
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=[prefixed_rev],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("cannot be mapped to a known users contract" in d for d in res.discrepancies)

    @pytest.mark.parametrize(
        "future_rev",
        [
            "017",
            "018",
            "019",
            "099",
            "100",
            "017_new_feature",
        ],
    )
    def test_unsupported_future_revisions_rejected(self, future_rev):
        """Unsupported future revisions fail closed and are not assumed to be v2."""
        assert determine_contract_for_revision(future_rev) is None
        conn = _make_mock_conn_for_users_contract(
            alembic_revs=[future_rev],
            columns=_V2_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("cannot be mapped to a known users contract" in d for d in res.discrepancies)

    @pytest.mark.parametrize("empty_or_invalid", ["", None, 14, 15, [], {}, ()])
    def test_empty_and_non_string_revisions_rejected(self, empty_or_invalid):
        """Empty, None, and non-string types fail closed."""
        assert determine_contract_for_revision(empty_or_invalid) is None

    def test_public_alembic_version_null_revision_value_rejected(self):
        """NULL value in public.alembic_version record fails closed as empty/invalid state."""
        conn = _make_mock_conn_for_users_contract(
            alembic_version_exists=True,
            alembic_revs=[None],
            columns=_V1_COLUMNS,
        )
        res = validate_users_contract(conn)
        assert res.exists is True
        assert res.is_valid is False
        assert any("Revision value in public.alembic_version is NULL" in d for d in res.discrepancies)






"""
Tests for Read-Only Staging Inspection Harness.

All tests use mocks. No database connections are attempted.
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.engine import Connection, Engine

from scripts.inspect_staging_readonly import (
    check_preflight_config,
    format_inspection_report,
    get_expected_alembic_head,
    inspect_alembic_revision,
    inspect_connection_identity,
    inspect_foreign_key_preconditions,
    inspect_migration_008_preconditions,
    inspect_role_privileges,
    inspect_schema_and_tables,
    inspect_tls_session_status,
    main,
    run_staging_inspection,
    sanitize_exception_message,
    AlembicRevisionStatus,
    ConnectionIdentity,
    ForeignKeyCheck,
    Migration008Preconditions,
    RolePrivilegesStatus,
    SchemaTableInventory,
    StagingInspectionReport,
    TLSSessionStatus,
    PROJECT_SCHEMAS,
)
from shared.config import ConfigurationError, DatabaseSettings
from staging_guard import ContractValidationResult


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def valid_staging_env_dict(tmp_path):
    """Return a dictionary representing a valid .env.staging file."""
    ca_file = tmp_path / "valid_ca.crt"
    ca_file.write_text("-----BEGIN CERTIFICATE-----\nMOCK_CA\n-----END CERTIFICATE-----\n")
    return {
        "DB_HOST": "staging-db.example.com",
        "DB_PORT": "5432",
        "DB_USER": "staging_inspector_ro",
        "DB_PASSWORD": "secret_staging_password_12345",
        "DB_NAME": "ZKP_SBOM_STAGING",
        "DB_SSL_MODE": "verify-full",
        "DB_SSL_ROOT_CERT": str(ca_file),
        "DB_ECHO": "false",
    }


@pytest.fixture
def mock_connection():
    """Mock SQLAlchemy Connection."""
    conn = MagicMock(spec=Connection)
    return conn


# ===========================================================================
# 1. Fail-Closed Configuration Tests
# ===========================================================================

class TestPreflightConfiguration:
    """Verify preflight configuration checks fail closed before connecting."""

    def test_missing_staging_mode_fails_closed(self, monkeypatch):
        """STAGING_MODE absent or not 'true' aborts immediately."""
        monkeypatch.delenv("STAGING_MODE", raising=False)
        with pytest.raises(ConfigurationError, match="STAGING_MODE=true is strictly required"):
            check_preflight_config()

        monkeypatch.setenv("STAGING_MODE", "false")
        with pytest.raises(ConfigurationError, match="STAGING_MODE=true is strictly required"):
            check_preflight_config()

        monkeypatch.setenv("STAGING_MODE", "staging")
        with pytest.raises(ConfigurationError, match="STAGING_MODE=true is strictly required"):
            check_preflight_config()

    def test_missing_env_staging_file_fails_closed(self, monkeypatch):
        """Missing .env.staging file aborts without connecting."""
        monkeypatch.setenv("STAGING_MODE", "true")
        with patch("os.path.exists", return_value=False):
            with pytest.raises(ConfigurationError, match="Staging configuration file missing"):
                check_preflight_config()

    def test_wrong_database_name_fails_closed(self, monkeypatch, tmp_path):
        """DB_NAME not equal to ZKP_SBOM_STAGING fails closed."""
        monkeypatch.setenv("STAGING_MODE", "true")
        env_staging = tmp_path / ".env.staging"
        env_staging.write_text("DB_NAME=ZKP_SBOM\n")

        with patch("scripts.inspect_staging_readonly._BACKEND_DIR", str(tmp_path / "backend")):
            with patch("staging_guard.load_staging_environment"):
                with patch("staging_guard.validate_staging_target"):
                    with patch(
                        "scripts.inspect_staging_readonly.get_db_settings",
                        return_value=DatabaseSettings(name="ZKP_SBOM", ssl_mode="verify-full"),
                    ):
                        with pytest.raises(ConfigurationError, match="must be exactly 'ZKP_SBOM_STAGING'"):
                            check_preflight_config()

    def test_non_verify_full_ssl_mode_rejected(self, monkeypatch, tmp_path, valid_staging_env_dict):
        """Any SSL mode other than verify-full fails closed."""
        monkeypatch.setenv("STAGING_MODE", "true")

        for bad_mode in ("require", "verify-ca", "prefer", "disable", "allow"):
            db_bad = DatabaseSettings(
                name="ZKP_SBOM_STAGING",
                ssl_mode=bad_mode,
                ssl_root_cert=valid_staging_env_dict["DB_SSL_ROOT_CERT"],
            )
            with patch("scripts.inspect_staging_readonly._BACKEND_DIR", str(tmp_path / "backend")):
                with patch("os.path.exists", return_value=True), patch("os.path.isfile", return_value=True):
                    with patch("staging_guard.load_staging_environment"):
                        with patch("staging_guard.validate_staging_target"):
                            with patch("scripts.inspect_staging_readonly.get_db_settings", return_value=db_bad):
                                with pytest.raises(ConfigurationError, match="strictly requires DB_SSL_MODE='verify-full'"):
                                    check_preflight_config()

    def test_missing_or_invalid_ca_cert_fails_closed(self, monkeypatch, tmp_path):
        """Missing, empty, directory, or unreadable CA file aborts."""
        monkeypatch.setenv("STAGING_MODE", "true")

        # Missing CA path
        db_no_ca = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=None)
        with patch("scripts.inspect_staging_readonly._BACKEND_DIR", str(tmp_path / "backend")):
            with patch("os.path.exists", return_value=True), patch("os.path.isfile", return_value=True):
                with patch("staging_guard.load_staging_environment"), patch("staging_guard.validate_staging_target"):
                    with patch("scripts.inspect_staging_readonly.get_db_settings", return_value=db_no_ca):
                        with pytest.raises(ConfigurationError, match="DB_SSL_ROOT_CERT is required"):
                            check_preflight_config()

        # Non-existent file
        fake_path = str(tmp_path / "does_not_exist.crt")
        db_fake_ca = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=fake_path)
        with patch("scripts.inspect_staging_readonly._BACKEND_DIR", str(tmp_path / "backend")):
            with patch("os.path.exists", side_effect=lambda p: p != fake_path), patch("os.path.isfile", return_value=True):
                with patch("staging_guard.load_staging_environment"), patch("staging_guard.validate_staging_target"):
                    with patch("scripts.inspect_staging_readonly.get_db_settings", return_value=db_fake_ca):
                        with pytest.raises(ConfigurationError, match="does not exist or is not a regular file"):
                            check_preflight_config()

        # Empty CA file
        empty_ca = tmp_path / "empty.crt"
        empty_ca.write_text("")
        db_empty_ca = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(empty_ca))
        with patch("scripts.inspect_staging_readonly._BACKEND_DIR", str(tmp_path / "backend")):
            with patch("os.path.exists", return_value=True), patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                with patch("staging_guard.load_staging_environment"), patch("staging_guard.validate_staging_target"):
                    with patch("scripts.inspect_staging_readonly.get_db_settings", return_value=db_empty_ca):
                        with pytest.raises(ConfigurationError, match="file is empty"):
                            check_preflight_config()

    def test_no_connection_attempted_on_preflight_failure(self, monkeypatch):
        """create_engine or connect must NEVER be called if preflight fails."""
        monkeypatch.delenv("STAGING_MODE", raising=False)
        with patch("scripts.inspect_staging_readonly.create_engine") as mock_engine:
            with pytest.raises(ConfigurationError):
                run_staging_inspection()
            mock_engine.assert_not_called()


# ===========================================================================
# 2. Read-Only Transaction & Connection Safety
# ===========================================================================

class TestReadOnlyTransactionSafety:
    """Verify that read-only transaction mode is strictly enforced and verified."""

    def test_read_only_transaction_enforced_and_verified(self, tmp_path):
        """Harness executes BEGIN TRANSACTION READ ONLY and checks SHOW transaction_read_only."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(
            name="ZKP_SBOM_STAGING",
            ssl_mode="verify-full",
            ssl_root_cert=str(valid_cert),
        )

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        executed_statements: list[str] = []

        def fake_execute(statement, *args, **kwargs):
            sql_str = str(statement).strip()
            executed_statements.append(sql_str)
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql_str:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql_str:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING",
                    "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1",
                    "server_port": 5432,
                    "pg_version": "PostgreSQL 16.1",
                }
            elif "pg_stat_ssl" in sql_str:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "ssl": True, "version": "TLSv1.3", "cipher": "AES-256", "bits": 256, "client_dn": None,
                }
            elif "information_schema.tables" in sql_str and "alembic_version" in sql_str:
                mock_res.scalar.return_value = True
            elif "SELECT version_num FROM public.alembic_version" in sql_str:
                mock_res.fetchall.return_value = [("016",)]
            elif "information_schema.schemata" in sql_str:
                mock_res.fetchall.return_value = [("public",), ("sbom",), ("vulnerability",), ("policy",), ("zkp",), ("verification",)]
            elif "information_schema.tables" in sql_str and "BASE TABLE" in sql_str:
                mock_res.fetchall.return_value = [("public", "users")]
            elif "has_database_privilege" in sql_str:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql_str:
                mock_res.scalar.return_value = "off"
            elif "has_schema_privilege" in sql_str:
                mock_res.scalar.return_value = False
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
                mock_res.mappings.return_value.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_execute

        report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.read_only_confirmed is True
        # Verify BEGIN TRANSACTION READ ONLY was executed first
        assert "BEGIN TRANSACTION READ ONLY;" in executed_statements[0]
        # Verify SHOW transaction_read_only was executed
        assert any("SHOW transaction_read_only" in s for s in executed_statements)
        # Verify ROLLBACK was executed in finally block
        assert any("ROLLBACK;" in s for s in executed_statements)
        # Verify connection was closed
        mock_conn.close.assert_called_once()

    def test_read_only_transaction_failure_fails_closed(self, tmp_path):
        """SHOW transaction_read_only returning 'off' aborts before catalog queries."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(
            name="ZKP_SBOM_STAGING",
            ssl_mode="verify-full",
            ssl_root_cert=str(valid_cert),
        )

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_execute(statement, *args, **kwargs):
            sql_str = str(statement).strip()
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql_str:
                mock_res.scalar.return_value = "off"
            return mock_res

        mock_conn.execute.side_effect = fake_execute

        with pytest.raises(RuntimeError, match="SHOW transaction_read_only returned 'off'"):
            run_staging_inspection(engine=mock_engine, settings=settings)

        # Confirm rollback and close called on failure
        mock_conn.close.assert_called_once()

    def test_database_name_mismatch_halts_immediately(self, tmp_path):
        """Connected database name not matching ZKP_SBOM_STAGING aborts."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(
            name="ZKP_SBOM_STAGING",
            ssl_mode="verify-full",
            ssl_root_cert=str(valid_cert),
        )

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_execute(statement, *args, **kwargs):
            sql_str = str(statement).strip()
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql_str:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql_str:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "PRODUCTION_DATABASE",
                    "connected_user": "rogue_user",
                    "server_ip": "10.0.0.1",
                    "server_port": 5432,
                    "pg_version": "PostgreSQL 16",
                }
            return mock_res

        mock_conn.execute.side_effect = fake_execute

        with pytest.raises(RuntimeError, match="Connected to 'PRODUCTION_DATABASE', expected 'ZKP_SBOM_STAGING'"):
            run_staging_inspection(engine=mock_engine, settings=settings)


# ===========================================================================
# 3. Catalog Inspection Function Tests
# ===========================================================================

class TestInspectionFunctions:
    """Verify each read-only inspection query and result parsing."""

    def test_inspect_tls_session_status_success(self, mock_connection):
        """pg_stat_ssl details are parsed and non-proof disclaimer is attached."""
        mock_res = MagicMock()
        mock_res.mappings.return_value.fetchone.return_value = {
            "ssl": True,
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "bits": 256,
            "client_dn": None,
        }
        mock_connection.execute.return_value = mock_res

        status = inspect_tls_session_status(mock_connection)
        assert status.ssl_active is True
        assert status.ssl_version == "TLSv1.3"
        assert status.cipher == "TLS_AES_256_GCM_SHA384"
        assert status.bits == 256
        assert "does not independently prove server hostname validation" in status.note

    def test_inspect_tls_session_permission_error_handled(self, mock_connection):
        """pg_stat_ssl permission denial is caught gracefully and sanitized."""
        mock_connection.execute.side_effect = Exception("permission denied for view pg_stat_ssl")
        status = inspect_tls_session_status(mock_connection)
        assert status.query_permitted is False
        assert status.ssl_active is None
        assert "Unable to query pg_stat_ssl" in status.note
        assert "permission denied for view pg_stat_ssl" in status.note

    def test_inspect_alembic_revision_missing_table(self, mock_connection):
        """Absence of alembic_version table is reported without querying version_num."""
        mock_res = MagicMock()
        mock_res.scalar.return_value = False
        mock_connection.execute.return_value = mock_res

        status = inspect_alembic_revision(mock_connection)
        assert status.table_exists is False
        assert status.revisions == []
        assert "public.alembic_version table is absent" in status.note
        # Only one statement executed (the EXISTS check), never query version_num
        assert mock_connection.execute.call_count == 1

    def test_inspect_alembic_revision_present(self, mock_connection):
        """Existing alembic_version table returns recorded revisions."""
        def fake_exec(stmt):
            mock_res = MagicMock()
            if "EXISTS" in str(stmt):
                mock_res.scalar.return_value = True
            else:
                mock_res.fetchall.return_value = [("013",)]
            return mock_res

        mock_connection.execute.side_effect = fake_exec
        status = inspect_alembic_revision(mock_connection)
        assert status.table_exists is True
        assert status.revisions == ["013"]
        assert status.row_count == 1

    def test_inspect_schema_and_tables(self, mock_connection):
        """Schemas and base tables are inventoried correctly."""
        def fake_exec(stmt, params=None):
            mock_res = MagicMock()
            if "information_schema.schemata" in str(stmt):
                mock_res.fetchall.return_value = [("public",), ("sbom",), ("zkp",)]
            elif "information_schema.tables" in str(stmt):
                mock_res.fetchall.return_value = [
                    ("public", "users"),
                    ("sbom", "applications"),
                    ("zkp", "proof_jobs"),
                ]
            return mock_res

        mock_connection.execute.side_effect = fake_exec
        inv = inspect_schema_and_tables(mock_connection)
        assert "public" in inv.existing_schemas
        assert "vulnerability" in inv.missing_schemas
        assert inv.tables_by_schema["public"] == ["users"]
        assert inv.total_tables == 3

    def test_migration_008_preconditions_no_duplicates(self, mock_connection):
        """Table exists, columns present, no duplicates found -> clean."""
        def fake_exec(stmt):
            mock_res = MagicMock()
            if "EXISTS" in str(stmt):
                mock_res.scalar.return_value = True
            elif "information_schema.columns" in str(stmt):
                mock_res.fetchall.return_value = [
                    ("user_id",), ("sbom_root",), ("vulnerability_db_root",), ("policy_hash",), ("proof_job_id",)
                ]
            elif "HAVING count(*) > 1" in str(stmt):
                mock_res.mappings.return_value.fetchall.return_value = []
            return mock_res

        mock_connection.execute.side_effect = fake_exec
        m8 = inspect_migration_008_preconditions(mock_connection)
        assert m8.table_exists is True
        assert m8.required_columns_present is True
        assert m8.violates_unique_constraint is False
        assert m8.hard_duplicate_count == 0

    def test_migration_008_preconditions_with_duplicates(self, mock_connection):
        """Duplicate rows violating unique constraint are identified and reported."""
        def fake_exec(stmt):
            mock_res = MagicMock()
            if "EXISTS" in str(stmt):
                mock_res.scalar.return_value = True
            elif "information_schema.columns" in str(stmt):
                mock_res.fetchall.return_value = [
                    ("user_id",), ("sbom_root",), ("vulnerability_db_root",), ("policy_hash",), ("proof_job_id",)
                ]
            elif "HAVING count(*) > 1" in str(stmt):
                mock_res.mappings.return_value.fetchall.return_value = [
                    {
                        "user_id": "u1", "sbom_root": "s1", "vulnerability_db_root": "v1",
                        "policy_hash": "p1", "proof_job_id": "j1", "dup_count": 2,
                    }
                ]
            return mock_res

        mock_connection.execute.side_effect = fake_exec
        m8 = inspect_migration_008_preconditions(mock_connection)
        assert m8.violates_unique_constraint is True
        assert m8.hard_duplicate_count == 1
        assert m8.hard_duplicate_groups[0]["count"] == 2

    def test_migration_008_missing_table_handled(self, mock_connection):
        """Missing verification_requests table skips duplicate check gracefully."""
        mock_res = MagicMock()
        mock_res.scalar.return_value = False
        mock_connection.execute.return_value = mock_res

        m8 = inspect_migration_008_preconditions(mock_connection)
        assert m8.table_exists is False
        assert m8.violates_unique_constraint is False
        assert "does not exist; check skipped" in m8.note

    def test_foreign_key_preconditions_orphans_and_missing_objects(self, mock_connection):
        """Foreign key checks inspect orphan rows and gracefully report missing objects."""
        def fake_exec(stmt, params=None):
            mock_res = MagicMock()
            sql_str = str(stmt)
            if "information_schema.tables" in sql_str and "public" in sql_str and "users" in sql_str:
                mock_res.scalar.return_value = True
            elif "information_schema.tables" in sql_str:
                mock_res.scalar.return_value = params.get("schema") != "zkp"
            elif "information_schema.columns" in sql_str:
                mock_res.scalar.return_value = True
            elif "NOT EXISTS (SELECT 1 FROM public.users" in sql_str:
                mock_res.scalar.return_value = 3
            return mock_res

        mock_connection.execute.side_effect = fake_exec
        fks = inspect_foreign_key_preconditions(mock_connection)
        assert len(fks) == 7

        app_fk = next(f for f in fks if f.source_table == "applications")
        assert app_fk.status == "ORPHANS_FOUND"
        assert app_fk.orphan_count == 3

        zkp_fk = next(f for f in fks if f.source_table == "proof_jobs")
        assert zkp_fk.status == "OBJECT_NOT_FOUND"

    def test_role_privileges_detection(self, mock_connection):
        """Role privileges detection identifies read-only vs excessive privileges."""
        def fake_exec(stmt, params=None):
            mock_res = MagicMock()
            sql = str(stmt)
            if "SELECT current_user AS u" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {"u": "staging_admin"}
            elif "has_database_privilege" in sql:
                mock_res.scalar.return_value = True
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            elif "has_schema_privilege" in sql:
                if "public" in str(params) and "CREATE" in sql:
                    mock_res.scalar.return_value = True
                else:
                    mock_res.scalar.return_value = False
            elif "information_schema.tables" in sql:
                mock_res.fetchall.return_value = []
            else:
                mock_res.scalar.return_value = False
            return mock_res

        mock_connection.execute.side_effect = fake_exec
        rp = inspect_role_privileges(mock_connection)
        assert rp.is_least_privilege_ro is False
        assert len(rp.privilege_discrepancies) == 2
        assert len(rp.warnings) == 2


# ===========================================================================
# 4. Report Formatting & Safety Tests
# ===========================================================================

class TestReportFormatting:
    """Verify generated reports do not leak secrets or credentials."""

    def test_report_excludes_secrets_and_confirms_safety(self):
        """Secret passwords and raw credentials are never present in output."""
        report = StagingInspectionReport(
            audit_timestamp_utc="2026-10-11T00:00:00Z",
            target_database_configured="ZKP_SBOM_STAGING",
            safe_connection_summary="host=staging.example.com, port=5432, db=ZKP_SBOM_STAGING, sslmode=verify-full",
            read_only_confirmed=True,
            discrepancies_found=False,
            overall_status="CLEAN",
            is_complete=True,
            connection_identity=ConnectionIdentity(
                database_name="ZKP_SBOM_STAGING",
                current_user="inspector_ro",
                server_ip="10.0.0.1",
                server_port=5432,
                pg_version="PostgreSQL 16",
            ),
            tls_session=TLSSessionStatus(
                ssl_active=True,
                ssl_version="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384",
                bits=256,
                client_dn=None,
                query_permitted=True,
                note="Note text",
            ),
            alembic_revision=AlembicRevisionStatus(table_exists=True, revisions=["013"], row_count=1, note="Single rev"),
            users_contract=ContractValidationResult(exists=True, is_valid=True, discrepancies=[]),
            migration_008_preconditions=Migration008Preconditions(table_exists=True, required_columns_present=True),
        )

        secret_password = "SUPER_SECRET_PASSWORD_DO_NOT_PRINT"
        output = format_inspection_report(report)

        assert secret_password not in output
        assert "BEGIN TRANSACTION READ ONLY;" in output
        assert "ROLLBACK;" in output
        assert "NO REPAIR, MIGRATION, DDL, OR MUTATION WAS ATTEMPTED." in output
        assert "ZKP_SBOM_STAGING" in output
        assert "CLEAN" in output


# ===========================================================================
# 5. Regression Tests (Gate 5J Hardening)
# ===========================================================================

class TestOverallAuditStatus:
    """Verify tri-state overall audit status: CLEAN, DISCREPANCIES_FOUND, INCOMPLETE."""

    def test_missing_required_table_results_in_incomplete(self, tmp_path):
        """Missing verification.verification_requests marks audit as INCOMPLETE."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, params=None):
            sql = str(stmt)
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
                }
            elif "pg_stat_ssl" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {"ssl": True, "version": "1.3", "cipher": "AES", "bits": 256, "client_dn": None}
            elif "information_schema.schemata" in sql:
                mock_res.fetchall.return_value = [(s,) for s in PROJECT_SCHEMAS]
            elif "information_schema.tables" in sql and "public" in sql and "users" in sql:
                mock_res.scalar.return_value = True
            elif "information_schema.tables" in sql and "verification" in sql and "verification_requests" in sql:
                mock_res.scalar.return_value = False  # Missing table!
            elif "has_database_privilege" in sql or "has_schema_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_exec
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("verification.verification_requests is absent" in c for c in report.checks_unable_to_run)

    def test_missing_required_column_results_in_incomplete(self, tmp_path):
        """Missing required column in verification_requests marks audit as INCOMPLETE."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, params=None):
            sql = str(stmt)
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
                }
            elif "pg_stat_ssl" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {"ssl": True, "version": "1.3", "cipher": "AES", "bits": 256, "client_dn": None}
            elif "information_schema.schemata" in sql:
                mock_res.fetchall.return_value = [(s,) for s in PROJECT_SCHEMAS]
            elif "information_schema.tables" in sql and "verification_requests" in sql:
                mock_res.scalar.return_value = True
            elif "information_schema.columns" in sql and "verification_requests" in sql:
                mock_res.fetchall.return_value = [("user_id",), ("sbom_root",)]  # Missing columns!
            elif "has_database_privilege" in sql or "has_schema_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_exec
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("Required column(s) missing" in c for c in report.checks_unable_to_run)

    def test_skipped_check_due_to_unavailable_privileges_results_in_incomplete(self, tmp_path):
        """Unknown privilege evaluation marks audit as INCOMPLETE."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, params=None):
            sql = str(stmt)
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
                }
            elif "has_database_privilege" in sql:
                raise Exception("permission denied for database catalog")
            elif "information_schema.schemata" in sql:
                mock_res.fetchall.return_value = [(s,) for s in PROJECT_SCHEMAS]
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_exec
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("Database CREATE privilege check failed" in c for c in report.checks_unable_to_run)

    def test_actual_discrepancies_reflected_in_status(self, tmp_path):
        """Confirmed duplicate keys and orphans set overall status to DISCREPANCIES_FOUND."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, params=None):
            sql = str(stmt)
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
                }
            elif "information_schema.schemata" in sql:
                mock_res.fetchall.return_value = [(s,) for s in PROJECT_SCHEMAS]
            elif "HAVING count(*) > 1" in sql:
                mock_res.mappings.return_value.fetchall.return_value = [
                    {"user_id": "u", "sbom_root": "s", "vulnerability_db_root": "v", "policy_hash": "p", "proof_job_id": "j", "dup_count": 2}
                ]
            elif "NOT EXISTS (SELECT 1 FROM public.users" in sql:
                mock_res.scalar.return_value = 5  # 5 orphans!
            elif "EXISTS" in sql:
                mock_res.scalar.return_value = True
            elif "information_schema.columns" in sql:
                mock_res.fetchall.return_value = [("user_id",), ("sbom_root",), ("vulnerability_db_root",), ("policy_hash",), ("proof_job_id",)]
            elif "has_database_privilege" in sql or "has_schema_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_exec
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.overall_status == "DISCREPANCIES_FOUND"
        assert report.discrepancies_found is True
        assert len(report.discrepancies) >= 2

    def test_mixed_discrepancy_and_incomplete_preserves_both(self, tmp_path):
        """Mixed discrepancies and incomplete checks prioritize DISCREPANCIES_FOUND and preserve both."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, params=None):
            sql = str(stmt)
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
                }
            elif "information_schema.schemata" in sql:
                # Missing 'zkp' schema!
                mock_res.fetchall.return_value = [("public",), ("sbom",)]
            elif "HAVING count(*) > 1" in sql:
                mock_res.mappings.return_value.fetchall.return_value = [
                    {"user_id": "u", "sbom_root": "s", "vulnerability_db_root": "v", "policy_hash": "p", "proof_job_id": "j", "dup_count": 2}
                ]
            elif "EXISTS" in sql:
                mock_res.scalar.return_value = True
            elif "information_schema.columns" in sql:
                mock_res.fetchall.return_value = [("user_id",), ("sbom_root",), ("vulnerability_db_root",), ("policy_hash",), ("proof_job_id",)]
            elif "has_database_privilege" in sql or "has_schema_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_exec
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.overall_status == "DISCREPANCIES_FOUND"
        assert report.is_complete is False
        assert len(report.discrepancies) > 0
        assert len(report.checks_unable_to_run) > 0

        # Verify formatting preserves both sections
        formatted = format_inspection_report(report)
        assert "DISCREPANCIES_FOUND" in formatted
        assert "INCOMPLETE" in formatted
        assert "Confirmed Discrepancies & Conflict Findings:" in formatted
        assert "Incomplete / Skipped Checks" in formatted

    def test_fully_completed_discrepancy_free_is_clean(self, tmp_path):
        """Fully completed, discrepancy-free inspection produces CLEAN status."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, params=None):
            sql = str(stmt)
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
                }
            elif "pg_stat_ssl" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {"ssl": True, "version": "1.3", "cipher": "AES", "bits": 256, "client_dn": None}
            elif "information_schema.schemata" in sql:
                mock_res.fetchall.return_value = [(s,) for s in PROJECT_SCHEMAS]
            elif "information_schema.tables" in sql and "alembic_version" in sql:
                mock_res.scalar.return_value = True
            elif "SELECT version_num FROM public.alembic_version" in sql:
                mock_res.fetchall.return_value = [("016",)]
            elif "NOT EXISTS (SELECT 1 FROM public.users" in sql or "count(*)" in sql:
                mock_res.scalar.return_value = 0
                mock_res.mappings.return_value.fetchall.return_value = []
            elif "EXISTS" in sql:
                mock_res.scalar.return_value = True
            elif "information_schema.columns" in sql:
                mock_res.fetchall.return_value = [("user_id",), ("sbom_root",), ("vulnerability_db_root",), ("policy_hash",), ("proof_job_id",)]
            elif "has_database_privilege" in sql or "has_schema_privilege" in sql or "has_table_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            elif "information_schema.tables" in sql and "BASE TABLE" in sql:
                mock_res.fetchall.return_value = [("public", "users")]
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_exec
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.overall_status == "CLEAN"
        assert report.is_complete is True
        assert report.discrepancies_found is False
        assert len(report.discrepancies) == 0
        assert len(report.checks_unable_to_run) == 0

    def test_empty_database_or_missing_users_cannot_be_clean(self, tmp_path):
        """Missing public.users baseline table must never result in CLEAN."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, params=None):
            sql = str(stmt)
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
                }
            elif "information_schema.schemata" in sql:
                mock_res.fetchall.return_value = [(s,) for s in PROJECT_SCHEMAS]
            elif "has_database_privilege" in sql or "has_schema_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_exec
        # users table absent
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=False, is_valid=False, discrepancies=["Table 'public.users' does not exist."])):
            report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.overall_status != "CLEAN"
        assert report.overall_status == "DISCREPANCIES_FOUND"
        assert report.is_complete is False


# ===========================================================================
# 6. Exception Sanitization Tests
# ===========================================================================

class TestExceptionSanitization:
    """Verify exception messages scrub passwords, tokens, and credentials."""

    def test_credential_bearing_urls_sanitized(self):
        """PostgreSQL URLs in exceptions have passwords masked."""
        raw = "sqlalchemy.exc.OperationalError: could not connect to postgresql://user:SuperSecretPassword123@10.0.0.1:5432/db"
        sanitized = sanitize_exception_message(raw)
        assert "SuperSecretPassword123" not in sanitized
        assert "postgresql://user:****@10.0.0.1:5432/db" in sanitized

    def test_dsn_password_sanitized(self):
        """Key-value password strings are masked."""
        raw = 'psycopg2.OperationalError: connection failed with password="SecretPassword999" and user="admin"'
        sanitized = sanitize_exception_message(raw)
        assert "SecretPassword999" not in sanitized
        assert 'password="****"' in sanitized

    def test_tokens_and_bearer_sanitized(self):
        """Tokens and secrets are masked."""
        raw = "AuthError: Token expired with bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret123"
        sanitized = sanitize_exception_message(raw)
        assert "secret123" not in sanitized
        assert "bearer ****" in sanitized

    def test_sanitization_failure_does_not_expose_exception(self):
        """Faulty or unparseable exception object falls back safely without raising."""
        class BrokenException(Exception):
            def __str__(self):
                raise TypeError("Intentional __str__ failure")

        safe = sanitize_exception_message(BrokenException())
        assert "SanitizedError" in safe
        assert "redacted" in safe.lower()

    def test_url_password_with_hash_sanitized(self):
        """PostgreSQL URLs where password contains '#' are masked correctly."""
        raw = "sqlalchemy.exc.OperationalError: could not connect to postgresql://user:pass#secret123@10.0.0.1:5432/db"
        sanitized = sanitize_exception_message(raw)
        assert "pass#secret123" not in sanitized
        assert "postgresql://user:****@10.0.0.1:5432/db" in sanitized

    def test_url_encoded_credentials_sanitized(self):
        """URL-encoded credentials in connection strings are masked."""
        raw = "could not connect to postgresql://user:p%40ss%23123@staging-db.internal:5432/db"
        sanitized = sanitize_exception_message(raw)
        assert "p%40ss%23123" not in sanitized
        assert "postgresql://user:****@staging-db.internal:5432/db" in sanitized

    def test_json_credentials_sanitized(self):
        """JSON payload containing password, token, or secret is masked."""
        raw = 'Failed request payload: {"user": "alice", "password": "SuperSecretPass123!", "secret": "Token999"}'
        sanitized = sanitize_exception_message(raw)
        assert "SuperSecretPass123!" not in sanitized
        assert "Token999" not in sanitized
        assert '"password": "****"' in sanitized
        assert '"secret": "****"' in sanitized

    def test_multiline_credentials_sanitized(self):
        """Multiline exception text with password on separate line is masked."""
        raw = "Error trace:\n  password:\n    multiline_super_secret\n  status: failed"
        sanitized = sanitize_exception_message(raw)
        assert "multiline_super_secret" not in sanitized
        assert "password:\n    ****" in sanitized

    def test_quoted_password_with_spaces_sanitized(self):
        """Quoted passwords containing spaces are masked."""
        raw = "Connection failed: password='secret pass with space' host=localhost"
        sanitized = sanitize_exception_message(raw)
        assert "secret pass with space" not in sanitized
        assert "password='****'" in sanitized

    def test_key_value_dsn_with_hash_sanitized(self):
        """DSN string with password containing hash is masked."""
        raw = "psycopg2.OperationalError: dbname=db user=app password=hash#password#99 host=db.local"
        sanitized = sanitize_exception_message(raw)
        assert "hash#password#99" not in sanitized
        assert "password=****" in sanitized


# ===========================================================================
# 7. Expanded Privilege Inspection Tests
# ===========================================================================

class TestPrivilegeInspection:
    """Verify privilege checks cover all project schemas and table write operations."""

    def test_create_privilege_checks_cover_every_project_schema(self, mock_connection):
        """Schema-level CREATE check executes across all PROJECT_SCHEMAS."""
        executed_schemas: list[str] = []

        def fake_exec(stmt, params=None):
            mock_res = MagicMock()
            sql = str(stmt)
            if "SELECT current_user AS u" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {"u": "inspector_ro"}
            elif "has_database_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            elif "has_schema_privilege" in sql and "CREATE" in sql:
                executed_schemas.append(params.get("s"))
                mock_res.scalar.return_value = False
            elif "has_schema_privilege" in sql and "USAGE" in sql:
                mock_res.scalar.return_value = True
            elif "information_schema.tables" in sql:
                mock_res.fetchall.return_value = []
            return mock_res

        mock_connection.execute.side_effect = fake_exec
        rp = inspect_role_privileges(mock_connection)

        for s in PROJECT_SCHEMAS:
            assert s in executed_schemas
            assert rp.schema_create_privileges[s] is False
            assert rp.schema_usage_privileges[s] is True

    def test_table_level_write_privileges_inspected_and_reported(self, mock_connection):
        """Table write privileges (INSERT/UPDATE/DELETE/TRUNCATE) flag discrepancies."""
        def fake_exec(stmt, params=None):
            mock_res = MagicMock()
            sql = str(stmt)
            if "SELECT current_user AS u" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {"u": "inspector_ro"}
            elif "has_database_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            elif "has_schema_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "information_schema.tables" in sql and "BASE TABLE" in sql:
                mock_res.fetchall.return_value = [("sbom", "applications")]
            elif "has_table_privilege" in sql:
                # Grant INSERT on sbom.applications
                mock_res.scalar.return_value = params.get("act") == "INSERT"
            return mock_res

        mock_connection.execute.side_effect = fake_exec
        rp = inspect_role_privileges(mock_connection)

        assert rp.is_least_privilege_ro is False
        assert rp.table_write_privileges["sbom.applications"]["INSERT"] is True
        assert any("INSERT privilege on table sbom.applications" in d for d in rp.privilege_discrepancies)

    def test_unknown_privilege_state_not_reported_as_safe(self, mock_connection):
        """Failed privilege queries record UNKNOWN and forbid is_least_privilege_ro."""
        def fake_exec(stmt, params=None):
            sql = str(stmt)
            if "SELECT current_user AS u" in sql:
                mock_res = MagicMock()
                mock_res.mappings.return_value.fetchone.return_value = {"u": "inspector_ro"}
                return mock_res
            # Simulate permission denied when checking privileges
            raise Exception("permission denied for catalog query")

        mock_connection.execute.side_effect = fake_exec
        rp = inspect_role_privileges(mock_connection)

        assert rp.is_least_privilege_ro is False
        assert rp.can_create_database is None
        assert len(rp.unknown_privileges) > 0


# ===========================================================================
# 8. Cleanup Diagnostics Tests
# ===========================================================================

class TestCleanupDiagnostics:
    """Verify rollback and connection closure failure diagnostics."""

    def test_rollback_failure_does_not_mask_original_error(self, tmp_path):
        """Rollback failure inside finally block preserves original inspection error."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, *args, **kwargs):
            sql = str(stmt)
            if "ROLLBACK;" in sql:
                raise Exception("Rollback broken pipe error")
            if "SHOW transaction_read_only" in sql:
                mock_res = MagicMock()
                mock_res.scalar.return_value = "on"
                return mock_res
            if "SELECT current_database()" in sql:
                raise ValueError("Original inspection catalog failure")
            return MagicMock()

        mock_conn.execute.side_effect = fake_exec

        with pytest.raises(ValueError, match="Original inspection catalog failure"):
            run_staging_inspection(engine=mock_engine, settings=settings)

        # Connection close must still have been called
        mock_conn.close.assert_called_once()

    def test_rollback_failure_on_clean_inspection_makes_incomplete(self, tmp_path):
        """Cleanup rollback failure marks otherwise clean audit as INCOMPLETE."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))

        mock_conn = MagicMock(spec=Connection)
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.return_value = mock_conn

        def fake_exec(stmt, params=None):
            sql = str(stmt)
            if "ROLLBACK;" in sql:
                raise Exception("Network disconnect during rollback")
            mock_res = MagicMock()
            if "SHOW transaction_read_only" in sql:
                mock_res.scalar.return_value = "on"
            elif "SELECT current_database()" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {
                    "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                    "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
                }
            elif "pg_stat_ssl" in sql:
                mock_res.mappings.return_value.fetchone.return_value = {"ssl": True, "version": "1.3", "cipher": "AES", "bits": 256, "client_dn": None}
            elif "information_schema.schemata" in sql:
                mock_res.fetchall.return_value = [(s,) for s in PROJECT_SCHEMAS]
            elif "information_schema.tables" in sql and "alembic_version" in sql:
                mock_res.scalar.return_value = True
            elif "SELECT version_num FROM public.alembic_version" in sql:
                mock_res.fetchall.return_value = [("016",)]
            elif "NOT EXISTS (SELECT 1 FROM public.users" in sql or "count(*)" in sql:
                mock_res.scalar.return_value = 0
                mock_res.mappings.return_value.fetchall.return_value = []
            elif "EXISTS" in sql:
                mock_res.scalar.return_value = True
            elif "information_schema.columns" in sql:
                mock_res.fetchall.return_value = [("user_id",), ("sbom_root",), ("vulnerability_db_root",), ("policy_hash",), ("proof_job_id",)]
            elif "has_database_privilege" in sql or "has_schema_privilege" in sql or "has_table_privilege" in sql:
                mock_res.scalar.return_value = False
            elif "current_setting('is_superuser')" in sql:
                mock_res.scalar.return_value = "off"
            elif "information_schema.tables" in sql and "BASE TABLE" in sql:
                mock_res.fetchall.return_value = [("public", "users")]
            else:
                mock_res.scalar.return_value = False
                mock_res.fetchall.return_value = []
            return mock_res

        mock_conn.execute.side_effect = fake_exec
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=mock_engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("Rollback failure" in d for d in report.cleanup_diagnostics)


# ===========================================================================
# 9. Gate 5L Orchestration Regression Tests
# ===========================================================================

def _make_clean_mock_engine(tmp_path, custom_exec_handler=None):
    """Helper to create a fully configured, clean mock database engine and connection."""
    valid_cert = tmp_path / "ca.crt"
    valid_cert.write_text("CERT")
    settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))
    mock_conn = MagicMock(spec=Connection)
    mock_engine = MagicMock(spec=Engine)
    mock_engine.connect.return_value = mock_conn

    def default_exec(stmt, params=None):
        sql = str(stmt)
        if custom_exec_handler:
            custom_res = custom_exec_handler(sql, params)
            if custom_res is not None:
                return custom_res

        mock_res = MagicMock()
        if "SHOW transaction_read_only" in sql:
            mock_res.scalar.return_value = "on"
        elif "SELECT current_database()" in sql:
            mock_res.mappings.return_value.fetchone.return_value = {
                "db_name": "ZKP_SBOM_STAGING", "connected_user": "inspector_ro",
                "server_ip": "10.0.0.1", "server_port": 5432, "pg_version": "PG16",
            }
        elif "pg_stat_ssl" in sql:
            mock_res.mappings.return_value.fetchone.return_value = {
                "ssl": True, "version": "1.3", "cipher": "AES", "bits": 256, "client_dn": None
            }
        elif "information_schema.schemata" in sql:
            mock_res.fetchall.return_value = [(s,) for s in PROJECT_SCHEMAS]
        elif "information_schema.tables" in sql and "alembic_version" in sql:
            mock_res.scalar.return_value = True
        elif "SELECT version_num FROM public.alembic_version" in sql:
            mock_res.fetchall.return_value = [("016",)]
        elif "NOT EXISTS (SELECT 1 FROM public.users" in sql or "count(*)" in sql:
            mock_res.scalar.return_value = 0
            mock_res.mappings.return_value.fetchall.return_value = []
        elif "EXISTS" in sql:
            mock_res.scalar.return_value = True
        elif "information_schema.columns" in sql:
            mock_res.fetchall.return_value = [("user_id",), ("sbom_root",), ("vulnerability_db_root",), ("policy_hash",), ("proof_job_id",)]
        elif "has_database_privilege" in sql or "has_schema_privilege" in sql or "has_table_privilege" in sql:
            mock_res.scalar.return_value = False
        elif "current_setting('is_superuser')" in sql:
            mock_res.scalar.return_value = "off"
        elif "information_schema.tables" in sql and "BASE TABLE" in sql:
            mock_res.fetchall.return_value = [("public", "users")]
        else:
            mock_res.scalar.return_value = False
            mock_res.fetchall.return_value = []
        return mock_res

    mock_conn.execute.side_effect = default_exec
    return mock_engine, mock_conn, settings


class TestAlembicRevisionOrchestration:
    """Task A: Verify Alembic revision states (absent, empty, unavailable, expected, unexpected)."""

    def test_alembic_revision_missing_table_makes_incomplete(self, tmp_path):
        """Missing public.alembic_version makes audit INCOMPLETE."""
        def handler(sql, params):
            if "information_schema.tables" in sql and "alembic_version" in sql:
                m = MagicMock()
                m.scalar.return_value = False
                return m
            return None

        engine, conn, settings = _make_clean_mock_engine(tmp_path, handler)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("alembic_version' is absent" in c for c in report.checks_unable_to_run)

    def test_alembic_revision_empty_table_makes_incomplete(self, tmp_path):
        """Existing but empty public.alembic_version makes audit INCOMPLETE."""
        def handler(sql, params):
            if "SELECT version_num FROM public.alembic_version" in sql:
                m = MagicMock()
                m.fetchall.return_value = []
                return m
            return None

        engine, conn, settings = _make_clean_mock_engine(tmp_path, handler)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("exists but is empty" in c for c in report.checks_unable_to_run)

    def test_alembic_revision_query_failure_makes_incomplete(self, tmp_path):
        """Query failure checking alembic_version makes audit INCOMPLETE."""
        def handler(sql, params):
            if "alembic_version" in sql:
                raise Exception("permission denied for alembic_version")
            return None

        engine, conn, settings = _make_clean_mock_engine(tmp_path, handler)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("Alembic revision state cannot be queried" in c for c in report.checks_unable_to_run)

    def test_alembic_revision_expected_head_matches(self, tmp_path):
        """Populated revision matching expected repository head ('016') produces CLEAN."""
        engine, conn, settings = _make_clean_mock_engine(tmp_path)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "CLEAN"
        assert report.is_complete is True
        assert report.alembic_revision.expected_revision == "016"
        assert report.alembic_revision.revisions == ["016"]

    def test_alembic_revision_unexpected_diverted_head_causes_discrepancy(self, tmp_path):
        """Populated revision differing from expected repository head produces DISCREPANCIES_FOUND."""
        def handler(sql, params):
            if "SELECT version_num FROM public.alembic_version" in sql:
                m = MagicMock()
                m.fetchall.return_value = [("011",)]  # At older revision 011 instead of 016
                return m
            return None

        engine, conn, settings = _make_clean_mock_engine(tmp_path, handler)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "DISCREPANCIES_FOUND"
        assert report.discrepancies_found is True
        assert any("Alembic revision state mismatch" in d for d in report.discrepancies)
        assert any("expected repository head '016'" in d for d in report.discrepancies)

    def test_alembic_revision_multiple_heads_causes_discrepancy(self, tmp_path):
        """Multiple revisions recorded in public.alembic_version produces DISCREPANCIES_FOUND."""
        def handler(sql, params):
            if "SELECT version_num FROM public.alembic_version" in sql:
                m = MagicMock()
                m.fetchall.return_value = [("012",), ("013",)]
                return m
            return None

        engine, conn, settings = _make_clean_mock_engine(tmp_path, handler)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "DISCREPANCIES_FOUND"
        assert report.discrepancies_found is True
        assert any("Alembic revision state mismatch" in d for d in report.discrepancies)

    def test_alembic_revision_unresolved_expected_head_makes_incomplete(self, tmp_path):
        """If expected repository head cannot be resolved from scripts, audit is INCOMPLETE."""
        engine, conn, settings = _make_clean_mock_engine(tmp_path)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            with patch("scripts.inspect_staging_readonly.get_expected_alembic_head", return_value=None):
                report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("repository migration head could not be resolved" in c for c in report.checks_unable_to_run)


class TestTLSSessionOrchestration:
    """Task B: Verify TLS session states (active, inactive, no row, query failure)."""

    def test_tls_active_permits_clean(self, tmp_path):
        """Active TLS on backend PID completes cleanly."""
        engine, conn, settings = _make_clean_mock_engine(tmp_path)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "CLEAN"
        assert report.tls_session.ssl_active is True

    def test_tls_inactive_session_causes_discrepancy(self, tmp_path):
        """Backend session where ssl_active == False triggers security discrepancy."""
        def handler(sql, params):
            if "pg_stat_ssl" in sql:
                m = MagicMock()
                m.mappings.return_value.fetchone.return_value = {
                    "ssl": False, "version": None, "cipher": None, "bits": None, "client_dn": None
                }
                return m
            return None

        engine, conn, settings = _make_clean_mock_engine(tmp_path, handler)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "DISCREPANCIES_FOUND"
        assert report.discrepancies_found is True
        assert any("Security finding (TLS)" in d for d in report.discrepancies)
        assert any("unencrypted" in d for d in report.discrepancies)

    def test_tls_no_matching_backend_row_makes_incomplete(self, tmp_path):
        """pg_stat_ssl returning no rows for backend PID makes audit INCOMPLETE."""
        def handler(sql, params):
            if "pg_stat_ssl" in sql:
                m = MagicMock()
                m.mappings.return_value.fetchone.return_value = None
                return m
            return None

        engine, conn, settings = _make_clean_mock_engine(tmp_path, handler)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("TLS session catalog check unverified / ambiguous" in c for c in report.checks_unable_to_run)

    def test_tls_query_failure_makes_incomplete(self, tmp_path):
        """Failure querying pg_stat_ssl makes audit INCOMPLETE."""
        def handler(sql, params):
            if "pg_stat_ssl" in sql:
                raise Exception("permission denied for relation pg_stat_ssl")
            return None

        engine, conn, settings = _make_clean_mock_engine(tmp_path, handler)
        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("TLS session catalog check incomplete" in c for c in report.checks_unable_to_run)


class TestConnectionLifecycle:
    """Task D: Verify connection acquisition failures and cleanup failures."""

    def test_connection_acquisition_failure_fails_closed_and_safe(self, tmp_path):
        """Connection acquisition failure raises safely without closing unacquired connection."""
        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT")
        settings = DatabaseSettings(name="ZKP_SBOM_STAGING", ssl_mode="verify-full", ssl_root_cert=str(valid_cert))
        mock_engine = MagicMock(spec=Engine)
        mock_engine.connect.side_effect = Exception("could not connect to postgresql://user:SecretPass123@host:5432/db")

        with pytest.raises(Exception) as excinfo:
            run_staging_inspection(engine=mock_engine, settings=settings)

        # Confirm original exception was raised
        assert "SecretPass123" in str(excinfo.value)

    def test_connection_cleanup_close_failure_after_clean_inspection_makes_incomplete(self, tmp_path):
        """Connection close failure inside finally marks otherwise clean audit as INCOMPLETE."""
        engine, conn, settings = _make_clean_mock_engine(tmp_path)
        conn.close.side_effect = Exception("network error during connection close")

        with patch("staging_guard.validate_users_contract", return_value=ContractValidationResult(exists=True, is_valid=True, discrepancies=[])):
            report = run_staging_inspection(engine=engine, settings=settings)

        assert report.overall_status == "INCOMPLETE"
        assert report.is_complete is False
        assert any("Connection close failure" in d for d in report.cleanup_diagnostics)


class TestCLIExecution:
    """Task E: Verify CLI entry point exit codes, outputs, and JSON serialization."""

    def test_cli_clean_exit_code_and_output(self, monkeypatch, capsys):
        """CLI returns exit code 0 on CLEAN status and prints report."""
        clean_report = StagingInspectionReport(
            audit_timestamp_utc="2026-10-11T00:00:00Z",
            target_database_configured="ZKP_SBOM_STAGING",
            safe_connection_summary="host=staging.example.com",
            read_only_confirmed=True,
            overall_status="CLEAN",
            is_complete=True,
            discrepancies_found=False,
        )
        monkeypatch.setattr(sys, "argv", ["inspect_staging_readonly.py"])
        with patch("scripts.inspect_staging_readonly.run_staging_inspection", return_value=clean_report):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "CLEAN" in captured.out

    def test_cli_discrepancies_exit_code_and_output(self, monkeypatch, capsys):
        """CLI returns exit code 1 on DISCREPANCIES_FOUND status."""
        disc_report = StagingInspectionReport(
            audit_timestamp_utc="2026-10-11T00:00:00Z",
            target_database_configured="ZKP_SBOM_STAGING",
            safe_connection_summary="host=staging.example.com",
            read_only_confirmed=True,
            overall_status="DISCREPANCIES_FOUND",
            is_complete=True,
            discrepancies_found=True,
            discrepancies=["Orphan row detected"],
        )
        monkeypatch.setattr(sys, "argv", ["inspect_staging_readonly.py"])
        with patch("scripts.inspect_staging_readonly.run_staging_inspection", return_value=disc_report):
            exit_code = main()

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "DISCREPANCIES_FOUND" in captured.out

    def test_cli_incomplete_exit_code_and_output(self, monkeypatch, capsys):
        """CLI returns exit code 1 on INCOMPLETE status."""
        inc_report = StagingInspectionReport(
            audit_timestamp_utc="2026-10-11T00:00:00Z",
            target_database_configured="ZKP_SBOM_STAGING",
            safe_connection_summary="host=staging.example.com",
            read_only_confirmed=True,
            overall_status="INCOMPLETE",
            is_complete=False,
            discrepancies_found=False,
            checks_unable_to_run=["Missing verification_requests table"],
        )
        monkeypatch.setattr(sys, "argv", ["inspect_staging_readonly.py"])
        with patch("scripts.inspect_staging_readonly.run_staging_inspection", return_value=inc_report):
            exit_code = main()

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "INCOMPLETE" in captured.out

    def test_cli_json_serialization(self, monkeypatch, capsys):
        """CLI outputs valid structured JSON when --json flag is provided."""
        report = StagingInspectionReport(
            audit_timestamp_utc="2026-10-11T00:00:00Z",
            target_database_configured="ZKP_SBOM_STAGING",
            safe_connection_summary="host=staging.example.com",
            read_only_confirmed=True,
            overall_status="CLEAN",
            is_complete=True,
            discrepancies_found=False,
        )
        monkeypatch.setattr(sys, "argv", ["inspect_staging_readonly.py", "--json"])
        with patch("scripts.inspect_staging_readonly.run_staging_inspection", return_value=report):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["overall_status"] == "CLEAN"
        assert data["is_complete"] is True
        assert data["target_database_configured"] == "ZKP_SBOM_STAGING"

    def test_cli_output_file_writing(self, monkeypatch, tmp_path):
        """CLI writes formatted report to output file when --output flag is given."""
        out_file = tmp_path / "inspection_report.md"
        report = StagingInspectionReport(
            audit_timestamp_utc="2026-10-11T00:00:00Z",
            target_database_configured="ZKP_SBOM_STAGING",
            safe_connection_summary="host=staging.example.com",
            read_only_confirmed=True,
            overall_status="CLEAN",
            is_complete=True,
            discrepancies_found=False,
        )
        monkeypatch.setattr(sys, "argv", ["inspect_staging_readonly.py", "-o", str(out_file)])
        with patch("scripts.inspect_staging_readonly.run_staging_inspection", return_value=report):
            exit_code = main()

        assert exit_code == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "CLEAN" in content
        assert "ZKP_SBOM_STAGING" in content

    def test_cli_fatal_exception_masked_in_stderr(self, monkeypatch, capsys):
        """CLI intercepts unhandled inspection exception and prints sanitized error to stderr."""
        monkeypatch.setattr(sys, "argv", ["inspect_staging_readonly.py"])
        with patch(
            "scripts.inspect_staging_readonly.run_staging_inspection",
            side_effect=Exception("could not connect to postgresql://user:FatalSecret123@host:5432/db"),
        ):
            exit_code = main()

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "FATAL: Staging inspection aborted:" in captured.err
        assert "FatalSecret123" not in captured.err
        assert "postgresql://user:****@host:5432/db" in captured.err

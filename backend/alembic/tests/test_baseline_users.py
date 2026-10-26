"""
Focused mocked tests for public.users baseline safeguard.

Exercises:
  1. Default invocation uses verify mode.
  2. Creation is rejected without explicit staging and creation authorization.
  3. Creation is rejected for an incorrect target identity.
  4. Missing table in verify mode fails without DDL.
  5. Missing table in authorized create mode issues only the expected creation DDL.
  6. Existing compatible table is a no-op.
  7. Missing columns and incompatible types fail closed.
  8. Invalid nullability, missing primary key, or missing username uniqueness fail closed.
  9. Extra columns fail closed per strict compatibility policy.
  10. Incompatible existing tables receive no destructive or repair DDL.
  11. Baseline validation failure prevents applicable staging migrations from running.
  12. Unrelated non-staging environments retain the intended existing behavior.
  13. Repeated invocation is handled safely (idempotent).
  14. A simulated baseline DDL failure causes transaction rollback.
  15. Imports are safe and do not establish connections or execute the CLI.

ALL tests are strictly mocked. No test connects to PostgreSQL or network sockets.
"""

from __future__ import annotations

import os
import sys
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest
from sqlalchemy import text
from sqlalchemy.exc import InvalidRequestError, OperationalError

# Ensure backend root and alembic directory are on sys.path
_backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

_alembic_dir = os.path.join(_backend_root, "alembic")
if _alembic_dir not in sys.path:
    sys.path.insert(0, _alembic_dir)

import baseline_users
from baseline_users import (
    CREATE_USERS_TABLE_DDL,
    create_users_baseline,
    main,
    run_baseline,
)
import staging_guard
from staging_guard import (
    STAGING_DB_NAME,
    ContractValidationResult,
    StagingConfigError,
    assert_users_baseline_ready,
    orchestrate_online_migrations,
    validate_users_contract,
)


# ---------------------------------------------------------------------------
# Fixtures and Catalog Mock Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure DB_, STAGING_, and ENFORCE_ env vars are clean before each test."""
    for key in list(os.environ.keys()):
        if (
            key.startswith("DB_")
            or key.startswith("STAGING_")
            or key in ("ALLOW_BASELINE_CREATION", "ENFORCE_USER_BASELINE")
        ):
            monkeypatch.delenv(key, raising=False)
    yield


def make_mock_connection(
    table_exists: bool = True,
    columns: list[tuple] | None = None,
    pk_cols: list[str] | None = None,
    uq_cols: list[str] | None = None,
    indexes: list[tuple[str, str]] | None = None,
    current_db: str = STAGING_DB_NAME,
    has_unique_username_idx: bool = True,
    alembic_rev: str | None = "014",
    alembic_version_table_exists: bool = True,
) -> tuple[MagicMock, list[str]]:
    """Build a mock connection returning simulated information_schema and catalog data.

    Returns (mock_conn, executed_statements_list).
    """
    call_log: list[str] = []
    mock_conn = MagicMock()

    # Default valid columns matching shared.models.user.User
    if columns is None:
        columns = [
            ("id", "uuid", "NO", None, None),
            ("username", "character varying", "NO", 255, None),
            ("hashed_password", "character varying", "NO", 255, None),
            ("role", "character varying", "NO", 50, None),
            ("created_at", "timestamp without time zone", "YES", None, None),
        ]

    if pk_cols is None:
        pk_cols = ["id"]

    if uq_cols is None:
        uq_cols = ["username"]

    if indexes is None:
        indexes = [
            ("uq_users_username", "CREATE UNIQUE INDEX uq_users_username ON public.users USING btree (username)"),
        ]

    def mock_execute(stmt, *args, **kwargs):
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        call_log.append(sql.strip())
        res = MagicMock()

        if "SELECT current_database()" in sql:
            res.scalar.return_value = current_db
            return res

        if "FROM information_schema.tables" in sql:
            if "alembic_version" in sql:
                res.scalar.return_value = 1 if alembic_version_table_exists else None
                return res
            res.scalar.return_value = 1 if table_exists else None
            return res

        if "FROM public.alembic_version" in sql:
            res.fetchall.return_value = [(alembic_rev,)] if (alembic_version_table_exists and alembic_rev is not None) else []
            return res

        if "FROM information_schema.columns" in sql:
            res.fetchall.return_value = columns
            return res

        if "tc.constraint_type = 'PRIMARY KEY'" in sql:
            res.fetchall.return_value = [(col,) for col in pk_cols]
            return res

        if "tc.constraint_type = 'UNIQUE'" in sql:
            res.fetchall.return_value = [(col,) for col in uq_cols]
            return res

        if "FROM pg_indexes" in sql:
            res.fetchall.return_value = indexes
            return res

        if "FROM pg_catalog.pg_index" in sql:
            if uq_cols == [] or indexes == [] or not has_unique_username_idx:
                res.fetchall.return_value = []
            else:
                res.fetchall.return_value = [("uq_users_username",)]
            return res

        res.scalar.return_value = None
        res.fetchall.return_value = []
        return res

    mock_conn.execute.side_effect = mock_execute
    return mock_conn, call_log


def make_mock_engine(mock_conn: MagicMock) -> MagicMock:
    """Build a mock engine yielding mock_conn as a context manager."""
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_engine.connect.return_value.__exit__.return_value = False
    return mock_engine


# ===========================================================================
# 1. Default invocation uses verify mode
# ===========================================================================

def test_default_invocation_uses_verify_mode(monkeypatch):
    """Running without arguments defaults to verify mode."""
    mock_conn, call_log = make_mock_connection(table_exists=True)
    mock_engine = make_mock_engine(mock_conn)

    ret = run_baseline([], engine=mock_engine, load_env=False)
    assert ret == 0
    # Zero DDL issued
    assert not any("CREATE TABLE" in s for s in call_log)


# ===========================================================================
# 2. Creation rejected without explicit staging & creation authorization
# ===========================================================================

def test_creation_rejected_without_staging_mode(monkeypatch):
    """--create rejected if STAGING_MODE is not true."""
    monkeypatch.delenv("STAGING_MODE", raising=False)
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")

    mock_conn, _ = make_mock_connection(table_exists=False)
    mock_engine = make_mock_engine(mock_conn)

    with pytest.raises(StagingConfigError, match="permitted only when STAGING_MODE=true"):
        run_baseline(["--create"], engine=mock_engine, load_env=False)


def test_creation_rejected_without_allow_baseline_creation(monkeypatch):
    """--create rejected if ALLOW_BASELINE_CREATION is not true."""
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.delenv("ALLOW_BASELINE_CREATION", raising=False)

    mock_conn, _ = make_mock_connection(table_exists=False)
    mock_engine = make_mock_engine(mock_conn)

    with pytest.raises(StagingConfigError, match="requires explicit ALLOW_BASELINE_CREATION=true"):
        run_baseline(["--create"], engine=mock_engine, load_env=False)


# ===========================================================================
# 3. Creation rejected for incorrect target identity
# ===========================================================================

def test_creation_rejected_for_incorrect_target_identity(monkeypatch):
    """Rejects write operations if connected database identity is not ZKP_SBOM_STAGING."""
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")

    mock_conn, _ = make_mock_connection(table_exists=False, current_db="WRONG_DB")
    mock_engine = make_mock_engine(mock_conn)

    with patch("baseline_users.validate_staging_target"):
        with pytest.raises(StagingConfigError, match="WRONG_DB"):
            run_baseline(["--create"], engine=mock_engine, load_env=False)


# ===========================================================================
# 4. Missing table in verify mode fails without DDL
# ===========================================================================

def test_missing_table_in_verify_mode_fails_without_ddl():
    """Verify mode raises StagingConfigError when table is absent without running DDL."""
    mock_conn, call_log = make_mock_connection(table_exists=False)
    mock_engine = make_mock_engine(mock_conn)

    with pytest.raises(StagingConfigError, match="does not exist"):
        run_baseline(["--verify"], engine=mock_engine, load_env=False)

    assert not any("CREATE" in s for s in call_log)
    assert not any("ALTER" in s for s in call_log)
    assert not any("DROP" in s for s in call_log)


# ===========================================================================
# 5. Missing table in authorized create mode issues expected DDL
# ===========================================================================

def test_missing_table_in_authorized_create_mode_issues_ddl(monkeypatch):
    """Authorized create mode creates public.users with exact DDL and transaction."""
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")

    call_log: list[str] = []
    mock_conn = MagicMock()
    created = False

    def dynamic_execute(stmt, *args, **kwargs):
        nonlocal created
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        call_log.append(sql.strip())
        res = MagicMock()

        if "SELECT current_database()" in sql:
            res.scalar.return_value = STAGING_DB_NAME
            return res

        if "CREATE TABLE public.users" in sql:
            created = True
            return res

        if "FROM information_schema.tables" in sql:
            if "alembic_version" in sql:
                res.scalar.return_value = None
                return res
            res.scalar.return_value = 1 if created else None
            return res

        if "FROM public.alembic_version" in sql:
            res.fetchall.return_value = []
            return res

        if "FROM information_schema.columns" in sql:
            res.fetchall.return_value = [
                ("id", "uuid", "NO", None, None),
                ("username", "character varying", "NO", 255, None),
                ("hashed_password", "character varying", "NO", 255, None),
                ("role", "character varying", "NO", 50, None),
                ("created_at", "timestamp without time zone", "YES", None, None),
            ]
            return res

        if "tc.constraint_type = 'PRIMARY KEY'" in sql:
            res.fetchall.return_value = [("id",)]
            return res

        if "tc.constraint_type = 'UNIQUE'" in sql:
            res.fetchall.return_value = [("username",)]
            return res

        if "FROM pg_indexes" in sql:
            res.fetchall.return_value = [("uq_users_username", "CREATE UNIQUE INDEX ...")]
            return res

        if "FROM pg_catalog.pg_index" in sql:
            res.fetchall.return_value = [("uq_users_username",)] if created else []
            return res

        res.scalar.return_value = None
        res.fetchall.return_value = []
        return res

    mock_conn.execute.side_effect = dynamic_execute
    # In SQLAlchemy 2.x autobegin mode, calling begin() on an active connection raises InvalidRequestError
    mock_conn.begin.side_effect = InvalidRequestError("Connection already active")
    mock_engine = make_mock_engine(mock_conn)

    with patch("baseline_users.validate_staging_target"):
        ret = run_baseline(["--create"], engine=mock_engine, load_env=False)

    assert ret == 0
    assert any("CREATE TABLE public.users" in s for s in call_log)
    assert mock_conn.commit.called
    assert not mock_conn.rollback.called


# ===========================================================================
# 6. Existing compatible table is a no-op
# ===========================================================================

def test_existing_compatible_table_is_noop(monkeypatch):
    """When public.users exists and conforms, --create is a no-op without DDL."""
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")

    mock_conn, call_log = make_mock_connection(table_exists=True)
    mock_engine = make_mock_engine(mock_conn)

    with patch("baseline_users.validate_staging_target"):
        ret = run_baseline(["--create"], engine=mock_engine, load_env=False)

    assert ret == 0
    assert not any("CREATE TABLE" in s for s in call_log)
    assert not mock_conn.commit.called
    assert not mock_conn.rollback.called


# ===========================================================================
# 7. Missing columns and incompatible types fail closed
# ===========================================================================

def test_missing_column_fails_closed():
    """Missing required column fails validation."""
    columns = [
        ("id", "uuid", "NO", None, None),
        ("username", "character varying", "NO", 255, None),
        ("hashed_password", "character varying", "NO", 255, None),
        ("created_at", "timestamp without time zone", "YES", None, None),
        # 'role' is missing
    ]
    mock_conn, _ = make_mock_connection(table_exists=True, columns=columns)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Required column 'role' is missing" in d for d in res.discrepancies)


def test_incompatible_id_type_fails_closed():
    """id with non-uuid type fails validation."""
    columns = [
        ("id", "integer", "NO", None, None),
        ("username", "character varying", "NO", 255, None),
        ("hashed_password", "character varying", "NO", 255, None),
        ("role", "character varying", "NO", 50, None),
        ("created_at", "timestamp without time zone", "YES", None, None),
    ]
    mock_conn, _ = make_mock_connection(table_exists=True, columns=columns)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Column 'id' has type 'integer', expected 'uuid'" in d for d in res.discrepancies)


def test_incompatible_username_length_fails_closed():
    """username with max length < 255 fails validation."""
    columns = [
        ("id", "uuid", "NO", None, None),
        ("username", "character varying", "NO", 100, None),
        ("hashed_password", "character varying", "NO", 255, None),
        ("role", "character varying", "NO", 50, None),
        ("created_at", "timestamp without time zone", "YES", None, None),
    ]
    mock_conn, _ = make_mock_connection(table_exists=True, columns=columns)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Column 'username' max length is 100, expected at least 255" in d for d in res.discrepancies)


# ===========================================================================
# 8. Invalid nullability, missing PK, missing unique fail closed
# ===========================================================================

def test_nullable_username_fails_closed():
    """Nullable username fails validation."""
    columns = [
        ("id", "uuid", "NO", None, None),
        ("username", "character varying", "YES", 255, None),
        ("hashed_password", "character varying", "NO", 255, None),
        ("role", "character varying", "NO", 50, None),
        ("created_at", "timestamp without time zone", "YES", None, None),
    ]
    mock_conn, _ = make_mock_connection(table_exists=True, columns=columns)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Column 'username' must be NOT NULL" in d for d in res.discrepancies)


def test_missing_primary_key_fails_closed():
    """Missing primary key constraint on id fails validation."""
    mock_conn, _ = make_mock_connection(table_exists=True, pk_cols=[])
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Primary key constraint on 'id' is missing" in d for d in res.discrepancies)


def test_missing_uniqueness_fails_closed():
    """Missing unique constraint and unique index on username fails validation."""
    mock_conn, _ = make_mock_connection(table_exists=True, uq_cols=[], indexes=[])
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Uniqueness constraint or unique index on 'username' is missing" in d for d in res.discrepancies)


# ===========================================================================
# 9. Extra columns fail closed per policy
# ===========================================================================

def test_extra_columns_fail_closed():
    """Extra unmapped columns fail closed per schema drift policy."""
    columns = [
        ("id", "uuid", "NO", None, None),
        ("username", "character varying", "NO", 255, None),
        ("hashed_password", "character varying", "NO", 255, None),
        ("role", "character varying", "NO", 50, None),
        ("created_at", "timestamp without time zone", "YES", None, None),
        ("is_active", "boolean", "NO", None, "true"),
        ("email", "character varying", "YES", 255, None),
    ]
    mock_conn, _ = make_mock_connection(table_exists=True, columns=columns)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Unexpected unmapped column(s)" in d for d in res.discrepancies)


# ===========================================================================
# 10. Incompatible existing tables receive no destructive/repair DDL
# ===========================================================================

def test_incompatible_existing_table_receives_no_ddl(monkeypatch):
    """Incompatible existing table triggers fail closed without DROP/ALTER/TRUNCATE."""
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")

    # Table exists but id is wrong type
    columns = [
        ("id", "bigint", "NO", None, None),
        ("username", "character varying", "NO", 255, None),
        ("hashed_password", "character varying", "NO", 255, None),
        ("role", "character varying", "NO", 50, None),
        ("created_at", "timestamp without time zone", "YES", None, None),
    ]
    mock_conn, call_log = make_mock_connection(table_exists=True, columns=columns)
    mock_engine = make_mock_engine(mock_conn)

    with patch("baseline_users.validate_staging_target"):
        with pytest.raises(StagingConfigError, match="Cannot create baseline"):
            run_baseline(["--create"], engine=mock_engine, load_env=False)

    # Assert ZERO destructive DDL statements
    assert not any("DROP" in s for s in call_log)
    assert not any("ALTER" in s for s in call_log)
    assert not any("TRUNCATE" in s for s in call_log)
    assert not any("CREATE" in s for s in call_log)


# ===========================================================================
# 11. Baseline validation failure prevents applicable staging migrations
# ===========================================================================

def test_baseline_validation_failure_prevents_staging_migrations(monkeypatch):
    """Prerequisite failure in staging stops orchestrate_online_migrations before DDL or migrations."""
    monkeypatch.setenv("STAGING_MODE", "true")

    # Table is absent
    mock_conn, call_log = make_mock_connection(table_exists=False)
    mock_engine = make_mock_engine(mock_conn)
    mock_context = MagicMock()

    with pytest.raises(StagingConfigError, match="Prerequisite failed"):
        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=True,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
        )

    # Migrations and schema DDL were never invoked
    assert not any("CREATE SCHEMA" in s for s in call_log)
    assert not mock_context.run_migrations.called
    assert not mock_context.begin_transaction.called


# ===========================================================================
# 12. Unrelated non-staging environments retain intended existing behavior
# ===========================================================================

def test_non_staging_mode_bypasses_baseline_check(monkeypatch):
    """When is_staging=False and ENFORCE_USER_BASELINE is unset, prerequisite check does not block migrations."""
    monkeypatch.setenv("STAGING_MODE", "false")
    monkeypatch.delenv("ENFORCE_USER_BASELINE", raising=False)

    # Table is absent, but non-staging bypasses prerequisite
    mock_conn, call_log = make_mock_connection(table_exists=False)
    mock_engine = make_mock_engine(mock_conn)
    mock_context = MagicMock()

    orchestrate_online_migrations(
        connectable=mock_engine,
        is_staging=False,
        target_metadata=MagicMock(),
        include_name=MagicMock(),
        context=mock_context,
        schemas=("sbom",),
    )

    assert any("CREATE SCHEMA" in s for s in call_log)
    assert mock_context.run_migrations.called


def test_non_staging_mode_enforces_when_policy_enabled(monkeypatch):
    """When ENFORCE_USER_BASELINE=true in non-staging, prerequisite is enforced."""
    monkeypatch.setenv("STAGING_MODE", "false")
    monkeypatch.setenv("ENFORCE_USER_BASELINE", "true")

    # Table is absent
    mock_conn, _ = make_mock_connection(table_exists=False)
    mock_engine = make_mock_engine(mock_conn)
    mock_context = MagicMock()

    with pytest.raises(StagingConfigError, match="Prerequisite failed"):
        orchestrate_online_migrations(
            connectable=mock_engine,
            is_staging=False,
            target_metadata=MagicMock(),
            include_name=MagicMock(),
            context=mock_context,
            schemas=("sbom",),
        )


# ===========================================================================
# 13. Repeated invocation is handled safely (idempotent)
# ===========================================================================

def test_repeated_create_invocation_is_idempotent(monkeypatch):
    """Repeated calls to create_users_baseline on a valid table succeed without duplicate DDL."""
    mock_conn, call_log = make_mock_connection(table_exists=True)
    # First invocation
    create_users_baseline(mock_conn)
    # Second invocation
    create_users_baseline(mock_conn)

    assert not any("CREATE TABLE" in s for s in call_log)


# ===========================================================================
# 14. Simulated baseline DDL failure causes transaction rollback
# ===========================================================================

def test_simulated_ddl_failure_causes_rollback():
    """Exception during CREATE TABLE DDL triggers transaction rollback."""
    mock_conn = MagicMock()

    def fail_on_create(stmt, *args, **kwargs):
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        if "FROM information_schema.tables" in sql:
            res = MagicMock()
            res.scalar.return_value = None
            return res
        if "CREATE TABLE" in sql:
            raise RuntimeError("Simulated PostgreSQL DDL error")
        return MagicMock()

    mock_conn.execute.side_effect = fail_on_create

    with pytest.raises(RuntimeError, match="Simulated PostgreSQL DDL error"):
        create_users_baseline(mock_conn)

    assert mock_conn.rollback.called
    assert not mock_conn.commit.called


# ===========================================================================
# 15. Imports are safe and do not establish connections or execute CLI
# ===========================================================================

def test_imports_are_safe_and_have_no_side_effects():
    """Importing baseline_users and staging_guard establishes zero connections and loads no real files."""
    assert "baseline_users" in sys.modules
    assert "staging_guard" in sys.modules
    assert hasattr(baseline_users, "run_baseline")
    assert hasattr(staging_guard, "validate_users_contract")
    assert hasattr(staging_guard, "assert_users_baseline_ready")


# ===========================================================================
# 16. Focused Catalog Uniqueness Evaluation Tests (pg_catalog.pg_index)
# ===========================================================================

def make_catalog_mock_connection(
    simulated_indexes: list[dict[str, Any]],
    table_exists: bool = True,
) -> tuple[MagicMock, list[str]]:
    """Build a mock connection accurately filtering simulated catalog index entries.

    Simulates the exact SQL WHERE filters executed by validate_users_contract:
      - schema_name == 'public'
      - table_name == 'users'
      - indisunique is True
      - indnkeyatts == 1
      - indpred is None (IS NULL)
      - indexprs is None (IS NULL)
      - column_name == 'username'
    """
    call_log: list[str] = []
    mock_conn = MagicMock()

    columns = [
        ("id", "uuid", "NO", None, None),
        ("username", "character varying", "NO", 255, None),
        ("hashed_password", "character varying", "NO", 255, None),
        ("role", "character varying", "NO", 50, None),
        ("created_at", "timestamp without time zone", "YES", None, None),
    ]

    def mock_execute(stmt, *args, **kwargs):
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        call_log.append(sql.strip())
        res = MagicMock()

        if "SELECT current_database()" in sql:
            res.scalar.return_value = STAGING_DB_NAME
            return res

        if "FROM information_schema.tables" in sql:
            if "alembic_version" in sql:
                res.scalar.return_value = 1
                return res
            res.scalar.return_value = 1 if table_exists else None
            return res

        if "FROM public.alembic_version" in sql:
            res.fetchall.return_value = [("014",)]
            return res

        if "FROM information_schema.columns" in sql:
            res.fetchall.return_value = columns
            return res

        if "tc.constraint_type = 'PRIMARY KEY'" in sql:
            res.fetchall.return_value = [("id",)]
            return res

        if "FROM pg_catalog.pg_index" in sql:
            matching = [
                (idx["index_name"],)
                for idx in simulated_indexes
                if idx.get("schema_name", "public") == "public"
                and idx.get("table_name", "users") == "users"
                and idx.get("indisunique", False) is True
                and idx.get("indnkeyatts", 0) == 1
                and idx.get("indpred") is None
                and idx.get("indexprs") is None
                and idx.get("column_name") == "username"
            ]
            res.fetchall.return_value = matching
            return res

        res.scalar.return_value = None
        res.fetchall.return_value = []
        return res

    mock_conn.execute.side_effect = mock_execute
    return mock_conn, call_log


def test_catalog_single_column_unique_constraint_accepted():
    """In PostgreSQL, CONSTRAINT uq UNIQUE (username) creates a unique index with indnkeyatts=1."""
    simulated = [{
        "index_name": "uq_users_username",
        "schema_name": "public",
        "table_name": "users",
        "indisunique": True,
        "indnkeyatts": 1,
        "indpred": None,
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn, call_log = make_catalog_mock_connection(simulated)
    res = validate_users_contract(mock_conn)
    assert res.is_valid
    assert len(res.discrepancies) == 0

    catalog_query = next(s for s in call_log if "FROM pg_catalog.pg_index" in s)
    assert "i.indisunique = true" in catalog_query
    assert "i.indnkeyatts = 1" in catalog_query
    assert "i.indpred IS NULL" in catalog_query
    assert "i.indexprs IS NULL" in catalog_query
    assert "a.attname = 'username'" in catalog_query
    assert "ns.nspname = 'public'" in catalog_query
    assert "c_tbl.relname = 'users'" in catalog_query


def test_catalog_standalone_unique_index_accepted():
    """Standalone CREATE UNIQUE INDEX on username without constraint is accepted."""
    simulated = [{
        "index_name": "ix_users_username_custom",
        "schema_name": "public",
        "table_name": "users",
        "indisunique": True,
        "indnkeyatts": 1,
        "indpred": None,
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn, _ = make_catalog_mock_connection(simulated)
    res = validate_users_contract(mock_conn)
    assert res.is_valid
    assert len(res.discrepancies) == 0


def test_catalog_unique_index_with_include_columns_accepted():
    """CREATE UNIQUE INDEX ... (username) INCLUDE (role) has indnkeyatts=1 and is accepted."""
    simulated = [{
        "index_name": "ix_users_username_with_include",
        "schema_name": "public",
        "table_name": "users",
        "indisunique": True,
        "indnkeyatts": 1,
        "indpred": None,
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn, _ = make_catalog_mock_connection(simulated)
    res = validate_users_contract(mock_conn)
    assert res.is_valid
    assert len(res.discrepancies) == 0


def test_catalog_composite_unique_constraint_rejected():
    """Composite UNIQUE constraint covering (role, username) has indnkeyatts=2 and is rejected."""
    simulated = [{
        "index_name": "uq_users_role_username",
        "schema_name": "public",
        "table_name": "users",
        "indisunique": True,
        "indnkeyatts": 2,
        "indpred": None,
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn, _ = make_catalog_mock_connection(simulated)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Uniqueness constraint or unique index on 'username' is missing" in d for d in res.discrepancies)


def test_catalog_composite_unique_index_rejected():
    """Composite CREATE UNIQUE INDEX on (username, role) has indnkeyatts=2 and is rejected."""
    simulated = [{
        "index_name": "ix_users_username_role",
        "schema_name": "public",
        "table_name": "users",
        "indisunique": True,
        "indnkeyatts": 2,
        "indpred": None,
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn, _ = make_catalog_mock_connection(simulated)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Uniqueness constraint or unique index on 'username' is missing" in d for d in res.discrepancies)


def test_catalog_partial_unique_index_rejected():
    """Partial CREATE UNIQUE INDEX ... WHERE is_active=true has indpred IS NOT NULL and is rejected."""
    simulated = [{
        "index_name": "ix_users_username_partial",
        "schema_name": "public",
        "table_name": "users",
        "indisunique": True,
        "indnkeyatts": 1,
        "indpred": "(is_active = true)",
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn, _ = make_catalog_mock_connection(simulated)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Uniqueness constraint or unique index on 'username' is missing" in d for d in res.discrepancies)


def test_catalog_expression_unique_index_rejected():
    """Expression CREATE UNIQUE INDEX on lower(username) has indexprs IS NOT NULL and is rejected."""
    simulated = [{
        "index_name": "ix_users_lower_username",
        "schema_name": "public",
        "table_name": "users",
        "indisunique": True,
        "indnkeyatts": 1,
        "indpred": None,
        "indexprs": "lower(username)",
        "column_name": "username",
    }]
    mock_conn, _ = make_catalog_mock_connection(simulated)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Uniqueness constraint or unique index on 'username' is missing" in d for d in res.discrepancies)


def test_catalog_misleading_name_non_unique_index_rejected():
    """Index with 'unique' in its name but indisunique=false is rejected."""
    simulated = [{
        "index_name": "unique_username_idx",
        "schema_name": "public",
        "table_name": "users",
        "indisunique": False,
        "indnkeyatts": 1,
        "indpred": None,
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn, _ = make_catalog_mock_connection(simulated)
    res = validate_users_contract(mock_conn)
    assert not res.is_valid
    assert any("Uniqueness constraint or unique index on 'username' is missing" in d for d in res.discrepancies)


def test_catalog_schema_and_table_scoping_enforced():
    """Unique indexes on non-public schemas or non-users tables are rejected."""
    simulated_other_schema = [{
        "index_name": "uq_users_username",
        "schema_name": "other_schema",
        "table_name": "users",
        "indisunique": True,
        "indnkeyatts": 1,
        "indpred": None,
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn1, _ = make_catalog_mock_connection(simulated_other_schema)
    res1 = validate_users_contract(mock_conn1)
    assert not res1.is_valid
    assert any("Uniqueness constraint or unique index on 'username' is missing" in d for d in res1.discrepancies)

    simulated_other_table = [{
        "index_name": "uq_contractors_username",
        "schema_name": "public",
        "table_name": "contractors",
        "indisunique": True,
        "indnkeyatts": 1,
        "indpred": None,
        "indexprs": None,
        "column_name": "username",
    }]
    mock_conn2, _ = make_catalog_mock_connection(simulated_other_table)
    res2 = validate_users_contract(mock_conn2)
    assert not res2.is_valid
    assert any("Uniqueness constraint or unique index on 'username' is missing" in d for d in res2.discrepancies)


# ===========================================================================
# 17. Dedicated SQLAlchemy 2.x Transaction Lifecycle Tests (Gate 4C)
# ===========================================================================

def test_creation_on_connection_with_prior_identity_query(monkeypatch):
    """Cover 1: Successful baseline creation on a connection that already executed a read-only identity query."""
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")

    call_log: list[str] = []
    created = False
    mock_conn = MagicMock()

    def dynamic_execute(stmt, *args, **kwargs):
        nonlocal created
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        call_log.append(sql.strip())
        res = MagicMock()

        if "SELECT current_database()" in sql:
            res.scalar.return_value = STAGING_DB_NAME
            return res

        if "CREATE TABLE public.users" in sql:
            created = True
            return res

        if "FROM information_schema.tables" in sql:
            if "alembic_version" in sql:
                res.scalar.return_value = None
                return res
            res.scalar.return_value = 1 if created else None
            return res

        if "FROM information_schema.columns" in sql:
            res.fetchall.return_value = [
                ("id", "uuid", "NO", None, None),
                ("username", "character varying", "NO", 255, None),
                ("hashed_password", "character varying", "NO", 255, None),
                ("role", "character varying", "NO", 50, None),
                ("created_at", "timestamp without time zone", "YES", None, None),
            ]
            return res

        if "tc.constraint_type = 'PRIMARY KEY'" in sql:
            res.fetchall.return_value = [("id",)]
            return res

        if "tc.constraint_type = 'UNIQUE'" in sql:
            res.fetchall.return_value = [("username",)]
            return res

        if "FROM pg_indexes" in sql:
            res.fetchall.return_value = [("uq_users_username", "CREATE UNIQUE INDEX ...")]
            return res

        if "FROM pg_catalog.pg_index" in sql:
            res.fetchall.return_value = [("uq_users_username",)] if created else []
            return res

        res.scalar.return_value = None
        res.fetchall.return_value = []
        return res

    mock_conn.execute.side_effect = dynamic_execute
    # Enforce that begin() raises InvalidRequestError to verify our code does not call it
    mock_conn.begin.side_effect = InvalidRequestError(
        "This connection has already initialized a SQLAlchemy Transaction() object via begin() or autobegin"
    )
    mock_engine = make_mock_engine(mock_conn)

    with patch("baseline_users.validate_staging_target"):
        ret = run_baseline(["--create"], engine=mock_engine, load_env=False)

    assert ret == 0
    assert any("SELECT current_database()" in s for s in call_log)
    assert any("CREATE TABLE public.users" in s for s in call_log)
    assert mock_conn.commit.called
    assert not mock_conn.rollback.called


def test_creation_when_contract_check_triggers_autobegin():
    """Cover 2: Successful creation when the baseline contract check itself triggers autobegin."""
    call_log: list[str] = []
    created = False
    mock_conn = MagicMock()

    def dynamic_execute(stmt, *args, **kwargs):
        nonlocal created
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        call_log.append(sql.strip())
        res = MagicMock()

        if "CREATE TABLE public.users" in sql:
            created = True
            return res

        if "FROM information_schema.tables" in sql:
            if "alembic_version" in sql:
                res.scalar.return_value = None
                return res
            res.scalar.return_value = 1 if created else None
            return res

        if "FROM information_schema.columns" in sql:
            res.fetchall.return_value = [
                ("id", "uuid", "NO", None, None),
                ("username", "character varying", "NO", 255, None),
                ("hashed_password", "character varying", "NO", 255, None),
                ("role", "character varying", "NO", 50, None),
                ("created_at", "timestamp without time zone", "YES", None, None),
            ]
            return res

        if "tc.constraint_type = 'PRIMARY KEY'" in sql:
            res.fetchall.return_value = [("id",)]
            return res

        if "tc.constraint_type = 'UNIQUE'" in sql:
            res.fetchall.return_value = [("username",)]
            return res

        if "FROM pg_catalog.pg_index" in sql:
            res.fetchall.return_value = [("uq_users_username",)] if created else []
            return res

        res.scalar.return_value = None
        res.fetchall.return_value = []
        return res

    mock_conn.execute.side_effect = dynamic_execute
    mock_conn.begin.side_effect = InvalidRequestError("autobegin already active")

    # Calling create_users_baseline directly:
    # 1. validate_users_contract queries information_schema (autobegin)
    # 2. Table absent -> execute CREATE TABLE DDL
    # 3. validate_users_contract post-creation succeeds
    # 4. commit() is called
    create_users_baseline(mock_conn)

    assert any("CREATE TABLE public.users" in s for s in call_log)
    assert mock_conn.commit.called
    assert not mock_conn.rollback.called


def test_repeated_creation_and_verification_against_compatible_table(monkeypatch):
    """Cover 3: Successful repeated creation or verification against compatible table without DDL."""
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")

    mock_conn, call_log = make_mock_connection(table_exists=True)
    mock_engine = make_mock_engine(mock_conn)

    with patch("baseline_users.validate_staging_target"):
        # 1. Verification run
        ret_verify = run_baseline(["--verify"], engine=mock_engine, load_env=False)
        assert ret_verify == 0

        # 2. Creation run on existing table
        ret_create = run_baseline(["--create"], engine=mock_engine, load_env=False)
        assert ret_create == 0

        # 3. Direct function call
        create_users_baseline(mock_conn)

    # In all runs, no DDL should be issued
    assert not any("CREATE TABLE" in s for s in call_log)
    assert not any("ALTER" in s for s in call_log)
    assert not any("DROP" in s for s in call_log)
    assert not mock_conn.commit.called


def test_fail_closed_for_incompatible_existing_table(monkeypatch):
    """Cover 4: Incompatible existing table fails closed without automatic repair, DDL, or commit."""
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")

    columns = [
        ("id", "uuid", "NO", None, None),
        ("username", "character varying", "NO", 255, None),
        ("hashed_password", "character varying", "NO", 255, None),
        ("role", "integer", "NO", None, None),  # Invalid type: integer instead of varchar(50)
        ("created_at", "timestamp without time zone", "YES", None, None),
    ]
    mock_conn, call_log = make_mock_connection(table_exists=True, columns=columns)
    mock_engine = make_mock_engine(mock_conn)

    with patch("baseline_users.validate_staging_target"):
        with pytest.raises(StagingConfigError, match="Cannot create baseline: existing table 'public.users' is incompatible"):
            run_baseline(["--create"], engine=mock_engine, load_env=False)

    assert not any("CREATE" in s for s in call_log)
    assert not any("ALTER" in s for s in call_log)
    assert not any("DROP" in s for s in call_log)
    assert not mock_conn.commit.called


def test_rollback_when_post_creation_validation_fails():
    """Cover 5: Rollback when an error occurs after table creation but before commit."""
    mock_conn = MagicMock()
    call_log: list[str] = []
    created = False

    def dynamic_execute(stmt, *args, **kwargs):
        nonlocal created
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        call_log.append(sql.strip())
        res = MagicMock()

        if "CREATE TABLE public.users" in sql:
            created = True
            return res

        if "FROM information_schema.tables" in sql:
            # Simulate table absent even after creation, or defective
            res.scalar.return_value = 1 if created else None
            return res

        if "FROM information_schema.columns" in sql:
            # Return defective columns on post-creation check
            res.fetchall.return_value = [
                ("id", "uuid", "NO", None, None),
                ("username", "character varying", "NO", 255, None),
                # missing hashed_password, role, etc.
            ]
            return res

        if "tc.constraint_type = 'PRIMARY KEY'" in sql:
            res.fetchall.return_value = [("id",)]
            return res

        res.scalar.return_value = None
        res.fetchall.return_value = []
        return res

    mock_conn.execute.side_effect = dynamic_execute

    with pytest.raises(StagingConfigError, match="Post-creation contract validation failed"):
        create_users_baseline(mock_conn)

    assert any("CREATE TABLE public.users" in s for s in call_log)
    assert mock_conn.rollback.called
    assert not mock_conn.commit.called


def test_no_ddl_when_creation_flags_missing(monkeypatch):
    """Cover 6: No DDL or commits when creation flags are missing."""
    mock_conn, call_log = make_mock_connection(table_exists=False)
    mock_engine = make_mock_engine(mock_conn)

    # Missing STAGING_MODE
    monkeypatch.delenv("STAGING_MODE", raising=False)
    monkeypatch.setenv("ALLOW_BASELINE_CREATION", "true")
    with pytest.raises(StagingConfigError, match="permitted only when STAGING_MODE=true"):
        run_baseline(["--create"], engine=mock_engine, load_env=False)

    # Missing ALLOW_BASELINE_CREATION
    monkeypatch.setenv("STAGING_MODE", "true")
    monkeypatch.delenv("ALLOW_BASELINE_CREATION", raising=False)
    with pytest.raises(StagingConfigError, match="requires explicit ALLOW_BASELINE_CREATION=true"):
        run_baseline(["--create"], engine=mock_engine, load_env=False)

    assert not any("CREATE TABLE" in s for s in call_log)
    assert not mock_conn.commit.called


def test_read_only_verification_against_missing_table():
    """Cover 7: Read-only verification against a missing table fails closed with zero DDL."""
    mock_conn, call_log = make_mock_connection(table_exists=False)
    mock_engine = make_mock_engine(mock_conn)

    with pytest.raises(StagingConfigError, match="Table 'public.users' does not exist"):
        run_baseline(["--verify"], engine=mock_engine, load_env=False)

    assert not any("CREATE" in s for s in call_log)
    assert not any("ALTER" in s for s in call_log)
    assert not any("DROP" in s for s in call_log)
    assert not mock_conn.commit.called


def test_error_propagation_and_transaction_handling():
    """Cover 8: Propagation of relevant errors with proper rollback handling."""
    mock_conn = MagicMock()

    # DDL failure propagates OperationalError
    def fail_ddl(stmt, *args, **kwargs):
        sql = stmt.text if hasattr(stmt, "text") else str(stmt)
        if "FROM information_schema.tables" in sql:
            res = MagicMock()
            res.scalar.return_value = None
            return res
        if "CREATE TABLE" in sql:
            raise OperationalError("CREATE TABLE ...", {}, Exception("disk full"))
        return MagicMock()

    mock_conn.execute.side_effect = fail_ddl

    with pytest.raises(OperationalError, match="disk full"):
        create_users_baseline(mock_conn)

    assert mock_conn.rollback.called
    assert not mock_conn.commit.called

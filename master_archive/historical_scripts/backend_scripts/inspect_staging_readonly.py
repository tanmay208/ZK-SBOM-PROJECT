"""
Read-Only Staging Inspection Harness.

Fail-closed, standalone inspection tool for auditing the ZKP-SBOM staging database
before authorizing migrations or schema changes.

SECURITY & SAFETY BOUNDARIES:
  - Requires STAGING_MODE=true in the process environment.
  - Requires .env.staging to exist and contain DB_NAME=ZKP_SBOM_STAGING.
  - Requires DB_SSL_MODE=verify-full with a verified CA certificate file.
  - Never connects if preflight configuration validation fails.
  - Opens an explicit READ ONLY transaction (BEGIN TRANSACTION READ ONLY;).
  - Verifies SHOW transaction_read_only is 'on' before running any catalog query.
  - Executes strictly SELECT and SHOW statements (never DDL, DML, or migrations).
  - Always rolls back and closes connection safely on completion or error.
  - Masks credentials and secret-bearing URLs in all output and logs.
  - Never mutates database objects or repairs data.
  - Does NOT claim staging is migration-ready merely because inspection completed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import re
import sys
from typing import Any

from sqlalchemy import create_engine, pool, text
from sqlalchemy.engine import Connection, Engine

# Ensure backend root and alembic directories are resolvable
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.abspath(os.path.join(_CURRENT_DIR, ".."))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)
_ALEMBIC_DIR = os.path.join(_BACKEND_DIR, "alembic")
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from shared.config import ConfigurationError, DatabaseSettings, get_db_settings
import staging_guard
from staging_guard import ContractValidationResult, StagingConfigError

logger = logging.getLogger("staging_inspector")

PROJECT_SCHEMAS = ("public", "sbom", "vulnerability", "policy", "zkp", "verification")


# ===========================================================================
# Exception & String Sanitization Helpers
# ===========================================================================

def sanitize_exception_message(exc: Any) -> str:
    """Sanitize exception messages to prevent credential leakage.

    Masks PostgreSQL connection URLs, password parameters, sensitive tokens,
    JSON key/value forms, multiline fields, and key-value DSNs.
    Guaranteed never to raise an exception or expose raw secrets.
    """
    try:
        if isinstance(exc, Exception):
            exc_type = type(exc).__name__
            raw_msg = str(exc)
        elif isinstance(exc, str):
            exc_type = "Error"
            raw_msg = exc
        else:
            exc_type = "Error"
            raw_msg = repr(exc)

        # 1. Mask URL passwords: :password@ -> :****@
        # Matches user:password@host where password may contain '#', '%', quotes, spaces, etc.
        sanitized = re.sub(r":([^@\s/?]+)@", r":****@", raw_msg)

        # 2. Mask key-value DSN or config passwords: quoted password='...' or unquoted password=...
        sanitized = re.sub(
            r"(password\s*=\s*(['\"]))([^\r\n]+?)\2",
            r"\1****\2",
            sanitized,
            flags=re.IGNORECASE,
        )
        sanitized = re.sub(
            r"(password\s*=\s*)([^\s;'\"]+)",
            r"\1****",
            sanitized,
            flags=re.IGNORECASE,
        )

        # 3. Mask query parameter passwords: ?password=... or &password=...
        sanitized = re.sub(
            r"([?&]password=)([^&\s\r\n]+)",
            r"\1****",
            sanitized,
            flags=re.IGNORECASE,
        )

        # 4. Mask JSON key/value forms: "password": "...", 'token': '...', etc.
        sanitized = re.sub(
            r"([\"']?(?:password|token|secret|api_key|bearer|access_token)[\"']?\s*:\s*[\"']?)([^\"'\r\n,{}]+)([\"']?)",
            r"\1****\3",
            sanitized,
            flags=re.IGNORECASE,
        )

        # 5. Mask multiline key/value forms: password:\n  secret_value
        sanitized = re.sub(
            r"((?:password|secret|token)\s*:\s*\r?\n\s*)([^\r\n]+)",
            r"\1****",
            sanitized,
            flags=re.IGNORECASE,
        )

        # 6. Mask bearer tokens and authorization headers
        sanitized = re.sub(
            r"(bearer\s+)([A-Za-z0-9_\-\.]+)",
            r"\1****",
            sanitized,
            flags=re.IGNORECASE,
        )

        # 7. Mask generic token/secret parameters (quoted or unquoted)
        sanitized = re.sub(
            r"((?:secret|token|api_key|access_token)\s*=\s*(['\"]))([^\r\n]+?)\2",
            r"\1****\2",
            sanitized,
            flags=re.IGNORECASE,
        )
        sanitized = re.sub(
            r"((?:secret|token|api_key|access_token)\s*=\s*)([^\s;'\"]+)",
            r"\1****",
            sanitized,
            flags=re.IGNORECASE,
        )

        if not sanitized.strip():
            return f"{exc_type}: [Redacted error details]"

        # Preserve exception type prefix if not already present
        if raw_msg.startswith(f"{exc_type}:"):
            return sanitized
        return f"{exc_type}: {sanitized}"
    except Exception:
        return "SanitizedError: [An error occurred but details were redacted for security]"


# ===========================================================================
# Inspection Data Structures
# ===========================================================================

@dataclass
class ConnectionIdentity:
    database_name: str
    current_user: str
    server_ip: str | None
    server_port: int | None
    pg_version: str


@dataclass
class TLSSessionStatus:
    ssl_active: bool | None
    ssl_version: str | None
    cipher: str | None
    bits: int | None
    client_dn: str | None
    query_permitted: bool
    note: str


def get_expected_alembic_head() -> str | None:
    """Determine expected Alembic head revision from repository migration files.

    Dynamically inspects backend/alembic script directory without connecting to DB.
    Returns the single head revision ID (e.g. '013'), or None if unavailable.
    """
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        cfg = Config()
        cfg.set_main_option("script_location", _ALEMBIC_DIR)
        sd = ScriptDirectory.from_config(cfg)
        heads = sd.get_heads()
        if heads and len(heads) == 1:
            return heads[0]
        return None
    except Exception as exc:
        logger.warning("Could not determine Alembic head from scripts: %s", exc)
        return None


@dataclass
class AlembicRevisionStatus:
    table_exists: bool
    revisions: list[str] = field(default_factory=list)
    row_count: int = 0
    expected_revision: str | None = None
    query_permitted: bool = True
    note: str = ""


@dataclass
class SchemaTableInventory:
    existing_schemas: list[str] = field(default_factory=list)
    missing_schemas: list[str] = field(default_factory=list)
    tables_by_schema: dict[str, list[str]] = field(default_factory=dict)
    total_tables: int = 0


@dataclass
class Migration008Preconditions:
    table_exists: bool
    required_columns_present: bool
    missing_columns: list[str] = field(default_factory=list)
    hard_duplicate_groups: list[dict[str, Any]] = field(default_factory=list)
    hard_duplicate_count: int = 0
    violates_unique_constraint: bool = False
    note: str = ""


@dataclass
class ForeignKeyCheck:
    migration_id: str
    source_schema: str
    source_table: str
    foreign_key_column: str
    target_table: str
    target_column: str
    table_exists: bool
    column_exists: bool
    orphan_count: int = 0
    status: str = "OK"  # OK, ORPHANS_FOUND, OBJECT_NOT_FOUND, USERS_TABLE_MISSING
    note: str = ""


@dataclass
class RolePrivilegesStatus:
    current_user: str
    can_create_database: bool | None
    can_create_in_public: bool | None
    is_superuser: bool | None = None
    schema_create_privileges: dict[str, bool | None] = field(default_factory=dict)
    schema_usage_privileges: dict[str, bool | None] = field(default_factory=dict)
    table_write_privileges: dict[str, dict[str, bool | None]] = field(default_factory=dict)
    is_least_privilege_ro: bool = False
    privilege_discrepancies: list[str] = field(default_factory=list)
    unknown_privileges: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class StagingInspectionReport:
    audit_timestamp_utc: str
    target_database_configured: str
    connection_identity: ConnectionIdentity | None = None
    tls_session: TLSSessionStatus | None = None
    alembic_revision: AlembicRevisionStatus | None = None
    schema_inventory: SchemaTableInventory | None = None
    users_contract: ContractValidationResult | None = None
    migration_008_preconditions: Migration008Preconditions | None = None
    foreign_key_checks: list[ForeignKeyCheck] = field(default_factory=list)
    role_privileges: RolePrivilegesStatus | None = None
    overall_status: str = "INCOMPLETE"  # CLEAN, DISCREPANCIES_FOUND, INCOMPLETE
    is_complete: bool = False
    discrepancies: list[str] = field(default_factory=list)
    checks_unable_to_run: list[str] = field(default_factory=list)
    cleanup_diagnostics: list[str] = field(default_factory=list)
    read_only_confirmed: bool = False
    discrepancies_found: bool = False
    execution_error: str | None = None
    safe_connection_summary: str = ""


# ===========================================================================
# Task 1: Fail-Closed Configuration
# ===========================================================================

def check_preflight_config() -> DatabaseSettings:
    """Validate all staging configuration fail-closed before any connection.

    Requirements:
      1. STAGING_MODE=true in the process environment.
      2. .env.staging exists at the repository root.
      3. staging_guard.load_staging_environment() succeeds without OS variable conflicts.
      4. staging_guard.validate_staging_target() confirms DB_NAME=ZKP_SBOM_STAGING.
      5. DB_SSL_MODE is strictly normalized 'verify-full'.
      6. DB_SSL_ROOT_CERT points to an existing, readable, regular, non-empty CA file.
      7. Secrets and passwords are never returned or logged.
    """
    # 1. Require explicit STAGING_MODE=true
    mode = os.environ.get("STAGING_MODE", "").strip().lower()
    if mode != "true":
        raise ConfigurationError(
            "STAGING_MODE=true is strictly required in the process environment. "
            "Refusing to execute staging inspection without explicit staging mode."
        )

    # 2. Require .env.staging file
    repo_root = os.path.abspath(os.path.join(_BACKEND_DIR, ".."))
    env_staging_path = os.path.join(repo_root, ".env.staging")
    if not os.path.exists(env_staging_path) or not os.path.isfile(env_staging_path):
        raise ConfigurationError(
            f"Staging configuration file missing or not a regular file: '{env_staging_path}'. "
            "Cannot run inspection without an authorized staging environment file."
        )

    # 3. Load staging environment via staging_guard
    try:
        staging_guard.load_staging_environment()
    except StagingConfigError as err:
        raise ConfigurationError(f"Staging environment load failed: {err}") from err

    # 4. Validate staging target (DB_NAME, DB_HOST, DB_PORT)
    try:
        staging_guard.validate_staging_target()
    except StagingConfigError as err:
        raise ConfigurationError(f"Staging target validation failed: {err}") from err

    # 5. Build settings from loaded environment
    settings = get_db_settings()

    # Enforce database name
    if settings.name != "ZKP_SBOM_STAGING":
        raise ConfigurationError(
            f"Configured database name is '{settings.name}'; "
            "must be exactly 'ZKP_SBOM_STAGING'."
        )

    # Enforce DB_SSL_MODE=verify-full
    if settings.normalized_ssl_mode != "verify-full":
        raise ConfigurationError(
            f"Staging inspection harness strictly requires DB_SSL_MODE='verify-full', "
            f"found '{settings.ssl_mode}'."
        )

    # Enforce CA certificate
    if not settings.ssl_root_cert or not settings.ssl_root_cert.strip():
        raise ConfigurationError(
            "DB_SSL_ROOT_CERT is required when DB_SSL_MODE is 'verify-full'."
        )

    cert_path = settings.ssl_root_cert.strip()
    if not os.path.exists(cert_path) or not os.path.isfile(cert_path):
        raise ConfigurationError(
            f"Configured DB_SSL_ROOT_CERT does not exist or is not a regular file: '{cert_path}'"
        )
    if not os.access(cert_path, os.R_OK):
        raise ConfigurationError(
            f"Configured DB_SSL_ROOT_CERT is not readable: '{cert_path}'"
        )
    if os.path.getsize(cert_path) == 0:
        raise ConfigurationError(
            f"Configured DB_SSL_ROOT_CERT file is empty: '{cert_path}'"
        )

    # Validate TLS settings through DatabaseSettings
    settings.validate_tls()

    return settings


# ===========================================================================
# Task 3: Inspection Functions (All Read-Only)
# ===========================================================================

def inspect_connection_identity(conn: Connection) -> ConnectionIdentity:
    """Inspect database name, connected user, server IP/port, and PG version."""
    res = conn.execute(
        text(
            "SELECT current_database() AS db_name, "
            "       current_user AS connected_user, "
            "       inet_server_addr() AS server_ip, "
            "       inet_server_port() AS server_port, "
            "       version() AS pg_version"
        )
    ).mappings().fetchone()

    if not res:
        raise RuntimeError("Failed to retrieve connection identity from catalog.")

    db_name = str(res["db_name"])
    if db_name != "ZKP_SBOM_STAGING":
        raise RuntimeError(
            f"Target database mismatch! Connected to '{db_name}', expected 'ZKP_SBOM_STAGING'."
        )

    server_ip = str(res["server_ip"]) if res["server_ip"] is not None else None
    server_port = int(res["server_port"]) if res["server_port"] is not None else None

    return ConnectionIdentity(
        database_name=db_name,
        current_user=str(res["connected_user"]),
        server_ip=server_ip,
        server_port=server_port,
        pg_version=str(res["pg_version"]),
    )


def inspect_tls_session_status(conn: Connection) -> TLSSessionStatus:
    """Query pg_stat_ssl for the current session PID."""
    try:
        res = conn.execute(
            text(
                "SELECT ssl, version, cipher, bits, client_dn "
                "FROM pg_stat_ssl "
                "WHERE pid = pg_backend_pid()"
            )
        ).mappings().fetchone()

        if res:
            return TLSSessionStatus(
                ssl_active=bool(res["ssl"]),
                ssl_version=str(res["version"]) if res["version"] else None,
                cipher=str(res["cipher"]) if res["cipher"] else None,
                bits=int(res["bits"]) if res["bits"] is not None else None,
                client_dn=str(res["client_dn"]) if res["client_dn"] else None,
                query_permitted=True,
                note=(
                    "TLS session is active on connected backend. Note: pg_stat_ssl catalog "
                    "establishes wire encryption on the backend PID, but does not independently "
                    "prove server hostname validation; hostname verification is enforced by libpq."
                ),
            )
        return TLSSessionStatus(
            ssl_active=None,
            ssl_version=None,
            cipher=None,
            bits=None,
            client_dn=None,
            query_permitted=True,
            note="pg_stat_ssl returned no rows for current backend PID.",
        )
    except Exception as exc:
        safe_exc = sanitize_exception_message(exc)
        return TLSSessionStatus(
            ssl_active=None,
            ssl_version=None,
            cipher=None,
            bits=None,
            client_dn=None,
            query_permitted=False,
            note=f"Unable to query pg_stat_ssl: {safe_exc}",
        )


def inspect_alembic_revision(
    conn: Connection, expected_head: str | None = None
) -> AlembicRevisionStatus:
    """Check existence of public.alembic_version and query recorded revisions."""
    expected = expected_head or get_expected_alembic_head()
    try:
        # First check table existence
        res_exists = conn.execute(
            text(
                "SELECT EXISTS ("
                "    SELECT 1 FROM information_schema.tables "
                "    WHERE table_schema = 'public' AND table_name = 'alembic_version'"
                ")"
            )
        ).scalar()

        if not res_exists:
            return AlembicRevisionStatus(
                table_exists=False,
                revisions=[],
                row_count=0,
                expected_revision=expected,
                query_permitted=True,
                note="public.alembic_version table is absent (unversioned database).",
            )

        res_revs = conn.execute(
            text("SELECT version_num FROM public.alembic_version ORDER BY version_num")
        ).fetchall()
        revisions = [str(row[0]) for row in res_revs]

        if not revisions:
            note = "Empty version table."
        elif expected and revisions == [expected]:
            note = f"Single expected revision recorded ({expected})."
        elif expected and len(revisions) == 1 and revisions[0] != expected:
            note = f"Recorded revision '{revisions[0]}' differs from expected repository head '{expected}'."
        else:
            note = f"Multiple revisions found ({len(revisions)})."

        return AlembicRevisionStatus(
            table_exists=True,
            revisions=revisions,
            row_count=len(revisions),
            expected_revision=expected,
            query_permitted=True,
            note=note,
        )
    except Exception as exc:
        safe_exc = sanitize_exception_message(exc)
        return AlembicRevisionStatus(
            table_exists=False,
            revisions=[],
            row_count=0,
            expected_revision=expected,
            query_permitted=False,
            note=f"Unable to query alembic_version: {safe_exc}",
        )


def inspect_schema_and_tables(
    conn: Connection, schemas: tuple[str, ...] = PROJECT_SCHEMAS
) -> SchemaTableInventory:
    """Inventory project schemas and base tables."""
    # Existing schemas
    res_schemas = conn.execute(
        text(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name IN :schemas "
            "ORDER BY schema_name"
        ),
        {"schemas": schemas},
    ).fetchall()
    existing_schemas = [str(row[0]) for row in res_schemas]
    missing_schemas = [s for s in schemas if s not in existing_schemas]

    # Tables by schema
    res_tables = conn.execute(
        text(
            "SELECT table_schema, table_name "
            "FROM information_schema.tables "
            "WHERE table_schema IN :schemas AND table_type = 'BASE TABLE' "
            "ORDER BY table_schema, table_name"
        ),
        {"schemas": schemas},
    ).fetchall()

    tables_by_schema: dict[str, list[str]] = {s: [] for s in existing_schemas}
    total = 0
    for s_name, t_name in res_tables:
        s_str = str(s_name)
        t_str = str(t_name)
        if s_str in tables_by_schema:
            tables_by_schema[s_str].append(t_str)
            total += 1

    return SchemaTableInventory(
        existing_schemas=existing_schemas,
        missing_schemas=missing_schemas,
        tables_by_schema=tables_by_schema,
        total_tables=total,
    )


def inspect_migration_008_preconditions(conn: Connection) -> Migration008Preconditions:
    """Inspect verification_requests for duplicate groups violating uq_verification_request_idempotency.

    Derived from 008_verification_idempotency_result_width.py:
      Constraint columns: ['user_id', 'sbom_root', 'vulnerability_db_root', 'policy_hash', 'proof_job_id']
      PostgreSQL UNIQUE semantics: In standard PostgreSQL, two rows conflict if and only if
      all columns in the tuple match and NONE of the columns are NULL.
    """
    # 1. Check table existence
    res_tbl = conn.execute(
        text(
            "SELECT EXISTS ("
            "    SELECT 1 FROM information_schema.tables "
            "    WHERE table_schema = 'verification' AND table_name = 'verification_requests'"
            ")"
        )
    ).scalar()

    if not res_tbl:
        return Migration008Preconditions(
            table_exists=False,
            required_columns_present=False,
            note="Table verification.verification_requests does not exist; check skipped.",
        )

    # 2. Check required columns existence
    target_cols = ["user_id", "sbom_root", "vulnerability_db_root", "policy_hash", "proof_job_id"]
    res_cols = conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'verification' AND table_name = 'verification_requests'"
        )
    ).fetchall()
    existing_cols = {str(r[0]) for r in res_cols}
    missing_cols = [c for c in target_cols if c not in existing_cols]

    if missing_cols:
        return Migration008Preconditions(
            table_exists=True,
            required_columns_present=False,
            missing_columns=missing_cols,
            note=f"Required columns missing in verification_requests: {missing_cols}; duplicate check skipped.",
        )

    # 3. Query duplicate groups under PostgreSQL UNIQUE constraint semantics (all non-null)
    query = text(
        "SELECT user_id, sbom_root, vulnerability_db_root, policy_hash, proof_job_id, "
        "       count(*) AS dup_count "
        "FROM verification.verification_requests "
        "WHERE user_id IS NOT NULL "
        "  AND sbom_root IS NOT NULL "
        "  AND vulnerability_db_root IS NOT NULL "
        "  AND policy_hash IS NOT NULL "
        "  AND proof_job_id IS NOT NULL "
        "GROUP BY user_id, sbom_root, vulnerability_db_root, policy_hash, proof_job_id "
        "HAVING count(*) > 1"
    )
    res_dups = conn.execute(query).mappings().fetchall()

    hard_dups = [
        {
            "user_id": str(r["user_id"]),
            "sbom_root": str(r["sbom_root"]),
            "vulnerability_db_root": str(r["vulnerability_db_root"]),
            "policy_hash": str(r["policy_hash"]),
            "proof_job_id": str(r["proof_job_id"]),
            "count": int(r["dup_count"]),
        }
        for r in res_dups
    ]

    violates = len(hard_dups) > 0
    note = (
        f"Found {len(hard_dups)} duplicate group(s) that would violate uq_verification_request_idempotency."
        if violates
        else "No duplicate groups found; table is compliant with migration 008 unique constraint."
    )

    return Migration008Preconditions(
        table_exists=True,
        required_columns_present=True,
        missing_columns=[],
        hard_duplicate_groups=hard_dups,
        hard_duplicate_count=len(hard_dups),
        violates_unique_constraint=violates,
        note=note,
    )


def inspect_foreign_key_preconditions(conn: Connection) -> list[ForeignKeyCheck]:
    """Inspect orphan references for user foreign keys added in migrations 011 and 013.

    Definitions:
      Migration 011:
        1. sbom.applications.user_id -> public.users.id
        2. verification.verification_requests.user_id -> public.users.id
        3. vulnerability.vulnerability_snapshots.created_by -> public.users.id
        4. zkp.proof_jobs.user_id -> public.users.id
      Migration 013:
        5. vulnerability.vulnerability_snapshots.frozen_by -> public.users.id
        6. vulnerability.vulnerability_snapshots.approved_by -> public.users.id
        7. vulnerability.vulnerability_snapshots.revoked_by -> public.users.id
    """
    fk_targets = [
        # (migration_id, schema, table, column, target_table, target_column)
        ("011", "sbom", "applications", "user_id", "users", "id"),
        ("011", "verification", "verification_requests", "user_id", "users", "id"),
        ("011", "vulnerability", "vulnerability_snapshots", "created_by", "users", "id"),
        ("011", "zkp", "proof_jobs", "user_id", "users", "id"),
        ("013", "vulnerability", "vulnerability_snapshots", "frozen_by", "users", "id"),
        ("013", "vulnerability", "vulnerability_snapshots", "approved_by", "users", "id"),
        ("013", "vulnerability", "vulnerability_snapshots", "revoked_by", "users", "id"),
    ]

    # Check if public.users exists
    res_users = conn.execute(
        text(
            "SELECT EXISTS ("
            "    SELECT 1 FROM information_schema.tables "
            "    WHERE table_schema = 'public' AND table_name = 'users'"
            ")"
        )
    ).scalar()
    users_exist = bool(res_users)

    results: list[ForeignKeyCheck] = []
    for mig_id, schema, table, col, tgt_table, tgt_col in fk_targets:
        # Check source table exists
        res_tbl = conn.execute(
            text(
                "SELECT EXISTS ("
                "    SELECT 1 FROM information_schema.tables "
                "    WHERE table_schema = :schema AND table_name = :table"
                ")"
            ),
            {"schema": schema, "table": table},
        ).scalar()
        if not res_tbl:
            results.append(
                ForeignKeyCheck(
                    migration_id=mig_id,
                    source_schema=schema,
                    source_table=table,
                    foreign_key_column=col,
                    target_table=tgt_table,
                    target_column=tgt_col,
                    table_exists=False,
                    column_exists=False,
                    status="OBJECT_NOT_FOUND",
                    note=f"Table {schema}.{table} does not exist.",
                )
            )
            continue

        # Check column exists
        res_col = conn.execute(
            text(
                "SELECT EXISTS ("
                "    SELECT 1 FROM information_schema.columns "
                "    WHERE table_schema = :schema AND table_name = :table AND column_name = :col"
                ")"
            ),
            {"schema": schema, "table": table, "col": col},
        ).scalar()
        if not res_col:
            results.append(
                ForeignKeyCheck(
                    migration_id=mig_id,
                    source_schema=schema,
                    source_table=table,
                    foreign_key_column=col,
                    target_table=tgt_table,
                    target_column=tgt_col,
                    table_exists=True,
                    column_exists=False,
                    status="OBJECT_NOT_FOUND",
                    note=f"Column {col} does not exist in {schema}.{table}.",
                )
            )
            continue

        if not users_exist:
            results.append(
                ForeignKeyCheck(
                    migration_id=mig_id,
                    source_schema=schema,
                    source_table=table,
                    foreign_key_column=col,
                    target_table=tgt_table,
                    target_column=tgt_col,
                    table_exists=True,
                    column_exists=True,
                    status="USERS_TABLE_MISSING",
                    note="Referenced table public.users does not exist; cannot evaluate orphan references.",
                )
            )
            continue

        # Count orphans (safe read-only SELECT)
        query = text(
            f'SELECT count(*) FROM "{schema}"."{table}" child '
            f'WHERE child."{col}" IS NOT NULL '
            f'  AND NOT EXISTS (SELECT 1 FROM public.users parent WHERE parent.id = child."{col}")'
        )
        orphan_count = int(conn.execute(query).scalar() or 0)
        status = "OK" if orphan_count == 0 else "ORPHANS_FOUND"
        note = (
            f"Found {orphan_count} orphan reference(s) pointing to non-existent user IDs."
            if orphan_count > 0
            else "Clean: zero orphan references found."
        )

        results.append(
            ForeignKeyCheck(
                migration_id=mig_id,
                source_schema=schema,
                source_table=table,
                foreign_key_column=col,
                target_table=tgt_table,
                target_column=tgt_col,
                table_exists=True,
                column_exists=True,
                orphan_count=orphan_count,
                status=status,
                note=note,
            )
        )

    return results


def inspect_role_privileges(conn: Connection) -> RolePrivilegesStatus:
    """Verify effective permissions of the connected role across all project schemas."""
    unknown_privileges: list[str] = []
    privilege_discrepancies: list[str] = []
    warnings: list[str] = []

    # 1. Connected role name
    try:
        res_u = conn.execute(text("SELECT current_user AS u")).mappings().fetchone()
        current_user = str(res_u["u"]) if res_u else "unknown"
    except Exception as exc:
        current_user = "unknown"
        unknown_privileges.append(f"Failed to query current_user: {sanitize_exception_message(exc)}")

    # 2. Database-level CREATE privilege
    can_create_db: bool | None = None
    try:
        res_db = conn.execute(
            text("SELECT has_database_privilege(current_user, current_database(), 'CREATE')")
        ).scalar()
        can_create_db = bool(res_db) if res_db is not None else None
    except Exception as exc:
        can_create_db = None
        unknown_privileges.append(f"Database CREATE privilege check failed: {sanitize_exception_message(exc)}")

    if can_create_db is True:
        msg = "Connected role possesses CREATE privilege on database (not strictly read-only)."
        privilege_discrepancies.append(msg)
        warnings.append(msg)

    # 3. Superuser status
    is_superuser: bool | None = None
    try:
        res_sup = conn.execute(text("SELECT current_setting('is_superuser')")).scalar()
        if res_sup is not None:
            is_superuser = str(res_sup).strip().lower() in ("on", "true", "yes", "1")
    except Exception:
        try:
            res_sup2 = conn.execute(
                text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            ).scalar()
            is_superuser = bool(res_sup2) if res_sup2 is not None else None
        except Exception as exc:
            is_superuser = None
            unknown_privileges.append(f"Superuser status check failed: {sanitize_exception_message(exc)}")

    if is_superuser is True:
        msg = "Connected role is a PostgreSQL SUPERUSER (violates least-privilege read-only)."
        privilege_discrepancies.append(msg)
        warnings.append(msg)

    # 4. Schema-level CREATE and USAGE privileges for all PROJECT_SCHEMAS
    schema_create: dict[str, bool | None] = {}
    schema_usage: dict[str, bool | None] = {}
    for s in PROJECT_SCHEMAS:
        # CREATE
        try:
            res_sc = conn.execute(
                text("SELECT has_schema_privilege(:u, :s, 'CREATE')"),
                {"u": current_user, "s": s},
            ).scalar()
            c_val = bool(res_sc) if res_sc is not None else None
            schema_create[s] = c_val
            if c_val is True:
                msg = f"Connected role possesses CREATE privilege on schema '{s}' (not strictly read-only)."
                privilege_discrepancies.append(msg)
                warnings.append(msg)
        except Exception as exc:
            schema_create[s] = None
            unknown_privileges.append(f"Schema '{s}' CREATE privilege check failed: {sanitize_exception_message(exc)}")

        # USAGE
        try:
            res_su = conn.execute(
                text("SELECT has_schema_privilege(:u, :s, 'USAGE')"),
                {"u": current_user, "s": s},
            ).scalar()
            schema_usage[s] = bool(res_su) if res_su is not None else None
        except Exception as exc:
            schema_usage[s] = None
            unknown_privileges.append(f"Schema '{s}' USAGE privilege check failed: {sanitize_exception_message(exc)}")

    can_create_public = schema_create.get("public")

    # 5. Table-level write privileges across PROJECT_SCHEMAS
    table_writes: dict[str, dict[str, bool | None]] = {}
    try:
        res_tables = conn.execute(
            text(
                "SELECT table_schema, table_name "
                "FROM information_schema.tables "
                "WHERE table_schema IN :schemas AND table_type = 'BASE TABLE' "
                "ORDER BY table_schema, table_name"
            ),
            {"schemas": PROJECT_SCHEMAS},
        ).fetchall()

        for s_row, t_row in res_tables:
            tbl_full = f"{s_row}.{t_row}"
            table_writes[tbl_full] = {}
            for action in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                try:
                    res_act = conn.execute(
                        text(f"SELECT has_table_privilege(:u, '\"{s_row}\".\"{t_row}\"', :act)"),
                        {"u": current_user, "act": action},
                    ).scalar()
                    val = bool(res_act) if res_act is not None else None
                    table_writes[tbl_full][action] = val
                    if val is True:
                        msg = f"Connected role possesses {action} privilege on table {tbl_full} (not strictly read-only)."
                        privilege_discrepancies.append(msg)
                        warnings.append(msg)
                except Exception as exc:
                    table_writes[tbl_full][action] = None
                    unknown_privileges.append(f"Table {tbl_full} {action} privilege check failed: {sanitize_exception_message(exc)}")
    except Exception as exc:
        unknown_privileges.append(f"Failed to query tables for privilege check: {sanitize_exception_message(exc)}")

    # Least privilege determination:
    # Must have 0 privilege discrepancies AND 0 unknown privileges AND not superuser AND not create_db
    is_ro = (
        len(privilege_discrepancies) == 0
        and len(unknown_privileges) == 0
        and is_superuser is False
        and can_create_db is False
    )

    return RolePrivilegesStatus(
        current_user=current_user,
        can_create_database=can_create_db,
        can_create_in_public=can_create_public,
        is_superuser=is_superuser,
        schema_create_privileges=schema_create,
        schema_usage_privileges=schema_usage,
        table_write_privileges=table_writes,
        is_least_privilege_ro=is_ro,
        privilege_discrepancies=privilege_discrepancies,
        unknown_privileges=unknown_privileges,
        warnings=warnings,
    )


# ===========================================================================
# Task 2: Inspection Engine Orchestrator
# ===========================================================================

def run_staging_inspection(
    engine: Engine | None = None,
    settings: DatabaseSettings | None = None,
) -> StagingInspectionReport:
    """Execute complete read-only staging audit in a single read-only transaction."""
    now_utc = datetime.now(timezone.utc).isoformat()

    # 1. Preflight checks
    if settings is None:
        settings = check_preflight_config()

    report = StagingInspectionReport(
        audit_timestamp_utc=now_utc,
        target_database_configured=settings.name,
        safe_connection_summary=f"host={settings.host}, port={settings.port}, db={settings.name}, sslmode={settings.normalized_ssl_mode}",
    )

    # 2. Establish connection if engine not injected
    if engine is None:
        engine = create_engine(
            settings.url,
            poolclass=pool.NullPool,
            connect_args=settings.connect_args,
        )

    # 3. Connect and enforce read-only transaction fail-closed
    conn: Connection | None = None
    try:
        try:
            conn = engine.connect()
        except Exception as conn_exc:
            safe_conn_err = sanitize_exception_message(conn_exc)
            report.execution_error = safe_conn_err
            report.overall_status = "INCOMPLETE"
            report.checks_unable_to_run.append(
                f"Connection acquisition failed: {safe_conn_err}"
            )
            report.is_complete = False
            raise conn_exc

        # Enforce explicit READ ONLY transaction
        conn.execute(text("BEGIN TRANSACTION READ ONLY;"))

        # Verify PostgreSQL confirmed read-only mode
        res_ro = conn.execute(text("SHOW transaction_read_only;")).scalar()
        if str(res_ro).strip().lower() not in ("on", "true"):
            raise RuntimeError(
                f"PostgreSQL SHOW transaction_read_only returned '{res_ro}', expected 'on'. "
                "Refusing to execute inspection in a non-read-only session."
            )
        report.read_only_confirmed = True

        # Check 1: Connection Identity
        report.connection_identity = inspect_connection_identity(conn)

        # Check 2: TLS Session
        report.tls_session = inspect_tls_session_status(conn)

        # Check 3: Alembic Revision
        report.alembic_revision = inspect_alembic_revision(conn)

        # Check 4: Schemas & Tables Inventory
        report.schema_inventory = inspect_schema_and_tables(conn)

        # Check 5: public.users Contract
        report.users_contract = staging_guard.validate_users_contract(conn)

        # Check 6: Migration 008 Preconditions
        report.migration_008_preconditions = inspect_migration_008_preconditions(conn)

        # Check 7: Migration 011 and 013 Foreign Key Preconditions
        report.foreign_key_checks = inspect_foreign_key_preconditions(conn)

        # Check 8: Role Privileges
        report.role_privileges = inspect_role_privileges(conn)

        # ===================================================================
        # Forensic Evaluation: Discrepancies vs Incomplete Checks
        # ===================================================================
        discrepancies: list[str] = []
        checks_unable_to_run: list[str] = []

        # 1. Schemas inventory
        if report.schema_inventory.missing_schemas:
            checks_unable_to_run.append(
                f"Project schema(s) missing from catalog: {report.schema_inventory.missing_schemas}"
            )

        # 2. public.users Contract / Baseline Check
        if not report.users_contract.exists:
            discrepancies.append("Prerequisite baseline table 'public.users' is absent.")
            checks_unable_to_run.append(
                "Table 'public.users' absent; downstream user foreign key orphan checks cannot verify parent keys."
            )
        elif not report.users_contract.is_valid:
            discrepancies.append(
                f"public.users schema contract violation: {'; '.join(report.users_contract.discrepancies)}"
            )

        # 3. Alembic Revision Evaluation
        if report.alembic_revision is None or not report.alembic_revision.query_permitted:
            note = report.alembic_revision.note if report.alembic_revision else "Check not run"
            checks_unable_to_run.append(f"Alembic revision state cannot be queried: {note}")
        elif not report.alembic_revision.table_exists:
            checks_unable_to_run.append(
                "Alembic revision table 'public.alembic_version' is absent (unversioned database)."
            )
        elif report.alembic_revision.row_count == 0:
            checks_unable_to_run.append(
                "Alembic revision table 'public.alembic_version' exists but is empty (no migration recorded)."
            )
        else:
            exp_head = report.alembic_revision.expected_revision
            if not exp_head:
                checks_unable_to_run.append(
                    "Unable to verify revision against expected head: repository migration head could not be resolved."
                )
            elif report.alembic_revision.revisions != [exp_head]:
                discrepancies.append(
                    f"Alembic revision state mismatch: observed {report.alembic_revision.revisions}, "
                    f"expected repository head '{exp_head}'. "
                    "(Database is at an unexpected migration revision; requires migration or reconciliation, "
                    "distinct from baseline absence)."
                )

        # 4. Migration 008 (Verification Idempotency)
        if not report.migration_008_preconditions.table_exists:
            checks_unable_to_run.append(
                "Table verification.verification_requests is absent; migration 008 unique constraint precondition unverified."
            )
        elif not report.migration_008_preconditions.required_columns_present:
            checks_unable_to_run.append(
                f"Required column(s) missing in verification.verification_requests: {report.migration_008_preconditions.missing_columns}; migration 008 unique constraint precondition unverified."
            )
        elif report.migration_008_preconditions.violates_unique_constraint:
            discrepancies.append(
                f"Migration 008 unique key duplicate conflict: {report.migration_008_preconditions.hard_duplicate_count} duplicate group(s) in verification.verification_requests."
            )

        # 5. Foreign Keys (Migrations 011 & 013)
        for fk in report.foreign_key_checks:
            if fk.status == "OBJECT_NOT_FOUND":
                checks_unable_to_run.append(
                    f"Target object missing for Rev {fk.migration_id} FK check: {fk.source_schema}.{fk.source_table}.{fk.foreign_key_column} ({fk.note})"
                )
            elif fk.status == "USERS_TABLE_MISSING":
                checks_unable_to_run.append(
                    f"Target public.users missing for Rev {fk.migration_id} FK check: {fk.source_schema}.{fk.source_table}.{fk.foreign_key_column}"
                )
            elif fk.orphan_count > 0:
                discrepancies.append(
                    f"Rev {fk.migration_id} foreign key orphan conflict: {fk.orphan_count} orphan row(s) in {fk.source_schema}.{fk.source_table}.{fk.foreign_key_column}"
                )

        # 6. Role Privileges Security Findings & Unknowns
        if report.role_privileges:
            for p_disc in report.role_privileges.privilege_discrepancies:
                discrepancies.append(f"Security finding (privilege): {p_disc}")
            for u_priv in report.role_privileges.unknown_privileges:
                checks_unable_to_run.append(f"Role privilege check incomplete: {u_priv}")

        # 7. TLS Session Check
        if report.tls_session is None:
            checks_unable_to_run.append("TLS session catalog check was not executed.")
        elif not report.tls_session.query_permitted:
            checks_unable_to_run.append(
                f"TLS session catalog check incomplete: {report.tls_session.note}"
            )
        elif report.tls_session.ssl_active is False:
            discrepancies.append(
                "Security finding (TLS): connected session PID is unencrypted "
                "(pg_stat_ssl reports ssl=False). Staging configuration requires verified TLS."
            )
        elif report.tls_session.ssl_active is not True:
            # Ambiguous or no rows returned for current PID
            checks_unable_to_run.append(
                f"TLS session catalog check unverified / ambiguous: {report.tls_session.note}"
            )

        # Store categorized findings
        report.discrepancies = discrepancies
        report.discrepancies_found = len(discrepancies) > 0
        report.checks_unable_to_run = checks_unable_to_run
        report.is_complete = len(checks_unable_to_run) == 0

        # Precedence Rule:
        # 1. If any confirmed discrepancy exists -> DISCREPANCIES_FOUND (preserving any incomplete checks).
        # 2. Else if any check was unable to run -> INCOMPLETE.
        # 3. Else (complete and zero discrepancies) -> CLEAN.
        if report.discrepancies_found:
            report.overall_status = "DISCREPANCIES_FOUND"
        elif not report.is_complete:
            report.overall_status = "INCOMPLETE"
        else:
            report.overall_status = "CLEAN"

    except Exception as exc:
        report.execution_error = sanitize_exception_message(exc)
        report.overall_status = "INCOMPLETE"
        raise exc
    finally:
        cleanup_diagnostics: list[str] = []
        if conn is not None:
            try:
                conn.execute(text("ROLLBACK;"))
            except Exception as rb_exc:
                safe_rb = sanitize_exception_message(rb_exc)
                cleanup_diagnostics.append(f"Rollback failure: {safe_rb}")
                logger.warning("Cleanup rollback failed: %s", safe_rb)

            try:
                conn.close()
            except Exception as cl_exc:
                safe_cl = sanitize_exception_message(cl_exc)
                cleanup_diagnostics.append(f"Connection close failure: {safe_cl}")
                logger.warning("Cleanup connection close failed: %s", safe_cl)

        if cleanup_diagnostics:
            report.cleanup_diagnostics = cleanup_diagnostics
            report.checks_unable_to_run.extend(cleanup_diagnostics)
            report.is_complete = False
            # If the report was marked CLEAN before cleanup, cleanup failure makes the result uncertain!
            if report.overall_status == "CLEAN":
                report.overall_status = "INCOMPLETE"

    return report


# ===========================================================================
# Task 4: Report Formatting
# ===========================================================================

def format_inspection_report(report: StagingInspectionReport) -> str:
    """Format the inspection report into a safe, credential-free markdown string."""
    lines: list[str] = [
        "# Staging Database Read-Only Inspection Audit Report",
        "",
        f"- **Audit Timestamp (UTC):** {report.audit_timestamp_utc}",
        f"- **Target Database Configured:** `{report.target_database_configured}`",
        f"- **Connection Summary:** `{report.safe_connection_summary}`",
        f"- **Read-Only Transaction Confirmed:** {'YES' if report.read_only_confirmed else 'NO'}",
        f"- **Overall Audit Status:** `{report.overall_status}`",
        f"- **Audit Completeness:** {'COMPLETE (All required checks ran successfully)' if report.is_complete else f'INCOMPLETE ({len(report.checks_unable_to_run)} check(s) unable to run/unverified)'}",
        f"- **Discrepancies / Conflict Findings:** {'YES (' + str(len(report.discrepancies)) + ' finding(s) require action)' if report.discrepancies_found else 'NONE (Clean)'}",
        "",
        "---",
        "",
        "## Overall Audit Evaluation Summary",
        f"- **Overall Status:** `{report.overall_status}`",
        f"- **Completeness Verified:** `{report.is_complete}`",
        f"- **Discrepancies Detected:** `{report.discrepancies_found}`",
    ]

    if report.discrepancies:
        lines.extend([
            "",
            "### Confirmed Discrepancies & Conflict Findings:",
        ])
        for d in report.discrepancies:
            lines.append(f"  - [!] {d}")

    if report.checks_unable_to_run:
        lines.extend([
            "",
            "### Incomplete / Skipped Checks (Prerequisites / Objects Missing):",
        ])
        for c in report.checks_unable_to_run:
            lines.append(f"  - [?] {c}")

    if report.cleanup_diagnostics:
        lines.extend([
            "",
            "### Cleanup Diagnostics (Rollback / Closure Errors):",
        ])
        for cd in report.cleanup_diagnostics:
            lines.append(f"  - [*] {cd}")

    lines.extend([
        "",
        "---",
        "",
        "## 1. Connection Identity & Engine",
    ])

    if report.connection_identity:
        ci = report.connection_identity
        lines.extend([
            f"- Connected Database: `{ci.database_name}`",
            f"- Connected User: `{ci.current_user}`",
            f"- Server IP / Port: `{ci.server_ip or 'unknown'}:{ci.server_port or 'unknown'}`",
            f"- PostgreSQL Version: {ci.pg_version}",
        ])
    else:
        lines.append("- Connection identity could not be retrieved.")

    lines.extend([
        "",
        "## 2. TLS Session Status",
    ])
    if report.tls_session:
        ts = report.tls_session
        lines.extend([
            f"- TLS Active: `{ts.ssl_active}`",
            f"- Protocol Version: `{ts.ssl_version or 'N/A'}`",
            f"- Cipher Suite: `{ts.cipher or 'N/A'}` ({ts.bits or 'N/A'} bits)",
            f"- Client DN: `{ts.client_dn or 'N/A'}`",
            f"- Note: {ts.note}",
        ])
    else:
        lines.append("- TLS session status could not be retrieved.")

    lines.extend([
        "",
        "## 3. Alembic Version State",
    ])
    if report.alembic_revision:
        ar = report.alembic_revision
        lines.extend([
            f"- Version Table Present: `{ar.table_exists}`",
            f"- Recorded Revisions: {ar.revisions if ar.revisions else 'None'}",
            f"- Expected Repository Head: `{ar.expected_revision or 'unknown'}`",
            f"- Row Count: {ar.row_count}",
            f"- Status: {ar.note}",
        ])
    else:
        lines.append("- Alembic version state could not be retrieved.")

    lines.extend([
        "",
        "## 4. Schema & Table Inventory",
    ])
    if report.schema_inventory:
        si = report.schema_inventory
        lines.extend([
            f"- Present Schemas: {', '.join(si.existing_schemas) if si.existing_schemas else 'None'}",
            f"- Missing Schemas: {', '.join(si.missing_schemas) if si.missing_schemas else 'None'}",
            f"- Total Base Tables Found: {si.total_tables}",
        ])
        for s, tables in si.tables_by_schema.items():
            lines.append(f"  - `{s}` ({len(tables)} tables): {', '.join(tables) if tables else 'none'}")
    else:
        lines.append("- Schema inventory could not be retrieved.")

    lines.extend([
        "",
        "## 5. public.users Baseline Contract",
    ])
    if report.users_contract:
        uc = report.users_contract
        lines.extend([
            f"- Table Exists: `{uc.exists}`",
            f"- Contract Valid: `{uc.is_valid}`",
        ])
        if uc.discrepancies:
            lines.append("- Discrepancies:")
            for d in uc.discrepancies:
                lines.append(f"  - [!] {d}")
        else:
            lines.append("- Discrepancies: None (Canonical User model contract satisfied)")
    else:
        lines.append("- Users contract could not be evaluated.")

    lines.extend([
        "",
        "## 6. Migration 008 Precondition (Verification Idempotency Unique Key)",
    ])
    if report.migration_008_preconditions:
        m8 = report.migration_008_preconditions
        lines.extend([
            f"- Table Present: `{m8.table_exists}`",
            f"- Required Columns Present: `{m8.required_columns_present}`",
            f"- Unique Key Conflict: `{'YES - DUPLICATES DETECTED' if m8.violates_unique_constraint else 'NO - CLEAN'}`",
            f"- Note: {m8.note}",
        ])
        if m8.hard_duplicate_groups:
            lines.append(f"- Duplicate Groups ({len(m8.hard_duplicate_groups)}):")
            for g in m8.hard_duplicate_groups:
                lines.append(f"  - user={g['user_id']}, sbom={g['sbom_root'][:16]}..., vuln={g['vulnerability_db_root'][:16]}..., count={g['count']}")
    else:
        lines.append("- Migration 008 preconditions could not be evaluated.")

    lines.extend([
        "",
        "## 7. Migration 011 and 013 Preconditions (User Foreign Keys & Orphans)",
    ])
    if report.foreign_key_checks:
        for fk in report.foreign_key_checks:
            lines.append(
                f"- [Rev {fk.migration_id}] `{fk.source_schema}.{fk.source_table}.{fk.foreign_key_column}` -> `public.{fk.target_table}.{fk.target_column}`: "
                f"Status=`{fk.status}`, Orphans=`{fk.orphan_count}` ({fk.note})"
            )
    else:
        lines.append("- Foreign key checks could not be evaluated.")

    lines.extend([
        "",
        "## 8. Connected Role Privileges",
    ])
    if report.role_privileges:
        rp = report.role_privileges
        lines.extend([
            f"- Connected User: `{rp.current_user}`",
            f"- Superuser: `{'YES' if rp.is_superuser else ('NO' if rp.is_superuser is False else 'UNKNOWN')}`",
            f"- Can CREATE Database: `{'YES' if rp.can_create_database else ('NO' if rp.can_create_database is False else 'UNKNOWN')}`",
            f"- Confirmed Least-Privilege Read-Only Account: `{rp.is_least_privilege_ro}`",
            "- Schema CREATE Privileges:",
        ])
        for s, can_c in rp.schema_create_privileges.items():
            c_str = "GRANTED" if can_c is True else ("NOT GRANTED" if can_c is False else "UNKNOWN")
            lines.append(f"  - `{s}`: {c_str}")
        lines.append("- Schema USAGE Privileges:")
        for s, can_u in rp.schema_usage_privileges.items():
            u_str = "GRANTED" if can_u is True else ("NOT GRANTED" if can_u is False else "UNKNOWN")
            lines.append(f"  - `{s}`: {u_str}")
        if rp.table_write_privileges:
            lines.append("- Table Write Privileges (INSERT/UPDATE/DELETE/TRUNCATE):")
            for tbl, actions in rp.table_write_privileges.items():
                act_str = ", ".join(f"{a}: {'GRANTED' if v is True else ('NOT GRANTED' if v is False else 'UNKNOWN')}" for a, v in actions.items())
                lines.append(f"  - `{tbl}`: {act_str}")
        if rp.privilege_discrepancies:
            lines.append("- Privilege Security Findings (Excessive Permissions):")
            for pd in rp.privilege_discrepancies:
                lines.append(f"  - [SECURITY FINDING] {pd}")
        if rp.unknown_privileges:
            lines.append("- Inconclusive Privilege Checks (Missing Metadata Visibility):")
            for up in rp.unknown_privileges:
                lines.append(f"  - [UNVERIFIED] {up}")
    else:
        lines.append("- Role privileges could not be evaluated.")

    lines.extend([
        "",
        "---",
        "",
        "## Explicit Safety Confirmation",
        "- NO REPAIR, MIGRATION, DDL, OR MUTATION WAS ATTEMPTED.",
        "- Zero writes, zero DDL, zero DML, and zero migrations were executed.",
        "- Inspection executed strictly inside `BEGIN TRANSACTION READ ONLY;` and concluded with `ROLLBACK;`.",
        "- No secret values or credentials were printed or recorded.",
        "- Inspection does NOT claim staging is migration-ready. Live migration authorization remains a separate gate.",
    ])

    return "\n".join(lines)


# ===========================================================================
# Main CLI Entry Point
# ===========================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="ZKP-SBOM Staging Database Read-Only Inspection Harness."
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional path to write markdown report (default: stdout).",
        default=None,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw structured JSON instead of markdown.",
    )
    args = parser.parse_args()

    try:
        report = run_staging_inspection()
        if args.json:
            # Safe JSON serialization (strip any non-serializable objects)
            output_str = json.dumps(
                {
                    "audit_timestamp_utc": report.audit_timestamp_utc,
                    "target_database_configured": report.target_database_configured,
                    "overall_status": report.overall_status,
                    "is_complete": report.is_complete,
                    "read_only_confirmed": report.read_only_confirmed,
                    "discrepancies_found": report.discrepancies_found,
                    "discrepancies": report.discrepancies,
                    "checks_unable_to_run": report.checks_unable_to_run,
                    "safe_connection_summary": report.safe_connection_summary,
                },
                indent=2,
            )
        else:
            output_str = format_inspection_report(report)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_str)
            print(f"Inspection report written to {args.output}")
        else:
            print(output_str)

        return 0 if report.overall_status == "CLEAN" else 1

    except Exception as exc:
        safe_msg = sanitize_exception_message(exc)
        print(f"FATAL: Staging inspection aborted: {safe_msg}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

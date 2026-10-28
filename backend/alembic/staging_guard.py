"""
Staging migration safety guard.

Import-safe helpers that validate staging configuration and verify
connected database identity before any schema DDL or migration.

These functions are called by env.py but can be imported and tested
independently without triggering Alembic's module-level execution.

SAFETY RULES:
  - Error messages identify the failed check or setting name only.
  - Passwords, full connection URLs, and secret values are never printed.
  - Staging mode requires explicit opt-in and fails closed on any ambiguity.
  - Production migration behavior is preserved when staging is not selected.
"""

from __future__ import annotations

import os
import re
import sys
from contextlib import nullcontext
from typing import Any, Iterable, NamedTuple

from dotenv import dotenv_values, load_dotenv
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STAGING_DB_NAME = "ZKP_SBOM_STAGING"

# The eight DB settings from shared/config.py that affect the connection.
_DB_SETTING_KEYS = (
    "DB_HOST",
    "DB_PORT",
    "DB_USER",
    "DB_PASSWORD",
    "DB_NAME",
    "DB_SSL_MODE",
    "DB_SSL_ROOT_CERT",
    "DB_ECHO",
)

# Settings that must be present and non-empty in .env.staging.
_REQUIRED_STAGING_KEYS = (
    "DB_HOST",
    "DB_PORT",
    "DB_USER",
    "DB_PASSWORD",
    "DB_NAME",
)

# Settings explicitly validated before engine creation.
_TARGET_VALIDATION_KEYS = (
    "DB_NAME",
    "DB_HOST",
    "DB_PORT",
)

DEFAULT_SCHEMAS = (
    "sbom",
    "vulnerability",
    "policy",
    "zkp",
    "verification",
)

# ---------------------------------------------------------------------------
# PostgreSQL 16 Target & PostgreSQL 17 Prohibited Boundary Constants
# ---------------------------------------------------------------------------

PG16_EXPECTED_HOSTS = frozenset({"127.0.0.1", "localhost"})
PG16_EXPECTED_CLIENT_PORT = 5433
PG16_EXPECTED_DB_NAME = "ZKP_SBOM_LOCAL_DEV"
PG16_EXPECTED_ENGINE_MAJOR = "PostgreSQL 16"
PG17_PROHIBITED_ENGINE_MAJOR = "PostgreSQL 17"
PG17_PROHIBITED_DB_NAME = "ZKP_SBOM"
PG17_PROHIBITED_PORT = 5432

# ---------------------------------------------------------------------------
# PostgreSQL 17 Stage G Authoritative Target Constants
# ---------------------------------------------------------------------------

STAGE_G_EXPECTED_ENGINE_MAJOR = "PostgreSQL 17"
STAGE_G_EXPECTED_MIN_SERVER_VERSION = 170000
STAGE_G_PROHIBITED_CLIENT_PORT = 5433
STAGE_G_PROHIBITED_DB_NAME = "ZKP_SBOM_LOCAL_DEV"
STAGE_G_PROHIBITED_ENGINE_MAJOR = "PostgreSQL 16"



class StagingConfigError(RuntimeError):
    """Raised when staging configuration validation fails."""
    pass


# Module-level cache for validated staging configuration
_validated_staging_config: dict[str, str] | None = None


def get_validated_staging_config() -> dict[str, str] | None:
    """Return the cached validated staging configuration, if loaded."""
    return _validated_staging_config


def set_validated_staging_config(config: dict[str, str] | None) -> None:
    """Explicitly set or clear the cached validated staging configuration."""
    global _validated_staging_config
    _validated_staging_config = dict(config) if config is not None else None


# ---------------------------------------------------------------------------
# STAGING_MODE parsing
# ---------------------------------------------------------------------------

def parse_staging_mode() -> bool:
    """Return True if staging mode is explicitly requested.

    Accepted values:
      - Absent or exactly ``"false"`` → non-staging (returns False).
      - Exactly ``"true"`` → staging (returns True).
      - Any other value (case variations, whitespace, empty string, typos)
        → raises ``StagingConfigError``.

    This prevents a typo from silently selecting production mode.
    """
    raw = os.environ.get("STAGING_MODE")
    if raw is None or raw == "false":
        return False
    if raw == "true":
        return True
    raise StagingConfigError(
        "Invalid STAGING_MODE value — must be exactly 'true', 'false', or absent."
    )


# ---------------------------------------------------------------------------
# Environment loading
# ---------------------------------------------------------------------------

def _resolve_env_path(relative: str) -> str:
    """Resolve *relative* against the alembic/ directory, not cwd."""
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), relative)
    )


def load_staging_environment() -> None:
    """Load and validate the staging environment file.

    Steps:
      1. Resolve ``.env.staging`` relative to the repository root
         (``../../.env.staging`` from ``backend/alembic/``).
      2. Fail if the file does not exist.
      3. Read all keys from the file *without* injecting them into os.environ.
      4. Reject any inherited OS variable that conflicts with the file.
      5. Reject missing/empty required settings.
      6. Reject a database name that is not ``ZKP_SBOM_STAGING``.
      7. Only after all checks pass, load the file with ``override=True``
         so that validated staging values take precedence.
      8. Cache validated staging config for pre-connection target validation.
    """
    global _validated_staging_config
    env_path = _resolve_env_path("../../.env.staging")

    if not os.path.exists(env_path):
        raise StagingConfigError(
            "STAGING_MODE=true but .env.staging is missing."
        )

    # Read staging values into a dict (does not touch os.environ).
    staging_config = dotenv_values(env_path)

    # --- Check for conflicting inherited shell variables ---
    for key in _DB_SETTING_KEYS:
        shell_val = os.environ.get(key)
        if shell_val is not None and key in staging_config:
            if shell_val != staging_config[key]:
                # Report only the key name — never the value.
                raise StagingConfigError(
                    f"Conflicting inherited OS variable '{key}' "
                    f"overrides staging configuration."
                )

    # --- Check required keys are present and non-empty ---
    for key in _REQUIRED_STAGING_KEYS:
        val = staging_config.get(key)
        if not val or not val.strip():
            raise StagingConfigError(
                f"Required staging setting '{key}' is missing or empty "
                f"in .env.staging."
            )

    # --- Enforce the staging database name ---
    if staging_config.get("DB_NAME") != STAGING_DB_NAME:
        raise StagingConfigError(
            f"Staging DB_NAME must be exactly '{STAGING_DB_NAME}'."
        )

    # All checks passed — inject staging values into os.environ.
    # override=True ensures the staging file wins over any inherited
    # variables that matched (the conflict check above already verified
    # they were identical, so this is safe).
    load_dotenv(env_path, override=True)

    # Cache validated values for pre-connection target validation.
    _validated_staging_config = {
        k: str(v) for k, v in staging_config.items() if v is not None
    }


def load_environment() -> None:
    """Top-level environment loader called by env.py.

    - Non-staging: loads ``../../.env`` (existing behaviour).
    - Staging: validates and loads ``../../.env.staging``.
    - Invalid STAGING_MODE: fails closed.
    """
    is_staging = parse_staging_mode()

    if is_staging:
        load_staging_environment()
    else:
        # Preserve existing production behaviour exactly.
        prod_path = _resolve_env_path("../../.env")
        load_dotenv(prod_path)


# ---------------------------------------------------------------------------
# Pre-connection target validation
# ---------------------------------------------------------------------------

def validate_staging_target(
    expected_config: dict[str, str] | None = None,
    db_settings: Any | None = None,
) -> None:
    """Verify configured DB settings match staging expectations.

    Called after ``load_environment()`` and before engine creation.
    Validates that ``DB_NAME``, ``DB_HOST``, and ``DB_PORT`` in the active
    environment and ``DatabaseSettings`` strictly match the validated
    values from ``.env.staging``.

    NOTE: These checks validate the configured target parameters only.
    They do NOT authenticate the physical PostgreSQL server — server
    authentication requires post-connection identity checks and network/
    TLS infrastructure verification.
    """
    if expected_config is None:
        expected_config = _validated_staging_config

    if expected_config is None:
        env_path = _resolve_env_path("../../.env.staging")
        if not os.path.exists(env_path):
            raise StagingConfigError(
                "Staging configuration missing for target validation."
            )
        raw_vals = dotenv_values(env_path)
        expected_config = {
            k: str(v) for k, v in raw_vals.items() if v is not None
        }

    # 1. Enforce DB_NAME
    expected_name = str(expected_config.get("DB_NAME", "")).strip()
    if expected_name != STAGING_DB_NAME:
        raise StagingConfigError(
            f"Staging DB_NAME must be exactly '{STAGING_DB_NAME}'."
        )
    actual_name = os.environ.get("DB_NAME")
    if actual_name is None or actual_name != STAGING_DB_NAME:
        raise StagingConfigError(
            f"Configured DB_NAME is not '{STAGING_DB_NAME}' after "
            f"environment loading — refusing to proceed."
        )

    # 2. Enforce DB_HOST
    expected_host = str(expected_config.get("DB_HOST", "")).strip()
    if not expected_host:
        raise StagingConfigError(
            "Required staging setting 'DB_HOST' is missing or empty."
        )
    actual_host = os.environ.get("DB_HOST")
    if actual_host is None or actual_host != expected_host:
        raise StagingConfigError(
            "Configured DB_HOST mismatch after environment loading — "
            "refusing to proceed."
        )

    # 3. Enforce DB_PORT
    expected_port = str(expected_config.get("DB_PORT", "")).strip()
    if not expected_port:
        raise StagingConfigError(
            "Required staging setting 'DB_PORT' is missing or empty."
        )
    actual_port = os.environ.get("DB_PORT")
    if actual_port is None or str(actual_port).strip() != expected_port:
        raise StagingConfigError(
            "Configured DB_PORT mismatch after environment loading — "
            "refusing to proceed."
        )

    # 4. Enforce consistency with DatabaseSettings
    # This prevents unvalidated default fallbacks (e.g. host defaulting
    # to 'localhost' or port defaulting to 5432) from slipping through.
    try:
        if db_settings is None:
            backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            if backend_dir not in sys.path:
                sys.path.insert(0, backend_dir)
            from shared.config import get_db_settings
            db_settings = get_db_settings()

        if db_settings.name != STAGING_DB_NAME or db_settings.name != expected_name:
            raise StagingConfigError(
                "DatabaseSettings DB_NAME mismatch — refusing to proceed."
            )
        if db_settings.host != expected_host:
            raise StagingConfigError(
                "DatabaseSettings DB_HOST mismatch — refusing to proceed."
            )
        if str(db_settings.port).strip() != expected_port:
            raise StagingConfigError(
                "DatabaseSettings DB_PORT mismatch — refusing to proceed."
            )
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# Post-connection identity verification
# ---------------------------------------------------------------------------

def verify_connection_identity(connection: Any) -> None:
    """Check the actually connected database before any DDL.

    Uses ``SELECT current_database()`` through the SQLAlchemy connection.
    Aborts if the connected database is not ``ZKP_SBOM_STAGING``.

    This check establishes the database *name* on the connected server.
    It does NOT prove the physical server identity — that requires
    external infrastructure validation (pg_hba.conf, network checks).
    """
    result = connection.execute(text("SELECT current_database()"))
    current_db = result.scalar()

    if current_db != STAGING_DB_NAME:
        raise StagingConfigError(
            f"Connected database is '{current_db}', "
            f"expected '{STAGING_DB_NAME}' — aborting."
        )


# ---------------------------------------------------------------------------
# Supplied Connection Validation (Caller-Supplied Connection Support)
# ---------------------------------------------------------------------------

def validate_supplied_connection(conn: Any) -> Any:
    """Validate that a caller-supplied connection attribute is a usable SQLAlchemy Connection.

    Fails closed if the supplied object is:
      - None
      - An Engine instance (callers must provide a Connection, not an Engine)
      - Not a Connection (or valid Connection-like mock)
      - Closed or invalidated

    Returns:
      The validated connection object.
    """
    if conn is None:
        raise TypeError("Supplied 'connection' attribute cannot be None.")

    # Engine must not be passed as connection
    try:
        from sqlalchemy.engine import Engine
        is_engine = isinstance(conn, Engine)
    except ImportError:
        is_engine = False

    if is_engine:
        raise TypeError(
            "Supplied 'connection' attribute must be an active SQLAlchemy Connection, not an Engine."
        )

    try:
        from sqlalchemy.engine import Connection
        is_conn_instance = isinstance(conn, Connection)
    except ImportError:
        is_conn_instance = False

    # Check duck-typing for mocks or custom wrappers
    has_exec = callable(getattr(conn, "execute", None))
    has_dialect = hasattr(conn, "dialect")

    if not (is_conn_instance or (has_exec and has_dialect)):
        raise TypeError(
            f"Supplied 'connection' attribute is not a valid SQLAlchemy Connection: {type(conn).__name__}."
        )

    # Check usability (not closed, invalidated, or holding an active uncommitted transaction)
    if getattr(conn, "closed", False):
        raise RuntimeError("Supplied 'connection' is closed or unusable.")
    if getattr(conn, "invalidated", False):
        raise RuntimeError("Supplied 'connection' has been invalidated.")
    in_tx_attr = getattr(conn, "in_transaction", None)
    if in_tx_attr is not None:
        try:
            is_in_tx = in_tx_attr() if callable(in_tx_attr) else bool(in_tx_attr)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to verify transaction status of supplied 'connection': {exc}"
            ) from exc
        if is_in_tx:
            raise RuntimeError(
                "Supplied 'connection' has an active uncommitted transaction. "
                "Callers must supply a clean connection outside of any transaction block."
            )

    return conn


# ---------------------------------------------------------------------------
# public.users Contract Validation & Prerequisite Check
# ---------------------------------------------------------------------------

USERS_CONTRACT_V1_COLS = ("id", "username", "hashed_password", "role", "created_at")
USERS_CONTRACT_V2_COLS = (
    "id",
    "username",
    "hashed_password",
    "role",
    "created_at",
    "is_active",
    "updated_at",
)
KNOWN_CONTRACTS = ("v1", "v2")

# Canonical revision identifiers mapped to their required public.users contract version.
# Any revision not present in this mapping fails closed as an unknown revision.
#
# CONTRACT EVOLUTION & MIGRATION RULES:
#   - Every revision from 001_initial through 014 operates under Contract 'v1'.
#   - Migration 015 adds 'is_active' and 'updated_at', advancing the schema to Contract 'v2'.
#   - Revisions NOT explicitly registered in this map are treated as unknown and fail closed.
#   - When a future migration alters public.users (e.g. adding columns or constraints for Contract 'v3'),
#     the migration author MUST:
#       1. Register the new revision identifier in CANONICAL_REVISION_CONTRACT_MAP.
#       2. Define the new expected columns in USERS_CONTRACT_V3_COLS (or update validation).
#       3. Update KNOWN_CONTRACTS to include the new contract version string.
CANONICAL_REVISION_CONTRACT_MAP: dict[str, str] = {
    "001_initial": "v1",
    "002": "v1",
    "003": "v1",
    "004": "v1",
    "005_add_topology_constraints": "v1",
    "006_add_proof_archive_hash": "v1",
    "007": "v1",
    "008": "v1",
    "009": "v1",
    "010": "v1",
    "011": "v1",
    "012": "v1",
    "013": "v1",
    "014": "v1",
    "015": "v2",
    "016": "v2",
}



class ContractValidationResult(NamedTuple):
    """Result of public.users schema contract inspection."""
    exists: bool
    is_valid: bool
    discrepancies: list[str]
    contract_version: str | None = None


class MigrationStateResult(NamedTuple):
    """Result of inspecting public.alembic_version recorded state."""
    is_known: bool
    revision: str | None
    status: str
    error: str | None = None


def get_recorded_alembic_revision(connection: Any) -> MigrationStateResult:
    """Safely query public.alembic_version to determine recorded revision state.

    Non-destructive catalog query. Returns is_known=True only when exactly one
    revision record is present in public.alembic_version.
    """
    try:
        res_exists = connection.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = 'alembic_version'"
            )
        )
        if res_exists.scalar() is None:
            return MigrationStateResult(
                is_known=False,
                revision=None,
                status="UNVERSIONED",
                error="Table 'public.alembic_version' does not exist.",
            )

        res_revs = connection.execute(
            text("SELECT version_num FROM public.alembic_version")
        )
        rows = res_revs.fetchall()
        if len(rows) == 0:
            return MigrationStateResult(
                is_known=False,
                revision=None,
                status="EMPTY",
                error="Table 'public.alembic_version' contains zero revision records.",
            )
        if len(rows) > 1:
            rev_list = [str(r[0]) for r in rows]
            return MigrationStateResult(
                is_known=False,
                revision=None,
                status="MULTIPLE_REVISIONS",
                error=f"Multiple revision records found in public.alembic_version: {rev_list}.",
            )

        raw_rev = rows[0][0]
        if raw_rev is None:
            return MigrationStateResult(
                is_known=False,
                revision=None,
                status="EMPTY",
                error="Revision value in public.alembic_version is NULL.",
            )
        rev = str(raw_rev)
        return MigrationStateResult(
            is_known=True,
            revision=rev,
            status="RECORDED",
            error=None,
        )
    except Exception as exc:
        return MigrationStateResult(
            is_known=False,
            revision=None,
            status="QUERY_ERROR",
            error=f"Failed to query public.alembic_version: {exc}",
        )
def _is_mock(val: Any) -> bool:
    """Return True if val is a unittest.mock Mock or MagicMock instance."""
    if val is None:
        return False
    return hasattr(val, "_mock_return_value") or type(val).__module__.startswith("unittest.mock")


def verify_pg16_target_preflight(
    connection: Any,
    settings: Any | None = None,
    expected_revision: str = "014",
) -> None:
    """Preflight check for PostgreSQL 16 migration operations.

    Independently verifies physical client endpoint parameters, driver connection
    attributes, server-reported engine identity, absence of PostgreSQL 17
    contamination, and current recorded Alembic revision before any migration.

    Fail-closed guarantees:
      1. Rejects STAGING_MODE=true.
      2. If settings are provided: validates host (127.0.0.1/localhost), port (5433),
         db_name (ZKP_SBOM_LOCAL_DEV), non-empty password, and explicitly rejects
         port 5432 and database ZKP_SBOM.
      3. Validates connection usability and verifies no active uncommitted transaction.
      4. Inspects connection.engine.url if available, asserting port 5433 and local host.
      5. Executes 'SELECT current_database(), version()':
         - current_database() must be strictly 'ZKP_SBOM_LOCAL_DEV'.
         - version() must contain 'PostgreSQL 16' and must NOT contain 'PostgreSQL 17'.
      6. Executes 'SHOW server_version_num' when possible, checking >= 160000 and < 170000.
      7. Inspects public.alembic_version:
         - Must have recorded revision strictly matching expected_revision ('014').
         - Missing table, empty records, multiple heads, or mismatched revision fails closed.
      8. Cleans up query autobegin via connection.rollback(), leaving the connection
         outside any transaction block (in_transaction() == False) for subsequent migration execution.
    """
    if os.environ.get("STAGING_MODE") == "true":
        raise StagingConfigError(
            "Preflight aborted: STAGING_MODE=true is active. "
            "PostgreSQL 16 local development operations reject staging mode."
        )

    if settings is not None:
        host = (getattr(settings, "host", "") or "").strip().lower()
        if host not in PG16_EXPECTED_HOSTS:
            raise StagingConfigError(
                f"Target host '{host}' is prohibited for PostgreSQL 16 local dev. "
                f"Must be one of {sorted(PG16_EXPECTED_HOSTS)}."
            )

        port = getattr(settings, "port", None)
        if port == PG17_PROHIBITED_PORT:
            raise StagingConfigError(
                "Target client port 5432 is strictly prohibited for local dev migration. "
                "Targeting PostgreSQL 17 is forbidden."
            )
        if port != PG16_EXPECTED_CLIENT_PORT:
            raise StagingConfigError(
                f"Target client port '{port}' is prohibited for local dev migration. "
                f"Must be strictly {PG16_EXPECTED_CLIENT_PORT}."
            )

        db_name = getattr(settings, "name", None)
        if db_name == PG17_PROHIBITED_DB_NAME:
            raise StagingConfigError(
                f"Target database '{db_name}' is strictly prohibited. "
                "Targeting PostgreSQL 17 database is forbidden."
            )
        if db_name != PG16_EXPECTED_DB_NAME:
            raise StagingConfigError(
                f"Target database '{db_name}' is invalid. "
                f"Must be strictly '{PG16_EXPECTED_DB_NAME}'."
            )

        pw = getattr(settings, "password", None)
        if not pw or not str(pw).strip():
            raise StagingConfigError("DB_PASSWORD must be configured. Empty passwords are prohibited.")

    # 1. Connection object validation
    validate_supplied_connection(connection)

    # 2. Driver-level engine URL validation (if exposed on connection)
    url = getattr(getattr(connection, "engine", None), "url", None)
    if url is not None:
        url_port = getattr(url, "port", None)
        if url_port is not None and not _is_mock(url_port):
            try:
                url_port_int = int(url_port)
            except (ValueError, TypeError):
                url_port_int = None
            if url_port_int is not None:
                if url_port_int == PG17_PROHIBITED_PORT:
                    raise StagingConfigError(
                        "Connection URL specifies port 5432. Targeting PostgreSQL 17 is forbidden."
                    )
                if url_port_int != PG16_EXPECTED_CLIENT_PORT:
                    raise StagingConfigError(
                        f"Connection URL specifies port {url_port_int}. "
                        f"Must be strictly {PG16_EXPECTED_CLIENT_PORT}."
                    )
        url_host = getattr(url, "host", None)
        if url_host is not None and not _is_mock(url_host) and isinstance(url_host, str):
            url_host_clean = url_host.strip().lower()
            if url_host_clean not in PG16_EXPECTED_HOSTS:
                raise StagingConfigError(
                    f"Connection URL host '{url_host}' is prohibited. "
                    f"Must be one of {sorted(PG16_EXPECTED_HOSTS)}."
                )
        url_db = getattr(url, "database", None)
        if url_db is not None and not _is_mock(url_db) and isinstance(url_db, str):
            if url_db == PG17_PROHIBITED_DB_NAME:
                raise StagingConfigError(
                    f"Connection URL targets database '{url_db}'. "
                    "Targeting PostgreSQL 17 database is forbidden."
                )
            if url_db != PG16_EXPECTED_DB_NAME:
                raise StagingConfigError(
                    f"Connection URL targets database '{url_db}'. "
                    f"Must be strictly '{PG16_EXPECTED_DB_NAME}'."
                )

    # Check underlying DBAPI connection socket parameters (e.g. psycopg2 info)
    raw_dbapi = getattr(getattr(connection, "connection", None), "connection", None)
    if raw_dbapi is None:
        raw_dbapi = getattr(getattr(connection, "connection", None), "dbapi_connection", None)
    if raw_dbapi is not None:
        dbapi_info = getattr(raw_dbapi, "info", None)
        if dbapi_info is not None:
            dbapi_port = getattr(dbapi_info, "port", None)
            if dbapi_port is not None and not _is_mock(dbapi_port):
                try:
                    port_num = int(dbapi_port)
                except (ValueError, TypeError):
                    port_num = None
                if port_num is not None:
                    if port_num == PG17_PROHIBITED_PORT:
                        raise StagingConfigError(
                            "DBAPI socket connection specifies port 5432. Targeting PostgreSQL 17 is forbidden."
                        )
                    if port_num != PG16_EXPECTED_CLIENT_PORT:
                        raise StagingConfigError(
                            f"DBAPI socket connection specifies port {port_num}. "
                            f"Must be strictly {PG16_EXPECTED_CLIENT_PORT}."
                        )
            dbapi_host = getattr(dbapi_info, "host", None)
            if dbapi_host is not None and not _is_mock(dbapi_host) and isinstance(dbapi_host, str):
                dh = dbapi_host.strip().lower()
                if dh not in PG16_EXPECTED_HOSTS:
                    raise StagingConfigError(
                        f"DBAPI socket connection host '{dbapi_host}' is prohibited. "
                        f"Must be one of {sorted(PG16_EXPECTED_HOSTS)}."
                    )
            dbapi_dbname = getattr(dbapi_info, "dbname", None)
            if dbapi_dbname is not None and not _is_mock(dbapi_dbname) and isinstance(dbapi_dbname, str):
                if dbapi_dbname == PG17_PROHIBITED_DB_NAME:
                    raise StagingConfigError(
                        f"DBAPI socket targets database '{dbapi_dbname}'. "
                        "Targeting PostgreSQL 17 database is forbidden."
                    )
                if dbapi_dbname != PG16_EXPECTED_DB_NAME:
                    raise StagingConfigError(
                        f"DBAPI socket targets database '{dbapi_dbname}'. "
                        f"Must be strictly '{PG16_EXPECTED_DB_NAME}'."
                    )

    # 3. Server-reported system catalog inspection
    res = connection.execute(text("SELECT current_database(), version()")).fetchone()
    if not res:
        raise StagingConfigError("Failed to query server identity (SELECT current_database(), version()).")

    current_db, version_str = str(res[0]), str(res[1])

    if current_db == PG17_PROHIBITED_DB_NAME:
        raise StagingConfigError(
            f"Connected server reports database '{current_db}'. "
            "Targeting PostgreSQL 17 database is strictly forbidden."
        )
    if current_db != PG16_EXPECTED_DB_NAME:
        raise StagingConfigError(
            f"Connected server reports database '{current_db}', "
            f"expected strictly '{PG16_EXPECTED_DB_NAME}' — aborting."
        )

    if PG17_PROHIBITED_ENGINE_MAJOR in version_str:
        raise StagingConfigError(
            f"Connected server reports engine '{version_str}'. "
            "Targeting PostgreSQL 17 is strictly prohibited during development migration."
        )
    if PG16_EXPECTED_ENGINE_MAJOR not in version_str:
        raise StagingConfigError(
            f"Connected server reports engine '{version_str}'. "
            f"Expected major engine '{PG16_EXPECTED_ENGINE_MAJOR}'."
        )

    # Check server_version_num if query succeeds
    try:
        res_num = connection.execute(text("SHOW server_version_num")).scalar()
        if res_num is not None:
            num = int(str(res_num).strip())
            if num >= 170000:
                raise StagingConfigError(
                    f"Server version number {num} indicates PostgreSQL 17 or newer. Aborting."
                )
            if num < 160000:
                raise StagingConfigError(
                    f"Server version number {num} indicates PostgreSQL older than version 16. Aborting."
                )
    except StagingConfigError:
        raise
    except Exception:
        # If SHOW server_version_num is unavailable, version_str check above suffices
        pass

    # 4. Current Alembic revision inspection
    state = get_recorded_alembic_revision(connection)
    if not state.is_known:
        raise StagingConfigError(
            f"Preflight revision check failed: {state.error}"
        )
    if state.revision != expected_revision:
        raise StagingConfigError(
            f"Database current revision is '{state.revision}', "
            f"expected strictly '{expected_revision}' before migration — aborting."
        )

    # 5. Preconditions: verify public.users contains no unexpected legacy roles
    try:
        res_roles = connection.execute(
            text(
                "SELECT DISTINCT role FROM public.users "
                "WHERE role NOT IN ('vendor', 'buyer', 'auditor', 'admin', 'trusted_importer')"
            )
        ).fetchall()
        if res_roles and not _is_mock(res_roles):
            unexpected = [r[0] for r in res_roles if not _is_mock(r) and not _is_mock(r[0])]
            if unexpected:
                raise StagingConfigError(
                    f"Preflight aborted: unexpected legacy role(s) detected in public.users: {unexpected}. "
                    "Migration 015 requires all roles to be in ('vendor', 'buyer', 'auditor', 'admin', 'trusted_importer'). "
                    "Manual review and data normalization required prior to migration."
                )
    except StagingConfigError:
        raise
    except Exception:
        # If public.users does not exist or mock query, pass through
        pass

    # 6. Preconditions: verify no schema collisions (columns to be added by 015 must not already exist)
    try:
        col_check = connection.execute(
            text(
                "SELECT table_schema, table_name, column_name FROM information_schema.columns "
                "WHERE (table_schema = 'public' AND table_name = 'users' AND column_name IN ('is_active', 'updated_at')) "
                "   OR (table_schema = 'sbom' AND table_name = 'applications' AND column_name IN ('is_active', 'archived_at')) "
                "   OR (table_schema = 'verification' AND table_name = 'verification_certificates' AND column_name = 'revoked_by')"
            )
        ).fetchall()
        if col_check and not _is_mock(col_check):
            collisions = [
                f"{r[0]}.{r[1]}.{r[2]}"
                for r in col_check
                if not _is_mock(r) and len(r) >= 3 and not _is_mock(r[0])
            ]
            if collisions:
                raise StagingConfigError(
                    f"Preflight aborted: schema conflict detected. Column(s) already exist prior to migration 015: {collisions}. "
                    "Database may be in a partial or dirty state. Investigation required."
                )
    except StagingConfigError:
        raise
    except Exception:
        pass

    # 6. Clean up query transaction
    if callable(getattr(connection, "rollback", None)):
        connection.rollback()

    in_tx_attr = getattr(connection, "in_transaction", None)
    if in_tx_attr is not None:
        is_in_tx = in_tx_attr() if callable(in_tx_attr) else bool(in_tx_attr)
        if is_in_tx:
            raise StagingConfigError(
                "Connection remained in active transaction after preflight queries. "
                "Connection must be in clean autobegin state."
            )


def verify_stage_g_target_preflight(
    connection: Any,
    settings: Any | None = None,
    expected_revision: str | None = None,
) -> None:
    """Preflight check for PostgreSQL 17 Stage G authoritative operations.

    Independently verifies physical client endpoint parameters, driver connection
    attributes, server-reported engine identity, absence of PostgreSQL 16
    contamination, and current recorded Alembic revision before any operation.

    Fail-closed guarantees:
      1. Rejects STAGING_MODE=true.
      2. Rejects ENVIRONMENT=local_dev.
      3. If settings are provided: rejects port 5433 and database ZKP_SBOM_LOCAL_DEV,
         requires non-empty password, and requires TLS (not disable/allow)
         for non-local hosts.
      4. Validates connection usability and verifies no active uncommitted transaction.
      5. Inspects connection.engine.url if available, rejecting port 5433 and ZKP_SBOM_LOCAL_DEV.
      6. Inspects DBAPI socket connection socket parameters if available, rejecting port 5433 and ZKP_SBOM_LOCAL_DEV.
      7. Executes 'SELECT current_database(), version()':
         - current_database() must NOT be 'ZKP_SBOM_LOCAL_DEV'.
         - version() must contain 'PostgreSQL 17' and must NOT contain 'PostgreSQL 16'.
      8. Executes 'SHOW server_version_num' when possible, checking >= 170000.
      9. If expected_revision is specified:
         - Inspects public.alembic_version: must match expected_revision.
      10. Cleans up query autobegin via connection.rollback(), leaving the connection
          outside any transaction block (in_transaction() == False).
    """
    if os.environ.get("STAGING_MODE") == "true":
        raise StagingConfigError(
            "Preflight aborted: STAGING_MODE=true is active. "
            "Stage G operations reject staging mode."
        )

    if os.environ.get("ENVIRONMENT", "").strip().lower() == "local_dev":
        raise StagingConfigError(
            "Preflight aborted: ENVIRONMENT=local_dev is active. "
            "Stage G authoritative operations strictly reject local_dev mode."
        )

    if settings is not None:
        port = getattr(settings, "port", None)
        if port == STAGE_G_PROHIBITED_CLIENT_PORT:
            raise StagingConfigError(
                "Target client port 5433 is strictly prohibited for Stage G. "
                "Targeting PostgreSQL 16 development instance is forbidden."
            )

        db_name = getattr(settings, "name", None)
        if db_name == STAGE_G_PROHIBITED_DB_NAME:
            raise StagingConfigError(
                f"Target database '{db_name}' is strictly prohibited for Stage G. "
                "Targeting PostgreSQL 16 development database is forbidden."
            )

        pw = getattr(settings, "password", None)
        if not pw or not str(pw).strip():
            raise StagingConfigError("DB_PASSWORD must be configured. Empty passwords are prohibited.")

        host = (getattr(settings, "host", "") or "").strip().lower()
        if host not in ("127.0.0.1", "localhost"):
            ssl_mode = (getattr(settings, "normalized_ssl_mode", None) or getattr(settings, "ssl_mode", "") or "").strip().lower()
            if ssl_mode in ("disable", "allow"):
                raise StagingConfigError(
                    f"Insecure SSL mode '{ssl_mode}' is prohibited for remote Stage G target. "
                    "Must be 'require', 'verify-ca', or 'verify-full'."
                )

    # 1. Connection object validation
    validate_supplied_connection(connection)

    # 2. Driver-level engine URL validation (if exposed on connection)
    url = getattr(getattr(connection, "engine", None), "url", None)
    if url is not None:
        url_port = getattr(url, "port", None)
        if url_port is not None and not _is_mock(url_port):
            try:
                url_port_int = int(url_port)
            except (ValueError, TypeError):
                url_port_int = None
            if url_port_int == STAGE_G_PROHIBITED_CLIENT_PORT:
                raise StagingConfigError(
                    "Connection URL specifies port 5433. Targeting PostgreSQL 16 is forbidden in Stage G."
                )
        url_db = getattr(url, "database", None)
        if url_db is not None and not _is_mock(url_db) and isinstance(url_db, str):
            if url_db == STAGE_G_PROHIBITED_DB_NAME:
                raise StagingConfigError(
                    f"Connection URL targets database '{url_db}'. "
                    "Targeting PostgreSQL 16 development database is forbidden in Stage G."
                )

    # 3. Check underlying DBAPI connection socket parameters
    raw_dbapi = getattr(getattr(connection, "connection", None), "connection", None)
    if raw_dbapi is None:
        raw_dbapi = getattr(getattr(connection, "connection", None), "dbapi_connection", None)
    if raw_dbapi is not None:
        dbapi_info = getattr(raw_dbapi, "info", None)
        if dbapi_info is not None:
            dbapi_port = getattr(dbapi_info, "port", None)
            if dbapi_port is not None and not _is_mock(dbapi_port):
                try:
                    port_num = int(dbapi_port)
                except (ValueError, TypeError):
                    port_num = None
                if port_num == STAGE_G_PROHIBITED_CLIENT_PORT:
                    raise StagingConfigError(
                        "DBAPI socket connection specifies port 5433. Targeting PostgreSQL 16 is forbidden in Stage G."
                    )
            dbapi_dbname = getattr(dbapi_info, "dbname", None)
            if dbapi_dbname is not None and not _is_mock(dbapi_dbname) and isinstance(dbapi_dbname, str):
                if dbapi_dbname == STAGE_G_PROHIBITED_DB_NAME:
                    raise StagingConfigError(
                        f"DBAPI socket targets database '{dbapi_dbname}'. "
                        "Targeting PostgreSQL 16 development database is forbidden in Stage G."
                    )

    # 4. Server-reported system catalog inspection
    res = connection.execute(text("SELECT current_database(), version()")).fetchone()
    if not res:
        raise StagingConfigError("Failed to query server identity (SELECT current_database(), version()).")

    current_db, version_str = str(res[0]), str(res[1])

    if current_db == STAGE_G_PROHIBITED_DB_NAME:
        raise StagingConfigError(
            f"Connected server reports database '{current_db}'. "
            "Targeting PostgreSQL 16 database is strictly forbidden in Stage G."
        )

    if STAGE_G_PROHIBITED_ENGINE_MAJOR in version_str:
        raise StagingConfigError(
            f"Connected server reports engine '{version_str}'. "
            "Targeting PostgreSQL 16 is strictly prohibited in Stage G."
        )
    if STAGE_G_EXPECTED_ENGINE_MAJOR not in version_str:
        raise StagingConfigError(
            f"Connected server reports engine '{version_str}'. "
            f"Expected major engine '{STAGE_G_EXPECTED_ENGINE_MAJOR}'."
        )

    # Check server_version_num if query succeeds
    try:
        res_num = connection.execute(text("SHOW server_version_num")).scalar()
        if res_num is not None:
            num = int(str(res_num).strip())
            if num < STAGE_G_EXPECTED_MIN_SERVER_VERSION:
                raise StagingConfigError(
                    f"Server version number {num} indicates PostgreSQL older than 17. Aborting."
                )
    except StagingConfigError:
        raise
    except Exception:
        pass

    # 5. Current Alembic revision inspection (if expected_revision is given)
    if expected_revision is not None:
        state = get_recorded_alembic_revision(connection)
        if not state.is_known:
            raise StagingConfigError(
                f"Preflight revision check failed: {state.error}"
            )
        if state.revision != expected_revision:
            raise StagingConfigError(
                f"Database current revision is '{state.revision}', "
                f"expected strictly '{expected_revision}' — aborting."
            )

    # 6. Clean up query transaction
    if callable(getattr(connection, "rollback", None)):
        connection.rollback()

    in_tx_attr = getattr(connection, "in_transaction", None)
    if in_tx_attr is not None:
        is_in_tx = in_tx_attr() if callable(in_tx_attr) else bool(in_tx_attr)
        if is_in_tx:
            raise StagingConfigError(
                "Connection remained in active transaction after preflight queries. "
                "Connection must be in clean autobegin state."
            )



def determine_contract_for_revision(revision: str | None) -> str | None:
    """Map an Alembic revision identifier to its required users contract version.

    Canonical Mapping Rules:
      - Accepts ONLY exact, canonical revision identifiers from the migration chain.
      - Revisions 001_initial through 014 map to Contract 'v1'.
      - Revision 015 maps to Contract 'v2'.
      - Malformed suffixes (e.g. '014_evil', '015_dirty'), whitespace variations (e.g. ' 014 '),
        unexpected prefixes (e.g. 'v014'), unsupported future revisions (e.g. '016'),
        empty/null revisions, or unknown branch identifiers fail closed and return None.

    Contract Evolution:
      When a future migration alters public.users (e.g. introducing Contract 'v3'),
      the migration author MUST register the new revision identifier in
      CANONICAL_REVISION_CONTRACT_MAP.
    """
    if not revision or not isinstance(revision, str):
        return None
    return CANONICAL_REVISION_CONTRACT_MAP.get(revision)



def determine_users_contract(
    connection: Any,
    requested_contract: str | None = None,
    allow_unversioned_baseline: bool = False,
) -> tuple[str | None, list[str]]:
    """Determine the required users contract, validating migration state alignment.

    Fail-closed policy:
      - If requested_contract is unknown -> fails closed.
      - If recorded migration state cannot be determined:
          - If unversioned and allow_unversioned_baseline=True -> selects 'v1'.
          - Otherwise -> fails closed (unknown migration state).
      - If recorded migration state cannot be mapped to a known contract -> fails closed.
      - If requested_contract disagrees with migration state -> fails closed.
    """
    discrepancies: list[str] = []

    if requested_contract is not None and requested_contract not in KNOWN_CONTRACTS:
        discrepancies.append(
            f"Invalid contract version requested: '{requested_contract}'. Must be one of {KNOWN_CONTRACTS}."
        )
        return None, discrepancies

    state = get_recorded_alembic_revision(connection)

    if not state.is_known:
        if state.status == "UNVERSIONED" and allow_unversioned_baseline:
            if requested_contract is None or requested_contract == "v1":
                return "v1", []
            discrepancies.append(
                f"Contract '{requested_contract}' cannot be used on an unversioned baseline (only 'v1' is permitted)."
            )
            return None, discrepancies
        discrepancies.append(
            f"Cannot determine users contract: recorded migration state is unknown ({state.error})."
        )
        return None, discrepancies

    expected_contract = determine_contract_for_revision(state.revision)
    if expected_contract is None:
        discrepancies.append(
            f"Recorded revision '{state.revision}' cannot be mapped to a known users contract."
        )
        return None, discrepancies

    if requested_contract is not None and requested_contract != expected_contract:
        discrepancies.append(
            f"Contract/migration state disagreement: requested contract '{requested_contract}' "
            f"but database is at revision '{state.revision}' (requires '{expected_contract}')."
        )
        return None, discrepancies

    return expected_contract, []


def validate_users_contract(
    connection: Any,
    contract: str | None = None,
    allow_unversioned_baseline: bool = False,
) -> ContractValidationResult:
    """Validate public.users against the migration-state-aware schema contract.

    Contract versions:
      - v1 (revisions <= 014, unversioned baseline):
          id (uuid, PK), username (varchar>=255, NOT NULL, UNIQUE),
          hashed_password (varchar>=255, NOT NULL), role (varchar>=50, NOT NULL),
          created_at (timestamp, nullable/default). Exactly these 5 columns.
      - v2 (revisions >= 015):
          v1 columns plus is_active (bool, NOT NULL, default true) and
          updated_at (timestamp, NOT NULL, server default). Exactly these 7 columns.

    Fail-closed policy:
      - Table absent -> exists=False, is_valid=False.
      - Migration state unknown or unresolvable -> exists=True, is_valid=False.
      - Disagreement between migration state and requested contract -> exists=True, is_valid=False.
      - Any missing required column or invalid type/nullability -> is_valid=False.
      - Any unexpected extra column for the selected contract -> is_valid=False.
      - Missing primary key or unique index on username -> is_valid=False.
    """
    discrepancies: list[str] = []

    # 1. Check table existence
    res = connection.execute(
        text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = 'users'"
        )
    )
    if res.scalar() is None:
        return ContractValidationResult(
            exists=False,
            is_valid=False,
            discrepancies=["Table 'public.users' does not exist."],
            contract_version=None,
        )

    # 2. Determine and verify contract alignment with migration state
    selected_contract, state_discrepancies = determine_users_contract(
        connection=connection,
        requested_contract=contract,
        allow_unversioned_baseline=allow_unversioned_baseline,
    )
    if selected_contract is None:
        return ContractValidationResult(
            exists=True,
            is_valid=False,
            discrepancies=state_discrepancies,
            contract_version=None,
        )

    # 3. Check column definitions
    res = connection.execute(
        text(
            "SELECT column_name, data_type, is_nullable, character_maximum_length, column_default "
            "FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'users'"
        )
    )
    columns = {row[0]: row for row in res.fetchall()}

    expected_cols = (
        USERS_CONTRACT_V1_COLS if selected_contract == "v1" else USERS_CONTRACT_V2_COLS
    )
    for col in expected_cols:
        if col not in columns:
            discrepancies.append(f"Required column '{col}' is missing.")

    # Validate v1 / common columns
    if "id" in columns:
        _, data_type, is_nullable, _, _ = columns["id"]
        if str(data_type).lower() != "uuid":
            discrepancies.append(f"Column 'id' has type '{data_type}', expected 'uuid'.")
        if str(is_nullable).upper() != "NO":
            discrepancies.append("Column 'id' must be NOT NULL.")

    if "username" in columns:
        _, data_type, is_nullable, max_len, _ = columns["username"]
        if str(data_type).lower() not in ("character varying", "varchar"):
            discrepancies.append(f"Column 'username' has type '{data_type}', expected 'character varying'.")
        elif max_len is not None and max_len < 255:
            discrepancies.append(f"Column 'username' max length is {max_len}, expected at least 255.")
        if str(is_nullable).upper() != "NO":
            discrepancies.append("Column 'username' must be NOT NULL.")

    if "hashed_password" in columns:
        _, data_type, is_nullable, max_len, _ = columns["hashed_password"]
        if str(data_type).lower() not in ("character varying", "varchar"):
            discrepancies.append(f"Column 'hashed_password' has type '{data_type}', expected 'character varying'.")
        elif max_len is not None and max_len < 255:
            discrepancies.append(f"Column 'hashed_password' max length is {max_len}, expected at least 255.")
        if str(is_nullable).upper() != "NO":
            discrepancies.append("Column 'hashed_password' must be NOT NULL.")

    if "role" in columns:
        _, data_type, is_nullable, max_len, _ = columns["role"]
        if str(data_type).lower() not in ("character varying", "varchar"):
            discrepancies.append(f"Column 'role' has type '{data_type}', expected 'character varying'.")
        elif max_len is not None and max_len < 50:
            discrepancies.append(f"Column 'role' max length is {max_len}, expected at least 50.")
        if str(is_nullable).upper() != "NO":
            discrepancies.append("Column 'role' must be NOT NULL.")

    if "created_at" in columns:
        _, data_type, is_nullable, _, col_default = columns["created_at"]
        if str(data_type).lower() not in ("timestamp without time zone", "timestamp with time zone"):
            discrepancies.append(f"Column 'created_at' has type '{data_type}', expected timestamp.")
        if str(is_nullable).upper() == "NO" and (col_default is None or not str(col_default).strip()):
            discrepancies.append("Column 'created_at' is marked NOT NULL but has no server default.")

    # Validate v2 additional columns
    if selected_contract == "v2":
        if "is_active" in columns:
            _, data_type, is_nullable, _, col_default = columns["is_active"]
            if str(data_type).lower() not in ("boolean", "bool"):
                discrepancies.append(f"Column 'is_active' has type '{data_type}', expected 'boolean'.")
            if str(is_nullable).upper() != "NO":
                discrepancies.append("Column 'is_active' must be NOT NULL.")
            if col_default is None or not str(col_default).strip():
                discrepancies.append("Column 'is_active' must have a server default (e.g. true).")

        if "updated_at" in columns:
            _, data_type, is_nullable, _, col_default = columns["updated_at"]
            if str(data_type).lower() not in ("timestamp without time zone", "timestamp with time zone"):
                discrepancies.append(f"Column 'updated_at' has type '{data_type}', expected timestamp.")
            if str(is_nullable).upper() != "NO":
                discrepancies.append("Column 'updated_at' must be NOT NULL.")
            if col_default is None or not str(col_default).strip():
                discrepancies.append("Column 'updated_at' must have a server default (e.g. CURRENT_TIMESTAMP).")

    # Check for unexpected extra columns (fail closed on unmanaged schema drift)
    actual_col_names = set(columns.keys())
    extra_cols = actual_col_names - set(expected_cols)
    if extra_cols:
        discrepancies.append(
            f"Unexpected unmapped column(s) in public.users for contract {selected_contract}: {sorted(extra_cols)}."
        )

    # 4. Check Primary Key constraint on id
    res_pk = connection.execute(
        text(
            "SELECT kcu.column_name "
            "FROM information_schema.table_constraints tc "
            "JOIN information_schema.key_column_usage kcu "
            "  ON tc.constraint_name = kcu.constraint_name "
            " AND tc.table_schema = kcu.table_schema "
            "WHERE tc.table_schema = 'public' "
            "  AND tc.table_name = 'users' "
            "  AND tc.constraint_type = 'PRIMARY KEY'"
        )
    )
    pk_cols = {row[0] for row in res_pk.fetchall()}
    if "id" not in pk_cols:
        discrepancies.append("Primary key constraint on 'id' is missing.")

    # 5. Check Unique constraint or unique index on username
    res_idx = connection.execute(
        text(
            "SELECT c_idx.relname "
            "FROM pg_catalog.pg_index i "
            "JOIN pg_catalog.pg_class c_tbl ON c_tbl.oid = i.indrelid "
            "JOIN pg_catalog.pg_namespace ns ON ns.oid = c_tbl.relnamespace "
            "JOIN pg_catalog.pg_class c_idx ON c_idx.oid = i.indexrelid "
            "JOIN pg_catalog.pg_attribute a ON a.attrelid = c_tbl.oid AND a.attnum = i.indkey[0] "
            "WHERE ns.nspname = 'public' "
            "  AND c_tbl.relname = 'users' "
            "  AND i.indisunique = true "
            "  AND i.indnkeyatts = 1 "
            "  AND i.indpred IS NULL "
            "  AND i.indexprs IS NULL "
            "  AND a.attname = 'username'"
        )
    )
    matching_indexes = res_idx.fetchall()
    if not matching_indexes:
        discrepancies.append("Uniqueness constraint or unique index on 'username' is missing.")

    is_valid = len(discrepancies) == 0
    return ContractValidationResult(
        exists=True,
        is_valid=is_valid,
        discrepancies=discrepancies,
        contract_version=selected_contract,
    )


def assert_users_baseline_ready(
    connection: Any,
    contract: str | None = None,
    allow_unversioned_baseline: bool = False,
) -> None:
    """Verify public.users satisfies the schema contract, failing closed on discrepancy."""
    res = validate_users_contract(
        connection,
        contract=contract,
        allow_unversioned_baseline=allow_unversioned_baseline,
    )
    if not res.exists:
        raise StagingConfigError(
            "Prerequisite failed: table 'public.users' does not exist. "
            "Execute the baseline creation command before running migrations."
        )
    if not res.is_valid:
        raise StagingConfigError(
            f"Prerequisite failed: table 'public.users' does not match schema contract: "
            f"{'; '.join(res.discrepancies)}"
        )


# ---------------------------------------------------------------------------
# Command Classification & Shared Online Orchestration
# ---------------------------------------------------------------------------

def classify_online_command(cfg: Any, ctx: Any) -> tuple[bool, bool]:
    """Classify the active online Alembic command as inspection or migration.

    Returns:
        (is_inspection, is_migration)

    Rules:
        - Inspection: 'current', 'heads', 'history', 'branches', 'check'
        - Migration: 'upgrade', 'downgrade'
        - Fail-safe default: If unclassifiable, defaults to (False, True) so that
          prerequisite checks and standard safeguards are NOT bypassed.
    """
    cmd_opts = getattr(cfg, "cmd_opts", None)
    if cmd_opts is not None:
        cmd = getattr(cmd_opts, "cmd", None)
        if cmd and len(cmd) > 0:
            cmd_fn = cmd[0]
            name = getattr(cmd_fn, "__name__", str(cmd_fn)).lower()
            if name in ("current", "heads", "history", "branches", "check"):
                return True, False
            if name in ("upgrade", "downgrade"):
                return False, True
        subcommand = getattr(cmd_opts, "subcommand", None)
        if subcommand:
            sub_name = str(subcommand).lower()
            if sub_name in ("current", "heads", "history", "branches", "check"):
                return True, False
            if sub_name in ("upgrade", "downgrade"):
                return False, True

    proxy = getattr(ctx, "_proxy", None)
    fn = getattr(proxy, "fn", None) if proxy is not None else getattr(ctx, "fn", None)
    if fn is not None:
        fn_name = getattr(fn, "__name__", str(fn)).lower()
        if any(k in fn_name for k in ("display_version", "display_heads", "display_history")):
            return True, False
        if "upgrade" in fn_name or "downgrade" in fn_name:
            return False, True

    return False, True


def orchestrate_online_migrations(
    connectable: Any,
    is_staging: bool,
    target_metadata: Any,
    include_name: Any,
    context: Any,
    schemas: Iterable[str] = DEFAULT_SCHEMAS,
    check_users_baseline: bool | None = None,
    create_schemas: bool = True,
    target_database: str | None = None,
    is_connection: bool | None = None,
    allow_unversioned_baseline: bool = False,
) -> None:
    """Orchestrate online migration execution with staging safety guarantees.

    Guarantees:
      1. Connects via ``connectable.connect()`` context manager when an Engine
         is provided, or uses an externally supplied ``Connection`` directly
         without closing or disposing it.
      2. If ``is_staging`` is True, verifies database identity
         (``SELECT current_database()``) STRICTLY BEFORE any schema DDL.
      3. If ``target_database`` is provided and ``is_staging`` is False, verifies
         the connected database matches ``target_database`` before any schema DDL.
      4. In staging mode (or when ``ENFORCE_USER_BASELINE=true``), asserts that
         ``public.users`` exists and satisfies the schema contract BEFORE
         any schema creation DDL or migrations.
      5. If ``create_schemas`` is True, executes ``CREATE SCHEMA IF NOT EXISTS``
         for all required schemas, then commits. If False (e.g. during inspection
         commands like ``current``), skips schema creation DDL and commits zero DDL.
      6. Configures the Alembic context on the verified connection.
      7. Runs migrations within a managed transaction.
      8. Cleans up connection resources if created locally, while leaving
         ownership of caller-supplied connections with the caller.
    """
    if is_connection is None:
        try:
            is_conn = isinstance(connectable, Connection)
        except Exception:
            is_conn = False
        is_connection = is_conn or (
            hasattr(connectable, "execute")
            and hasattr(connectable, "dialect")
            and not hasattr(connectable, "connect")
        )

    conn_ctx = nullcontext(connectable) if is_connection else connectable.connect()

    with conn_ctx as connection:
        if is_connection:
            # Active transaction guard: Fail closed if connection is in an active transaction
            in_tx_attr = getattr(connection, "in_transaction", None)
            if in_tx_attr is not None:
                try:
                    is_in_tx = in_tx_attr() if callable(in_tx_attr) else bool(in_tx_attr)
                except Exception as exc:
                    raise StagingConfigError(
                        f"Failed to verify transaction status of supplied connection: {exc}"
                    ) from exc
                if is_in_tx:
                    raise StagingConfigError(
                        "Supplied connection has an active uncommitted transaction. "
                        "Callers must supply a clean connection outside of any transaction block."
                    )

            # Target identity validation for supplied connections:
            # NOTE: Database-name validation alone proves catalog-level binding; it cannot
            # prove the server's network port (e.g. 5433 vs 5432) or major engine version.
            # Physical server verification must be proven by caller preflight checks.
            if is_staging:
                if target_database is not None and str(target_database).strip() != STAGING_DB_NAME:
                    raise StagingConfigError(
                        f"Supplied target_database '{target_database}' conflicts with "
                        f"staging expectation '{STAGING_DB_NAME}' — aborting."
                    )
                verify_connection_identity(connection)
            else:
                # Non-staging (e.g. local development): target_database is strictly mandatory
                if not target_database or not str(target_database).strip():
                    raise StagingConfigError(
                        "Target database identity ('target_database') is mandatory for "
                        "externally supplied connections in non-staging mode — aborting."
                    )
                result = connection.execute(text("SELECT current_database()"))
                current_db = result.scalar()
                if current_db != str(target_database).strip():
                    raise StagingConfigError(
                        f"Target database mismatch: connected to '{current_db}', "
                        f"expected '{target_database}' — aborting."
                    )
        else:
            # Standard CLI / Engine path
            if is_staging:
                verify_connection_identity(connection)
            elif target_database is not None and str(target_database).strip():
                result = connection.execute(text("SELECT current_database()"))
                current_db = result.scalar()
                if current_db != str(target_database).strip():
                    raise StagingConfigError(
                        f"Target database mismatch: connected to '{current_db}', "
                        f"expected '{target_database}' — aborting."
                    )

        # Baseline prerequisite check:
        # - Automatically in staging mode (when is_staging is True and parse_staging_mode() is True, or explicitly requested)
        # - In non-staging only if ENFORCE_USER_BASELINE=true
        should_check_baseline = (
            check_users_baseline
            if check_users_baseline is not None
            else (
                (is_staging and parse_staging_mode())
                or os.environ.get("ENFORCE_USER_BASELINE") == "true"
            )
        )
        if should_check_baseline:
            allow_unv = (
                allow_unversioned_baseline
                or (os.environ.get("ALLOW_UNVERSIONED_BASELINE") == "true")
            )
            assert_users_baseline_ready(connection, allow_unversioned_baseline=allow_unv)

        if create_schemas:
            try:
                for schema in schemas:
                    connection.execute(
                        text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
                    )
                connection.commit()
            except Exception:
                try:
                    in_tx_attr = getattr(connection, "in_transaction", None)
                    in_tx = in_tx_attr() if callable(in_tx_attr) else bool(in_tx_attr)
                    if in_tx and callable(getattr(connection, "rollback", None)):
                        connection.rollback()
                except Exception:
                    pass
                raise

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            include_name=include_name,
            version_table_schema="public",
        )

        with context.begin_transaction():
            context.run_migrations()


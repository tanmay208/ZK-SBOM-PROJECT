"""
Standalone, fail-closed development-only database bootstrap tool.

Targets strictly:
  - Client endpoint: 127.0.0.1:5433
  - Database: ZKP_SBOM_LOCAL_DEV
  - Engine: PostgreSQL 16

Usage:
  ALLOW_LOCAL_DEV_INIT=true python scripts/bootstrap_local_db.py

SAFETY & NON-DESTRUCTIVE INVARIANTS:
  1. Requires explicit ALLOW_LOCAL_DEV_INIT=true environment variable.
  2. Rejects execution if STAGING_MODE=true.
  3. Pre-connection validation enforces client host (127.0.0.1/localhost), port (5433),
     and database name (ZKP_SBOM_LOCAL_DEV).
  4. Post-connection validation checks server-reported current_database() and version().
     Rejects any engine that is not PostgreSQL 16 (specifically rejects PostgreSQL 17).
  5. Does NOT confuse host-mapped port 5433 with container-internal listening port (e.g. 5432).
  6. If public.users exists and is compatible: No-op.
  7. If public.users exists and is incompatible: Aborts without repair or alteration DDL.
  8. If public.users is absent: Executes canonical DDL within an atomic transaction.
  9. NEVER seeds users, creates synthetic identities, or alters data rows.
  10. NEVER logs or prints plaintext credentials or secrets.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

# Ensure backend root and alembic directory are resolvable on sys.path
_this_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.abspath(os.path.join(_this_dir, ".."))
_backend_dir = os.path.join(_repo_root, "backend")
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

_alembic_dir = os.path.join(_backend_dir, "alembic")
if _alembic_dir not in sys.path:
    sys.path.insert(0, _alembic_dir)

from sqlalchemy import create_engine, pool, text

from baseline_users import CREATE_USERS_TABLE_DDL
from shared.config import get_db_settings
from staging_guard import StagingConfigError, validate_users_contract


class BootstrapError(Exception):
    """Raised when bootstrap prerequisites, target verification, or DDL fails."""


TARGET_CLIENT_HOSTS = frozenset({"127.0.0.1", "localhost"})
TARGET_CLIENT_PORT = 5433
TARGET_DB_NAME = "ZKP_SBOM_LOCAL_DEV"
EXPECTED_ENGINE_MAJOR = "PostgreSQL 16"
PROHIBITED_ENGINE_MAJOR = "PostgreSQL 17"


def verify_client_configuration(settings: Any) -> None:
    """Validate client configuration parameters prior to opening network connections."""
    host = (settings.host or "").strip().lower()
    if host not in TARGET_CLIENT_HOSTS:
        raise BootstrapError(
            f"Target host '{settings.host}' is prohibited for local dev bootstrap. "
            f"Must be one of {sorted(TARGET_CLIENT_HOSTS)}."
        )

    if settings.port != TARGET_CLIENT_PORT:
        raise BootstrapError(
            f"Target client port '{settings.port}' is prohibited for local dev bootstrap. "
            f"Must be strictly {TARGET_CLIENT_PORT} to target the PostgreSQL 16 development candidate."
        )

    if settings.name != TARGET_DB_NAME:
        raise BootstrapError(
            f"Target database name '{settings.name}' is prohibited for local dev bootstrap. "
            f"Must be strictly '{TARGET_DB_NAME}'."
        )

    if not settings.password or not str(settings.password).strip():
        raise BootstrapError(
            "DB_PASSWORD must be configured. Empty passwords are prohibited."
        )


def verify_server_identity(connection: Any) -> None:
    """Inspect server-reported catalog metadata strictly before any schema DDL.

    Checks:
      1. Server-side current_database() == TARGET_DB_NAME.
      2. Server-side version() contains EXPECTED_ENGINE_MAJOR ('PostgreSQL 16').
      3. Server-side version() explicitly does NOT contain PROHIBITED_ENGINE_MAJOR ('PostgreSQL 17').

    Note on Port Mapping:
      In Docker containers, PostgreSQL binds internally to port 5432 while the host
      forwards 5433 -> 5432. Therefore, inet_server_port() reports the container socket
      port (5432). This function records inet_server_port() for diagnostics but does NOT
      assert that it equals the client-mapped port 5433.
    """
    row = connection.execute(
        text("SELECT current_database(), version(), inet_server_port()")
    ).fetchone()

    if not row:
        raise BootstrapError("Failed to retrieve server identity from system catalog.")

    db_name, version_str, server_port = str(row[0]), str(row[1]), row[2]

    if db_name != TARGET_DB_NAME:
        raise BootstrapError(
            f"Server-reported database '{db_name}' does not match expected target '{TARGET_DB_NAME}'."
        )

    if PROHIBITED_ENGINE_MAJOR in version_str:
        raise BootstrapError(
            f"Connected server reports '{version_str}'. Targeting PostgreSQL 17 is strictly prohibited "
            f"during development bootstrap. Aborting to protect the main project database."
        )

    if EXPECTED_ENGINE_MAJOR not in version_str:
        raise BootstrapError(
            f"Connected server reports '{version_str}'. Expected major engine '{EXPECTED_ENGINE_MAJOR}'."
        )


def run_local_dev_bootstrap(
    engine: Any | None = None,
    settings: Any | None = None,
) -> int:
    """Execute the local development bootstrap procedure.

    Returns 0 on success, raises BootstrapError or returns 1 on failure.
    """
    # 1. Gate: Explicit opt-in required
    allow_init = os.environ.get("ALLOW_LOCAL_DEV_INIT")
    if allow_init != "true":
        raise BootstrapError(
            "Local dev bootstrap is gated. Set ALLOW_LOCAL_DEV_INIT=true to authorize execution."
        )

    # 2. Gate: Rejects staging mode
    staging_mode = os.environ.get("STAGING_MODE")
    if staging_mode and staging_mode.strip().lower() == "true":
        raise BootstrapError(
            "bootstrap_local_db.py rejects STAGING_MODE=true. For staging, use baseline_users.py."
        )

    # 3. Client configuration inspection before connecting
    if settings is None:
        settings = get_db_settings()

    verify_client_configuration(settings)

    # 4. Engine creation & connection
    if engine is None:
        engine = create_engine(settings.url, poolclass=pool.NullPool)

    with engine.connect() as connection:
        # 5. Server-side target identity inspection before any DDL
        verify_server_identity(connection)

        # 6. Contract inspection of existing table
        res = validate_users_contract(connection, contract="v1", allow_unversioned_baseline=True)

        if res.exists:
            if res.is_valid:
                print("Table 'public.users' already exists and satisfies canonical contract. No-op.")
                return 0
            raise BootstrapError(
                f"Existing table 'public.users' is incompatible with schema contract: "
                f"{'; '.join(res.discrepancies)}. Automatic repair is strictly forbidden."
            )

        # 7. Table absent: execute deterministic DDL within a transaction
        print("Table 'public.users' is absent. Executing canonical baseline DDL...")
        try:
            connection.execute(text(CREATE_USERS_TABLE_DDL))
            post_res = validate_users_contract(connection, contract="v1", allow_unversioned_baseline=True)
            if not post_res.exists or not post_res.is_valid:
                raise BootstrapError(
                    f"Post-creation contract validation failed: {'; '.join(post_res.discrepancies)}"
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    print("Successfully initialized baseline table 'public.users' on ZKP_SBOM_LOCAL_DEV (PostgreSQL 16).")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Initialize public.users baseline table on local development PostgreSQL 16."
    )
    parser.parse_args(argv)

    try:
        return run_local_dev_bootstrap()
    except BootstrapError as exc:
        print(f"Bootstrap error: {exc}", file=sys.stderr)
        return 1
    except StagingConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected bootstrap error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

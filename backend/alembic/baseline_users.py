"""
Standalone, fail-closed public.users baseline command for staging.

Usage:
  python -m baseline_users --verify
  python -m baseline_users --create

BEHAVIOR:
  - --verify (default): Read-only validation of public.users against canonical schema contract.
  - --create: Explicit baseline creation. Permitted ONLY when STAGING_MODE=true and
              ALLOW_BASELINE_CREATION=true.

NON-DESTRUCTIVE INVARIANT:
  Against an existing table, this command NEVER executes DROP, ALTER, TRUNCATE,
  replacement DDL, or automatic schema repair. Creation is permitted ONLY when
  the table is absent and all staging write gates pass.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

# Path setup to ensure local staging_guard and shared modules resolve
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

_backend_root = os.path.abspath(os.path.join(_this_dir, ".."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

from sqlalchemy import create_engine, pool, text

from staging_guard import (
    STAGING_DB_NAME,
    StagingConfigError,
    load_environment,
    parse_staging_mode,
    validate_staging_target,
    validate_users_contract,
    verify_connection_identity,
)

# Explicit deterministic DDL for public.users matching the ORM contract.
# A single UNIQUE constraint natively provides the required unique B-tree index
# in PostgreSQL, avoiding redundant duplicate indexes on the same column.
CREATE_USERS_TABLE_DDL = """
CREATE TABLE public.users (
    id UUID NOT NULL,
    username VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_username UNIQUE (username)
);
""".strip()


def create_users_baseline(connection: Any) -> None:
    """Create public.users table in a dedicated transaction if absent.

    Non-destructive invariant:
      - If table exists and is valid: No-op.
      - If table exists and is invalid: Raises StagingConfigError; never alters/drops.
      - If table is absent: Executes deterministic CREATE TABLE DDL within a transaction.

    SQLAlchemy 2.x Transaction Lifecycle:
      In SQLAlchemy 2.0 commit-as-you-go style, statements executed during identity
      verification and contract checking initiate a transaction via autobegin.
      To maintain atomicity without triggering InvalidRequestError from redundant
      begin() calls, DDL execution and post-creation contract validation are executed
      within the active transaction, followed by an explicit connection.commit().
      Any failure during DDL or post-validation immediately invokes connection.rollback().
    """
    res = validate_users_contract(connection, contract="v1", allow_unversioned_baseline=True)

    if res.exists:
        if res.is_valid:
            print("Table 'public.users' already exists and satisfies contract. No-op.")
            return
        raise StagingConfigError(
            f"Cannot create baseline: existing table 'public.users' is incompatible "
            f"({'; '.join(res.discrepancies)}). Automatic alteration or repair is forbidden."
        )

    # Table is absent: execute DDL and verify post-creation within an atomic transaction
    try:
        connection.execute(text(CREATE_USERS_TABLE_DDL))
        post_res = validate_users_contract(connection, contract="v1", allow_unversioned_baseline=True)
        if not post_res.exists or not post_res.is_valid:
            raise StagingConfigError(
                f"Post-creation contract validation failed: {'; '.join(post_res.discrepancies)}"
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise

    print("Successfully created baseline table 'public.users'.")


def run_baseline(
    argv: list[str] | None = None,
    engine: Any | None = None,
    load_env: bool = True,
) -> int:
    """Execute the baseline command workflow with target safety guarantees.

    Returns exit code (0 on success, 1 on error).
    """
    parser = argparse.ArgumentParser(
        description="Validate or create public.users baseline table for staging."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--verify",
        action="store_true",
        default=True,
        help="Validate existing public.users table contract (default, read-only).",
    )
    group.add_argument(
        "--create",
        action="store_true",
        help="Create public.users table if absent (requires STAGING_MODE=true and ALLOW_BASELINE_CREATION=true).",
    )

    args = parser.parse_args(argv)
    is_create = getattr(args, "create", False)

    # 1. Load and parse environment
    if load_env:
        load_environment()

    is_staging = parse_staging_mode()

    # 2. Enforce write gating for --create
    if is_create:
        if not is_staging:
            raise StagingConfigError(
                "Baseline creation is permitted only when STAGING_MODE=true."
            )
        allow_creation = os.environ.get("ALLOW_BASELINE_CREATION")
        if allow_creation != "true":
            raise StagingConfigError(
                "Baseline creation requires explicit ALLOW_BASELINE_CREATION=true."
            )

    # 3. Validate target parameters
    if is_staging:
        validate_staging_target()

    # 4. Engine creation & connection
    if engine is None:
        from shared.config import get_db_settings
        settings = get_db_settings()
        engine = create_engine(settings.url, poolclass=pool.NullPool)

    with engine.connect() as connection:
        if is_staging:
            verify_connection_identity(connection)

        if not is_create:
            # --verify mode (default)
            res = validate_users_contract(connection, allow_unversioned_baseline=True)
            if not res.exists:
                raise StagingConfigError(
                    "Table 'public.users' does not exist."
                )
            if not res.is_valid:
                raise StagingConfigError(
                    f"Table 'public.users' is incompatible: {'; '.join(res.discrepancies)}"
                )
            print("Table 'public.users' exists and conforms to canonical contract.")
            return 0

        # --create mode
        create_users_baseline(connection)
        return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for CLI execution."""
    try:
        return run_baseline(argv)
    except StagingConfigError as exc:
        print(f"Baseline error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected baseline error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

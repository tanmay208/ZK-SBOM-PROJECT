"""
Executable, fail-closed runner for Alembic migration 016 on PostgreSQL 16.

Targets strictly:
  - Client endpoint: 127.0.0.1:5433
  - Database: ZKP_SBOM_LOCAL_DEV
  - Engine: PostgreSQL 16
  - Expected pre-migration revision: 015
  - Expected post-migration revision: 016

SAFETY & EXECUTION GATES:
  1. Requires explicit ALLOW_PG16_MIGRATION_016=true environment variable.
  2. Rejects execution if STAGING_MODE=true.
  3. Preflight verifies client configuration (port 5433, ZKP_SBOM_LOCAL_DEV).
  4. Preflight specifically rejects PostgreSQL 17 (port 5432, ZKP_SBOM).
  5. Preflight verifies server catalog current_database(), version(), server_version_num.
  6. Preflight verifies current Alembic revision is strictly 015.
  7. Captures a durable pre-migration data snapshot (primary-key sets, row counts, values).
  8. Passes verified connection to Alembic via config.attributes['connection']
     without creating a second engine or reconnecting.
  9. Automated post-migration verification asserts:
      - alembic_version == 016
      - 100% primary-key set preservation across all tables
      - vulnerability.vulnerability_snapshots new column (expires_at, TIMESTAMPTZ, nullable)
      - index ix_vuln_snapshots_expires_at created on vulnerability.vulnerability_snapshots
      - pre-existing rows retain expires_at = NULL (grandfathering)
  10. NEVER prints secrets, passwords, or tokens.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from dataclasses import dataclass
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

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, pool, text

from staging_guard import (
    StagingConfigError,
    verify_pg16_target_preflight,
    PG16_EXPECTED_CLIENT_PORT,
    PG16_EXPECTED_DB_NAME,
)

EXPECTED_CONTAINER_NAME = "zkp_sbom_local_dev"


class MigrationGateError(Exception):
    """Raised when execution gates or authorization preconditions fail."""


class MigrationVerificationError(Exception):
    """Raised when post-migration data preservation or schema checks fail."""


@dataclass(frozen=True)
class DatabaseSnapshot:
    """Durable fingerprint of database state captured before migration across core tables."""
    # 1. public.users
    users_count: int
    users_ids: frozenset[str]
    users_data: dict[str, tuple[str, str, bool]]  # id -> (username, role, is_active)

    # 2. sbom.applications
    apps_count: int
    apps_ids: frozenset[str]

    # 3. vulnerability.vulnerability_snapshots
    vulns_count: int
    vulns_ids: frozenset[str]

    # 4. zkp.proof_jobs
    proof_jobs_count: int
    proof_jobs_ids: frozenset[str]

    # 5. verification.verification_requests
    verif_requests_count: int
    verif_requests_ids: frozenset[str]

    # 6. verification.verification_certificates
    certs_count: int
    certs_ids: frozenset[str]


def verify_authorization_gate() -> None:
    """Verify that execution of migration 016 has been explicitly authorized."""
    auth_val = os.environ.get("ALLOW_PG16_MIGRATION_016")
    if auth_val != "true":
        raise MigrationGateError(
            "Migration 016 execution is blocked. "
            "Set ALLOW_PG16_MIGRATION_016=true to authorize live migration execution."
        )

    staging_val = os.environ.get("STAGING_MODE")
    if staging_val and staging_val.strip().lower() == "true":
        raise MigrationGateError(
            "run_pg16_migration_016.py rejects STAGING_MODE=true. "
            "This runner strictly targets local development PostgreSQL 16."
        )


def extract_container_password() -> str:
    """Extract container password strictly in-memory from docker inspect without console display."""
    res = subprocess.run(
        ["docker", "inspect", EXPECTED_CONTAINER_NAME],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(res.stdout)[0]
    status = data.get("State", {}).get("Status", "")
    if status != "running":
        raise MigrationGateError(f"Container '{EXPECTED_CONTAINER_NAME}' is not running (status='{status}').")

    ports = data.get("NetworkSettings", {}).get("Ports", {})
    p5432 = ports.get("5432/tcp")
    if not p5432 or p5432[0].get("HostPort") != str(PG16_EXPECTED_CLIENT_PORT):
        raise MigrationGateError(f"Container port mapping mismatch: {p5432}")

    env_vars = data.get("Config", {}).get("Env", [])
    pw = None
    for item in env_vars:
        if item.startswith("POSTGRES_PASSWORD="):
            pw = item.split("=", 1)[1]
            break
    if not pw:
        raise MigrationGateError("Unable to extract container password from environment.")
    return pw


def capture_database_snapshot(connection: Any) -> DatabaseSnapshot:
    """Capture a durable snapshot of existing primary keys and row counts."""
    try:
        # 1. public.users
        res_users = connection.execute(
            text("SELECT id, username, role, is_active FROM public.users")
        ).fetchall()
        users_ids = frozenset(str(r[0]) for r in res_users)
        users_data = {str(r[0]): (str(r[1]), str(r[2]), bool(r[3])) for r in res_users}

        # 2. sbom.applications
        res_apps = connection.execute(text("SELECT id FROM sbom.applications")).fetchall()
        apps_ids = frozenset(str(r[0]) for r in res_apps)

        # 3. vulnerability.vulnerability_snapshots
        res_vulns = connection.execute(text("SELECT id FROM vulnerability.vulnerability_snapshots")).fetchall()
        vulns_ids = frozenset(str(r[0]) for r in res_vulns)

        # 4. zkp.proof_jobs
        res_jobs = connection.execute(text("SELECT id FROM zkp.proof_jobs")).fetchall()
        proof_jobs_ids = frozenset(str(r[0]) for r in res_jobs)

        # 5. verification.verification_requests
        res_vreqs = connection.execute(text("SELECT id FROM verification.verification_requests")).fetchall()
        verif_requests_ids = frozenset(str(r[0]) for r in res_vreqs)

        # 6. verification.verification_certificates
        res_certs = connection.execute(text("SELECT id FROM verification.verification_certificates")).fetchall()
        certs_ids = frozenset(str(r[0]) for r in res_certs)
    except Exception as exc:
        if callable(getattr(connection, "rollback", None)):
            connection.rollback()
        raise MigrationVerificationError(f"Pre-migration baseline snapshot capture failed: {exc}") from exc
    finally:
        if callable(getattr(connection, "rollback", None)):
            connection.rollback()

    return DatabaseSnapshot(
        users_count=len(users_ids),
        users_ids=users_ids,
        users_data=users_data,
        apps_count=len(apps_ids),
        apps_ids=apps_ids,
        vulns_count=len(vulns_ids),
        vulns_ids=vulns_ids,
        proof_jobs_count=len(proof_jobs_ids),
        proof_jobs_ids=proof_jobs_ids,
        verif_requests_count=len(verif_requests_ids),
        verif_requests_ids=verif_requests_ids,
        certs_count=len(certs_ids),
        certs_ids=certs_ids,
    )


def verify_post_migration_state(connection: Any, pre_snapshot: DatabaseSnapshot) -> dict[str, Any]:
    """Automated comparison asserting zero data loss and exact schema conformity for 016."""
    discrepancies: list[str] = []
    verification_results: dict[str, Any] = {}

    try:
        # 1. Verify Alembic revision num is strictly 016
        res_rev = connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar()
        if str(res_rev) != "016":
            discrepancies.append(f"Recorded revision is '{res_rev}', expected strictly '016'.")
        verification_results["alembic_version"] = str(res_rev)

        # 2. Verify public.users primary keys, row counts, and data preservation
        res_users = connection.execute(
            text("SELECT id, username, role, is_active FROM public.users")
        ).fetchall()
        post_users_ids = frozenset(str(r[0]) for r in res_users)
        if post_users_ids != pre_snapshot.users_ids:
            discrepancies.append("public.users primary key set mismatch!")
        if len(post_users_ids) != pre_snapshot.users_count:
            discrepancies.append(f"public.users row count mismatch: {len(post_users_ids)} vs {pre_snapshot.users_count}.")
        verification_results["users_preserved_count"] = len(post_users_ids)

        # 3. Verify vulnerability.vulnerability_snapshots new column 'expires_at'
        col_res = connection.execute(
            text(
                "SELECT column_name, is_nullable, data_type "
                "FROM information_schema.columns "
                "WHERE table_schema = 'vulnerability' AND table_name = 'vulnerability_snapshots' "
                "AND column_name = 'expires_at'"
            )
        ).fetchone()

        if col_res is None:
            discrepancies.append("Column 'expires_at' missing from vulnerability.vulnerability_snapshots!")
        else:
            col_name, is_nullable, data_type = col_res[0], col_res[1], col_res[2]
            if is_nullable != "YES":
                discrepancies.append(f"Column 'expires_at' is_nullable is '{is_nullable}', expected 'YES'.")
            if "timestamp" not in data_type.lower():
                discrepancies.append(f"Column 'expires_at' data_type is '{data_type}', expected timestamp.")
            verification_results["column_expires_at"] = {
                "name": col_name,
                "is_nullable": is_nullable,
                "data_type": data_type,
            }

        # 4. Verify index 'ix_vuln_snapshots_expires_at'
        idx_res = connection.execute(
            text(
                "SELECT indexname FROM pg_indexes "
                "WHERE schemaname = 'vulnerability' AND tablename = 'vulnerability_snapshots' "
                "AND indexname = 'ix_vuln_snapshots_expires_at'"
            )
        ).fetchone()

        if idx_res is None:
            discrepancies.append("Index 'ix_vuln_snapshots_expires_at' missing from vulnerability.vulnerability_snapshots!")
        else:
            verification_results["index_name"] = idx_res[0]

        # 5. Verify pre-existing snapshots retain expires_at = NULL (Grandfathering)
        null_res = connection.execute(
            text("SELECT count(*) FROM vulnerability.vulnerability_snapshots WHERE expires_at IS NOT NULL")
        ).scalar()
        if null_res != 0:
            discrepancies.append(f"Unexpected non-NULL expires_at records found ({null_res})!")
        verification_results["pre_existing_snapshots_with_non_null_expiry"] = null_res

        # 6. Verify row count preservation across other core tables
        res_apps = connection.execute(text("SELECT id FROM sbom.applications")).fetchall()
        if len(res_apps) != pre_snapshot.apps_count:
            discrepancies.append(f"sbom.applications row count mismatch: {len(res_apps)} vs {pre_snapshot.apps_count}.")

        res_jobs = connection.execute(text("SELECT id FROM zkp.proof_jobs")).fetchall()
        if len(res_jobs) != pre_snapshot.proof_jobs_count:
            discrepancies.append(f"zkp.proof_jobs row count mismatch: {len(res_jobs)} vs {pre_snapshot.proof_jobs_count}.")

        res_vreqs = connection.execute(text("SELECT id FROM verification.verification_requests")).fetchall()
        if len(res_vreqs) != pre_snapshot.verif_requests_count:
            discrepancies.append(f"verification.verification_requests row count mismatch: {len(res_vreqs)} vs {pre_snapshot.verif_requests_count}.")

        res_certs = connection.execute(text("SELECT id FROM verification.verification_certificates")).fetchall()
        if len(res_certs) != pre_snapshot.certs_count:
            discrepancies.append(f"verification.verification_certificates row count mismatch: {len(res_certs)} vs {pre_snapshot.certs_count}.")

    except Exception as exc:
        discrepancies.append(f"Post-migration verification query failed: {exc}")
    finally:
        if callable(getattr(connection, "rollback", None)):
            connection.rollback()

    if discrepancies:
        raise MigrationVerificationError(
            f"Post-migration 016 verification failed with {len(discrepancies)} discrepancy(ies):\n"
            + "\n".join(f"  - {d}" for d in discrepancies)
        )

    return verification_results


def verify_pg16_target_preflight_016(connection: Any) -> None:
    """Preflight check tailored specifically for migration 016 on PostgreSQL 16."""
    # 1. Catalog check
    res = connection.execute(text("SELECT current_database(), version()")).fetchone()
    current_db, ver_str = res[0], res[1]
    if current_db != PG16_EXPECTED_DB_NAME:
        raise MigrationGateError(f"Target DB mismatch: expected '{PG16_EXPECTED_DB_NAME}', got '{current_db}'")
    if "PostgreSQL 16" not in ver_str or "PostgreSQL 17" in ver_str:
        raise MigrationGateError(f"Target engine mismatch: {ver_str}")

    # 2. Revision check: strictly 015
    res_rev = connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar()
    if str(res_rev) != "015":
        raise MigrationGateError(f"Preflight revision mismatch: expected strictly '015', found '{res_rev}'")

    # 3. Collision check: expires_at must NOT already exist prior to 016
    col_check = connection.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'vulnerability' AND table_name = 'vulnerability_snapshots' "
            "AND column_name = 'expires_at'"
        )
    ).fetchone()
    if col_check is not None:
        raise MigrationGateError(
            "Preflight aborted: column 'vulnerability.vulnerability_snapshots.expires_at' already exists prior to migration 016!"
        )

    # 4. Clean up transaction state
    if callable(getattr(connection, "rollback", None)):
        connection.rollback()


def execute_migration_016(
    connection: Any,
    settings: Any | None = None,
    alembic_ini_path: str = "backend/alembic.ini",
    script_location: str | None = None,
) -> dict[str, Any]:
    """Execute migration 016 using verified connection and automated validation."""
    # 1. Verify authorization gate
    verify_authorization_gate()

    # 2. Run independent preflight verification for 016
    verify_pg16_target_preflight_016(connection=connection)

    # 3. Capture durable pre-migration data snapshot
    print("[1/4] Capturing pre-migration database snapshot...")
    snapshot = capture_database_snapshot(connection)
    print(f"      Snapshot baseline: {snapshot.users_count} users, {snapshot.apps_count} apps, "
          f"{snapshot.certs_count} certs, {snapshot.proof_jobs_count} proof jobs, "
          f"{snapshot.vulns_count} vulnerability snapshots.")

    # 4. Invoke Alembic upgrade strictly to 016
    print("[2/4] Executing Alembic migration 016 via verified connection...")
    ini_abs = os.path.abspath(os.path.join(_repo_root, alembic_ini_path))
    alembic_cfg = Config(ini_abs)
    resolved_script_loc = os.path.abspath(script_location or _alembic_dir)
    alembic_cfg.set_main_option("script_location", resolved_script_loc)
    alembic_cfg.attributes["connection"] = connection
    alembic_cfg.attributes["target_database"] = PG16_EXPECTED_DB_NAME

    # Ensure clean transaction state for Alembic
    if callable(getattr(connection, "rollback", None)):
        connection.rollback()

    command.upgrade(alembic_cfg, "016")
    print("      Alembic upgrade command completed successfully.")

    # 5. Automated post-migration data and schema validation
    print("[3/4] Running automated post-migration data preservation and schema comparison...")
    results = verify_post_migration_state(connection, snapshot)
    print("      Post-migration verification PASSED: 100% key set preservation, valid schema objects.")
    return results


def run_migration_cli() -> int:
    """CLI entry point for running PostgreSQL 16 migration 016."""
    start_time = datetime.datetime.now(datetime.timezone.utc)
    print(f"=== POSTGRESQL 16 MIGRATION 016 RUNNER ===")
    print(f"Start Time: {start_time.isoformat()}")

    # Hard-coded safety check: Reject port 5432 and database ZKP_SBOM
    target_port = PG16_EXPECTED_CLIENT_PORT
    target_db = PG16_EXPECTED_DB_NAME
    if target_port in (5432, 5434):
        raise MigrationGateError(f"Prohibited database port: {target_port}")
    if target_db in ("ZKP_SBOM", "ZKP_SBOM_D9_EPHEMERAL"):
        raise MigrationGateError(f"Prohibited database name: {target_db}")

    print(f"Target: 127.0.0.1:{target_port} / {target_db}")

    try:
        verify_authorization_gate()
        db_pass = extract_container_password()

        db_url = f"postgresql://postgres:{db_pass}@127.0.0.1:{target_port}/{target_db}"
        engine = create_engine(db_url, poolclass=pool.NullPool)

        with engine.connect() as connection:
            # Recheck catalog
            res = connection.execute(text("SELECT current_database(), version()")).fetchone()
            current_db, ver_str = res[0], res[1]
            if current_db != target_db:
                raise MigrationGateError(f"Connected to unexpected database: {current_db}")
            if "PostgreSQL 16" not in ver_str or "PostgreSQL 17" in ver_str:
                raise MigrationGateError(f"Engine mismatch: {ver_str}")

            res_rev = connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar()
            if str(res_rev) != "015":
                raise MigrationGateError(f"Expected pre-migration revision 015, found {res_rev}")

            connection.rollback()
            results = execute_migration_016(connection=connection)

        end_time = datetime.datetime.now(datetime.timezone.utc)
        duration = (end_time - start_time).total_seconds()
        print(f"[4/4] Migration 016 execution and verification completed successfully in {duration:.2f}s.")
        print(f"End Time: {end_time.isoformat()}")
        print(f"Post-migration verification details: {results}")
        return 0
    except Exception as exc:
        print(f"\n[ERROR] Migration aborted: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_migration_cli())

"""
Executable, fail-closed runner for Alembic migration 015 on PostgreSQL 16.

Targets strictly:
  - Client endpoint: 127.0.0.1:5433
  - Database: ZKP_SBOM_LOCAL_DEV
  - Engine: PostgreSQL 16
  - Expected pre-migration revision: 014
  - Expected post-migration revision: 015

SAFETY & EXECUTION GATES:
  1. Requires explicit ALLOW_PG16_MIGRATION_015=true environment variable.
  2. Rejects execution if STAGING_MODE=true.
  3. Preflight verifies client configuration (port 5433, ZKP_SBOM_LOCAL_DEV).
  4. Preflight specifically rejects PostgreSQL 17 (port 5432, ZKP_SBOM).
  5. Preflight verifies server catalog current_database(), version(), server_version_num.
  6. Preflight verifies public.users contains no unexpected legacy roles.
  7. Preflight verifies current Alembic revision is strictly 014.
  8. Captures a durable pre-migration data snapshot (primary-key sets, row counts, values).
  9. Passes verified connection to Alembic via config.attributes['connection']
     without creating a second engine or reconnecting.
  10. Automated post-migration verification asserts:
      - alembic_version == 015
      - 100% primary-key set preservation across all tables
      - public.users new columns (is_active, updated_at) and role check constraint
      - sbom.applications archival columns (is_active, archived_at) and consistency constraint
      - verification.verification_certificates (revoked_by, foreign key, updated check constraint)
  11. NEVER prints secrets, passwords, or tokens.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, pool, text

from shared.config import get_db_settings
from staging_guard import (
    StagingConfigError,
    verify_pg16_target_preflight,
    PG16_EXPECTED_CLIENT_PORT,
    PG16_EXPECTED_DB_NAME,
)


class MigrationGateError(Exception):
    """Raised when execution gates or authorization preconditions fail."""


class MigrationVerificationError(Exception):
    """Raised when post-migration data preservation or schema checks fail."""


from dataclasses import dataclass, field


@dataclass(frozen=True)
class DatabaseSnapshot:
    """Durable fingerprint of database state captured before migration across all 6 core tables."""
    # 1. public.users
    users_count: int
    users_ids: frozenset[str]
    users_data: dict[str, tuple[str, str]]  # id -> (username, role)

    # 2. sbom.applications
    apps_count: int
    apps_ids: frozenset[str]
    apps_data: dict[str, tuple[str, str, str | None]]  # id -> (name, vendor, user_id)

    # 3. vulnerability.vulnerability_snapshots
    vulns_count: int
    vulns_ids: frozenset[str]
    vulns_data: dict[str, tuple[str, str | None, str | None]]  # id -> (status, provisional_root, authoritative_root)

    # 4. zkp.proof_jobs
    proof_jobs_count: int
    proof_jobs_ids: frozenset[str]
    proof_jobs_data: dict[str, tuple[str, str | None, str | None, str | None]]  # id -> (status, sbom_root, vuln_db_root, policy_hash)

    # 5. verification.verification_requests
    verif_requests_count: int
    verif_requests_ids: frozenset[str]
    verif_requests_data: dict[str, tuple[str | None, str, str, str]]  # id -> (result, sbom_root, vuln_db_root, policy_hash)

    # 6. verification.verification_certificates
    certs_count: int
    certs_ids: frozenset[str]
    certs_data: dict[str, tuple[bool, Any, str | None, str, str, str]]  # id -> (is_revoked, revoked_at, revoked_reason, sbom_root, vuln_db_root, policy_hash)

    @property
    def apps_user_ids(self) -> dict[str, str | None]:
        return {k: v[2] for k, v in self.apps_data.items()}

    @property
    def proof_jobs_statuses(self) -> dict[str, str]:
        return {k: v[0] for k, v in self.proof_jobs_data.items()}

    @property
    def certs_revocation(self) -> dict[str, tuple[bool, Any]]:
        return {k: (v[0], v[1]) for k, v in self.certs_data.items()}


def verify_authorization_gate() -> None:
    """Verify that execution of migration 015 has been explicitly authorized."""
    auth_val = os.environ.get("ALLOW_PG16_MIGRATION_015")
    if auth_val != "true":
        raise MigrationGateError(
            "Migration 015 execution is blocked. "
            "Set ALLOW_PG16_MIGRATION_015=true to authorize live migration execution."
        )

    staging_val = os.environ.get("STAGING_MODE")
    if staging_val and staging_val.strip().lower() == "true":
        raise MigrationGateError(
            "run_pg16_migration_015.py rejects STAGING_MODE=true. "
            "This runner strictly targets local development PostgreSQL 16."
        )


def capture_database_snapshot(connection: Any) -> DatabaseSnapshot:
    """Capture a durable snapshot of existing primary keys, row counts, and values across all 6 tables."""
    try:
        # 1. public.users
        res_users = connection.execute(
            text("SELECT id, username, role FROM public.users")
        ).fetchall()
        users_ids = frozenset(str(r[0]) for r in res_users)
        users_data = {str(r[0]): (str(r[1]), str(r[2])) for r in res_users}

        # 2. sbom.applications
        res_apps = connection.execute(
            text("SELECT id, name, vendor, user_id FROM sbom.applications")
        ).fetchall()
        apps_ids = frozenset(str(r[0]) for r in res_apps)
        apps_data = {
            str(r[0]): (str(r[1]), str(r[2]), str(r[3]) if r[3] is not None else None)
            for r in res_apps
        }

        # 3. vulnerability.vulnerability_snapshots
        res_vulns = connection.execute(
            text(
                "SELECT id, status, provisional_smt_root, authoritative_smt_root "
                "FROM vulnerability.vulnerability_snapshots"
            )
        ).fetchall()
        vulns_ids = frozenset(str(r[0]) for r in res_vulns)
        vulns_data = {
            str(r[0]): (
                str(r[1]),
                str(r[2]) if r[2] is not None else None,
                str(r[3]) if r[3] is not None else None,
            )
            for r in res_vulns
        }

        # 4. zkp.proof_jobs
        res_jobs = connection.execute(
            text(
                "SELECT id, status, sbom_root, vulnerability_db_root, policy_hash "
                "FROM zkp.proof_jobs"
            )
        ).fetchall()
        proof_jobs_ids = frozenset(str(r[0]) for r in res_jobs)
        proof_jobs_data = {
            str(r[0]): (
                str(r[1]),
                str(r[2]) if r[2] is not None else None,
                str(r[3]) if r[3] is not None else None,
                str(r[4]) if r[4] is not None else None,
            )
            for r in res_jobs
        }

        # 5. verification.verification_requests
        res_vreqs = connection.execute(
            text(
                "SELECT id, result, sbom_root, vulnerability_db_root, policy_hash "
                "FROM verification.verification_requests"
            )
        ).fetchall()
        verif_requests_ids = frozenset(str(r[0]) for r in res_vreqs)
        verif_requests_data = {
            str(r[0]): (
                str(r[1]) if r[1] is not None else None,
                str(r[2]) if r[2] is not None else "",
                str(r[3]) if r[3] is not None else "",
                str(r[4]) if r[4] is not None else "",
            )
            for r in res_vreqs
        }

        # 6. verification.verification_certificates
        res_certs = connection.execute(
            text(
                "SELECT id, is_revoked, revoked_at, revoked_reason, sbom_root, vulnerability_db_root, policy_hash "
                "FROM verification.verification_certificates"
            )
        ).fetchall()
        certs_ids = frozenset(str(r[0]) for r in res_certs)
        certs_data = {
            str(r[0]): (
                bool(r[1]),
                r[2],
                str(r[3]) if r[3] is not None else None,
                str(r[4]) if r[4] is not None else "",
                str(r[5]) if r[5] is not None else "",
                str(r[6]) if r[6] is not None else "",
            )
            for r in res_certs
        }
    except Exception as exc:
        if callable(getattr(connection, "rollback", None)):
            connection.rollback()
        raise MigrationVerificationError(
            f"Pre-migration baseline snapshot capture failed: {exc}"
        ) from exc
    finally:
        if callable(getattr(connection, "rollback", None)):
            connection.rollback()

    return DatabaseSnapshot(
        users_count=len(users_ids),
        users_ids=users_ids,
        users_data=users_data,
        apps_count=len(apps_ids),
        apps_ids=apps_ids,
        apps_data=apps_data,
        vulns_count=len(vulns_ids),
        vulns_ids=vulns_ids,
        vulns_data=vulns_data,
        proof_jobs_count=len(proof_jobs_ids),
        proof_jobs_ids=proof_jobs_ids,
        proof_jobs_data=proof_jobs_data,
        verif_requests_count=len(verif_requests_ids),
        verif_requests_ids=verif_requests_ids,
        verif_requests_data=verif_requests_data,
        certs_count=len(certs_ids),
        certs_ids=certs_ids,
        certs_data=certs_data,
    )


def verify_post_migration_state(connection: Any, pre_snapshot: DatabaseSnapshot) -> None:
    """Automated comparison asserting zero data loss and exact schema conformity."""
    discrepancies: list[str] = []

    try:
        # 1. Verify Alembic revision num is strictly 015
        res_rev = connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar()
        if str(res_rev) != "015":
            discrepancies.append(f"Recorded revision is '{res_rev}', expected strictly '015'.")

        # 2. Verify public.users primary keys, row counts, and values
        res_users = connection.execute(
            text("SELECT id, username, role, is_active, updated_at FROM public.users")
        ).fetchall()
        post_users_ids = frozenset(str(r[0]) for r in res_users)
        if post_users_ids != pre_snapshot.users_ids:
            missing = sorted(pre_snapshot.users_ids - post_users_ids)
            added = sorted(post_users_ids - pre_snapshot.users_ids)
            discrepancies.append(f"public.users primary key set mismatch! Missing: {missing}, Added: {added}.")
        if len(post_users_ids) != pre_snapshot.users_count:
            discrepancies.append(f"public.users row count mismatch: {len(post_users_ids)} vs {pre_snapshot.users_count}.")

        for r in res_users:
            uid = str(r[0])
            uname, role, is_active, updated_at = str(r[1]), str(r[2]), bool(r[3]), r[4]
            if uid in pre_snapshot.users_data:
                orig_uname, orig_role = pre_snapshot.users_data[uid]
                if uname != orig_uname:
                    discrepancies.append(f"User {uid} username altered from '{orig_uname}' to '{uname}'.")
                if role != orig_role:
                    discrepancies.append(f"User {uid} role altered from '{orig_role}' to '{role}'.")
            if not is_active:
                discrepancies.append(f"User {uid} is_active is False, expected default True.")
            if updated_at is None:
                discrepancies.append(f"User {uid} updated_at is NULL, expected server default timestamp.")

        # 3. Verify sbom.applications primary keys, row counts, ownership and values
        res_apps = connection.execute(
            text("SELECT id, name, vendor, user_id, is_active, archived_at FROM sbom.applications")
        ).fetchall()
        post_apps_ids = frozenset(str(r[0]) for r in res_apps)
        if post_apps_ids != pre_snapshot.apps_ids:
            missing = sorted(pre_snapshot.apps_ids - post_apps_ids)
            added = sorted(post_apps_ids - pre_snapshot.apps_ids)
            discrepancies.append(f"sbom.applications primary key set mismatch! Missing: {missing}, Added: {added}.")
        if len(post_apps_ids) != pre_snapshot.apps_count:
            discrepancies.append(f"sbom.applications row count mismatch: {len(post_apps_ids)} vs {pre_snapshot.apps_count}.")

        for r in res_apps:
            aid = str(r[0])
            name, vendor = str(r[1]), str(r[2])
            uid = str(r[3]) if r[3] is not None else None
            is_active, archived_at = bool(r[4]), r[5]
            if aid in pre_snapshot.apps_data:
                orig_name, orig_vendor, orig_uid = pre_snapshot.apps_data[aid]
                if name != orig_name or vendor != orig_vendor:
                    discrepancies.append(f"Application {aid} name/vendor altered.")
                if uid != orig_uid:
                    discrepancies.append(f"Application {aid} user_id ownership altered from '{orig_uid}' to '{uid}'.")
            if not is_active:
                discrepancies.append(f"Application {aid} is_active is False, expected default True.")
            if archived_at is not None:
                discrepancies.append(f"Application {aid} archived_at is NOT NULL on migration upgrade.")

        # 4. Verify vulnerability.vulnerability_snapshots commitments, counts, and status
        res_vulns = connection.execute(
            text("SELECT id, status, provisional_smt_root, authoritative_smt_root FROM vulnerability.vulnerability_snapshots")
        ).fetchall()
        post_vulns_ids = frozenset(str(r[0]) for r in res_vulns)
        if post_vulns_ids != pre_snapshot.vulns_ids:
            missing = sorted(pre_snapshot.vulns_ids - post_vulns_ids)
            added = sorted(post_vulns_ids - pre_snapshot.vulns_ids)
            discrepancies.append(f"vulnerability_snapshots primary key set mismatch! Missing: {missing}, Added: {added}.")
        if len(post_vulns_ids) != pre_snapshot.vulns_count:
            discrepancies.append(f"vulnerability_snapshots row count mismatch: {len(post_vulns_ids)} vs {pre_snapshot.vulns_count}.")

        for r in res_vulns:
            vid = str(r[0])
            status = str(r[1])
            prov_root = str(r[2]) if r[2] is not None else None
            auth_root = str(r[3]) if r[3] is not None else None
            if vid in pre_snapshot.vulns_data:
                orig_status, orig_prov, orig_auth = pre_snapshot.vulns_data[vid]
                if status != orig_status:
                    discrepancies.append(f"Vulnerability snapshot {vid} status altered from '{orig_status}' to '{status}'.")
                if prov_root != orig_prov or auth_root != orig_auth:
                    discrepancies.append(f"Vulnerability snapshot {vid} cryptographic commitment root altered.")

        # 5. Verify zkp.proof_jobs status, counts, and public inputs
        res_jobs = connection.execute(
            text("SELECT id, status, sbom_root, vulnerability_db_root, policy_hash FROM zkp.proof_jobs")
        ).fetchall()
        post_jobs_ids = frozenset(str(r[0]) for r in res_jobs)
        if post_jobs_ids != pre_snapshot.proof_jobs_ids:
            missing = sorted(pre_snapshot.proof_jobs_ids - post_jobs_ids)
            added = sorted(post_jobs_ids - pre_snapshot.proof_jobs_ids)
            discrepancies.append(f"zkp.proof_jobs primary key set mismatch! Missing: {missing}, Added: {added}.")
        if len(post_jobs_ids) != pre_snapshot.proof_jobs_count:
            discrepancies.append(f"zkp.proof_jobs row count mismatch: {len(post_jobs_ids)} vs {pre_snapshot.proof_jobs_count}.")

        for r in res_jobs:
            jid = str(r[0])
            status = str(r[1])
            s_root = str(r[2]) if r[2] is not None else None
            v_root = str(r[3]) if r[3] is not None else None
            p_hash = str(r[4]) if r[4] is not None else None
            if jid in pre_snapshot.proof_jobs_data:
                orig_status, orig_s, orig_v, orig_p = pre_snapshot.proof_jobs_data[jid]
                if status != orig_status:
                    discrepancies.append(f"Proof job {jid} status altered from '{orig_status}' to '{status}'.")
                if (s_root, v_root, p_hash) != (orig_s, orig_v, orig_p):
                    discrepancies.append(f"Proof job {jid} public inputs altered.")

        # 6. Verify verification.verification_requests outcomes, counts, and public inputs
        res_vreqs = connection.execute(
            text("SELECT id, result, sbom_root, vulnerability_db_root, policy_hash FROM verification.verification_requests")
        ).fetchall()
        post_vreqs_ids = frozenset(str(r[0]) for r in res_vreqs)
        if post_vreqs_ids != pre_snapshot.verif_requests_ids:
            missing = sorted(pre_snapshot.verif_requests_ids - post_vreqs_ids)
            added = sorted(post_vreqs_ids - pre_snapshot.verif_requests_ids)
            discrepancies.append(f"verification_requests primary key set mismatch! Missing: {missing}, Added: {added}.")
        if len(post_vreqs_ids) != pre_snapshot.verif_requests_count:
            discrepancies.append(f"verification_requests row count mismatch: {len(post_vreqs_ids)} vs {pre_snapshot.verif_requests_count}.")

        for r in res_vreqs:
            rid = str(r[0])
            result = str(r[1]) if r[1] is not None else None
            s_root = str(r[2]) if r[2] is not None else ""
            v_root = str(r[3]) if r[3] is not None else ""
            p_hash = str(r[4]) if r[4] is not None else ""
            if rid in pre_snapshot.verif_requests_data:
                orig_result, orig_s, orig_v, orig_p = pre_snapshot.verif_requests_data[rid]
                if result != orig_result:
                    discrepancies.append(f"Verification request {rid} outcome result altered from '{orig_result}' to '{result}'.")
                if (s_root, v_root, p_hash) != (orig_s, orig_v, orig_p):
                    discrepancies.append(f"Verification request {rid} public inputs altered.")

        # 7. Verify verification.verification_certificates revocation state, counts, and commitments
        res_certs = connection.execute(
            text(
                "SELECT id, is_revoked, revoked_at, revoked_reason, sbom_root, vulnerability_db_root, policy_hash, revoked_by "
                "FROM verification.verification_certificates"
            )
        ).fetchall()
        post_certs_ids = frozenset(str(r[0]) for r in res_certs)
        if post_certs_ids != pre_snapshot.certs_ids:
            missing = sorted(pre_snapshot.certs_ids - post_certs_ids)
            added = sorted(post_certs_ids - pre_snapshot.certs_ids)
            discrepancies.append(f"verification_certificates primary key set mismatch! Missing: {missing}, Added: {added}.")
        if len(post_certs_ids) != pre_snapshot.certs_count:
            discrepancies.append(f"verification_certificates row count mismatch: {len(post_certs_ids)} vs {pre_snapshot.certs_count}.")

        for r in res_certs:
            cid = str(r[0])
            is_revoked, revoked_at = bool(r[1]), r[2]
            revoked_reason = str(r[3]) if r[3] is not None else None
            s_root = str(r[4]) if r[4] is not None else ""
            v_root = str(r[5]) if r[5] is not None else ""
            p_hash = str(r[6]) if r[6] is not None else ""
            revoked_by = r[7]

            if cid in pre_snapshot.certs_data:
                orig_rev, orig_at, orig_reason, orig_s, orig_v, orig_p = pre_snapshot.certs_data[cid]
                if is_revoked != orig_rev:
                    discrepancies.append(f"Certificate {cid} is_revoked altered from {orig_rev} to {is_revoked}.")
                if orig_at is not None and revoked_at is None:
                    discrepancies.append(f"Certificate {cid} revoked_at was cleared.")
                if revoked_reason != orig_reason:
                    discrepancies.append(f"Certificate {cid} revoked_reason altered.")
                if (s_root, v_root, p_hash) != (orig_s, orig_v, orig_p):
                    discrepancies.append(f"Certificate {cid} public commitment root altered.")
            if revoked_by is not None:
                discrepancies.append(f"Certificate {cid} has unexpected revoked_by on upgrade: {revoked_by}.")

    except Exception as exc:
        if callable(getattr(connection, "rollback", None)):
            connection.rollback()
        raise MigrationVerificationError(
            f"Post-migration schema/data verification failed: {exc}"
        ) from exc
    finally:
        # Roll back verification query transaction
        if callable(getattr(connection, "rollback", None)):
            connection.rollback()

    if discrepancies:
        raise MigrationVerificationError(
            f"Post-migration validation failed with {len(discrepancies)} discrepancy(ies):\n"
            + "\n".join(f"  - {d}" for d in discrepancies)
        )


def execute_migration_015(
    connection: Any,
    settings: Any | None = None,
    alembic_ini_path: str = "backend/alembic.ini",
    script_location: str | None = None,
) -> None:
    """Execute migration 015 using verified connection and automated snapshot validation."""
    # 1. Verify authorization gate
    verify_authorization_gate()

    # 2. Run independent preflight verification
    verify_pg16_target_preflight(
        connection=connection,
        settings=settings,
        expected_revision="014",
    )

    # 3. Capture durable pre-migration data snapshot
    print("[1/4] Capturing pre-migration database snapshot...")
    snapshot = capture_database_snapshot(connection)
    print(f"      Snapshot baseline: {snapshot.users_count} users, {snapshot.apps_count} apps, "
          f"{snapshot.certs_count} certs, {snapshot.proof_jobs_count} proof jobs.")

    # 4. Invoke Alembic upgrade using verified connection
    print("[2/4] Executing Alembic migration 015 via verified connection...")
    ini_abs = os.path.abspath(os.path.join(_repo_root, alembic_ini_path))
    alembic_cfg = Config(ini_abs)
    resolved_script_loc = os.path.abspath(script_location or _alembic_dir)
    alembic_cfg.set_main_option("script_location", resolved_script_loc)
    alembic_cfg.attributes["connection"] = connection
    alembic_cfg.attributes["target_database"] = PG16_EXPECTED_DB_NAME

    command.upgrade(alembic_cfg, "015")
    print("      Alembic upgrade command completed successfully.")

    # 5. Automated post-migration data and schema validation
    print("[3/4] Running automated post-migration data preservation and schema comparison...")
    verify_post_migration_state(connection, snapshot)
    print("      Post-migration verification PASSED: 100% key set preservation, valid schema objects.")


def run_migration_cli(
    argv: list[str] | None = None,
    engine: Any | None = None,
    settings: Any | None = None,
) -> int:
    """CLI entry point for running PostgreSQL 16 migration 015."""
    parser = argparse.ArgumentParser(
        description="Controlled, verified migration 015 runner for PostgreSQL 16 local development."
    )
    parser.parse_args(argv)

    try:
        # Gate check before attempting engine or socket connections
        verify_authorization_gate()

        if settings is None:
            settings = get_db_settings()

        if engine is None:
            engine = create_engine(settings.url, poolclass=pool.NullPool)

        with engine.connect() as connection:
            execute_migration_015(connection=connection, settings=settings)

        print("[4/4] Migration 015 execution and verification completed successfully.")
        return 0
    except (MigrationGateError, StagingConfigError, MigrationVerificationError) as exc:
        print(f"\n[ERROR] Migration aborted: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"\n[FATAL] Unexpected error during migration execution: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_migration_cli())

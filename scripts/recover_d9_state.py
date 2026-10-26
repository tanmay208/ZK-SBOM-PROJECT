"""
Offline Validator and Guarded Recovery Utility for Stage D9 Acceptance Manifests.
Authoritative Location: scripts/recover_d9_state.py

MODES:
  1. Offline Validation & Dry-Run (Default):
     - Validates manifest schema, UUIDs, baseline protection, and foreign-key sequence.
     - Computes and prints the exact reverse foreign-key deletion plan.
     - Performs ZERO network or database connections.
  2. Guarded Live Recovery (Requires explicit CLI flag and authorization env var):
     - Strictly blocked unless --execute-live-recovery is provided.
     - Strictly blocked unless ALLOW_D9_LIVE_RECOVERY=true is set in process environment.
     - Connects strictly to PostgreSQL 16 on 127.0.0.1:5433, database ZKP_SBOM_LOCAL_DEV.
     - Specifically rejects PostgreSQL 17 or port 5432 (Gate 5R).
     - Deletes only exact manifest test IDs in verified reverse foreign-key order.
     - Never uses broad deletes or infers missing IDs.
     - Preserves manifest and diagnostic output on failure; never downgrades migrations.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure scripts and backend directories are on sys.path
_scripts_dir = Path(__file__).resolve().parent
_repo_root = _scripts_dir.parent
_backend_dir = _repo_root / "backend"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from d9_cleanup_manifest import (
    BASELINE_PROTECTED_UUIDS,
    ORDERED_CLEANUP_TABLES,
    TABLE_SQL_NAMES,
    BaselineProtectionViolationError,
    CorruptedManifestError,
    DurableCleanupManifest,
    ManifestError,
    ManifestValidationError,
)

# -----------------------------------------------------------------------------
# Recovery Precondition Constants
# -----------------------------------------------------------------------------
EXPECTED_HOST = "127.0.0.1"
EXPECTED_PORT = 5433
EXPECTED_DB = "ZKP_SBOM_LOCAL_DEV"
EXPECTED_MAJOR_VER = 16
EXPECTED_REVISION = "015"
PROHIBITED_PORT = 5432
PROHIBITED_DB = "ZKP_SBOM"


@dataclass(frozen=True)
class DeletionStep:
    step_number: int
    table_name: str
    sql_table: str
    target_count: int
    target_ids: Tuple[str, ...]


# -----------------------------------------------------------------------------
# Offline Validation & Dry-Run Planning (Zero Database Connections)
# -----------------------------------------------------------------------------
def compute_dry_run_plan(manifest: DurableCleanupManifest) -> List[DeletionStep]:
    """
    Computes the exact reverse foreign-key deletion sequence from the manifest.
    Asserts zero overlap with protected baseline UUIDs.
    Performs zero network or database queries.
    """
    plan: List[DeletionStep] = []
    step_num = 1

    for table in ORDERED_CLEANUP_TABLES:
        ids = tuple(manifest.entities.get(table, []))
        if ids:
            # Re-verify baseline protection for every step
            overlap = set(ids).intersection(BASELINE_PROTECTED_UUIDS)
            if overlap:
                raise BaselineProtectionViolationError(
                    f"SAFETY GATE HALT: Manifest step for table '{table}' contains protected UUID(s): {overlap}"
                )

            step = DeletionStep(
                step_number=step_num,
                table_name=table,
                sql_table=TABLE_SQL_NAMES[table],
                target_count=len(ids),
                target_ids=ids,
            )
            plan.append(step)
            step_num += 1

    return plan


def run_dry_run_inspection(manifest_path: Path) -> int:
    """
    Performs full offline schema validation and displays the dry-run deletion plan.
    Guaranteed zero database connections.
    """
    print("=" * 70)
    print("STAGE D9 MANIFEST OFFLINE VALIDATOR & DRY-RUN INSPECTION")
    print("=" * 70)
    print(f"Manifest Path: {manifest_path.resolve()}")

    try:
        manifest = DurableCleanupManifest.load_from_file(manifest_path)
    except ManifestError as exc:
        print(f"\n[VALIDATION FAILED] Manifest rejected: {exc}", file=sys.stderr)
        return 1

    print(f"Run ID:        {manifest.run_id}")
    print(f"Status:        {manifest.status}")
    print(f"Created:       {manifest.created_at}")
    print(f"Updated:       {manifest.updated_at}")
    print(f"Target DB:     {manifest.expected_db} on {manifest.expected_host}:{manifest.expected_port} (Rev {manifest.expected_revision})")
    print(f"Errors Logged: {len(manifest.errors)}")

    try:
        plan = compute_dry_run_plan(manifest)
    except BaselineProtectionViolationError as exc:
        print(f"\n[SECURITY VIOLATION] Dry-run plan rejected: {exc}", file=sys.stderr)
        return 2

    total_entities = sum(s.target_count for s in plan)
    print(f"\nTotal Ephemeral Test Entities Recorded: {total_entities}")
    print("-" * 70)
    print("PLANNED REVERSE FOREIGN-KEY DELETION SEQUENCE:")
    print("-" * 70)

    if not plan:
        print("  (Manifest contains zero ephemeral entities. No deletions planned.)")
    else:
        for s in plan:
            print(f"  Step {s.step_number:02d}: Delete {s.target_count:3d} record(s) from {s.sql_table}")
            for item_id in s.target_ids:
                print(f"           - ID: {item_id}")

    if manifest.baseline_policy_states:
        print("-" * 70)
        print("BASELINE POLICY STATE RESTORATION PLAN:")
        print("-" * 70)
        for pol_id, orig_active in manifest.baseline_policy_states.items():
            print(f"  - Restore policy {pol_id} -> is_active={orig_active}")

    print("-" * 70)
    print("[DRY-RUN COMPLETE] Manifest is valid and consistent. Zero DB connections made.")
    return 0


# -----------------------------------------------------------------------------
# Guarded Live Recovery Execution (Strictly Blocked by Default)
# -----------------------------------------------------------------------------
def execute_live_recovery(
    manifest_path: Path,
    connection: Any = None,
    engine: Any = None,
) -> int:
    """
    Executes live recovery using verified target connection and exact manifest IDs.
    Fails closed on any ambiguity or safety gate failure.
    """
    # 1. Authorization Gate Check
    allow_env = os.environ.get("ALLOW_D9_LIVE_RECOVERY", "").strip().lower()
    if allow_env != "true":
        print(
            "FAIL_CLOSED: Live recovery requires explicit process environment variable: "
            "ALLOW_D9_LIVE_RECOVERY=true",
            file=sys.stderr,
        )
        return 1

    # 2. Load and validate manifest offline first
    try:
        manifest = DurableCleanupManifest.load_from_file(manifest_path)
        plan = compute_dry_run_plan(manifest)
    except Exception as exc:
        print(f"FAIL_CLOSED: Manifest validation failed before connection: {exc}", file=sys.stderr)
        return 1

    # 3. Connection and Target Safety Verification
    from sqlalchemy import bindparam, create_engine, text
    from sqlalchemy.engine import Engine, URL

    db_pass = os.environ.get("DB_PASSWORD", "").strip()
    if not db_pass:
        print("FAIL_CLOSED: DB_PASSWORD is empty or unset. No recovery will be attempted.", file=sys.stderr)
        return 1

    conn_url = URL.create(
        drivername="postgresql+psycopg2",
        username=os.environ.get("DB_USER", "postgres").strip(),
        password=db_pass,
        host=os.environ.get("DB_HOST", EXPECTED_HOST).strip(),
        port=int(os.environ.get("DB_PORT", str(EXPECTED_PORT)).strip()),
        database=os.environ.get("DB_NAME", EXPECTED_DB).strip(),
    )

    # Hard-coded safety check: Reject port 5432 or any non-authorized database
    if conn_url.port == PROHIBITED_PORT or conn_url.database == PROHIBITED_DB:
        print(f"FATAL: Attempted connection to prohibited target {conn_url.host}:{conn_url.port} / {conn_url.database}", file=sys.stderr)
        sys.exit(1)

    if conn_url.port != EXPECTED_PORT or conn_url.database != EXPECTED_DB or conn_url.host != EXPECTED_HOST:
        print(f"FATAL: Unauthorized recovery target: {conn_url.render_as_string(hide_password=True)}", file=sys.stderr)
        return 1

    if engine is None:
        engine = create_engine(conn_url)

    # 4. Read-only Target Catalog Verification
    with engine.connect() as conn:
        ident = conn.execute(
            text(
                "SELECT current_database(), current_setting('server_version_num')::int / 10000, version_num "
                "FROM alembic_version LIMIT 1"
            )
        ).fetchone()
        if not ident:
            print("FAIL_CLOSED: Cannot read database catalog identity.", file=sys.stderr)
            return 1

        db_name, major_ver, rev = str(ident[0]), int(ident[1]), str(ident[2])
        if db_name != EXPECTED_DB or major_ver != EXPECTED_MAJOR_VER or rev != EXPECTED_REVISION:
            print(f"FAIL_CLOSED: Target identity mismatch: DB={db_name}, Ver={major_ver}, Rev={rev}", file=sys.stderr)
            return 1

        # Check baseline users intact
        baseline_users = conn.execute(
            text("SELECT id::text, role, is_active FROM public.users WHERE id IN :uuids").bindparams(
                bindparam("uuids", expanding=True)
            ),
            {"uuids": [str(x) for x in BASELINE_PROTECTED_UUIDS]},
        ).fetchall()
        if len(baseline_users) != 5:
            print(f"FAIL_CLOSED: Baseline user count altered ({len(baseline_users)} != 5)", file=sys.stderr)
            return 1

    # 5. Execute Exact Reverse Foreign-Key Deletion Transaction
    manifest.update_status("cleaning")
    try:
        with engine.begin() as tx:
            for step in plan:
                if step.target_ids:
                    id_strings = [str(x) for x in step.target_ids]
                    # public.users deletion must additionally protect baseline UUIDs in SQL
                    if step.table_name == "users":
                        stmt = text(
                            f"DELETE FROM {step.sql_table} "
                            f"WHERE id IN :ids AND id NOT IN :protected_uuids"
                        ).bindparams(
                            bindparam("ids", expanding=True),
                            bindparam("protected_uuids", expanding=True),
                        )
                        res = tx.execute(stmt, {"ids": id_strings, "protected_uuids": list(BASELINE_PROTECTED_UUIDS)})
                    else:
                        stmt = text(f"DELETE FROM {step.sql_table} WHERE id IN :ids").bindparams(
                            bindparam("ids", expanding=True)
                        )
                        res = tx.execute(stmt, {"ids": id_strings})
                    print(f"[RECOVERY STEP] Deleted {res.rowcount} row(s) from {step.sql_table}")

            # Restore baseline policies
            if manifest.baseline_policy_states:
                for pid_str, active_val in manifest.baseline_policy_states.items():
                    tx.execute(
                        text("UPDATE policy.security_policies SET is_active = :act WHERE id = :pid"),
                        {"act": active_val, "pid": str(pid_str)},
                    )
                print(f"[RECOVERY STEP] Restored {len(manifest.baseline_policy_states)} baseline policy states.")

        manifest.update_status("cleaned")
        print("\n[SUCCESS] Guarded live recovery completed successfully. Manifest marked cleaned.")
        return 0

    except Exception as exc:
        manifest.update_status("failed", error_message=str(exc))
        print(f"\n[CRITICAL RECOVERY FAILURE] Deletion transaction aborted: {exc}", file=sys.stderr)
        return 2


# -----------------------------------------------------------------------------
# CLI Entrypoint
# -----------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stage D9 Manifest Offline Validator and Guarded Recovery Utility."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to the manifest_<run_id>.json file to inspect or recover.",
    )
    parser.add_argument(
        "--execute-live-recovery",
        action="store_true",
        default=False,
        help="Explicit opt-in required to execute live database deletions. Defaults to False (dry-run).",
    )

    args = parser.parse_args()

    if not args.execute_live_recovery:
        return run_dry_run_inspection(args.manifest)
    else:
        return execute_live_recovery(args.manifest)


if __name__ == "__main__":
    sys.exit(main())

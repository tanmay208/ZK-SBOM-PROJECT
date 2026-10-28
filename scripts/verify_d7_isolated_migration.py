"""
Authoritative D7 Isolated Live PostgreSQL 16 Migration Verification.

Executes forward-only Alembic migration 016 on an isolated ephemeral database (ZKP_SBOM_D7_EPHEMERAL)
hosted on container 'zkp_sbom_d9_ephemeral_db' (127.0.0.1:5434).

Strict Safeguards:
  - FORBIDDEN: Connecting to or mutating port 5432 (ZKP_SBOM) or port 5433 (ZKP_SBOM_LOCAL_DEV).
  - FORBIDDEN: Mutating ZKP_SBOM_D9_EPHEMERAL (preserved for D9 evidence).
  - Credentials extracted strictly in-memory from Docker inspection; never logged or written.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone

from alembic.config import Config
from alembic import command
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from sqlalchemy import create_engine, text


EXPECTED_HOST = "127.0.0.1"
EXPECTED_PORT = 5434
EXPECTED_CONTAINER_NAME = "zkp_sbom_d9_ephemeral_db"
ISOLATED_DB_NAME = "ZKP_SBOM_D7_EPHEMERAL"

USERS_BASELINE_V1_DDL = """
CREATE TABLE public.users (
    id UUID NOT NULL,
    username VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_username UNIQUE (username)
);
""".strip()


def run_cmd(cmd: list[str]) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return res.stdout.strip()


def verify_container_and_get_password() -> str:
    # 1. Assert host and port safety
    if EXPECTED_PORT in (5432, 5433):
        raise RuntimeError("FAIL_CLOSED: Prohibited database port")

    # 2. Inspect container
    out = run_cmd(["docker", "inspect", EXPECTED_CONTAINER_NAME])
    data = json.loads(out)[0]

    # Verify status
    status = data.get("State", {}).get("Status", "")
    health = data.get("State", {}).get("Health", {}).get("Status", "")
    if status != "running" or health != "healthy":
        raise RuntimeError(f"FAIL_CLOSED: Container not ready (status='{status}', health='{health}')")

    # Verify port mapping
    ports = data.get("NetworkSettings", {}).get("Ports", {})
    p5432 = ports.get("5432/tcp")
    if not p5432 or p5432[0].get("HostPort") != str(EXPECTED_PORT) or p5432[0].get("HostIp") != EXPECTED_HOST:
        raise RuntimeError(f"FAIL_CLOSED: Port binding violation: {p5432}")

    # Extract password
    env_vars = data.get("Config", {}).get("Env", [])
    db_pass = None
    for item in env_vars:
        if item.startswith("POSTGRES_PASSWORD="):
            db_pass = item.split("=", 1)[1]
            break
    if not db_pass:
        raise RuntimeError("FAIL_CLOSED: Unable to extract container password")

    return db_pass


def main() -> int:
    print("=== D7 ISOLATED LIVE MIGRATION 016 VERIFICATION ===")
    results = {}

    db_pass = verify_container_and_get_password()
    print(f"[1/8] Verified container '{EXPECTED_CONTAINER_NAME}' on {EXPECTED_HOST}:{EXPECTED_PORT}")

    # Connect to default postgres DB on port 5434 to create isolated test DB
    admin_conn = psycopg2.connect(
        host=EXPECTED_HOST,
        port=EXPECTED_PORT,
        user="postgres",
        password=db_pass,
        dbname="postgres",
    )
    admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    admin_cur = admin_conn.cursor()

    # Drop old test db if left over, and create freshly
    admin_cur.execute(f'DROP DATABASE IF EXISTS "{ISOLATED_DB_NAME}";')
    admin_cur.execute(f'CREATE DATABASE "{ISOLATED_DB_NAME}";')
    admin_cur.close()
    admin_conn.close()
    print(f"[2/8] Created isolated test database '{ISOLATED_DB_NAME}'")

    # Connect to isolated DB with psycopg2 for direct queries
    conn = psycopg2.connect(
        host=EXPECTED_HOST,
        port=EXPECTED_PORT,
        user="postgres",
        password=db_pass,
        dbname=ISOLATED_DB_NAME,
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    # Verify connection identity
    cur.execute("SELECT current_database(), inet_server_port(), version();")
    row = cur.fetchone()
    connected_db, server_port, version = row[0], row[1], row[2]
    if connected_db != ISOLATED_DB_NAME:
        raise RuntimeError(f"Database mismatch: connected to {connected_db}")
    if "PostgreSQL 16" not in version:
        raise RuntimeError(f"Engine mismatch: expected PG16, got {version}")
    print(f"[3/8] Verified database identity: {connected_db} on PG16 (server_port={server_port})")

    # Create users baseline
    cur.execute(USERS_BASELINE_V1_DDL)
    print("[4/8] Applied public.users baseline DDL")

    # Setup SQLAlchemy Engine and Alembic config pointing to this isolated DB
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
    alembic_dir = os.path.join(backend_dir, "alembic")
    alembic_ini = os.path.join(backend_dir, "alembic.ini")

    db_url = f"postgresql://postgres:{db_pass}@{EXPECTED_HOST}:{EXPECTED_PORT}/{ISOLATED_DB_NAME}"
    sa_engine = create_engine(db_url, isolation_level="AUTOCOMMIT")

    alembic_cfg = Config(alembic_ini)
    alembic_cfg.set_main_option("script_location", alembic_dir)

    # Set required environment variables for Alembic staging_guard
    os.environ["LOCAL_DEV_PORT_ALLOW"] = "true"
    os.environ["ALLOW_UNVERSIONED_BASELINE"] = "true"
    os.environ["TARGET_DATABASE"] = ISOLATED_DB_NAME

    # Upgrade to 015 first
    print("[5/8] Migrating up to revision 015...")
    with sa_engine.connect() as sa_conn:
        alembic_cfg.attributes["connection"] = sa_conn
        alembic_cfg.attributes["target_database"] = ISOLATED_DB_NAME
        alembic_cfg.attributes["allow_unversioned_baseline"] = True
        command.upgrade(alembic_cfg, "015")

    cur.execute("SELECT version_num FROM public.alembic_version;")
    rev = cur.fetchone()[0]
    if rev != "015":
        raise RuntimeError(f"Expected revision 015, found {rev}")
    results["pre_016_revision"] = rev
    print(f"      Current revision verified: {rev}")

    # Seed legacy snapshot and user
    user_id = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO public.users (id, username, hashed_password, role) VALUES (%s, %s, %s, %s);",
        (user_id, "test_admin", "hash123", "admin")
    )
    snap_legacy_id = str(uuid.uuid4())
    t_frozen = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    cur.execute(
        """
        INSERT INTO vulnerability.vulnerability_snapshots
        (id, snapshot_label, record_count, status, authoritative_smt_root, frozen_at, frozen_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
        """,
        (snap_legacy_id, "legacy_snap_001", 100, "frozen", "0xlegacyroot123", t_frozen, user_id)
    )
    print("      Seeded representative legacy snapshot (status='frozen', prior to migration 016)")

    # Verify column 'expires_at' does NOT exist yet
    cur.execute(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'vulnerability' AND table_name = 'vulnerability_snapshots'
        AND column_name = 'expires_at';
        """
    )
    assert cur.fetchone() is None, "expires_at column unexpectedly already exists before 016"
    print("      Verified: 'expires_at' does not exist in schema at rev 015")

    # Apply migration 016
    print("[6/8] Executing forward-only migration 016...")
    with sa_engine.connect() as sa_conn:
        alembic_cfg.attributes["connection"] = sa_conn
        alembic_cfg.attributes["target_database"] = ISOLATED_DB_NAME
        alembic_cfg.attributes["allow_unversioned_baseline"] = True
        command.upgrade(alembic_cfg, "016")

    cur.execute("SELECT version_num FROM public.alembic_version;")
    post_rev = cur.fetchone()[0]
    if post_rev != "016":
        raise RuntimeError(f"Expected revision 016, found {post_rev}")
    results["post_016_revision"] = post_rev
    print(f"      Current revision verified: {post_rev}")

    # Verify 'expires_at' column definition
    cur.execute(
        """
        SELECT column_name, is_nullable, data_type
        FROM information_schema.columns
        WHERE table_schema = 'vulnerability' AND table_name = 'vulnerability_snapshots'
        AND column_name = 'expires_at';
        """
    )
    col_info = cur.fetchone()
    assert col_info is not None, "expires_at column missing after migration 016"
    assert col_info[1] == "YES", "expires_at is not nullable"
    assert "timestamp" in col_info[2].lower(), f"Unexpected data type for expires_at: {col_info[2]}"
    results["column_verification"] = {
        "column_name": col_info[0],
        "is_nullable": col_info[1],
        "data_type": col_info[2],
    }
    print(f"      Verified column 'expires_at': nullable={col_info[1]}, type={col_info[2]}")

    # Verify legacy snapshot retains expires_at = NULL (D7-POL-03 Grandfathering)
    cur.execute(
        "SELECT id, snapshot_label, status, expires_at FROM vulnerability.vulnerability_snapshots WHERE id = %s;",
        (snap_legacy_id,)
    )
    legacy_row = cur.fetchone()
    assert legacy_row[3] is None, f"Legacy snapshot expires_at is not NULL: {legacy_row[3]}"
    results["legacy_snapshot_grandfathered"] = {
        "id": legacy_row[0],
        "label": legacy_row[1],
        "status": legacy_row[2],
        "expires_at": None,
    }
    print("      Verified: legacy snapshot retains expires_at = NULL (grandfathered)")

    # Verify index existence
    cur.execute(
        """
        SELECT indexname FROM pg_indexes
        WHERE schemaname = 'vulnerability' AND tablename = 'vulnerability_snapshots'
        AND indexname = 'ix_vuln_snapshots_expires_at';
        """
    )
    assert cur.fetchone() is not None, "Index ix_vuln_snapshots_expires_at missing"
    print("      Verified: index 'ix_vuln_snapshots_expires_at' created successfully")

    # Insert newly frozen snapshot with computed expires_at (D7-POL-02)
    snap_new_id = str(uuid.uuid4())
    t_now = datetime.now(timezone.utc)
    t_exp = t_now + timedelta(seconds=2592000)  # 30 days
    cur.execute(
        """
        INSERT INTO vulnerability.vulnerability_snapshots
        (id, snapshot_label, record_count, status, authoritative_smt_root, frozen_at, expires_at, frozen_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """,
        (snap_new_id, "new_frozen_snap_002", 50, "frozen", "0xnewroot456", t_now, t_exp, user_id)
    )
    cur.execute(
        "SELECT id, status, expires_at FROM vulnerability.vulnerability_snapshots WHERE id = %s;",
        (snap_new_id,)
    )
    new_row = cur.fetchone()
    assert new_row[2] is not None, "Newly frozen snapshot failed to store expires_at"
    results["new_snapshot_expiry_verified"] = {
        "id": new_row[0],
        "status": new_row[1],
        "expires_at": new_row[2].isoformat(),
    }
    print(f"      Verified: new snapshot stored with expires_at: {new_row[2].isoformat()}")

    # Test downgrade / rollback safety
    print("[7/8] Verifying migration downgrade (016 -> 015) and re-upgrade idempotency...")
    with sa_engine.connect() as sa_conn:
        alembic_cfg.attributes["connection"] = sa_conn
        alembic_cfg.attributes["target_database"] = ISOLATED_DB_NAME
        alembic_cfg.attributes["allow_unversioned_baseline"] = True
        command.downgrade(alembic_cfg, "015")

    cur.execute("SELECT version_num FROM public.alembic_version;")
    assert cur.fetchone()[0] == "015"
    cur.execute(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'vulnerability' AND table_name = 'vulnerability_snapshots'
        AND column_name = 'expires_at';
        """
    )
    assert cur.fetchone() is None, "expires_at column not dropped on downgrade"
    print("      Downgrade to 015 verified: column dropped cleanly.")

    # Re-upgrade to 016
    with sa_engine.connect() as sa_conn:
        alembic_cfg.attributes["connection"] = sa_conn
        alembic_cfg.attributes["target_database"] = ISOLATED_DB_NAME
        alembic_cfg.attributes["allow_unversioned_baseline"] = True
        command.upgrade(alembic_cfg, "016")

    cur.execute("SELECT version_num FROM public.alembic_version;")
    assert cur.fetchone()[0] == "016"
    print("      Re-upgrade to 016 verified: restored cleanly.")

    # Cleanup test database
    cur.close()
    conn.close()
    sa_engine.dispose()

    admin_conn = psycopg2.connect(
        host=EXPECTED_HOST,
        port=EXPECTED_PORT,
        user="postgres",
        password=db_pass,
        dbname="postgres",
    )
    admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    admin_cur = admin_conn.cursor()
    admin_cur.execute(f'DROP DATABASE "{ISOLATED_DB_NAME}";')
    admin_cur.close()
    admin_conn.close()
    print(f"[8/8] Cleaned up isolated test database '{ISOLATED_DB_NAME}'")

    print("\nALL 8 LIVE MIGRATION 016 CHECKS PASSED ON POSTGRESQL 16 (PORT 5434)!")
    return 0


if __name__ == "__main__":
    sys.exit(main())

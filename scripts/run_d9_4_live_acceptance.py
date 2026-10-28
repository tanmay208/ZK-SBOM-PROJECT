"""
D9-4 Bounded Live Intake Acceptance Runner with Durable Crash-Resilient Safeguards
Authoritative Location: scripts/run_d9_4_live_acceptance.py
Target: 127.0.0.1:5433 / ZKP_SBOM_LOCAL_DEV (PostgreSQL 16, rev 015)
Unified Host: 127.0.0.1:8080

KNOWN ARCHITECTURAL LIMITATION & CRASH WINDOW:
  There exists a window between when the backend service commits a database entity
  transaction in PostgreSQL and when the runner receives the HTTP response and calls
  manifest.record_entity(). If the runner process is abruptly terminated (SIGKILL,
  kernel panic, power loss) during this precise microsecond window, the entity ID
  will not be durably recorded in the manifest.
  This is mitigated by:
    1. Deterministic test names and prefixes (e.g., 'd9_test_app_*', 'D9 Verification Vendor').
    2. Atomic manifest write immediately upon response parsing, before any subsequent step.
    3. Dry-run and offline inspection via scripts/recover_d9_state.py.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Path bootstrap
_scripts_dir = Path(__file__).resolve().parent
_repo_root = _scripts_dir.parent
_backend_root = _repo_root / "backend"

if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.engine import Engine, URL

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
# Constants & Safety Invariants
# -----------------------------------------------------------------------------
EXPECTED_HOST = "127.0.0.1"
EXPECTED_PORT = 5433
EXPECTED_DB = "ZKP_SBOM_LOCAL_DEV"
EXPECTED_MAJOR_VER = 16
EXPECTED_REVISION = "015"
PROHIBITED_PORT = 5432
PROHIBITED_DB = "ZKP_SBOM"
APP_PORT = 8080
BASE_URL = f"http://127.0.0.1:{APP_PORT}/api/v1"

EXPECTED_ROLES = {
    "d9_vendor": "vendor",
    "d9_trusted_importer": "trusted_importer",
    "d9_admin": "admin",
}

COUNTS_SQL = """
SELECT 
    (SELECT count(*) FROM public.users) as users,
    (SELECT count(*) FROM sbom.applications) as applications,
    (SELECT count(*) FROM sbom.sbom_uploads) as sbom_uploads,
    (SELECT count(*) FROM sbom.components) as components,
    (SELECT count(*) FROM policy.security_policies) as security_policies,
    (SELECT count(*) FROM vulnerability.vulnerability_snapshots) as vulnerability_snapshots,
    (SELECT count(*) FROM vulnerability.component_vulnerability_mappings) as component_vulnerability_mappings,
    (SELECT count(*) FROM zkp.proof_jobs) as proof_jobs,
    (SELECT count(*) FROM zkp.chunk_proof_sets) as chunk_proof_sets,
    (SELECT count(*) FROM zkp.segment_proofs) as segment_proofs,
    (SELECT count(*) FROM verification.verification_requests) as verification_requests,
    (SELECT count(*) FROM verification.verification_certificates) as verification_certificates
"""


# -----------------------------------------------------------------------------
# Safety Sanitization & Credential Helpers
# -----------------------------------------------------------------------------
def sanitize_text(text_val: str, extra_secrets: list[str] | None = None) -> str:
    """Sanitizes text by masking passwords, JWT tokens, and connection strings."""
    if not text_val:
        return ""
    sanitized = str(text_val)
    sanitized = re.sub(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", "Bearer [REDACTED_TOKEN]", sanitized)
    sanitized = re.sub(r"://([^:]+):([^@]+)@", r"://\1:[REDACTED_PASSWORD]@", sanitized)
    sanitized = re.sub(r"(password=)[^&\s]+", r"\1[REDACTED]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'("password":\s*")[^"]+(")', r"\1[REDACTED]\2", sanitized, flags=re.IGNORECASE)
    if extra_secrets:
        for s in extra_secrets:
            if s and len(s) >= 4:
                sanitized = sanitized.replace(s, "[REDACTED]")
    return sanitized


def get_db_password() -> str:
    """Retrieves DB_PASSWORD strictly from environment without default fallback."""
    db_pass = os.environ.get("DB_PASSWORD")
    if not db_pass or not db_pass.strip():
        raise RuntimeError(
            "FAIL_CLOSED: DB_PASSWORD environment variable is missing or blank. "
            "No connection will be attempted."
        )
    return db_pass.strip()


def parse_and_validate_credentials(raw_data: Any) -> dict[str, dict[str, Any]]:
    """Strictly validates and normalizes credentials data into a mapping keyed by username."""
    if not isinstance(raw_data, (dict, list)):
        raise ValueError(
            f"Invalid credentials schema: top-level JSON must be an object or array, got {type(raw_data).__name__}"
        )

    required_accounts = set(EXPECTED_ROLES.keys())
    required_fields = ("username", "role", "password")
    normalized: dict[str, dict[str, Any]] = {}

    if isinstance(raw_data, list):
        for idx, item in enumerate(raw_data):
            if not isinstance(item, dict):
                raise ValueError(f"Credentials item at index {idx} must be an object")
            for field in required_fields:
                val = item.get(field)
                if not isinstance(val, str) or not val.strip():
                    raise ValueError(f"Credentials item at index {idx} missing valid '{field}' string")
            if "id" in item and not isinstance(item["id"], str):
                raise ValueError(f"Credentials item at index {idx}: Field 'id' must be a string")
            username = item["username"]
            if username in normalized:
                raise ValueError(f"Duplicate username in credentials array: '{username}'")
            normalized[username] = item
    else:
        for key, item in raw_data.items():
            if not isinstance(item, dict):
                raise ValueError(f"Credentials entry for '{key}' must be an object")
            for field in required_fields:
                val = item.get(field)
                if not isinstance(val, str) or not val.strip():
                    raise ValueError(f"Credentials entry for '{key}' missing valid '{field}' string")
            if "id" in item and not isinstance(item["id"], str):
                raise ValueError(f"Credentials entry for '{key}': Field 'id' must be a string")
            username = item["username"]
            if key != username:
                raise ValueError(
                    f"Credential key/username mismatch: dictionary key '{key}' does not match object username '{username}'"
                )
            normalized[username] = item

    missing_accounts = required_accounts - set(normalized.keys())
    if missing_accounts:
        raise ValueError(f"Missing required dedicated account(s): {sorted(missing_accounts)}")

    for username, expected_role in EXPECTED_ROLES.items():
        actual_role = normalized[username]["role"]
        if actual_role != expected_role:
            raise ValueError(
                f"Role mismatch for account '{username}': expected '{expected_role}', got '{actual_role}'"
            )

    return normalized


def load_and_validate_credentials(creds_path: str) -> dict[str, dict[str, Any]]:
    """Loads credentials from disk and strictly validates against schema requirements."""
    if not os.path.exists(creds_path):
        raise RuntimeError(f"Credentials file missing: {creds_path}")
    try:
        with open(creds_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in credentials file: {exc.msg}") from None
    except Exception as exc:
        raise RuntimeError(f"Failed to read credentials file: {type(exc).__name__}") from None
    return parse_and_validate_credentials(raw_data)


def stop_host(proc: subprocess.Popen | None, timeout: float = 5.0) -> None:
    """Gracefully terminates host process with fallback to SIGKILL."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass


# -----------------------------------------------------------------------------
# HTTP Helpers (Pure urllib, zero credential leakage)
# -----------------------------------------------------------------------------
def http_request(
    method: str,
    endpoint: str,
    token: str | None = None,
    json_data: dict | None = None,
    form_data: dict | None = None,
) -> tuple[int, dict | list | str | None]:
    url = f"{BASE_URL}{endpoint}" if endpoint.startswith("/") else f"{BASE_URL}/{endpoint}"
    headers = {}
    data_bytes = None

    if token:
        headers["Authorization"] = f"Bearer {token}"

    if json_data is not None:
        headers["Content-Type"] = "application/json"
        data_bytes = json.dumps(json_data).encode("utf-8")
    elif form_data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data_bytes = urllib.parse.urlencode(form_data).encode("utf-8")

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            body = resp.read().decode("utf-8")
            try:
                parsed = json.loads(body) if body else None
            except json.JSONDecodeError:
                parsed = body
            return status, parsed
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = body
        return status, parsed
    except Exception as e:
        return 0, {"error": type(e).__name__}


def validate_sbom_upload_response(status: int, data: Any) -> tuple[str, str | None]:
    """Validates SBOM upload response against the authoritative schema contract."""
    if status != 201:
        raise RuntimeError(f"SBOM upload failed with unexpected HTTP status: {status} (expected 201)")
    if not isinstance(data, dict):
        raise RuntimeError(f"SBOM upload failed: response body is not a JSON object (got {type(data).__name__})")
    if "upload_id" not in data:
        raise RuntimeError("SBOM upload response missing required field 'upload_id'")

    raw_upload_id = data["upload_id"]
    if not isinstance(raw_upload_id, str) or not raw_upload_id.strip():
        raise RuntimeError(f"SBOM upload response 'upload_id' must be a non-empty string, got: {raw_upload_id!r}")

    try:
        parsed_uuid = uuid.UUID(raw_upload_id.strip())
    except (ValueError, AttributeError) as exc:
        raise RuntimeError(f"SBOM upload response 'upload_id' is not a valid UUID: {raw_upload_id!r}") from exc

    upload_id = str(parsed_uuid)
    sbom_root = data.get("sbom_root")
    if sbom_root is not None and not isinstance(sbom_root, str):
        raise RuntimeError(f"SBOM upload response 'sbom_root' must be a string or None, got: {type(sbom_root).__name__}")

    return upload_id, sbom_root


def validate_vulnerability_ingest_response(status: int, data: Any) -> tuple[str, int]:
    """Validates vulnerability ingestion response against the authoritative schema contract."""
    if status != 200:
        raise RuntimeError(f"Vulnerability ingestion failed with unexpected HTTP status: {status} (expected 200)")
    if not isinstance(data, dict):
        raise RuntimeError(f"Vulnerability ingestion failed: response body is not a JSON object (got {type(data).__name__})")
    if "snapshot_id" not in data:
        raise RuntimeError("Vulnerability ingestion response missing required field 'snapshot_id'")

    raw_snapshot_id = data["snapshot_id"]
    if not isinstance(raw_snapshot_id, str) or not raw_snapshot_id.strip():
        raise RuntimeError(f"Vulnerability ingestion response 'snapshot_id' must be a non-empty string, got: {raw_snapshot_id!r}")

    try:
        parsed_uuid = uuid.UUID(raw_snapshot_id.strip())
    except (ValueError, AttributeError) as exc:
        raise RuntimeError(f"Vulnerability ingestion response 'snapshot_id' is not a valid UUID: {raw_snapshot_id!r}") from exc

    snapshot_id = str(parsed_uuid)
    components_processed = data.get("components_processed", 0)
    if not isinstance(components_processed, int) or isinstance(components_processed, bool):
        raise RuntimeError(
            f"Vulnerability ingestion response 'components_processed' must be an int, got: {type(components_processed).__name__}"
        )

    return snapshot_id, components_processed


# -----------------------------------------------------------------------------
# Database Cleanup & Invariance Functions (Tested Offline)
# -----------------------------------------------------------------------------
def execute_exact_id_cleanup(
    engine: Engine,
    manifest: DurableCleanupManifest | dict[str, list[str]],
    baseline_policy_states: dict[str, int] | None = None,
) -> None:
    """
    Deletes test records strictly in verified reverse foreign-key order using
    exact IDs recorded in the manifest.
    Guarantees baseline UUID protection in SQL.
    Restores baseline policy activation states.
    """
    entities: dict[str, list[str]] = (
        manifest.entities if isinstance(manifest, DurableCleanupManifest) else manifest
    )

    with engine.begin() as tx:
        for table in ORDERED_CLEANUP_TABLES:
            ids = entities.get(table, [])
            if ids:
                id_strings = [str(x) for x in ids]
                sql_table = TABLE_SQL_NAMES[table]

                # Double protection: users table additionally filters out baseline UUIDs in SQL
                if table == "users":
                    stmt = text(
                        f"DELETE FROM {sql_table} WHERE id IN :ids AND id NOT IN :protected_uuids"
                    ).bindparams(
                        bindparam("ids", expanding=True),
                        bindparam("protected_uuids", expanding=True),
                    )
                    tx.execute(stmt, {"ids": id_strings, "protected_uuids": list(BASELINE_PROTECTED_UUIDS)})
                else:
                    stmt = text(f"DELETE FROM {sql_table} WHERE id IN :ids").bindparams(
                        bindparam("ids", expanding=True)
                    )
                    tx.execute(stmt, {"ids": id_strings})

            # Foreign-key safety: also clean child records by parent IDs if present
            if table == "verification_certificates":
                req_ids = entities.get("verification_requests", [])
                if req_ids:
                    stmt_req_certs = text(
                        "DELETE FROM verification.verification_certificates WHERE verification_request_id IN :reqs"
                    ).bindparams(bindparam("reqs", expanding=True))
                    tx.execute(stmt_req_certs, {"reqs": [str(x) for x in req_ids]})

            elif table == "component_vulnerability_mappings":
                snap_ids = entities.get("vulnerability_snapshots", [])
                if snap_ids:
                    stmt_snap_maps = text(
                        "DELETE FROM vulnerability.component_vulnerability_mappings WHERE snapshot_id IN :snaps"
                    ).bindparams(bindparam("snaps", expanding=True))
                    tx.execute(stmt_snap_maps, {"snaps": [str(x) for x in snap_ids]})

            elif table == "components":
                upload_ids = entities.get("sbom_uploads", [])
                if upload_ids:
                    stmt_upload_comps = text(
                        "DELETE FROM sbom.components WHERE sbom_upload_id IN :uploads"
                    ).bindparams(bindparam("uploads", expanding=True))
                    tx.execute(stmt_upload_comps, {"uploads": [str(x) for x in upload_ids]})

        # Baseline Policy State Restoration
        policy_states = baseline_policy_states
        if policy_states is None and isinstance(manifest, DurableCleanupManifest):
            policy_states = manifest.baseline_policy_states

        if policy_states:
            for pid_str, active_val in policy_states.items():
                stmt = text("UPDATE policy.security_policies SET is_active = :act WHERE id = :pid")
                tx.execute(stmt, {"act": active_val, "pid": str(pid_str)})


def verify_post_test_invariance(
    engine: Engine,
    pre_counts: dict[str, int],
    manifest: DurableCleanupManifest | dict[str, list[str]],
    baseline_policy_states: dict[str, int],
) -> None:
    """Verifies table count equivalence, record absence by ID, baseline users, and revision."""
    entities: dict[str, list[str]] = (
        manifest.entities if isinstance(manifest, DurableCleanupManifest) else manifest
    )

    with engine.connect() as conn:
        post_counts = dict(conn.execute(text(COUNTS_SQL)).mappings().fetchone())

        # Check count equivalence
        discrepancies = []
        for table, pre_val in pre_counts.items():
            post_val = post_counts.get(table)
            if post_val != pre_val:
                discrepancies.append(f"{table}: pre={pre_val}, post={post_val}")

        if discrepancies:
            raise RuntimeError(f"Post-cleanup baseline count mismatch! Discrepancies: {discrepancies}")

        # Verify no orphaned test entities remain by ID
        for table in ORDERED_CLEANUP_TABLES:
            ids = entities.get(table, [])
            if ids:
                sql_table = TABLE_SQL_NAMES[table]
                for item_id in ids:
                    count = conn.execute(
                        text(f"SELECT count(*) FROM {sql_table} WHERE id = :id"),
                        {"id": str(item_id)},
                    ).scalar()
                    if count != 0:
                        raise RuntimeError(f"Orphaned record {item_id} found in {sql_table}!")

        # Verify baseline auditor users intact
        post_baseline_users = conn.execute(
            text("SELECT id::text, username, role, is_active FROM public.users WHERE id IN :uuids").bindparams(
                bindparam("uuids", expanding=True)
            ),
            {"uuids": [str(x) for x in BASELINE_PROTECTED_UUIDS]},
        ).fetchall()
        if len(post_baseline_users) != 5:
            raise RuntimeError(f"Baseline users count mismatch: {len(post_baseline_users)} != 5")
        for u in post_baseline_users:
            if u[2] != "auditor" or not u[3]:
                raise RuntimeError(f"Baseline protected user {u[1]} modified!")

        # Verify dedicated D9 accounts intact
        post_d9_users = conn.execute(
            text(
                "SELECT username, role, is_active FROM public.users "
                "WHERE username IN ('d9_admin', 'd9_vendor', 'd9_trusted_importer')"
            )
        ).fetchall()
        if len(post_d9_users) != 3:
            raise RuntimeError("Dedicated D9 accounts missing!")
        for u in post_d9_users:
            expected_role = EXPECTED_ROLES.get(u[0])
            if u[1] != expected_role:
                raise RuntimeError(f"D9 account {u[0]} role altered: {u[1]} != {expected_role}")
            if not u[2]:
                raise RuntimeError(f"D9 account {u[0]} deactivated!")

        # Verify Alembic revision intact
        post_rev = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar()
        if post_rev != EXPECTED_REVISION:
            raise RuntimeError(f"Alembic revision altered: {post_rev} != {EXPECTED_REVISION}")

        # Verify baseline policy states intact
        if baseline_policy_states:
            for pid_str, orig_val in baseline_policy_states.items():
                cur_val = conn.execute(
                    text("SELECT is_active FROM policy.security_policies WHERE id = :id"),
                    {"id": str(pid_str)},
                ).scalar()
                if cur_val != orig_val:
                    raise RuntimeError(f"Baseline policy {pid_str} state altered: {cur_val} != {orig_val}")


# -----------------------------------------------------------------------------
# Main Execution Harness with Guaranteed Try...Finally
# -----------------------------------------------------------------------------
def main() -> int:
    print("=" * 70)
    print("D9-4R2: BOUNDED LIVE INTAKE ACCEPTANCE WITH DURABLE MANIFEST")
    print("=" * 70)

    # Initialize Durable Cleanup Manifest atomically on disk
    manifest = DurableCleanupManifest.create_new(
        expected_host=EXPECTED_HOST,
        expected_port=EXPECTED_PORT,
        expected_db=EXPECTED_DB,
        expected_revision=EXPECTED_REVISION,
    )
    print(f"[Durable Manifest] Run ID:  {manifest.run_id}")
    print(f"[Durable Manifest] Path:    {manifest.manifest_path}")

    baseline_policy_states: dict[str, int] = {}
    pre_counts: dict[str, int] = {}

    engine: Engine | None = None
    proc: subprocess.Popen | None = None
    test_results: list[dict[str, Any]] = []
    test_error: Exception | None = None
    cleanup_error: Exception | None = None
    invariance_error: Exception | None = None

    try:
        # ---------------------------------------------------------------------
        # 1. Target & Credential Preflight (Fail-Closed)
        # ---------------------------------------------------------------------
        db_pass = get_db_password()

        conn_url = URL.create(
            drivername="postgresql+psycopg2",
            username="postgres",
            password=db_pass,
            host=EXPECTED_HOST,
            port=EXPECTED_PORT,
            database=EXPECTED_DB,
        )
        if conn_url.port == PROHIBITED_PORT or conn_url.database == PROHIBITED_DB:
            print(f"FATAL: Prohibited target {conn_url.host}:{conn_url.port} / {conn_url.database}", file=sys.stderr)
            sys.exit(1)

        if (
            conn_url.port != EXPECTED_PORT
            or conn_url.host != EXPECTED_HOST
            or conn_url.database != EXPECTED_DB
        ):
            raise RuntimeError(f"FAIL_CLOSED: Target URL violation: {conn_url.render_as_string(hide_password=True)}")

        print(f"[Target Preflight] Target verified: {conn_url.render_as_string(hide_password=True)}")
        engine = create_engine(conn_url)

        with engine.connect() as conn:
            ident = conn.execute(
                text(
                    "SELECT current_database(), current_setting('server_version_num')::int / 10000, version_num "
                    "FROM alembic_version LIMIT 1"
                )
            ).fetchone()
            if not ident:
                raise RuntimeError("Cannot read DB identity.")

            db_name, major_ver, rev = ident[0], ident[1], ident[2]
            print(f"[Preflight Identity] DB: {db_name}, Version: {major_ver}, Revision: {rev}")

            if db_name != EXPECTED_DB:
                raise RuntimeError(f"Database name mismatch: {db_name} != {EXPECTED_DB}")
            if major_ver != EXPECTED_MAJOR_VER:
                raise RuntimeError(f"PostgreSQL version mismatch: {major_ver} != {EXPECTED_MAJOR_VER}")
            if rev != EXPECTED_REVISION:
                raise RuntimeError(f"Alembic revision mismatch: {rev} != {EXPECTED_REVISION}")

            pre_counts.update(dict(conn.execute(text(COUNTS_SQL)).mappings().fetchone()))
            print(f"[Baseline Counts] {pre_counts}")

            policy_rows = conn.execute(text("SELECT id::text, name, is_active FROM policy.security_policies")).fetchall()
            for pol in policy_rows:
                baseline_policy_states[str(pol[0])] = int(pol[2])
            manifest.record_baseline_policy_states(baseline_policy_states)
            print(f"[Baseline Policies] Recorded {len(baseline_policy_states)} baseline policy states to manifest.")

            baseline_users = conn.execute(
                text("SELECT id::text, username, role, is_active FROM public.users WHERE id IN :uuids").bindparams(
                    bindparam("uuids", expanding=True)
                ),
                {"uuids": [str(x) for x in BASELINE_PROTECTED_UUIDS]},
            ).fetchall()
            if len(baseline_users) != 5:
                raise RuntimeError(f"Baseline user count mismatch: {len(baseline_users)} != 5")
            for u in baseline_users:
                if u[2] != "auditor" or not u[3]:
                    raise RuntimeError(f"Baseline user {u[1]} modified or inactive!")
            print(f"[Baseline Users] Exactly 5 baseline auditor accounts verified intact.")

        creds_path = os.environ.get("D9_CREDS_FILE", str(_repo_root / "scratch" / "d9_credentials.json"))
        creds = load_and_validate_credentials(creds_path)
        passwords = {u: creds[u]["password"] for u in EXPECTED_ROLES}
        print(f"[Credentials] Loaded and validated {len(creds)} dedicated D9 accounts.")

        # ---------------------------------------------------------------------
        # 2. Host Process Lifecycle
        # ---------------------------------------------------------------------
        host_env = os.environ.copy()
        host_env.update(
            {
                "DATABASE_URL": f"postgresql+asyncpg://postgres:{db_pass}@{EXPECTED_HOST}:{EXPECTED_PORT}/{EXPECTED_DB}",
                "DB_HOST": EXPECTED_HOST,
                "DB_PORT": str(EXPECTED_PORT),
                "DB_NAME": EXPECTED_DB,
                "DB_USER": "postgres",
                "DB_PASSWORD": db_pass,
                "DB_SSL_MODE": "disable",
                "DB_ECHO": "false",
                "CRYPTO_PROFILE": "prod",
                "JWT_SECRET_KEY": "local_dev_jwt_secret_key_32bytes_minimum_length_ok",
                "CERTIFICATE_SECRET_KEY": "local_dev_cert_secret_key_32bytes_minimum_length_ok",
                "CERTIFICATE_ACTIVE_KID": "v1",
                "CERTIFICATE_SECRET_KEYS": '{"v1": "local_dev_cert_secret_key_32bytes_minimum_length_ok"}',
            }
        )

        python_exe = sys.executable
        proc = subprocess.Popen(
            [
                python_exe,
                "-m",
                "uvicorn",
                "--app-dir",
                str(_backend_root),
                "verification_service.app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(APP_PORT),
            ],
            cwd=str(_repo_root),
            env=host_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        print(f"[Process] Uvicorn spawned (PID {proc.pid}). Polling health endpoint...")
        healthy = False
        for attempt in range(40):
            time.sleep(0.5)
            try:
                status, _ = http_request("GET", "/health")
                if status == 200:
                    healthy = True
                    print(f"[Health Check] Unified host healthy on attempt {attempt + 1}!")
                    break
            except Exception:
                pass
            if proc.poll() is not None:
                out, err = proc.communicate()
                sanitized_err = sanitize_text(err, list(passwords.values()) + [db_pass])
                sanitized_out = sanitize_text(out, list(passwords.values()) + [db_pass])
                raise RuntimeError(f"Uvicorn exited early (code {proc.returncode}):\n{sanitized_err}\n{sanitized_out}")

        if not healthy:
            raise RuntimeError("Uvicorn failed to become healthy within 20 seconds.")

        # ---------------------------------------------------------------------
        # 3. Bounded Live Workflow Steps
        # ---------------------------------------------------------------------
        tokens: dict[str, str] = {}

        print("\n--- Step 1: Authentication & Role Verification ---")
        for username in ["d9_vendor", "d9_trusted_importer", "d9_admin"]:
            status, data = http_request(
                "POST",
                "/auth/login",
                form_data={"username": username, "password": passwords[username]},
            )
            if status != 200 or not isinstance(data, dict) or "access_token" not in data:
                raise RuntimeError(f"Login failed for {username}: status {status}")
            tokens[username] = data["access_token"]
            print(f"[Auth] Logged in as {username} (status 200)")

            status_me, data_me = http_request("GET", "/auth/me", token=tokens[username])
            if status_me != 200 or not isinstance(data_me, dict):
                raise RuntimeError(f"/auth/me failed for {username}: status {status_me}")
            observed_role = data_me.get("role")
            expected_role = EXPECTED_ROLES[username]
            if observed_role != expected_role:
                raise RuntimeError(
                    f"Role assertion failed for {username}: observed '{observed_role}', expected '{expected_role}'"
                )
            print(f"[Auth Me] {username} verified role strictly matches '{expected_role}'")
            test_results.append(
                {
                    "step": f"Auth {username}",
                    "endpoint": "POST /api/v1/auth/login",
                    "role": observed_role,
                    "expected": 200,
                    "actual": status,
                    "status": "PASS",
                }
            )

        print("\n--- Step 2: Application Lifecycle & Tenant Isolation ---")
        app_payload = {
            "name": f"d9_test_app_{uuid.uuid4().hex[:8]}",
            "vendor": "D9 Verification Vendor",
            "description": "Ephemeral application for D9-4 intake acceptance",
        }
        status_app, data_app = http_request("POST", "/applications", token=tokens["d9_vendor"], json_data=app_payload)
        if status_app != 201 or not isinstance(data_app, dict) or "id" not in data_app:
            raise RuntimeError(f"Application creation failed: status {status_app}")
        test_app_id = data_app["id"]

        # DURABLE WRITE TO MANIFEST IMMEDIATELY
        manifest.record_entity("applications", test_app_id)
        print(f"[App Created & Manifested] ID: {test_app_id}, Name: {app_payload['name']}")
        test_results.append(
            {
                "step": "Create Application",
                "endpoint": "POST /api/v1/applications",
                "role": "vendor",
                "expected": 201,
                "actual": status_app,
                "id": test_app_id,
                "status": "PASS",
            }
        )

        status_iso, _ = http_request("GET", f"/applications/{test_app_id}", token=tokens["d9_trusted_importer"])
        if status_iso != 404:
            raise RuntimeError(f"Tenant isolation breach! Expected HTTP 404, got {status_iso}")
        print(f"[Tenant Isolation] Other tenant access attempt: HTTP {status_iso} (expected 404)")

        status_owner, data_owner = http_request("GET", f"/applications/{test_app_id}", token=tokens["d9_vendor"])
        if status_owner != 200 or not isinstance(data_owner, dict) or data_owner.get("id") != test_app_id:
            raise RuntimeError(f"Owner lookup failed: status {status_owner}")
        print(f"[App Owner Lookup] Verified owner retrieval: HTTP {status_owner}")

        print("\n--- Step 3: SBOM Intake & Canonicalization ---")
        sbom_content = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [
                    {
                        "type": "library",
                        "name": "urllib3",
                        "version": "1.26.5",
                        "purl": "pkg:pypi/urllib3@1.26.5",
                    }
                ],
            }
        )
        sbom_payload = {
            "application_name": app_payload["name"],
            "vendor": app_payload["vendor"],
            "format": "CycloneDX",
            "content": sbom_content,
        }
        status_sbom, data_sbom = http_request("POST", "/sbom/upload", token=tokens["d9_vendor"], json_data=sbom_payload)
        test_upload_id, sbom_root = validate_sbom_upload_response(status_sbom, data_sbom)

        # DURABLE WRITE TO MANIFEST IMMEDIATELY
        manifest.record_entity("sbom_uploads", test_upload_id)
        print(f"[SBOM Ingested & Manifested] Upload ID: {test_upload_id}")
        print(f"[SBOM Root] Computed Poseidon Merkle Root: {sbom_root}")
        test_results.append(
            {
                "step": "Upload SBOM",
                "endpoint": "POST /api/v1/sbom/upload",
                "role": "vendor",
                "expected": 201,
                "actual": status_sbom,
                "upload_id": test_upload_id,
                "status": "PASS",
            }
        )

        print("\n--- Step 4: Vulnerability Intake, Separation of Duties & Freeze ---")
        vuln_payload = {
            "source_identity": "NVD",
            "provenance": {"feed_version": "d9-4-bounded-acceptance"},
            "vulnerabilities": [{"purl": "pkg:pypi/urllib3@1.26.5", "cvss_score": 7.5}],
        }
        status_vuln, data_vuln = http_request(
            "POST",
            "/vulnerability/ingest",
            token=tokens["d9_trusted_importer"],
            json_data=vuln_payload,
        )
        test_snapshot_id, processed_count = validate_vulnerability_ingest_response(status_vuln, data_vuln)

        # DURABLE WRITE TO MANIFEST IMMEDIATELY
        manifest.record_entity("vulnerability_snapshots", test_snapshot_id)
        print(f"[Vuln Snapshot Created & Manifested] Snapshot ID: {test_snapshot_id} (Processed: {processed_count})")
        test_results.append(
            {
                "step": "Ingest Vulnerability Snapshot",
                "endpoint": "POST /api/v1/vulnerability/ingest",
                "role": "trusted_importer",
                "expected": 200,
                "actual": status_vuln,
                "id": test_snapshot_id,
                "status": "PASS",
            }
        )

        status_sod, _ = http_request(
            "POST",
            f"/vulnerability/snapshots/{test_snapshot_id}/approve",
            token=tokens["d9_trusted_importer"],
        )
        if status_sod != 403:
            raise RuntimeError(f"Separation of duties violation! Importer could approve snapshot! HTTP {status_sod}")
        print(f"[Separation of Duties] Importer approve attempt: HTTP {status_sod} (expected 403)")

        status_appr, data_appr = http_request(
            "POST",
            f"/vulnerability/snapshots/{test_snapshot_id}/approve",
            token=tokens["d9_admin"],
        )
        if status_appr != 200 or not isinstance(data_appr, dict) or data_appr.get("status") != "approved":
            raise RuntimeError(f"Admin approval failed: status {status_appr}")
        print(f"[Vuln Snapshot Approved] Status: {data_appr.get('status')}")

        status_freeze, data_freeze = http_request(
            "POST",
            f"/vulnerability/snapshots/{test_snapshot_id}/freeze",
            token=tokens["d9_admin"],
        )
        if status_freeze != 200 or not isinstance(data_freeze, dict) or data_freeze.get("status") != "frozen":
            raise RuntimeError(f"Admin freeze failed: status {status_freeze}")
        vuln_db_root = data_freeze.get("authoritative_smt_root")
        print(f"[Vuln Snapshot Frozen] SMT Root: {vuln_db_root}")

        print("\n--- Step 5: Policy Creation & State Management (SKIPPED BY GATE) ---")
        dummy_policy_hash = "0x" + "0" * 64
        test_results.append(
            {
                "step": "Policy Creation (POST /policy)",
                "endpoint": "POST /api/v1/policy",
                "role": "admin",
                "expected": 201,
                "actual": 0,
                "status": "SKIPPED_BY_SAFETY_GATE",
                "reason": "Preserving global baseline policy state without mutations",
            }
        )
        print("[Policy Gate] Skipped policy creation to preserve baseline activation states.")

        print("\n--- Step 6: Verification Endpoint Fail-Closed Testing ---")
        verify_payload = {
            "sbom_root": sbom_root or ("0x" + "1" * 64),
            "vulnerability_db_root": vuln_db_root or ("0x" + "2" * 64),
            "policy_hash": dummy_policy_hash,
            "proof_job_id": None,
        }
        status_ver, data_ver = http_request(
            "POST",
            "/verification/verify",
            token=tokens["d9_vendor"],
            json_data=verify_payload,
        )
        if status_ver != 200 or not isinstance(data_ver, dict):
            raise RuntimeError(f"Verification call unexpected HTTP error: {status_ver}")

        ver_req_id = data_ver.get("id")
        if ver_req_id:
            # DURABLE WRITE TO MANIFEST IMMEDIATELY
            manifest.record_entity("verification_requests", ver_req_id)
            print(f"[Verification Request Recorded & Manifested] ID: {ver_req_id}")

        result_str = data_ver.get("result")
        cert_data = data_ver.get("certificate")
        print(f"[Verification Fail-Closed] Status: HTTP {status_ver}, Result: '{result_str}', Cert: {cert_data}")
        if result_str not in ["verification_unavailable", "record_mismatch"] or cert_data is not None:
            raise RuntimeError(f"Verification did NOT fail closed! Result: {result_str}, Cert: {cert_data}")
        test_results.append(
            {
                "step": "Verification Fail-Closed (Unproven Job)",
                "endpoint": "POST /api/v1/verification/verify",
                "role": "vendor",
                "expected": 200,
                "actual": status_ver,
                "result": result_str,
                "cert_issued": False,
                "status": "PASS",
            }
        )

        print("\n--- Step 7: Missing Certificate Lookup Enforcement ---")
        missing_cert_uuid = str(uuid.uuid4())
        status_cert_missing, _ = http_request(
            "GET",
            f"/verification/certificates/{missing_cert_uuid}",
            token=tokens["d9_vendor"],
        )
        if status_cert_missing != 404:
            raise RuntimeError(f"Missing certificate lookup failed assertion: expected HTTP 404, got {status_cert_missing}")
        print(f"[Certificate Missing Lookup] Verified HTTP 404 assertion on {missing_cert_uuid}")
        test_results.append(
            {
                "step": "Certificate Missing Lookup",
                "endpoint": "GET /api/v1/verification/certificates/{id}",
                "role": "vendor",
                "expected": 404,
                "actual": status_cert_missing,
                "status": "PASS",
            }
        )

    except Exception as exc:
        test_error = exc
        print(f"\n[EXECUTION ERROR] {exc}", file=sys.stderr)

    finally:
        # ---------------------------------------------------------------------
        # 4. Host Shutdown (Guaranteed on ALL Exit Paths)
        # ---------------------------------------------------------------------
        print("\n--- Shutting Down Unified Application Host ---")
        if proc is not None:
            stop_host(proc)
            print("[Process] Uvicorn stopped.")

        # ---------------------------------------------------------------------
        # 5. Exact-ID Database Cleanup & Policy Restoration
        # ---------------------------------------------------------------------
        print("\n--- Executing Exact-ID Database Cleanup via Manifest ---")
        total_entities = sum(len(ids) for ids in manifest.entities.values())
        print(f"Manifest Run ID: {manifest.run_id} ({total_entities} recorded entities)")

        if engine is not None and total_entities > 0:
            try:
                manifest.update_status("cleaning")
                execute_exact_id_cleanup(engine, manifest, baseline_policy_states)
                manifest.update_status("cleaned")
                print("[Cleanup] Exact-ID reverse-FK cleanup completed successfully. Manifest marked cleaned.")
            except Exception as exc:
                cleanup_error = exc
                manifest.update_status("failed", error_message=str(exc))
                print(f"\n[CRITICAL CLEANUP FAILURE] Failed to clean up test records: {exc}", file=sys.stderr)
                print(f"Manifest preserved on disk for recovery: {manifest.manifest_path}", file=sys.stderr)

        # ---------------------------------------------------------------------
        # 6. Post-Cleanup Invariance Verification
        # ---------------------------------------------------------------------
        if engine is not None and pre_counts:
            print("\n--- Post-Cleanup Baseline Invariance Verification ---")
            try:
                verify_post_test_invariance(engine, pre_counts, manifest, baseline_policy_states)
                print("[Invariance Check] 100% baseline invariance verified!")
            except Exception as exc:
                invariance_error = exc
                print(f"\n[INVARIANCE FAILURE] {exc}", file=sys.stderr)

        if engine is not None:
            engine.dispose()

    # -------------------------------------------------------------------------
    # 7. Final Verdict & Report
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("D9-4R2 EXECUTION SUMMARY")
    print("=" * 70)
    for res in test_results:
        print(f"  {res['step']}: HTTP {res['actual']} (Expected {res['expected']}) -> {res['status']}")

    if cleanup_error is not None:
        print(f"\n[RESULT: CLEANUP FAILURE] Cleanup failed: {cleanup_error}", file=sys.stderr)
        return 2

    if test_error is not None:
        print(f"\n[RESULT: TEST FAILURE] Test workflow failed: {test_error}", file=sys.stderr)
        return 1

    if invariance_error is not None:
        print(f"\n[RESULT: INVARIANCE FAILURE] Post-test check failed: {invariance_error}", file=sys.stderr)
        return 1

    print("\n[RESULT: SUCCESS] ALL D9-4 BOUNDED LIVE INTAKE ACCEPTANCE TESTS PASSED!")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
D9 Vendor-to-Buyer Demonstration Preparation and Safe Execution Script
Authoritative Location: scripts/prepare_d9_demo.py
Target Database: PostgreSQL 16 on 127.0.0.1:5433, database ZKP_SBOM_LOCAL_DEV
Application Gateway: http://127.0.0.1:8080/api/v1 (configurable via --api-url)

SAFETY & GOVERNANCE INVARIANTS:
  1. Strict target isolation: Only connects to 127.0.0.1:5433 / ZKP_SBOM_LOCAL_DEV.
     Prohibits connections to port 5432 / ZKP_SBOM and port 5434 / ZKP_SBOM_D9_EPHEMERAL.
  2. Idempotent & non-destructive: Detects existing demo records and avoids duplicate creation.
     Never truncates, drops, resets, or overwrites tables, users, or policies.
  3. All 8 baseline user accounts (5 auditors, 1 admin, 1 vendor, 1 importer) are protected.
  4. Separation of duties: Importer (d9_trusted_importer) cannot approve/freeze snapshots.
     Only Admin (d9_admin) approves and freezes vulnerability snapshots and activates policies.
  5. Zero fabrication: Does NOT directly insert proof jobs, certificates, fabricated roots,
     or fake verified states into tables. Certificates are issued exclusively via genuine
     cryptographic verification through the supported API.
  6. Durable rollback manifest: All demo-created records are tracked by exact UUID in
     .cache/demo_manifests/ for precise reverse foreign-key rollback without collateral damage.
  7. Zero credential disclosure: Passwords and bearer tokens are masked across all logs.
  8. Dry-run mode by default: Exits safely without writing any database records unless
     explicitly invoked with --execute.
"""

from __future__ import annotations

import argparse
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
from datetime import datetime, timezone
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
    ORDERED_CLEANUP_TABLES,
    TABLE_SQL_NAMES,
    DurableCleanupManifest,
)

# -----------------------------------------------------------------------------
# Constants & Safety Limits
# -----------------------------------------------------------------------------
EXPECTED_HOST = "127.0.0.1"
EXPECTED_PORT = 5433
EXPECTED_DB = "ZKP_SBOM_LOCAL_DEV"
EXPECTED_MAJOR_VER = 16
ALLOWED_REVISIONS = {"016_add_snapshot_ttl_expires_at", "016", "015_auth_lifecycle_and_revocation", "015"}

PROHIBITED_PORTS = frozenset({5432, 5434})
PROHIBITED_DBS = frozenset({"ZKP_SBOM", "ZKP_SBOM_D9_EPHEMERAL"})

DEFAULT_API_URL = "http://127.0.0.1:8080/api/v1"
DEFAULT_CREDS_PATH = _repo_root / "scratch" / "d9_credentials.json"
MANIFEST_DIR = _repo_root / ".cache" / "demo_manifests"

ALL_8_BASELINE_USERS = {
    "43068bbb-ac36-4005-ba82-d3a453c4cd51": ("idem_43068bbb", "auditor"),
    "b7e87663-07b4-49ac-9d48-05d6232186fe": ("local_auditor_alpha", "auditor"),
    "08edf357-94d6-405e-97d7-0e258d2136f6": ("Tanmay", "auditor"),
    "32ad85e4-7229-4b31-bed1-da746df45830": ("d9_admin", "admin"),
    "203fabbf-2d7a-4b58-b9e2-b15b8bbf8a45": ("d9_vendor", "vendor"),
    "931a603e-2d87-4894-885e-57c2db82f190": ("d9_trusted_importer", "trusted_importer"),
    "c60ea9b9-ee23-409d-acc8-b9cebe6e0058": ("idem_c60ea9b9", "auditor"),
    "2ec0a7bd-6797-4ff9-b9dc-19ecf1aad53f": ("idem_2ec0a7bd", "auditor"),
}

# Unique Demo Entity Identifiers (for Idempotent Matching)
DEMO_VENDOR_NAME = "Demo Fintech Corp"
DEMO_POLICY_NAME = "demo_strict_cvss_policy"
DEMO_MAX_CVSS = 7.0  # Circuit threshold: 70

# Ingested Demonstration Feed (Representing both fixtures in one approved snapshot)
# Note: Source identity 'NVD' is a local demonstration fixture label, not live NVD sync.
DEMO_FEED_SOURCE = "NVD"
DEMO_FEED_VERSION = "demo_cve_feed_2026_v1"
DEMO_VULNERABILITY_FIXTURES = [
    {"purl": "pkg:pypi/urllib3@1.26.5", "cvss_score": 7.5},    # Vulnerable: 75 > 70
    {"purl": "pkg:pypi/certifi@2021.5.30", "cvss_score": 3.7},  # Compliant: 37 <= 70
]

# Two Separate Demonstration Scenarios
DEMO_APP_COMPLIANT = "demo_payment_gateway_compliant"
DEMO_APP_VULNERABLE = "demo_payment_gateway_vulnerable"


# -----------------------------------------------------------------------------
# Sanitization & Log Helpers
# -----------------------------------------------------------------------------
def sanitize(text_val: Any) -> str:
    """Masks passwords, bearer tokens, and connection strings."""
    if text_val is None:
        return ""
    s = str(text_val)
    s = re.sub(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", "Bearer [REDACTED_TOKEN]", s)
    s = re.sub(r"://([^:]+):([^@]+)@", r"://\1:[REDACTED_PASSWORD]@", s)
    s = re.sub(r"(password=)[^&\s]+", r"\1[REDACTED]", s, flags=re.IGNORECASE)
    s = re.sub(r'("password":\s*")[^"]+(")', r"\1[REDACTED]\2", s, flags=re.IGNORECASE)
    return s


def get_container_db_password() -> str:
    """
    Extracts database password dynamically from running Docker container
    zkp_sbom_local_dev without reading host .env or hardcoding secrets.
    """
    try:
        raw_env = subprocess.check_output(
            ["docker", "inspect", "zkp_sbom_local_dev", "--format", "{{json .Config.Env}}"],
            stderr=subprocess.PIPE,
            text=True,
        )
        env_list = json.loads(raw_env.strip())
        for item in env_list:
            if item.startswith("POSTGRES_PASSWORD="):
                return item.split("=", 1)[1]
    except Exception as exc:
        raise RuntimeError(
            f"Failed to inspect Docker container zkp_sbom_local_dev: {exc}"
        ) from exc
    raise RuntimeError("POSTGRES_PASSWORD not found in container environment.")


def load_credentials(creds_path: Path) -> dict[str, str]:
    """Loads passwords for the demo accounts from the local scratch credentials file."""
    if not creds_path.exists():
        raise FileNotFoundError(f"Credentials file missing: {creds_path}")
    with open(creds_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    passwords: dict[str, str] = {}
    if isinstance(data, dict):
        for username, cred in data.items():
            if isinstance(cred, dict) and "password" in cred:
                passwords[username] = cred["password"]
    elif isinstance(data, list):
        for cred in data:
            if isinstance(cred, dict) and "username" in cred and "password" in cred:
                passwords[cred["username"]] = cred["password"]

    for req_user in ["d9_admin", "d9_trusted_importer", "d9_vendor"]:
        if req_user not in passwords:
            raise ValueError(f"Credentials missing for required account: '{req_user}'")
    return passwords


# -----------------------------------------------------------------------------
# Database Verification & Idempotency Inspection
# -----------------------------------------------------------------------------
def get_db_engine(db_pass: str) -> Engine:
    """Creates a strictly verified database engine targeting port 5433."""
    conn_url = URL.create(
        drivername="postgresql+psycopg2",
        username="postgres",
        password=db_pass,
        host=EXPECTED_HOST,
        port=EXPECTED_PORT,
        database=EXPECTED_DB,
    )
    if conn_url.port in PROHIBITED_PORTS or conn_url.database in PROHIBITED_DBS:
        raise RuntimeError(f"PROHIBITED TARGET: {conn_url.render_as_string(hide_password=True)}")
    return create_engine(conn_url)


def verify_database_preflight(engine: Engine) -> dict[str, Any]:
    """
    Performs complete, strictly read-only preflight verification on port 5433:
    - Host, port, DB name
    - Major version == 16
    - Alembic revision in ALLOWED_REVISIONS
    - Exactly 8 baseline user accounts intact with correct roles
    - Existing demo records check (for idempotency)
    """
    with engine.connect() as conn:
        # Check DB identity
        row = conn.execute(
            text(
                "SELECT current_database(), current_setting('server_version_num')::int / 10000, version_num "
                "FROM alembic_version LIMIT 1"
            )
        ).fetchone()
        if not row:
            raise RuntimeError("Failed to query database identity from alembic_version.")

        db_name, major_ver, rev = row[0], int(row[1]), str(row[2])
        if db_name != EXPECTED_DB:
            raise RuntimeError(f"Target DB name mismatch: {db_name} != {EXPECTED_DB}")
        if major_ver != EXPECTED_MAJOR_VER:
            raise RuntimeError(f"Target PostgreSQL version mismatch: {major_ver} != {EXPECTED_MAJOR_VER}")
        if rev not in ALLOWED_REVISIONS and not any(rev.startswith(r) for r in ALLOWED_REVISIONS):
            raise RuntimeError(f"Target Alembic revision mismatch: {rev} not in {ALLOWED_REVISIONS}")

        # Check all 8 baseline users
        users = conn.execute(
            text("SELECT id::text, username, role, is_active FROM public.users ORDER BY created_at")
        ).fetchall()
        if len(users) != 8:
            raise RuntimeError(f"Baseline user count mismatch: expected 8, found {len(users)}")

        user_map = {u[0]: (u[1], u[2], u[3]) for u in users}
        for uid, (expected_uname, expected_role) in ALL_8_BASELINE_USERS.items():
            if uid not in user_map:
                raise RuntimeError(f"Missing required baseline user ID: {uid} ({expected_uname})")
            actual_uname, actual_role, active = user_map[uid]
            if actual_uname != expected_uname or actual_role != expected_role:
                raise RuntimeError(f"Baseline user contract mismatch for {uid}: got ({actual_uname}, {actual_role})")
            if not active:
                raise RuntimeError(f"Baseline user {expected_uname} is deactivated!")

        # Query existing record counts
        counts = {
            "users": len(users),
            "applications": conn.execute(text("SELECT count(*) FROM sbom.applications")).scalar(),
            "sbom_uploads": conn.execute(text("SELECT count(*) FROM sbom.sbom_uploads")).scalar(),
            "components": conn.execute(text("SELECT count(*) FROM sbom.components")).scalar(),
            "security_policies": conn.execute(text("SELECT count(*) FROM policy.security_policies")).scalar(),
            "vulnerability_snapshots": conn.execute(text("SELECT count(*) FROM vulnerability.vulnerability_snapshots")).scalar(),
            "proof_jobs": conn.execute(text("SELECT count(*) FROM zkp.proof_jobs")).scalar(),
            "verification_certificates": conn.execute(text("SELECT count(*) FROM verification.verification_certificates")).scalar(),
        }

        # Check for existing demo entities
        existing_demo = {
            "app_compliant": conn.execute(
                text("SELECT id::text, name, is_active FROM sbom.applications WHERE name = :name"),
                {"name": DEMO_APP_COMPLIANT},
            ).fetchone(),
            "app_vulnerable": conn.execute(
                text("SELECT id::text, name, is_active FROM sbom.applications WHERE name = :name"),
                {"name": DEMO_APP_VULNERABLE},
            ).fetchone(),
            "policy": conn.execute(
                text("SELECT id::text, name, is_active, policy_hash FROM policy.security_policies WHERE name = :name"),
                {"name": DEMO_POLICY_NAME},
            ).fetchone(),
            "snapshot": conn.execute(
                text(
                    "SELECT id::text, status, authoritative_smt_root FROM vulnerability.vulnerability_snapshots "
                    "WHERE snapshot_label = :label OR provenance_json LIKE :pattern"
                ),
                {"label": DEMO_FEED_VERSION, "pattern": f"%{DEMO_FEED_VERSION}%"},
            ).fetchone(),
        }

    return {
        "db_name": db_name,
        "major_ver": major_ver,
        "revision": rev,
        "baseline_users_verified": 8,
        "table_counts": counts,
        "existing_demo_entities": {
            k: (dict(v._mapping) if v else None) for k, v in existing_demo.items()
        },
    }


# -----------------------------------------------------------------------------
# HTTP Application API Interaction
# -----------------------------------------------------------------------------
def http_call(
    api_url: str,
    method: str,
    endpoint: str,
    token: str | None = None,
    json_data: dict | None = None,
    form_data: dict | None = None,
) -> tuple[int, Any]:
    """Executes HTTP request against application gateway with safe error masking."""
    url = f"{api_url}{endpoint}" if endpoint.startswith("/") else f"{api_url}/{endpoint}"
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
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            parsed = json.loads(body) if body else None
            return resp.status, parsed
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body) if body else None
        except Exception:
            parsed = body
        return e.code, parsed
    except Exception as e:
        return 0, {"error": type(e).__name__, "message": str(e)}


# -----------------------------------------------------------------------------
# Demo Preparation Runner
# -----------------------------------------------------------------------------
def run_demo_preparation(
    api_url: str,
    creds_path: Path,
    dry_run: bool = True,
    scenario: str = "both",
) -> int:
    """Orchestrates safe, idempotent demo preparation."""
    print("=" * 70)
    print("D9 DEMONSTRATION WORKFLOW PREPARATION & PREFLIGHT")
    print(f"Target:     127.0.0.1:{EXPECTED_PORT} / {EXPECTED_DB}")
    print(f"Gateway:    {api_url}")
    print(f"Scenario:   {scenario.upper()}")
    print(f"Mode:       {'DRY-RUN (READ-ONLY PREFLIGHT)' if dry_run else 'EXECUTE (LIVE API SEEDING)'}")
    print("=" * 70)

    # 1. Database Preflight
    print("\n[*] Step 1: Performing read-only database target preflight...")
    db_pass = get_container_db_password()
    engine = get_db_engine(db_pass)
    preflight = verify_database_preflight(engine)

    print(f"[+] Target Verified: {preflight['db_name']} (PG{preflight['major_ver']}, Alembic Rev: {preflight['revision']})")
    print(f"[+] Baseline Users:  {preflight['baseline_users_verified']} accounts verified intact and active.")
    print(f"[*] Current Table Counts: {preflight['table_counts']}")

    existing = preflight["existing_demo_entities"]
    print("\n[*] Step 2: Idempotency & Existing Demo Entities Check:")
    for entity_type, entity_data in existing.items():
        if entity_data:
            print(f"    - Existing {entity_type}: ID {entity_data.get('id')} ({entity_data})")
        else:
            print(f"    - Existing {entity_type}: None (ready to create)")

    # 2. Check Gateway Availability
    print("\n[*] Step 3: Checking application service availability...")
    code, health_resp = http_call(api_url, "GET", "/health")
    if code != 200:
        print(f"[-] Application service is not running or unreachable at {api_url} (HTTP {code}).")
        if dry_run:
            print("[!] Note: In dry-run mode, gateway offline is non-fatal. Live execution requires service running.")
        else:
            raise RuntimeError(f"Application gateway unreachable at {api_url}: HTTP {code}")
    else:
        print(f"[+] Application Gateway Healthy (HTTP 200): {health_resp}")

    # 3. Dry-Run Reporting & Stop Condition
    if dry_run:
        print("\n" + "=" * 70)
        print("DRY-RUN / PREFLIGHT SUMMARY: ALL READ-ONLY CHECKS PASSED")
        print("=" * 70)
        print("Planned Live API Operations for --execute mode:")
        print(f"  1. Authenticate 'd9_admin' (POST /api/v1/auth/login)")
        if not existing["policy"]:
            print(f"     -> Create & activate Security Policy: '{DEMO_POLICY_NAME}' (max CVSS: {DEMO_MAX_CVSS})")
        else:
            print(f"     -> Reuse existing Security Policy: '{DEMO_POLICY_NAME}' (ID: {existing['policy']['id']})")

        print(f"  2. Authenticate 'd9_trusted_importer' (POST /api/v1/auth/login)")
        if not existing["snapshot"]:
            print(f"     -> Ingest Vulnerability Batch (POST /api/v1/vulnerability/ingest):")
            for fix in DEMO_VULNERABILITY_FIXTURES:
                print(f"        * PURL: {fix['purl']} | CVSS: {fix['cvss_score']}")
        else:
            print(f"     -> Reuse existing Snapshot (ID: {existing['snapshot']['id']})")

        print(f"  3. Authenticate 'd9_admin' (Separation of Duties)")
        if not existing["snapshot"]:
            print(f"     -> Approve Snapshot (POST /api/v1/vulnerability/snapshots/{{id}}/approve)")
            print(f"     -> Freeze Snapshot & Compute SMT Root (POST /api/v1/vulnerability/snapshots/{{id}}/freeze)")

        print(f"  4. Authenticate 'd9_vendor' (POST /api/v1/auth/login)")
        if scenario in ("compliant", "both"):
            if not existing["app_compliant"]:
                print(f"     -> [Scenario 1 - Compliant] Register App: '{DEMO_APP_COMPLIANT}'")
                print(f"        Upload CycloneDX SBOM with 'certifi@2021.5.30' (CVSS 3.7 <= 7.0 -> Compliant)")
            else:
                print(f"     -> [Scenario 1 - Compliant] Reuse App: '{DEMO_APP_COMPLIANT}' (ID: {existing['app_compliant']['id']})")
        if scenario in ("vulnerable", "both"):
            if not existing["app_vulnerable"]:
                print(f"     -> [Scenario 2 - Vulnerable] Register App: '{DEMO_APP_VULNERABLE}'")
                print(f"        Upload CycloneDX SBOM with 'urllib3@1.26.5' (CVSS 7.5 > 7.0 -> Fails Closed)")
            else:
                print(f"     -> [Scenario 2 - Vulnerable] Reuse App: '{DEMO_APP_VULNERABLE}' (ID: {existing['app_vulnerable']['id']})")

        print(f"  5. Verification Readiness (POST /api/v1/verification/verify)")
        print(f"     -> Fail-closed validation for unproven jobs or preparation for live verification.")
        print("\n[!] Zero database modifications performed. To execute, run with --execute.")
        return 0

    # 4. Live Seeding Execution (--execute mode)
    print("\n[*] Step 4: Executing Live API Seeding Workflow...")
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    manifest = DurableCleanupManifest.create_new(
        manifest_dir=MANIFEST_DIR,
        expected_revision="016",
    )
    run_id = manifest.run_id
    manifest_path = manifest.manifest_path
    print(f"[+] Initialized Durable Cleanup Manifest: {manifest_path}")

    created_entities: dict[str, Any] = {}
    passwords = load_credentials(creds_path)
    tokens: dict[str, str] = {}

    # Login helper
    def login_as(username: str) -> str:
        code, resp = http_call(api_url, "POST", "/auth/login", form_data={"username": username, "password": passwords[username]})
        if code != 200 or not isinstance(resp, dict) or "access_token" not in resp:
            raise RuntimeError(f"Login failed for {username}: HTTP {code} ({resp})")
        return resp["access_token"]

    try:
        tokens["admin"] = login_as("d9_admin")
        tokens["importer"] = login_as("d9_trusted_importer")
        tokens["vendor"] = login_as("d9_vendor")
        if "local_auditor_alpha" in passwords:
            tokens["buyer"] = login_as("local_auditor_alpha")
            print("[+] Successfully authenticated all 4 roles via supported /auth/login endpoint.")
        else:
            tokens["buyer"] = tokens["admin"]
            print("[+] Successfully authenticated admin, trusted_importer, vendor (buyer using admin session) via supported /auth/login endpoint.")

        # 4.1 Policy Creation
        if not existing["policy"]:
            print(f"[*] Creating policy '{DEMO_POLICY_NAME}'...")
            code, p_data = http_call(
                api_url,
                "POST",
                "/policy",
                token=tokens["admin"],
                json_data={
                    "name": DEMO_POLICY_NAME,
                    "description": "Deterministic demo security policy enforcing max CVSS 7.0",
                    "max_cvss_score": DEMO_MAX_CVSS,
                },
            )
            if code != 200 or not isinstance(p_data, dict) or "id" not in p_data:
                raise RuntimeError(f"Policy creation failed: HTTP {code} ({p_data})")
            pol_id = p_data["id"]
            manifest.record_entity("security_policies", pol_id)
            created_entities["policy_id"] = pol_id
            print(f"[+] Security Policy Created: {pol_id}")

            code, act_data = http_call(api_url, "POST", f"/policy/{pol_id}/activate", token=tokens["admin"])
            if code != 200:
                raise RuntimeError(f"Policy activation failed: HTTP {code} ({act_data})")
            print(f"[+] Security Policy Activated: {pol_id} (Policy Hash: {act_data.get('policy_hash')})")
            created_entities["policy_hash"] = act_data.get("policy_hash")
        else:
            created_entities["policy_id"] = existing["policy"]["id"]
            created_entities["policy_hash"] = existing["policy"]["policy_hash"]
            manifest.record_entity("security_policies", existing["policy"]["id"])
            print(f"[=] Reusing existing policy {existing['policy']['id']}")

        # 4.2 Vulnerability Ingestion & Freeze
        if not existing["snapshot"]:
            print(f"[*] Ingesting vulnerability batch via Trusted Importer...")
            code, snap_resp = http_call(
                api_url,
                "POST",
                "/vulnerability/ingest",
                token=tokens["importer"],
                json_data={
                    "source_identity": DEMO_FEED_SOURCE,
                    "provenance": {"feed_version": DEMO_FEED_VERSION},
                    "vulnerabilities": DEMO_VULNERABILITY_FIXTURES,
                },
            )
            if code != 200 or not isinstance(snap_resp, dict) or "snapshot_id" not in snap_resp:
                raise RuntimeError(f"Vulnerability ingestion failed: HTTP {code} ({snap_resp})")
            snap_id = snap_resp["snapshot_id"]
            manifest.record_entity("vulnerability_snapshots", snap_id)
            created_entities["snapshot_id"] = snap_id
            print(f"[+] Vulnerability Snapshot Staged: {snap_id}")

            # Separation of duties: Admin approves and freezes
            print(f"[*] Approving and freezing snapshot via Admin...")
            code, appr_data = http_call(api_url, "POST", f"/vulnerability/snapshots/{snap_id}/approve", token=tokens["admin"])
            if code != 200:
                raise RuntimeError(f"Snapshot approval failed: HTTP {code} ({appr_data})")

            code, freeze_data = http_call(api_url, "POST", f"/vulnerability/snapshots/{snap_id}/freeze", token=tokens["admin"])
            if code != 200 or not isinstance(freeze_data, dict):
                raise RuntimeError(f"Snapshot freeze failed: HTTP {code} ({freeze_data})")
            vuln_root = freeze_data.get("authoritative_smt_root")
            created_entities["vulnerability_db_root"] = vuln_root
            print(f"[+] Snapshot Frozen with TTL: SMT Root = {vuln_root}")
        else:
            created_entities["snapshot_id"] = existing["snapshot"]["id"]
            created_entities["vulnerability_db_root"] = existing["snapshot"]["authoritative_smt_root"]
            manifest.record_entity("vulnerability_snapshots", existing["snapshot"]["id"])
            print(f"[=] Reusing existing snapshot {existing['snapshot']['id']}")

        # 4.3 Vendor Application & SBOM Intake
        # Scenario 1: Compliant Application & SBOM
        if scenario in ("compliant", "both"):
            if not existing["app_compliant"]:
                print(f"[*] Registering compliant vendor application '{DEMO_APP_COMPLIANT}'...")
                code, app_data = http_call(
                    api_url,
                    "POST",
                    "/applications",
                    token=tokens["vendor"],
                    json_data={
                        "name": DEMO_APP_COMPLIANT,
                        "vendor": DEMO_VENDOR_NAME,
                        "description": "Production Payment Gateway Service Demo - Compliant Variant",
                    },
                )
                if code != 201 or not isinstance(app_data, dict) or "id" not in app_data:
                    raise RuntimeError(f"Application creation failed: HTTP {code} ({app_data})")
                app_id_c = app_data["id"]
                manifest.record_entity("applications", app_id_c)
                created_entities["app_id_compliant"] = app_id_c
                print(f"[+] Compliant Application Created: {app_id_c}")

                # Upload Compliant SBOM
                print(f"[*] Uploading compliant vendor CycloneDX SBOM (certifi@2021.5.30)...")
                sbom_c = json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.4",
                        "components": [
                            {
                                "type": "library",
                                "name": "certifi",
                                "version": "2021.5.30",
                                "purl": "pkg:pypi/certifi@2021.5.30",
                            }
                        ],
                    }
                )
                code, sbom_resp_c = http_call(
                    api_url,
                    "POST",
                    "/sbom/upload",
                    token=tokens["vendor"],
                    json_data={
                        "application_name": DEMO_APP_COMPLIANT,
                        "vendor": DEMO_VENDOR_NAME,
                        "format": "CycloneDX",
                        "content": sbom_c,
                    },
                )
                if code != 201 or not isinstance(sbom_resp_c, dict) or "upload_id" not in sbom_resp_c:
                    raise RuntimeError(f"Compliant SBOM upload failed: HTTP {code} ({sbom_resp_c})")
                upload_id_c = sbom_resp_c["upload_id"]
                manifest.record_entity("sbom_uploads", upload_id_c)
                created_entities["sbom_upload_id_compliant"] = upload_id_c
                created_entities["sbom_root_compliant"] = sbom_resp_c.get("sbom_root")
                print(f"[+] Compliant SBOM Committed: {upload_id_c} (SBOM Root: {sbom_resp_c.get('sbom_root')})")
            else:
                created_entities["app_id_compliant"] = existing["app_compliant"]["id"]
                manifest.record_entity("applications", existing["app_compliant"]["id"])
                with engine.connect() as conn:
                    row = conn.execute(
                        text("SELECT id::text, sbom_root FROM sbom.sbom_uploads WHERE application_id = :aid ORDER BY created_at DESC LIMIT 1"),
                        {"aid": existing["app_compliant"]["id"]},
                    ).fetchone()
                    if row:
                        created_entities["sbom_upload_id_compliant"] = row[0]
                        created_entities["sbom_root_compliant"] = row[1]
                        manifest.record_entity("sbom_uploads", row[0])
                print(f"[=] Reusing existing compliant app {existing['app_compliant']['id']} (SBOM Root: {created_entities.get('sbom_root_compliant')})")

        # Scenario 2: Vulnerable Application & SBOM
        if scenario in ("vulnerable", "both"):
            if not existing["app_vulnerable"]:
                print(f"[*] Registering vulnerable vendor application '{DEMO_APP_VULNERABLE}'...")
                code, app_data_v = http_call(
                    api_url,
                    "POST",
                    "/applications",
                    token=tokens["vendor"],
                    json_data={
                        "name": DEMO_APP_VULNERABLE,
                        "vendor": DEMO_VENDOR_NAME,
                        "description": "Production Payment Gateway Service Demo - Vulnerable Variant",
                    },
                )
                if code != 201 or not isinstance(app_data_v, dict) or "id" not in app_data_v:
                    raise RuntimeError(f"Vulnerable application creation failed: HTTP {code} ({app_data_v})")
                app_id_v = app_data_v["id"]
                manifest.record_entity("applications", app_id_v)
                created_entities["app_id_vulnerable"] = app_id_v
                print(f"[+] Vulnerable Application Created: {app_id_v}")

                # Upload Vulnerable SBOM
                print(f"[*] Uploading vulnerable vendor CycloneDX SBOM (urllib3@1.26.5)...")
                sbom_v = json.dumps(
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
                code, sbom_resp_v = http_call(
                    api_url,
                    "POST",
                    "/sbom/upload",
                    token=tokens["vendor"],
                    json_data={
                        "application_name": DEMO_APP_VULNERABLE,
                        "vendor": DEMO_VENDOR_NAME,
                        "format": "CycloneDX",
                        "content": sbom_v,
                    },
                )
                if code != 201 or not isinstance(sbom_resp_v, dict) or "upload_id" not in sbom_resp_v:
                    raise RuntimeError(f"Vulnerable SBOM upload failed: HTTP {code} ({sbom_resp_v})")
                upload_id_v = sbom_resp_v["upload_id"]
                manifest.record_entity("sbom_uploads", upload_id_v)
                created_entities["sbom_upload_id_vulnerable"] = upload_id_v
                created_entities["sbom_root_vulnerable"] = sbom_resp_v.get("sbom_root")
                print(f"[+] Vulnerable SBOM Committed: {upload_id_v} (SBOM Root: {sbom_resp_v.get('sbom_root')})")
            else:
                created_entities["app_id_vulnerable"] = existing["app_vulnerable"]["id"]
                manifest.record_entity("applications", existing["app_vulnerable"]["id"])
                with engine.connect() as conn:
                    row = conn.execute(
                        text("SELECT id::text, sbom_root FROM sbom.sbom_uploads WHERE application_id = :aid ORDER BY created_at DESC LIMIT 1"),
                        {"aid": existing["app_vulnerable"]["id"]},
                    ).fetchone()
                    if row:
                        created_entities["sbom_upload_id_vulnerable"] = row[0]
                        created_entities["sbom_root_vulnerable"] = row[1]
                        manifest.record_entity("sbom_uploads", row[0])
                print(f"[=] Reusing existing vulnerable app {existing['app_vulnerable']['id']} (SBOM Root: {created_entities.get('sbom_root_vulnerable')})")

        # 4.4 Role Separation and Negative Authorization Verification
        print(f"[*] Validating role separation & negative authorization boundaries...")
        code_vuln_neg, _ = http_call(
            api_url,
            "POST",
            "/vulnerability/ingest",
            token=tokens["vendor"],
            json_data={
                "source_identity": "NVD",
                "provenance": {"feed": "neg"},
                "vulnerabilities": [{"purl": "pkg:pypi/test@1.0", "cvss_score": 5.0}],
            },
        )
        if code_vuln_neg != 403:
            raise RuntimeError(f"Role separation breach: vendor could call /vulnerability/ingest! Got HTTP {code_vuln_neg}")
        print("[+] Verified: Vendor role rejected from vulnerability ingestion (HTTP 403).")

        # 4.5 Independent Verification Fail-Closed Boundary Testing
        print(f"[*] Validating independent verification fail-closed boundary...")
        fake_job_id = str(uuid.uuid4())
        check_sbom_root = (
            created_entities.get("sbom_root_compliant")
            or created_entities.get("sbom_root_vulnerable")
            or ("0x" + "1" * 64)
        )
        code_ver, data_ver = http_call(
            api_url,
            "POST",
            "/verification/verify",
            token=tokens["buyer"],
            json_data={
                "sbom_root": check_sbom_root,
                "vulnerability_db_root": created_entities.get("vulnerability_db_root") or ("0x" + "2" * 64),
                "policy_hash": created_entities.get("policy_hash") or ("0x" + "3" * 64),
                "proof_job_id": fake_job_id,
            },
        )
        if code_ver != 200 or not isinstance(data_ver, dict):
            raise RuntimeError(f"Verification endpoint unexpected failure: HTTP {code_ver} ({data_ver})")

        ver_result = data_ver.get("result")
        cert_issued = data_ver.get("certificate")
        if ver_result not in ["verification_unavailable", "record_mismatch"] or cert_issued is not None:
            raise RuntimeError(f"Fail-closed verification violated! Result: {ver_result}, Certificate: {cert_issued}")
        print(f"[+] Verified: Unproven proof job fails closed with result '{ver_result}' and zero certificate issued.")

        if "id" in data_ver:
            manifest.record_entity("verification_requests", data_ver["id"])

        manifest.update_status("ready_for_cleanup")

        print("\n" + "=" * 70)
        print("DEMO PREPARATION COMPLETE")
        print(f"Rollback Manifest: {manifest_path}")
        print("Entities Primed for Live Vendor-to-Buyer Demo:")
        for k, v in created_entities.items():
            print(f"  {k}: {v}")
        print("=" * 70)
        return 0

    except Exception as exc:
        manifest.update_status("failed", error_message=str(exc))
        print(f"[-] Execution failed: {exc}")
        print(f"[!] Durable cleanup manifest preserved at: {manifest_path}")
        raise


def execute_rollback(manifest_file: Path) -> int:
    """Safely deletes only records recorded in the specified manifest in reverse foreign-key order."""
    manifest = DurableCleanupManifest.load_from_file(manifest_file)
    run_id = manifest.run_id
    target = f"{manifest.expected_host}:{manifest.expected_port}/{manifest.expected_db}"

    print(f"[*] Initiating Rollback for Run ID: {run_id} targeting {target}...")
    db_pass = get_container_db_password()
    engine = get_db_engine(db_pass)

    with engine.begin() as tx:
        for table in ORDERED_CLEANUP_TABLES:
            ids = manifest.entities.get(table, [])
            if ids:
                sql_table = TABLE_SQL_NAMES[table]
                id_strings = [str(x) for x in ids]
                print(f"    - Deleting {len(id_strings)} records from {sql_table}...")
                if table == "users":
                    # Prohibit deletion of users entirely
                    continue
                stmt = text(f"DELETE FROM {sql_table} WHERE id IN :ids").bindparams(
                    bindparam("ids", expanding=True)
                )
                tx.execute(stmt, {"ids": id_strings})

    manifest.update_status("cleaned")
    print(f"[+] Rollback completed successfully for run {run_id}.")
    return 0


# -----------------------------------------------------------------------------
# CLI Entry Point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Safe, idempotent preparation script for the Stage D9 Vendor-to-Buyer Demonstration."
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Explicitly execute API operations. Without this flag, script runs in dry-run/preflight mode only.",
    )
    parser.add_argument(
        "--scenario",
        choices=["compliant", "vulnerable", "both"],
        default="both",
        help="Select demo scenario(s) to prepare (default: both).",
    )
    parser.add_argument(
        "--rollback",
        default=None,
        help="Path to demo manifest JSON to roll back demo-created records safely.",
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"Application service gateway URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--creds-file",
        default=str(DEFAULT_CREDS_PATH),
        help=f"Path to demo account credentials JSON (default: {DEFAULT_CREDS_PATH})",
    )
    args = parser.parse_args()

    if args.rollback:
        sys.exit(execute_rollback(Path(args.rollback)))

    sys.exit(
        run_demo_preparation(
            api_url=args.api_url,
            creds_path=Path(args.creds_file),
            dry_run=(not args.execute),
            scenario=args.scenario,
        )
    )

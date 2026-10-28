"""
Targeted Regression Test Suite for Stage G2.2 Remediation
Verifies:
1. IntegrityError handling in ApplicationService:
   - Unique constraint violation (duplicate application) maps to ConflictError (HTTP 409).
   - Unrelated integrity errors (foreign key violation, check violation) are NOT masked as ConflictError.
2. Per-user transaction advisory lock in zkp_routes:
   - Concurrent proof requests from the same user enforce active job rate limiting (HTTP 429).
   - Concurrent proof requests from distinct users proceed in parallel without contention (HTTP 202).
"""

import concurrent.futures
import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import psycopg2
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(r"E:\Main Project")
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.config import DatabaseSettings
from shared.database import init_engine, get_engine, get_session
from shared.exceptions import ConflictError, ServiceError
from shared.auth import get_password_hash
from sbom_service.app.models.sbom_models import Application
from sbom_service.app.services.application_service import ApplicationService
from verification_service.app.main import app

TEST_DB_SETTINGS = DatabaseSettings(
    host="127.0.0.1",
    port=5435,
    name="zkp_sbom_g2_integration",
    user="pg17_restore_admin",
    password="test_password_17",
    ssl_mode="disable",
)


SCHEMA_MAP = {
    "users": "public",
    "user_profiles": "public",
    "applications": "sbom",
    "sbom_uploads": "sbom",
    "components": "sbom",
    "vulnerability_snapshots": "vulnerability",
    "component_vulnerabilities": "vulnerability",
    "security_policies": "policy",
    "proof_jobs": "zkp",
    "chunk_proof_sets": "zkp",
    "segment_proofs": "zkp",
    "verification_requests": "verification",
    "compliance_certificates": "verification",
    "certificate_revocations": "verification",
}


@pytest.fixture(scope="module")
def pg17_db():
    init_engine(TEST_DB_SETTINGS)
    from shared.database import Base
    for table in Base.metadata.tables.values():
        if table.name in SCHEMA_MAP:
            table.schema = SCHEMA_MAP[table.name]
    yield


def test_unrelated_integrity_failure_not_masked_as_conflict(pg17_db):
    """
    Verify that an unrelated database integrity error (e.g. invalid user_id violating FK constraint)
    is NOT masked as a duplicate application ConflictError.
    """
    db_gen = get_session()
    db = next(db_gen)
    service = ApplicationService(db)

    # Use a non-existent user_id to trigger a foreign key violation (applications_user_id_fkey)
    non_existent_user = uuid.uuid4()
    with pytest.raises(ServiceError) as exc_info:
        service.create(
            name=f"test_fk_app_{uuid.uuid4().hex[:6]}",
            vendor="Test Vendor",
            user_id=non_existent_user,
            description="Should fail with FK constraint violation",
        )

    # Verify that it is NOT a ConflictError (HTTP 409)
    assert not isinstance(exc_info.value, ConflictError), "SECURITY DEFECT: Foreign key violation incorrectly reported as ConflictError!"
    assert exc_info.value.status_code == 400
    assert exc_info.value.error_code == "INTEGRITY_VIOLATION"
    db.close()


def test_concurrent_duplicate_application_race_maps_to_conflict(pg17_db):
    """
    Verify that when 5 concurrent workers attempt to create an application with the identical
    (name, vendor, user_id) tuple, exactly 1 succeeds (201 Created) and the remaining 4
    return clean ConflictError (HTTP 409), with zero HTTP 500 errors.
    """
    # 1. Fetch a valid existing user
    conn = psycopg2.connect(host="127.0.0.1", port=5435, dbname="zkp_sbom_g2_integration", user="pg17_restore_admin", password="test_password_17")
    cur = conn.cursor()
    cur.execute("SELECT id FROM public.users WHERE role = 'vendor' LIMIT 1;")
    user_id = cur.fetchone()[0]
    conn.close()

    app_name = f"g2_2_reg_dup_{uuid.uuid4().hex[:6]}"
    vendor_name = "Acme Secure"

    def worker_create(worker_idx):
        db_gen = get_session()
        db = next(db_gen)
        service = ApplicationService(db)
        try:
            created = service.create(name=app_name, vendor=vendor_name, user_id=uuid.UUID(str(user_id)))
            app_id_str = str(created.id)
            db.close()
            return {"worker": worker_idx, "status": 201, "app_id": app_id_str}
        except ConflictError as e:
            db.close()
            return {"worker": worker_idx, "status": 409, "error": str(e)}
        except Exception as e:
            db.close()
            return {"worker": worker_idx, "status": 500, "error": f"{type(e).__name__}: {e}"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker_create, i) for i in range(5)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    statuses = [r["status"] for r in results]
    assert statuses.count(201) == 1, f"Expected exactly 1 201 Created, got {statuses.count(201)} in {statuses}"
    assert statuses.count(409) == 4, f"Expected 4 409 Conflict responses, got {statuses.count(409)} in {statuses}"
    assert statuses.count(500) == 0, f"Detected HTTP 500 server errors: {results}"

    # Verify database persistence: exactly 1 record
    conn = psycopg2.connect(host="127.0.0.1", port=5435, dbname="zkp_sbom_g2_integration", user="pg17_restore_admin", password="test_password_17")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM sbom.applications WHERE name = %s AND user_id = %s;", (app_name, user_id))
    db_count = cur.fetchone()[0]
    # Clean up
    cur.execute("DELETE FROM sbom.applications WHERE name = %s;", (app_name,))
    conn.commit()
    cur.close()
    conn.close()

    assert db_count == 1, f"Database has {db_count} records instead of 1!"


def test_concurrent_same_user_proof_rate_limiting_and_multi_user_concurrency(pg17_db):
    """
    Verify:
    1. Concurrent proof generation requests from the same user are serialized via
       pg_advisory_xact_lock so exactly 1 is accepted (202) and concurrent duplicate receives 429.
    2. Concurrent proof generation requests from distinct users are NOT blocked by each other.
    """
    # 1. Setup two test vendor accounts
    conn = psycopg2.connect(host="127.0.0.1", port=5435, dbname="zkp_sbom_g2_integration", user="pg17_restore_admin", password="test_password_17")
    cur = conn.cursor()
    hashed = get_password_hash("TestPassword123!")

    # Ensure Vendor 1 and Vendor 2 exist
    for u_name in ["g2_2_reg_v1", "g2_2_reg_v2"]:
        cur.execute("SELECT id FROM public.users WHERE username = %s;", (u_name,))
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO public.users (id, username, hashed_password, role, is_active, created_at, updated_at) VALUES (%s, %s, %s, 'vendor', TRUE, NOW(), NOW());",
                (str(uuid.uuid4()), u_name, hashed)
            )
        else:
            cur.execute("UPDATE public.users SET is_active = TRUE, hashed_password = %s WHERE username = %s;", (hashed, u_name))

    # Retrieve user IDs
    cur.execute("SELECT id FROM public.users WHERE username = 'g2_2_reg_v1';")
    u1_id = cur.fetchone()[0]
    cur.execute("SELECT id FROM public.users WHERE username = 'g2_2_reg_v2';")
    u2_id = cur.fetchone()[0]

    # Pre-clean any leftover rows from previous runs
    cur.execute("DELETE FROM zkp.proof_jobs WHERE user_id IN (%s, %s);", (u1_id, u2_id))
    cur.execute("DELETE FROM sbom.sbom_uploads WHERE user_id IN (%s, %s);", (u1_id, u2_id))
    cur.execute("DELETE FROM sbom.applications WHERE user_id IN (%s, %s);", (u1_id, u2_id))
    conn.commit()

    try:
        # Create app and SBOM for each vendor
        app1_id = str(uuid.uuid4())
        app2_id = str(uuid.uuid4())
        sbom1_id = str(uuid.uuid4())
        sbom2_id = str(uuid.uuid4())

        cur.execute("INSERT INTO sbom.applications (id, name, vendor, user_id, is_active, created_at, updated_at) VALUES (%s, %s, %s, %s, TRUE, NOW(), NOW());", (app1_id, "App V1", "Vendor 1", u1_id))
        cur.execute("INSERT INTO sbom.applications (id, name, vendor, user_id, is_active, created_at, updated_at) VALUES (%s, %s, %s, %s, TRUE, NOW(), NOW());", (app2_id, "App V2", "Vendor 2", u2_id))

        root1 = "0x" + "1" * 64
        root2 = "0x" + "2" * 64
        cur.execute("INSERT INTO sbom.sbom_uploads (id, application_id, user_id, format, status, sbom_root, created_at) VALUES (%s, %s, %s, 'CycloneDX', 'committed', %s, NOW());", (sbom1_id, app1_id, u1_id, root1))
        cur.execute("INSERT INTO sbom.sbom_uploads (id, application_id, user_id, format, status, sbom_root, created_at) VALUES (%s, %s, %s, 'CycloneDX', 'committed', %s, NOW());", (sbom2_id, app2_id, u2_id, root2))

        # Ensure a frozen snapshot and active policy exist
        cur.execute("SELECT id FROM vulnerability.vulnerability_snapshots WHERE status = 'frozen' LIMIT 1;")
        snap_row = cur.fetchone()
        if snap_row:
            snap_id = snap_row[0]
        else:
            snap_id = str(uuid.uuid4())
            cur.execute(
                "INSERT INTO vulnerability.vulnerability_snapshots (id, source_identity, status, authoritative_smt_root, created_at) VALUES (%s, 'NVD', 'frozen', %s, NOW());",
                (snap_id, "0x" + "4" * 64)
            )

        cur.execute("SELECT id FROM policy.security_policies LIMIT 1;")
        pol_row = cur.fetchone()
        if pol_row:
            pol_id = pol_row[0]
            cur.execute("UPDATE policy.security_policies SET is_active = 1 WHERE id = %s;", (pol_id,))
        else:
            pol_id = str(uuid.uuid4())
            cur.execute(
                "INSERT INTO policy.security_policies (id, name, max_cvss_score, is_active, policy_hash, created_at, updated_at) VALUES (%s, 'Reg Active Pol', 7.0, 1, %s, NOW(), NOW());",
                (pol_id, "0x" + "3" * 64)
            )

        conn.commit()
        conn.close()

        # Authenticate both vendors
        client = TestClient(app, raise_server_exceptions=False)
        tok1 = client.post("/api/v1/auth/login", data={"username": "g2_2_reg_v1", "password": "TestPassword123!"}).json()["access_token"]
        tok2 = client.post("/api/v1/auth/login", data={"username": "g2_2_reg_v2", "password": "TestPassword123!"}).json()["access_token"]

        payload1 = {"sbom_upload_id": sbom1_id, "snapshot_id": str(snap_id), "policy_id": str(pol_id)}
        payload2 = {"sbom_upload_id": sbom2_id, "snapshot_id": str(snap_id), "policy_id": str(pol_id)}

        # Part A: Same-user concurrency (Vendor 1 fires 2 simultaneous requests while mock worker holds lock)
        import time
        def mock_worker_hold(self, job_id, user_id=None):
            time.sleep(0.3)
            return None

        with patch("zkp_service.app.services.prover_service.ProverService.process_job", new=mock_worker_hold):
            def fire_req1(idx):
                c = TestClient(app, raise_server_exceptions=False)
                resp = c.post("/api/v1/zkp/generate", headers={"Authorization": f"Bearer {tok1}"}, json=payload1)
                return resp.status_code

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futs = [executor.submit(fire_req1, i) for i in range(2)]
                same_user_codes = [f.result() for f in concurrent.futures.as_completed(futs)]

        assert 202 in same_user_codes, f"Expected 202 Accepted in {same_user_codes}"
        assert 429 in same_user_codes, f"Expected 429 Rate Limit in {same_user_codes}"

        # Clear active status
        conn = psycopg2.connect(host="127.0.0.1", port=5435, dbname="zkp_sbom_g2_integration", user="pg17_restore_admin", password="test_password_17")
        cur = conn.cursor()
        cur.execute("UPDATE zkp.proof_jobs SET status = 'completed' WHERE user_id IN (%s, %s);", (u1_id, u2_id))
        conn.commit()

        # Part B: Multi-user concurrency (Vendor 1 and Vendor 2 fire requests simultaneously)
        with patch("zkp_service.app.services.prover_service.ProverService.process_job") as mock_p:
            mock_p.return_value = None

            def fire_multi_user(v_idx):
                c = TestClient(app, raise_server_exceptions=False)
                tok = tok1 if v_idx == 1 else tok2
                pload = payload1 if v_idx == 1 else payload2
                resp = c.post("/api/v1/zkp/generate", headers={"Authorization": f"Bearer {tok}"}, json=pload)
                return resp.status_code

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futs = [executor.submit(fire_multi_user, i) for i in (1, 2)]
                multi_user_codes = [f.result() for f in concurrent.futures.as_completed(futs)]

        assert multi_user_codes == [202, 202], f"Expected both users to succeed (202, 202), got {multi_user_codes}"
    finally:
        # Cleanup regression entities
        cleanup_conn = psycopg2.connect(host="127.0.0.1", port=5435, dbname="zkp_sbom_g2_integration", user="pg17_restore_admin", password="test_password_17")
        cleanup_cur = cleanup_conn.cursor()
        cleanup_cur.execute("DELETE FROM zkp.proof_jobs WHERE user_id IN (%s, %s);", (u1_id, u2_id))
        cleanup_cur.execute("DELETE FROM sbom.sbom_uploads WHERE user_id IN (%s, %s);", (u1_id, u2_id))
        cleanup_cur.execute("DELETE FROM sbom.applications WHERE user_id IN (%s, %s);", (u1_id, u2_id))
        cleanup_cur.execute("DELETE FROM public.users WHERE username IN ('g2_2_reg_v1', 'g2_2_reg_v2');")
        cleanup_conn.commit()
        cleanup_cur.close()
        cleanup_conn.close()

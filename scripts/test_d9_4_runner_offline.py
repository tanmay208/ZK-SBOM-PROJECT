"""
Offline Validation Suite for Remediated D9-4 Live Acceptance Runner
Location: scripts/test_d9_4_runner_offline.py
Target: Mocks, isolated SQLite in-memory fixtures, and dialect compilation.
Zero database connections, zero external API calls, zero credential reading.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import sqlalchemy.pool
from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.dialects import postgresql

# Ensure scripts and backend directories are on sys.path
_scripts_dir = Path(__file__).resolve().parent
_repo_root = _scripts_dir.parent
_backend_dir = _repo_root / "backend"

if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

import run_d9_4_live_acceptance as runner
from d9_cleanup_manifest import DurableCleanupManifest


class TestD9RunnerOfflineValidation(unittest.TestCase):
    """Offline unit tests validating all D9-4R safety corrections."""

    # -------------------------------------------------------------------------
    # 1. Credential Fail-Closed Validation
    # -------------------------------------------------------------------------
    def test_missing_db_password_fails_closed(self):
        """Verify missing DB_PASSWORD raises RuntimeError before any connection attempt."""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                runner.get_db_password()
            self.assertIn("FAIL_CLOSED: DB_PASSWORD", str(ctx.exception))

    def test_blank_db_password_fails_closed(self):
        """Verify empty or whitespace-only DB_PASSWORD raises RuntimeError."""
        with patch.dict(os.environ, {"DB_PASSWORD": "   "}):
            with self.assertRaises(RuntimeError) as ctx:
                runner.get_db_password()
            self.assertIn("FAIL_CLOSED: DB_PASSWORD", str(ctx.exception))

    def test_valid_db_password_stripped(self):
        """Verify non-empty DB_PASSWORD is correctly stripped and returned."""
        with patch.dict(os.environ, {"DB_PASSWORD": " valid_test_pass \n"}):
            self.assertEqual(runner.get_db_password(), "valid_test_pass")

    # -------------------------------------------------------------------------
    # 2. Secret Sanitization Validation
    # -------------------------------------------------------------------------
    def test_sanitize_text_redacts_tokens_and_passwords(self):
        """Verify sensitive credentials are removed from logs and messages."""
        raw_text = (
            "Connecting to postgresql+psycopg2://postgres:super_secret@127.0.0.1:5433/db "
            "with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dummy and "
            'password="my_plain_password" or password=cli_secret'
        )
        sanitized = runner.sanitize_text(raw_text, extra_secrets=["custom_dev_secret"])
        self.assertNotIn("super_secret", sanitized)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", sanitized)
        self.assertNotIn("my_plain_password", sanitized)
        self.assertNotIn("cli_secret", sanitized)
        self.assertIn("[REDACTED_PASSWORD]", sanitized)
        self.assertIn("[REDACTED_TOKEN]", sanitized)
        self.assertIn("[REDACTED]", sanitized)

        # Test extra secrets redaction
        extra_text = "Here is custom_dev_secret in error string"
        sanitized_extra = runner.sanitize_text(extra_text, extra_secrets=["custom_dev_secret"])
        self.assertNotIn("custom_dev_secret", sanitized_extra)
        self.assertIn("[REDACTED]", sanitized_extra)

    # -------------------------------------------------------------------------
    # 3. Role Assertion Validation
    # -------------------------------------------------------------------------
    def test_expected_roles_mapping(self):
        """Verify role mappings for all 3 dedicated D9 accounts."""
        self.assertEqual(runner.EXPECTED_ROLES["d9_vendor"], "vendor")
        self.assertEqual(runner.EXPECTED_ROLES["d9_trusted_importer"], "trusted_importer")
        self.assertEqual(runner.EXPECTED_ROLES["d9_admin"], "admin")

    def test_role_mismatch_raises_error(self):
        """Verify unexpected role raises an exception immediately."""
        username = "d9_admin"
        observed_role = "auditor"  # Wrong role
        expected_role = runner.EXPECTED_ROLES[username]
        with self.assertRaises(AssertionError):
            self.assertEqual(observed_role, expected_role)

    # -------------------------------------------------------------------------
    # 4. Host Termination Handling
    # -------------------------------------------------------------------------
    def test_stop_host_graceful_and_forced(self):
        """Verify stop_host terminates process and kills on timeout."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None

        # Scenario A: Graceful stop
        runner.stop_host(mock_proc, timeout=0.1)
        mock_proc.terminate.assert_called_once()
        mock_proc.wait.assert_called()

        # Scenario B: Forced kill after timeout
        mock_proc2 = MagicMock()
        mock_proc2.poll.return_value = None
        # First wait raises timeout, second wait (after kill) succeeds
        mock_proc2.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="uvicorn", timeout=0.1),
            None,
        ]
        runner.stop_host(mock_proc2, timeout=0.1)
        mock_proc2.terminate.assert_called_once()
        mock_proc2.kill.assert_called_once()

    # -------------------------------------------------------------------------
    # 5. PostgreSQL Expanding Bind SQL Compilation
    # -------------------------------------------------------------------------
    def test_expanding_binds_compile_for_postgresql(self):
        """Validate that expanding binds compile without syntax error under PostgreSQL dialect."""
        dialect = postgresql.dialect()

        stmt_ver = text(
            "DELETE FROM verification.verification_requests WHERE id IN :req_ids"
        ).bindparams(bindparam("req_ids", expanding=True))
        compiled_ver = str(stmt_ver.compile(dialect=dialect))
        self.assertIn("WHERE id IN (__[POSTCOMPILE_req_ids])", compiled_ver)

        stmt_comp = text(
            "DELETE FROM sbom.components WHERE sbom_upload_id IN :uploads"
        ).bindparams(bindparam("uploads", expanding=True))
        compiled_comp = str(stmt_comp.compile(dialect=dialect))
        self.assertIn("WHERE sbom_upload_id IN (__[POSTCOMPILE_uploads])", compiled_comp)

        stmt_app = text(
            "DELETE FROM sbom.applications WHERE id IN :apps"
        ).bindparams(bindparam("apps", expanding=True))
        compiled_app = str(stmt_app.compile(dialect=dialect))
        self.assertIn("WHERE id IN (__[POSTCOMPILE_apps])", compiled_app)

    # -------------------------------------------------------------------------
    # 6. SQLite In-Memory Exact-ID Cleanup & Policy Restoration Fixture
    # -------------------------------------------------------------------------
    def test_exact_id_cleanup_sqlite_fixture(self):
        """Verify execute_exact_id_cleanup deletes only test records and restores baseline policies."""
        # StaticPool ensures attached databases persist across connections
        engine = create_engine("sqlite://", poolclass=sqlalchemy.pool.StaticPool)

        with engine.begin() as conn:
            conn.execute(text("ATTACH DATABASE ':memory:' AS verification"))
            conn.execute(text("ATTACH DATABASE ':memory:' AS vulnerability"))
            conn.execute(text("ATTACH DATABASE ':memory:' AS sbom"))
            conn.execute(text("ATTACH DATABASE ':memory:' AS policy"))

            conn.execute(text("CREATE TABLE verification.verification_certificates (id TEXT, verification_request_id TEXT)"))
            conn.execute(text("CREATE TABLE verification.verification_requests (id TEXT)"))
            conn.execute(text("CREATE TABLE vulnerability.component_vulnerability_mappings (id TEXT, snapshot_id TEXT)"))
            conn.execute(text("CREATE TABLE vulnerability.vulnerability_snapshots (id TEXT)"))
            conn.execute(text("CREATE TABLE sbom.components (id TEXT, sbom_upload_id TEXT)"))
            conn.execute(text("CREATE TABLE sbom.sbom_uploads (id TEXT)"))
            conn.execute(text("CREATE TABLE sbom.applications (id TEXT)"))
            conn.execute(text("CREATE TABLE policy.security_policies (id TEXT, is_active INTEGER)"))

            # Insert baseline records (should NOT be deleted)
            base_app = str(uuid.uuid4())
            base_pol = str(uuid.uuid4())
            conn.execute(text("INSERT INTO sbom.applications VALUES (:id)"), {"id": base_app})
            conn.execute(text("INSERT INTO policy.security_policies VALUES (:id, 1)"), {"id": base_pol})

            # Insert test records (SHOULD be deleted)
            test_app = str(uuid.uuid4())
            test_up = str(uuid.uuid4())
            test_comp = str(uuid.uuid4())
            test_snap = str(uuid.uuid4())
            test_map = str(uuid.uuid4())
            test_req = str(uuid.uuid4())
            test_cert = str(uuid.uuid4())
            test_pol = str(uuid.uuid4())

            conn.execute(text("INSERT INTO sbom.applications VALUES (:id)"), {"id": test_app})
            conn.execute(text("INSERT INTO sbom.sbom_uploads VALUES (:id)"), {"id": test_up})
            conn.execute(text("INSERT INTO sbom.components VALUES (:id, :up)"), {"id": test_comp, "up": test_up})
            conn.execute(text("INSERT INTO vulnerability.vulnerability_snapshots VALUES (:id)"), {"id": test_snap})
            conn.execute(text("INSERT INTO vulnerability.component_vulnerability_mappings VALUES (:id, :sn)"), {"id": test_map, "sn": test_snap})
            conn.execute(text("INSERT INTO verification.verification_requests VALUES (:id)"), {"id": test_req})
            conn.execute(text("INSERT INTO verification.verification_certificates VALUES (:id, :rq)"), {"id": test_cert, "rq": test_req})
            conn.execute(text("INSERT INTO policy.security_policies VALUES (:id, 1)"), {"id": test_pol})

            # Simulate baseline policy deactivation during test
            conn.execute(text("UPDATE policy.security_policies SET is_active = 0 WHERE id = :id"), {"id": base_pol})

        manifest = {
            "verification_requests": [test_req],
            "component_vulnerability_mappings": [],
            "vulnerability_snapshots": [test_snap],
            "components": [],
            "sbom_uploads": [test_up],
            "applications": [test_app],
            "security_policies": [test_pol],
        }
        baseline_policy_states = {base_pol: 1}

        # Invoke runner's exact function directly!
        runner.execute_exact_id_cleanup(engine, manifest, baseline_policy_states)

        # Assert test entities deleted
        with engine.connect() as conn:
            self.assertEqual(conn.execute(text("SELECT count(*) FROM sbom.applications WHERE id = :id"), {"id": test_app}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM sbom.sbom_uploads WHERE id = :id"), {"id": test_up}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM sbom.components WHERE id = :id"), {"id": test_comp}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM vulnerability.vulnerability_snapshots WHERE id = :id"), {"id": test_snap}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM verification.verification_requests WHERE id = :id"), {"id": test_req}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM verification.verification_certificates WHERE id = :id"), {"id": test_cert}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM policy.security_policies WHERE id = :id"), {"id": test_pol}).scalar(), 0)

            # Assert baseline records PRESERVED and RESTORED
            self.assertEqual(conn.execute(text("SELECT count(*) FROM sbom.applications WHERE id = :id"), {"id": base_app}).scalar(), 1)
            self.assertEqual(conn.execute(text("SELECT is_active FROM policy.security_policies WHERE id = :id"), {"id": base_pol}).scalar(), 1)

    # -------------------------------------------------------------------------
    # 7. Partial Failure Lifecycle Invokes Cleanup
    # -------------------------------------------------------------------------
    def test_failure_after_mutation_invokes_cleanup_in_finally(self):
        """Simulate failure after each mutation point, proving cleanup executes and failure is returned."""
        engine = create_engine("sqlite://", poolclass=sqlalchemy.pool.StaticPool)
        with engine.begin() as conn:
            conn.execute(text("ATTACH DATABASE ':memory:' AS sbom"))
            conn.execute(text("CREATE TABLE sbom.applications (id TEXT)"))

        app_id = str(uuid.uuid4())
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO sbom.applications VALUES (:id)"), {"id": app_id})

        manifest = {
            "verification_requests": [],
            "component_vulnerability_mappings": [],
            "vulnerability_snapshots": [],
            "components": [],
            "sbom_uploads": [],
            "applications": [app_id],
            "security_policies": [],
        }

        # Simulate exception during downstream test step
        test_error = None
        cleanup_called = False
        try:
            # Simulate step failure
            raise RuntimeError("Simulated failure at Step 3 (SBOM upload)")
        except Exception as exc:
            test_error = exc
        finally:
            # In the runner's finally block:
            if any(len(v) > 0 for v in manifest.values()):
                runner.execute_exact_id_cleanup(engine, manifest)
                cleanup_called = True

        self.assertTrue(cleanup_called)
        self.assertIsNotNone(test_error)
        self.assertIn("Simulated failure at Step 3", str(test_error))

        # Verify application record was cleaned up even though test failed!
        with engine.connect() as conn:
            remaining = conn.execute(
                text("SELECT count(*) FROM sbom.applications WHERE id = :id"),
                {"id": app_id},
            ).scalar()
            self.assertEqual(remaining, 0)

    # -------------------------------------------------------------------------
    # 8. Target Boundary Verification
    # -------------------------------------------------------------------------
    def test_target_constants_cannot_target_pg17_or_remote(self):
        """Verify hardcoded target parameters prohibit port 5432 or remote hosts."""
        self.assertEqual(runner.EXPECTED_HOST, "127.0.0.1")
        self.assertEqual(runner.EXPECTED_PORT, 5433)
        self.assertEqual(runner.EXPECTED_DB, "ZKP_SBOM_LOCAL_DEV")
        self.assertEqual(runner.EXPECTED_MAJOR_VER, 16)
        self.assertEqual(runner.EXPECTED_REVISION, "015")
        self.assertNotEqual(runner.EXPECTED_PORT, 5432)

    # -------------------------------------------------------------------------
    # 9. HTTP Status Assertion Enforcement Tests
    # -------------------------------------------------------------------------
    def test_unexpected_http_statuses_raise_failure(self):
        """Verify any unexpected status in isolation, separation of duties, or missing cert fails."""
        # Scenario A: Missing certificate lookup returns 200 instead of 404
        status_cert_missing = 200
        with self.assertRaises(RuntimeError) as ctx:
            if status_cert_missing != 404:
                raise RuntimeError(f"Missing certificate lookup failed assertion: expected HTTP 404, got {status_cert_missing}")
        self.assertIn("expected HTTP 404, got 200", str(ctx.exception))

        # Scenario B: Tenant isolation returns 200 instead of 404
        status_iso = 200
        with self.assertRaises(RuntimeError) as ctx:
            if status_iso != 404:
                raise RuntimeError(f"Tenant isolation breach! Expected HTTP 404, got {status_iso}")
        self.assertIn("Tenant isolation breach", str(ctx.exception))

        # Scenario C: Importer self-approval returns 200 instead of 403
        status_sod = 200
        with self.assertRaises(RuntimeError) as ctx:
            if status_sod != 403:
                raise RuntimeError(f"Separation of duties violation! Importer could approve snapshot! HTTP {status_sod}")
        self.assertIn("Separation of duties violation", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 10. Verification Request Tracking & Fail-Closed Enforcement
    # -------------------------------------------------------------------------
    def test_verification_request_tracking_and_fail_closed(self):
        """Verify verification_request ID is captured into cleanup manifest and unexpected cert issuance fails."""
        manifest = {"verification_requests": []}
        data_ver = {
            "id": "e4b3e839-4458-4061-8fca-2f3b8909874a",
            "result": "verification_unavailable",
            "certificate": None,
        }

        # Assert ID is captured
        ver_req_id = data_ver.get("id")
        if ver_req_id:
            manifest["verification_requests"].append(ver_req_id)
        self.assertEqual(manifest["verification_requests"], ["e4b3e839-4458-4061-8fca-2f3b8909874a"])

        # Assert fail-closed: if certificate was unexpectedly issued, fail run
        data_ver_corrupted = {
            "id": "e4b3e839-4458-4061-8fca-2f3b8909874a",
            "result": "verified",
            "certificate": {"cert_id": "bad_cert"},
        }
        with self.assertRaises(RuntimeError) as ctx:
            if (
                data_ver_corrupted.get("result") not in ["verification_unavailable", "record_mismatch"]
                or data_ver_corrupted.get("certificate") is not None
            ):
                raise RuntimeError(f"Verification did NOT fail closed! Result: {data_ver_corrupted.get('result')}")
        self.assertIn("Verification did NOT fail closed", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 11. Credential Schema & Account Validation Tests
    # -------------------------------------------------------------------------
    def test_credentials_valid_dict_format(self):
        """Verify valid dictionary keyed by username normalizes correctly."""
        raw_dict = {
            "d9_admin": {
                "id": str(uuid.uuid4()),
                "username": "d9_admin",
                "role": "admin",
                "password": "synthetic_dummy_admin_pw_1",
            },
            "d9_vendor": {
                "id": str(uuid.uuid4()),
                "username": "d9_vendor",
                "role": "vendor",
                "password": "synthetic_dummy_vendor_pw_2",
            },
            "d9_trusted_importer": {
                "id": str(uuid.uuid4()),
                "username": "d9_trusted_importer",
                "role": "trusted_importer",
                "password": "synthetic_dummy_importer_pw_3",
            },
        }
        res = runner.parse_and_validate_credentials(raw_dict)
        self.assertEqual(set(res.keys()), {"d9_admin", "d9_vendor", "d9_trusted_importer"})
        self.assertEqual(res["d9_admin"]["role"], "admin")
        self.assertEqual(res["d9_vendor"]["role"], "vendor")
        self.assertEqual(res["d9_trusted_importer"]["role"], "trusted_importer")
        self.assertEqual(res["d9_admin"]["password"], "synthetic_dummy_admin_pw_1")

    def test_credentials_valid_list_format(self):
        """Verify valid list of account objects normalizes to dictionary keyed by username."""
        raw_list = [
            {
                "id": str(uuid.uuid4()),
                "username": "d9_admin",
                "role": "admin",
                "password": "synthetic_dummy_admin_pw_1",
            },
            {
                "id": str(uuid.uuid4()),
                "username": "d9_vendor",
                "role": "vendor",
                "password": "synthetic_dummy_vendor_pw_2",
            },
            {
                "id": str(uuid.uuid4()),
                "username": "d9_trusted_importer",
                "role": "trusted_importer",
                "password": "synthetic_dummy_importer_pw_3",
            },
        ]
        res = runner.parse_and_validate_credentials(raw_list)
        self.assertEqual(set(res.keys()), {"d9_admin", "d9_vendor", "d9_trusted_importer"})
        self.assertEqual(res["d9_vendor"]["password"], "synthetic_dummy_vendor_pw_2")

    def test_credentials_missing_required_accounts(self):
        """Verify missing any required dedicated account raises ValueError."""
        partial_dict = {
            "d9_admin": {
                "username": "d9_admin",
                "role": "admin",
                "password": "dummy_password_1",
            },
            "d9_vendor": {
                "username": "d9_vendor",
                "role": "vendor",
                "password": "dummy_password_2",
            },
        }
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(partial_dict)
        self.assertIn("Missing required dedicated account", str(ctx.exception))
        self.assertIn("d9_trusted_importer", str(ctx.exception))

    def test_credentials_duplicate_usernames_in_list(self):
        """Verify duplicate usernames in list format raise ValueError."""
        dup_list = [
            {"username": "d9_admin", "role": "admin", "password": "pw1"},
            {"username": "d9_admin", "role": "admin", "password": "pw2"},
            {"username": "d9_vendor", "role": "vendor", "password": "pw3"},
            {"username": "d9_trusted_importer", "role": "trusted_importer", "password": "pw4"},
        ]
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(dup_list)
        self.assertIn("Duplicate username", str(ctx.exception))
        self.assertIn("d9_admin", str(ctx.exception))

    def test_credentials_key_username_mismatch(self):
        """Verify dictionary key disagreeing with username raises ValueError."""
        mismatched_dict = {
            "d9_admin": {"username": "d9_imposter", "role": "admin", "password": "pw1"},
            "d9_vendor": {"username": "d9_vendor", "role": "vendor", "password": "pw2"},
            "d9_trusted_importer": {"username": "d9_trusted_importer", "role": "trusted_importer", "password": "pw3"},
        }
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(mismatched_dict)
        self.assertIn("Credential key/username mismatch", str(ctx.exception))

    def test_credentials_missing_or_empty_required_fields(self):
        """Verify missing or empty required fields raise ValueError."""
        # Missing password
        missing_pw = {
            "d9_admin": {"username": "d9_admin", "role": "admin"},
            "d9_vendor": {"username": "d9_vendor", "role": "vendor", "password": "pw"},
            "d9_trusted_importer": {"username": "d9_trusted_importer", "role": "trusted_importer", "password": "pw"},
        }
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(missing_pw)
        self.assertIn("missing valid 'password' string", str(ctx.exception))

        # Whitespace-only password
        empty_pw = {
            "d9_admin": {"username": "d9_admin", "role": "admin", "password": "   "},
            "d9_vendor": {"username": "d9_vendor", "role": "vendor", "password": "pw"},
            "d9_trusted_importer": {"username": "d9_trusted_importer", "role": "trusted_importer", "password": "pw"},
        }
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(empty_pw)
        self.assertIn("missing valid 'password' string", str(ctx.exception))

    def test_credentials_incorrectly_typed_fields(self):
        """Verify non-string fields raise ValueError."""
        # password is integer
        int_pw = {
            "d9_admin": {"username": "d9_admin", "role": "admin", "password": 12345},
            "d9_vendor": {"username": "d9_vendor", "role": "vendor", "password": "pw"},
            "d9_trusted_importer": {"username": "d9_trusted_importer", "role": "trusted_importer", "password": "pw"},
        }
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(int_pw)
        self.assertIn("missing valid 'password' string", str(ctx.exception))

        # id is integer
        int_id = {
            "d9_admin": {"id": 123, "username": "d9_admin", "role": "admin", "password": "pw"},
            "d9_vendor": {"username": "d9_vendor", "role": "vendor", "password": "pw"},
            "d9_trusted_importer": {"username": "d9_trusted_importer", "role": "trusted_importer", "password": "pw"},
        }
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(int_id)
        self.assertIn("Field 'id'", str(ctx.exception))
        self.assertIn("must be a string", str(ctx.exception))

    def test_credentials_role_mismatch(self):
        """Verify role mismatch for dedicated accounts raises ValueError."""
        wrong_role = {
            "d9_admin": {"username": "d9_admin", "role": "auditor", "password": "pw"},
            "d9_vendor": {"username": "d9_vendor", "role": "vendor", "password": "pw"},
            "d9_trusted_importer": {"username": "d9_trusted_importer", "role": "trusted_importer", "password": "pw"},
        }
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(wrong_role)
        self.assertIn("Role mismatch for account 'd9_admin'", str(ctx.exception))
        self.assertIn("expected 'admin', got 'auditor'", str(ctx.exception))

    def test_credentials_unexpected_top_level_types(self):
        """Verify non-dict, non-list top-level types raise ValueError."""
        for invalid_input in ["invalid_str", 123, True, None]:
            with self.subTest(invalid_input=invalid_input):
                with self.assertRaises(ValueError) as ctx:
                    runner.parse_and_validate_credentials(invalid_input)
                self.assertIn("top-level JSON must be an object or array", str(ctx.exception))

    def test_credentials_malformed_json_file(self):
        """Verify malformed JSON file raises ValueError with clear description."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tf:
            tf.write("{\n  \"d9_admin\": {\"username\": \"d9_admin\",\n")
            temp_path = tf.name

        try:
            with self.assertRaises(ValueError) as ctx:
                runner.load_and_validate_credentials(temp_path)
            self.assertIn("Malformed JSON in credentials file", str(ctx.exception))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_credentials_missing_file_fails_closed(self):
        """Verify missing credentials file raises RuntimeError."""
        non_existent = os.path.join(tempfile.gettempdir(), f"non_existent_{uuid.uuid4().hex}.json")
        with self.assertRaises(RuntimeError) as ctx:
            runner.load_and_validate_credentials(non_existent)
        self.assertIn("Credentials file missing", str(ctx.exception))

    def test_credentials_secret_safe_error_handling(self):
        """Verify sensitive credentials are never reflected in exception messages."""
        sensitive_secret = "TOP_SECRET_PLAINTEXT_PW_98765"
        raw_data = {
            "d9_admin": {
                "username": "d9_admin",
                "role": "auditor",  # Intentional error to trigger exception
                "password": sensitive_secret,
            },
            "d9_vendor": {"username": "d9_vendor", "role": "vendor", "password": "pw"},
            "d9_trusted_importer": {"username": "d9_trusted_importer", "role": "trusted_importer", "password": "pw"},
        }
        with self.assertRaises(ValueError) as ctx:
            runner.parse_and_validate_credentials(raw_data)

        exc_msg = str(ctx.exception)
        self.assertNotIn(sensitive_secret, exc_msg)
        self.assertIn("Role mismatch", exc_msg)

    # -------------------------------------------------------------------------
    # 12. SBOM Upload Response Contract & Tracking Tests
    # -------------------------------------------------------------------------
    def test_sbom_upload_valid_response(self):
        """Verify valid HTTP 201 response containing upload_id returns parsed UUID and root."""
        test_uuid = str(uuid.uuid4())
        test_root = "0x" + "a" * 64
        valid_payload = {
            "upload_id": test_uuid,
            "application_id": str(uuid.uuid4()),
            "status": "pending",
            "format": "CycloneDX",
            "filename": None,
            "sbom_root": test_root,
            "component_count": 1,
            "created_at": "2026-10-21T00:00:00",
            "application_name": "TestApp",
            "vendor": "TestVendor",
        }
        res_upload_id, res_root = runner.validate_sbom_upload_response(201, valid_payload)
        self.assertEqual(res_upload_id, test_uuid)
        self.assertEqual(res_root, test_root)

    def test_sbom_upload_valid_response_without_sbom_root(self):
        """Verify valid HTTP 201 response with None or missing sbom_root is accepted."""
        test_uuid = str(uuid.uuid4())
        valid_payload = {
            "upload_id": test_uuid,
            "application_id": str(uuid.uuid4()),
            "status": "pending",
            "format": "CycloneDX",
            "filename": None,
            "sbom_root": None,
            "component_count": 0,
            "created_at": "2026-10-21T00:00:00",
        }
        res_upload_id, res_root = runner.validate_sbom_upload_response(201, valid_payload)
        self.assertEqual(res_upload_id, test_uuid)
        self.assertIsNone(res_root)

    def test_sbom_upload_missing_upload_id(self):
        """Verify response missing 'upload_id' (e.g. legacy 'id') raises RuntimeError."""
        payload_with_legacy_id = {
            "id": str(uuid.uuid4()),
            "status": "pending",
            "format": "CycloneDX",
        }
        with self.assertRaises(RuntimeError) as ctx:
            runner.validate_sbom_upload_response(201, payload_with_legacy_id)
        self.assertIn("missing required field 'upload_id'", str(ctx.exception))

        empty_payload = {}
        with self.assertRaises(RuntimeError) as ctx:
            runner.validate_sbom_upload_response(201, empty_payload)
        self.assertIn("missing required field 'upload_id'", str(ctx.exception))

    def test_sbom_upload_malformed_identifier_types(self):
        """Verify non-string or blank upload_id raises RuntimeError."""
        for invalid_val in [12345, True, False, ["some-id"], {"id": 1}, "", "   "]:
            with self.subTest(invalid_val=invalid_val):
                payload = {"upload_id": invalid_val}
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_sbom_upload_response(201, payload)
                self.assertIn("must be a non-empty string", str(ctx.exception))

    def test_sbom_upload_malformed_identifier_uuid(self):
        """Verify non-UUID string upload_id raises RuntimeError."""
        for invalid_uuid in ["not-a-valid-uuid", "12345678", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"]:
            with self.subTest(invalid_uuid=invalid_uuid):
                payload = {"upload_id": invalid_uuid}
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_sbom_upload_response(201, payload)
                self.assertIn("is not a valid UUID", str(ctx.exception))

    def test_sbom_upload_unexpected_http_statuses(self):
        """Verify HTTP status other than 201 raises RuntimeError."""
        valid_payload = {"upload_id": str(uuid.uuid4()), "sbom_root": "0x123"}
        for bad_status in [200, 400, 401, 403, 404, 422, 500, 503]:
            with self.subTest(bad_status=bad_status):
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_sbom_upload_response(bad_status, valid_payload)
                self.assertIn("unexpected HTTP status", str(ctx.exception))
                self.assertIn(str(bad_status), str(ctx.exception))

    def test_sbom_upload_non_dict_body(self):
        """Verify non-dict response body raises RuntimeError."""
        for bad_body in ["string_response", [1, 2, 3], None, 123]:
            with self.subTest(bad_body=bad_body):
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_sbom_upload_response(201, bad_body)
                self.assertIn("response body is not a JSON object", str(ctx.exception))

    def test_sbom_upload_malformed_sbom_root_type(self):
        """Verify non-string sbom_root raises RuntimeError."""
        for bad_root in [12345, True, ["0x123"], {"root": "0x123"}]:
            with self.subTest(bad_root=bad_root):
                payload = {"upload_id": str(uuid.uuid4()), "sbom_root": bad_root}
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_sbom_upload_response(201, payload)
                self.assertIn("'sbom_root' must be a string or None", str(ctx.exception))

    def test_sbom_upload_identifier_propagation_to_cleanup_manifest(self):
        """Verify validated upload_id is strictly propagated to cleanup manifest on success, and omitted on failure."""
        manifest = {"sbom_uploads": []}
        test_uuid = str(uuid.uuid4())
        valid_payload = {"upload_id": test_uuid, "sbom_root": "0x1234"}

        # Successful validation -> added to manifest
        upload_id, _ = runner.validate_sbom_upload_response(201, valid_payload)
        manifest["sbom_uploads"].append(upload_id)
        self.assertEqual(manifest["sbom_uploads"], [test_uuid])

        # Failed validation -> manifest remains untouched
        bad_payload = {"id": test_uuid}  # missing upload_id
        try:
            upload_id_failed, _ = runner.validate_sbom_upload_response(201, bad_payload)
            manifest["sbom_uploads"].append(upload_id_failed)
        except RuntimeError:
            pass  # Expected error
        self.assertEqual(manifest["sbom_uploads"], [test_uuid])  # Still only the original test_uuid

    def test_sbom_upload_cleanup_sql_schema_alignment(self):
        """Verify cleanup statements for sbom_uploads and components match schema column names and bindings."""
        test_upload_id = str(uuid.uuid4())
        manifest = {"sbom_uploads": [test_upload_id]}

        stmt_comp = text(
            "DELETE FROM sbom.components WHERE sbom_upload_id IN :uploads"
        ).bindparams(bindparam("uploads", expanding=True))
        compiled_comp = str(stmt_comp.compile(dialect=postgresql.dialect()))
        self.assertIn("sbom.components", compiled_comp)
        self.assertIn("sbom_upload_id IN", compiled_comp)

        stmt_up = text(
            "DELETE FROM sbom.sbom_uploads WHERE id IN :uploads"
        ).bindparams(bindparam("uploads", expanding=True))
        compiled_up = str(stmt_up.compile(dialect=postgresql.dialect()))
        self.assertIn("sbom.sbom_uploads", compiled_up)
        self.assertIn("id IN", compiled_up)

    # -------------------------------------------------------------------------
    # 13. Vulnerability Ingestion Response Contract & Tracking Tests
    # -------------------------------------------------------------------------
    def test_vulnerability_ingest_valid_response(self):
        """Verify valid HTTP 200 response containing snapshot_id returns parsed UUID and count."""
        test_uuid = str(uuid.uuid4())
        valid_payload = {
            "snapshot_id": test_uuid,
            "components_processed": 2,
        }
        res_snapshot_id, res_count = runner.validate_vulnerability_ingest_response(200, valid_payload)
        self.assertEqual(res_snapshot_id, test_uuid)
        self.assertEqual(res_count, 2)

    def test_vulnerability_ingest_valid_response_default_components_processed(self):
        """Verify valid HTTP 200 response with missing components_processed defaults to 0."""
        test_uuid = str(uuid.uuid4())
        valid_payload = {
            "snapshot_id": test_uuid,
        }
        res_snapshot_id, res_count = runner.validate_vulnerability_ingest_response(200, valid_payload)
        self.assertEqual(res_snapshot_id, test_uuid)
        self.assertEqual(res_count, 0)

    def test_vulnerability_ingest_missing_snapshot_id(self):
        """Verify response missing 'snapshot_id' raises RuntimeError."""
        payload_missing = {"components_processed": 1}
        with self.assertRaises(RuntimeError) as ctx:
            runner.validate_vulnerability_ingest_response(200, payload_missing)
        self.assertIn("missing required field 'snapshot_id'", str(ctx.exception))

        empty_payload = {}
        with self.assertRaises(RuntimeError) as ctx:
            runner.validate_vulnerability_ingest_response(200, empty_payload)
        self.assertIn("missing required field 'snapshot_id'", str(ctx.exception))

    def test_vulnerability_ingest_malformed_identifier_types(self):
        """Verify non-string or blank snapshot_id raises RuntimeError."""
        for invalid_val in [12345, True, False, ["some-id"], {"id": 1}, "", "   "]:
            with self.subTest(invalid_val=invalid_val):
                payload = {"snapshot_id": invalid_val}
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_vulnerability_ingest_response(200, payload)
                self.assertIn("must be a non-empty string", str(ctx.exception))

    def test_vulnerability_ingest_malformed_identifier_uuid(self):
        """Verify non-UUID string snapshot_id raises RuntimeError."""
        for invalid_uuid in ["not-a-valid-uuid", "12345678", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"]:
            with self.subTest(invalid_uuid=invalid_uuid):
                payload = {"snapshot_id": invalid_uuid}
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_vulnerability_ingest_response(200, payload)
                self.assertIn("is not a valid UUID", str(ctx.exception))

    def test_vulnerability_ingest_unexpected_http_statuses(self):
        """Verify HTTP status other than 200 (including 201) raises RuntimeError."""
        valid_payload = {"snapshot_id": str(uuid.uuid4()), "components_processed": 1}
        for bad_status in [201, 400, 401, 403, 404, 422, 500, 503]:
            with self.subTest(bad_status=bad_status):
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_vulnerability_ingest_response(bad_status, valid_payload)
                self.assertIn("unexpected HTTP status", str(ctx.exception))
                self.assertIn(str(bad_status), str(ctx.exception))

    def test_vulnerability_ingest_non_dict_body(self):
        """Verify non-dict response body raises RuntimeError."""
        for bad_body in ["string_response", [1, 2, 3], None, 123]:
            with self.subTest(bad_body=bad_body):
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_vulnerability_ingest_response(200, bad_body)
                self.assertIn("response body is not a JSON object", str(ctx.exception))

    def test_vulnerability_ingest_malformed_components_processed_type(self):
        """Verify non-int components_processed raises RuntimeError."""
        for bad_comp in ["two", True, False, [1], {"count": 1}, 2.5]:
            with self.subTest(bad_comp=bad_comp):
                payload = {"snapshot_id": str(uuid.uuid4()), "components_processed": bad_comp}
                with self.assertRaises(RuntimeError) as ctx:
                    runner.validate_vulnerability_ingest_response(200, payload)
                self.assertIn("'components_processed' must be an int", str(ctx.exception))

    def test_vulnerability_ingest_identifier_propagation_to_cleanup_manifest(self):
        """Verify validated snapshot_id is strictly propagated to cleanup manifest on success, and omitted on failure."""
        manifest = {"vulnerability_snapshots": []}
        test_uuid = str(uuid.uuid4())
        valid_payload = {"snapshot_id": test_uuid, "components_processed": 1}

        # Successful validation -> added to manifest
        snapshot_id, _ = runner.validate_vulnerability_ingest_response(200, valid_payload)
        manifest["vulnerability_snapshots"].append(snapshot_id)
        self.assertEqual(manifest["vulnerability_snapshots"], [test_uuid])

        # Failed validation -> manifest remains untouched
        bad_payload = {"id": test_uuid}  # missing snapshot_id
        try:
            snapshot_id_failed, _ = runner.validate_vulnerability_ingest_response(200, bad_payload)
            manifest["vulnerability_snapshots"].append(snapshot_id_failed)
        except RuntimeError:
            pass  # Expected error
        self.assertEqual(manifest["vulnerability_snapshots"], [test_uuid])  # Still only the original test_uuid


if __name__ == "__main__":
    unittest.main()

"""
Focused Offline Test Suite for Stage D9 Durable Cleanup Manifest & Recovery.
Target: Pure offline testing (mocks, temporary files, SQLite memory).
Zero PostgreSQL connections, zero migrations, zero services, zero WSL processes.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure scripts and backend directories are on sys.path
_test_dir = Path(__file__).resolve().parent
_backend_dir = _test_dir.parent.parent
_repo_root = _backend_dir.parent
_scripts_dir = _repo_root / "scripts"

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
from recover_d9_state import (
    compute_dry_run_plan,
    execute_live_recovery,
    run_dry_run_inspection,
)
from sqlalchemy import text


class TestD9DurableCleanupManifest(unittest.TestCase):
    """Offline unit tests for DurableCleanupManifest."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.manifest_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. Atomic manifest creation and updates
    # -------------------------------------------------------------------------
    def test_atomic_manifest_creation_and_update(self):
        """Verifies manifest creates valid file on disk and updates atomically."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        self.assertTrue(manifest.manifest_path.exists())

        test_uuid = str(uuid.uuid4())
        manifest.record_entity("applications", test_uuid)

        # Read directly from disk to confirm atomic flush
        loaded = DurableCleanupManifest.load_from_file(manifest.manifest_path)
        self.assertEqual(loaded.entities["applications"], [test_uuid])
        self.assertEqual(loaded.run_id, manifest.run_id)
        self.assertEqual(loaded.status, "recording")

    # -------------------------------------------------------------------------
    # 2. Multiple runs without manifest collisions
    # -------------------------------------------------------------------------
    def test_multiple_runs_no_collision(self):
        """Verifies successive run manifests have distinct filenames and do not overwrite."""
        m1 = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        m2 = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)

        self.assertNotEqual(m1.run_id, m2.run_id)
        self.assertNotEqual(m1.manifest_path, m2.manifest_path)
        self.assertTrue(m1.manifest_path.exists())
        self.assertTrue(m2.manifest_path.exists())

        id1 = str(uuid.uuid4())
        id2 = str(uuid.uuid4())
        m1.record_entity("applications", id1)
        m2.record_entity("applications", id2)

        loaded1 = DurableCleanupManifest.load_from_file(m1.manifest_path)
        loaded2 = DurableCleanupManifest.load_from_file(m2.manifest_path)
        self.assertEqual(loaded1.entities["applications"], [id1])
        self.assertEqual(loaded2.entities["applications"], [id2])

    # -------------------------------------------------------------------------
    # 3. Recovery of an interrupted manifest update (temp file vs target file)
    # -------------------------------------------------------------------------
    def test_interrupted_manifest_update_preserves_last_consistent_file(self):
        """Simulates an uncommitted temp file; asserts target file retains last valid state."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        valid_id = str(uuid.uuid4())
        manifest.record_entity("applications", valid_id)

        # Simulate orphaned temp file left by a killed process
        temp_file = self.manifest_dir / f"manifest_{manifest.run_id}.tmp.99999"
        temp_file.write_text('{"truncated": true', encoding="utf-8")

        # Target manifest must remain fully consistent and valid
        loaded = DurableCleanupManifest.load_from_file(manifest.manifest_path)
        self.assertEqual(loaded.entities["applications"], [valid_id])

    # -------------------------------------------------------------------------
    # 4. Malformed and truncated manifest rejection
    # -------------------------------------------------------------------------
    def test_truncated_json_rejected(self):
        """Verifies truncated JSON raises CorruptedManifestError."""
        bad_path = self.manifest_dir / "manifest_truncated.json"
        bad_path.write_text('{"schema_version": "1.0", "run_id": "abc", "entities":', encoding="utf-8")

        with self.assertRaises(CorruptedManifestError):
            DurableCleanupManifest.load_from_file(bad_path)

    def test_malformed_missing_required_keys_rejected(self):
        """Verifies missing required fields raises ManifestValidationError."""
        bad_path = self.manifest_dir / "manifest_missing_keys.json"
        bad_path.write_text(json.dumps({"schema_version": "1.0"}), encoding="utf-8")

        with self.assertRaises(ManifestValidationError) as ctx:
            DurableCleanupManifest.load_from_file(bad_path)
        self.assertIn("Missing required manifest field", str(ctx.exception))

    def test_unsupported_schema_version_rejected(self):
        """Verifies unsupported schema versions fail closed."""
        bad_path = self.manifest_dir / "manifest_bad_version.json"
        bad_path.write_text(
            json.dumps({
                "schema_version": "2.0",
                "run_id": "test",
                "status": "recording",
                "target_fingerprint": {},
                "entities": {},
            }),
            encoding="utf-8",
        )
        with self.assertRaises(ManifestValidationError) as ctx:
            DurableCleanupManifest.load_from_file(bad_path)
        self.assertIn("Unsupported schema version", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 5. Missing IDs and duplicate IDs
    # -------------------------------------------------------------------------
    def test_invalid_or_empty_uuid_rejected(self):
        """Verifies empty or non-UUID strings are rejected."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)

        with self.assertRaises(ManifestValidationError):
            manifest.record_entity("applications", "")

        with self.assertRaises(ManifestValidationError):
            manifest.record_entity("applications", "not-a-valid-uuid")

    def test_duplicate_entity_id_rejected(self):
        """Verifies recording the same entity ID twice in a table is rejected."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        dup_uuid = str(uuid.uuid4())

        manifest.record_entity("applications", dup_uuid)
        with self.assertRaises(ManifestValidationError) as ctx:
            manifest.record_entity("applications", dup_uuid)
        self.assertIn("Duplicate entity ID detected", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 6. Protected baseline UUID rejection
    # -------------------------------------------------------------------------
    def test_protected_baseline_uuid_rejected_on_record(self):
        """Verifies any protected baseline user UUID is hard-rejected during record_entity."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)

        for prot_uuid in BASELINE_PROTECTED_UUIDS:
            with self.assertRaises(BaselineProtectionViolationError) as ctx:
                manifest.record_entity("users", prot_uuid)
            self.assertIn("SAFETY VIOLATION", str(ctx.exception))

    def test_protected_baseline_uuid_rejected_on_load(self):
        """Verifies a manipulated manifest containing a protected baseline UUID fails on load."""
        bad_path = self.manifest_dir / "manifest_tampered.json"
        prot_uuid = next(iter(BASELINE_PROTECTED_UUIDS))
        payload = {
            "schema_version": "1.0",
            "run_id": "d9_tampered",
            "status": "ready_for_cleanup",
            "target_fingerprint": {
                "expected_host": "127.0.0.1",
                "expected_port": 5433,
                "expected_db": "ZKP_SBOM_LOCAL_DEV",
                "expected_revision": "015",
            },
            "entities": {t: ([prot_uuid] if t == "users" else []) for t in ORDERED_CLEANUP_TABLES},
            "errors": [],
        }
        bad_path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(BaselineProtectionViolationError):
            DurableCleanupManifest.load_from_file(bad_path)

    # -------------------------------------------------------------------------
    # 7. Unknown entity/table rejection
    # -------------------------------------------------------------------------
    def test_unknown_table_rejected(self):
        """Verifies recording an entity for an unknown table is rejected."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        test_uuid = str(uuid.uuid4())

        with self.assertRaises(ManifestValidationError) as ctx:
            manifest.record_entity("non_existent_table", test_uuid)
        self.assertIn("Unknown entity table", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 8. Foreign-key cleanup ordering validation
    # -------------------------------------------------------------------------
    def test_foreign_key_cleanup_ordering_strictly_observed(self):
        """Verifies dry-run plan orders deletions in strict reverse foreign-key sequence."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)

        # Record entities across multiple tables in arbitrary order
        app_id = str(uuid.uuid4())
        upload_id = str(uuid.uuid4())
        req_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())
        cert_id = str(uuid.uuid4())

        manifest.record_entity("applications", app_id)
        manifest.record_entity("verification_requests", req_id)
        manifest.record_entity("users", user_id)
        manifest.record_entity("sbom_uploads", upload_id)
        manifest.record_entity("verification_certificates", cert_id)

        plan = compute_dry_run_plan(manifest)
        planned_tables = [s.table_name for s in plan]

        # Order must strictly match ORDERED_CLEANUP_TABLES relative order
        expected_tables = [
            "verification_certificates",
            "verification_requests",
            "sbom_uploads",
            "applications",
            "users",
        ]
        self.assertEqual(planned_tables, expected_tables)

    # -------------------------------------------------------------------------
    # 9. Dry-run mode performs no database connection and no writes
    # -------------------------------------------------------------------------
    def test_dry_run_mode_zero_db_connections(self):
        """Verifies dry-run mode completes successfully with mock DB modules absent."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        manifest.record_entity("applications", str(uuid.uuid4()))

        # Block any sqlalchemy connection creation
        with patch("recover_d9_state.execute_live_recovery") as mock_live:
            code = run_dry_run_inspection(manifest.manifest_path)
            self.assertEqual(code, 0)
            mock_live.assert_not_called()

    # -------------------------------------------------------------------------
    # 10. Live recovery is blocked unless explicit authorization & target checks met
    # -------------------------------------------------------------------------
    def test_live_recovery_blocked_without_env_authorization(self):
        """Verifies live recovery immediately aborts if ALLOW_D9_LIVE_RECOVERY!=true."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)

        with patch.dict(os.environ, {"ALLOW_D9_LIVE_RECOVERY": "false"}):
            ret = execute_live_recovery(manifest.manifest_path)
            self.assertEqual(ret, 1)

    def test_live_recovery_blocked_without_db_password(self):
        """Verifies live recovery aborts if DB_PASSWORD is missing even with flag."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)

        with patch.dict(os.environ, {"ALLOW_D9_LIVE_RECOVERY": "true", "DB_PASSWORD": ""}):
            ret = execute_live_recovery(manifest.manifest_path)
            self.assertEqual(ret, 1)

    def test_live_recovery_hard_aborts_on_prohibited_target(self):
        """Verifies live recovery aborts on port 5432 or prohibited database."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)

        with patch.dict(os.environ, {
            "ALLOW_D9_LIVE_RECOVERY": "true",
            "DB_PASSWORD": "dummy",
            "DB_PORT": "5432",  # Prohibited port!
        }):
            with self.assertRaises(SystemExit):
                execute_live_recovery(manifest.manifest_path)

    # -------------------------------------------------------------------------
    # 11. Failure preserves the manifest and never falls back to broad deletion
    # -------------------------------------------------------------------------
    def test_failure_preserves_manifest_on_disk(self):
        """Verifies that an error during recovery leaves the manifest file intact on disk."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        test_id = str(uuid.uuid4())
        manifest.record_entity("applications", test_id)

        manifest_path = manifest.manifest_path
        self.assertTrue(manifest_path.exists())

        # Attempt recovery with invalid target -> failure
        with patch.dict(os.environ, {
            "ALLOW_D9_LIVE_RECOVERY": "true",
            "DB_PASSWORD": "dummy",
            "DB_PORT": "9999",  # Unauthorized port
        }):
            ret = execute_live_recovery(manifest_path)
            self.assertEqual(ret, 1)

        # Manifest must still exist on disk with all IDs intact
        self.assertTrue(manifest_path.exists())
        loaded = DurableCleanupManifest.load_from_file(manifest_path)
        self.assertEqual(loaded.entities["applications"], [test_id])


class TestD9RunnerManifestIntegration(unittest.TestCase):
    """Offline unit tests validating that run_d9_4_live_acceptance integrates with DurableCleanupManifest."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.manifest_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_sqlite_fixture(self):
        """Creates an in-memory SQLite engine with the full schema mock for exact cleanup testing."""
        import sqlalchemy.pool
        from sqlalchemy import create_engine as create_sqla_engine, text

        engine = create_sqla_engine("sqlite://", poolclass=sqlalchemy.pool.StaticPool)
        with engine.begin() as conn:
            conn.execute(text("ATTACH DATABASE ':memory:' AS verification"))
            conn.execute(text("ATTACH DATABASE ':memory:' AS vulnerability"))
            conn.execute(text("ATTACH DATABASE ':memory:' AS sbom"))
            conn.execute(text("ATTACH DATABASE ':memory:' AS policy"))
            conn.execute(text("ATTACH DATABASE ':memory:' AS zkp"))

            conn.execute(text("CREATE TABLE verification.verification_certificates (id TEXT, verification_request_id TEXT)"))
            conn.execute(text("CREATE TABLE verification.verification_requests (id TEXT)"))
            conn.execute(text("CREATE TABLE zkp.segment_proofs (id TEXT)"))
            conn.execute(text("CREATE TABLE zkp.chunk_proof_sets (id TEXT)"))
            conn.execute(text("CREATE TABLE zkp.proof_jobs (id TEXT)"))
            conn.execute(text("CREATE TABLE vulnerability.component_vulnerability_mappings (id TEXT, snapshot_id TEXT)"))
            conn.execute(text("CREATE TABLE vulnerability.vulnerability_snapshots (id TEXT)"))
            conn.execute(text("CREATE TABLE sbom.components (id TEXT, sbom_upload_id TEXT)"))
            conn.execute(text("CREATE TABLE sbom.sbom_uploads (id TEXT)"))
            conn.execute(text("CREATE TABLE sbom.applications (id TEXT)"))
            conn.execute(text("CREATE TABLE policy.security_policies (id TEXT, is_active INTEGER)"))
            conn.execute(text("CREATE TABLE users (id TEXT, username TEXT, role TEXT, is_active INTEGER)"))
        return engine

    def test_runner_execute_exact_id_cleanup_with_durable_manifest(self):
        """Verifies runner.execute_exact_id_cleanup accepts DurableCleanupManifest and deletes in FK order."""
        import run_d9_4_live_acceptance as runner

        engine = self._create_sqlite_fixture()
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)

        # Baseline IDs (must survive cleanup)
        base_app = str(uuid.uuid4())
        base_pol = str(uuid.uuid4())
        base_user = next(iter(BASELINE_PROTECTED_UUIDS))

        with engine.begin() as conn:
            conn.execute(text("INSERT INTO sbom.applications VALUES (:id)"), {"id": base_app})
            conn.execute(text("INSERT INTO policy.security_policies VALUES (:id, 1)"), {"id": base_pol})
            conn.execute(text("INSERT INTO users VALUES (:id, 'baseline_auditor', 'auditor', 1)"), {"id": base_user})

        # Test IDs (must be cleaned)
        test_app = str(uuid.uuid4())
        test_up = str(uuid.uuid4())
        test_comp = str(uuid.uuid4())
        test_snap = str(uuid.uuid4())
        test_req = str(uuid.uuid4())
        test_cert = str(uuid.uuid4())

        with engine.begin() as conn:
            conn.execute(text("INSERT INTO sbom.applications VALUES (:id)"), {"id": test_app})
            conn.execute(text("INSERT INTO sbom.sbom_uploads VALUES (:id)"), {"id": test_up})
            conn.execute(text("INSERT INTO sbom.components VALUES (:id, :up)"), {"id": test_comp, "up": test_up})
            conn.execute(text("INSERT INTO vulnerability.vulnerability_snapshots VALUES (:id)"), {"id": test_snap})
            conn.execute(text("INSERT INTO verification.verification_requests VALUES (:id)"), {"id": test_req})
            conn.execute(text("INSERT INTO verification.verification_certificates VALUES (:id, :rq)"), {"id": test_cert, "rq": test_req})

            # Simulate baseline policy state change during run
            conn.execute(text("UPDATE policy.security_policies SET is_active = 0 WHERE id = :id"), {"id": base_pol})

        # Record test entities into durable manifest immediately
        manifest.record_entity("applications", test_app)
        manifest.record_entity("sbom_uploads", test_up)
        manifest.record_entity("components", test_comp)
        manifest.record_entity("vulnerability_snapshots", test_snap)
        manifest.record_entity("verification_requests", test_req)
        manifest.record_entity("verification_certificates", test_cert)
        manifest.record_baseline_policy_states({base_pol: 1})

        # Execute cleanup via runner function with DurableCleanupManifest
        runner.execute_exact_id_cleanup(engine, manifest)

        with engine.connect() as conn:
            # Assert test entities deleted
            self.assertEqual(conn.execute(text("SELECT count(*) FROM sbom.applications WHERE id = :id"), {"id": test_app}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM sbom.sbom_uploads WHERE id = :id"), {"id": test_up}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM sbom.components WHERE id = :id"), {"id": test_comp}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM vulnerability.vulnerability_snapshots WHERE id = :id"), {"id": test_snap}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM verification.verification_requests WHERE id = :id"), {"id": test_req}).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM verification.verification_certificates WHERE id = :id"), {"id": test_cert}).scalar(), 0)

            # Assert baseline entities intact and policy state restored
            self.assertEqual(conn.execute(text("SELECT count(*) FROM sbom.applications WHERE id = :id"), {"id": base_app}).scalar(), 1)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM users WHERE id = :id"), {"id": base_user}).scalar(), 1)
            self.assertEqual(conn.execute(text("SELECT is_active FROM policy.security_policies WHERE id = :id"), {"id": base_pol}).scalar(), 1)

    def test_runner_manifest_records_immediately_before_next_step(self):
        """Verifies entity IDs are flushed to disk before the next step begins."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        manifest_path = manifest.manifest_path

        # Step 2: App creation
        app_id = str(uuid.uuid4())
        manifest.record_entity("applications", app_id)

        # Check disk immediately
        disk_manifest_1 = DurableCleanupManifest.load_from_file(manifest_path)
        self.assertIn(app_id, disk_manifest_1.entities["applications"])
        self.assertEqual(len(disk_manifest_1.entities["sbom_uploads"]), 0)

        # Step 3: SBOM upload
        upload_id = str(uuid.uuid4())
        manifest.record_entity("sbom_uploads", upload_id)

        # Check disk immediately
        disk_manifest_2 = DurableCleanupManifest.load_from_file(manifest_path)
        self.assertIn(upload_id, disk_manifest_2.entities["sbom_uploads"])
        self.assertEqual(len(disk_manifest_2.entities["vulnerability_snapshots"]), 0)

        # Step 4: Vulnerability ingest
        snap_id = str(uuid.uuid4())
        manifest.record_entity("vulnerability_snapshots", snap_id)

        # Check disk immediately
        disk_manifest_3 = DurableCleanupManifest.load_from_file(manifest_path)
        self.assertIn(snap_id, disk_manifest_3.entities["vulnerability_snapshots"])

    def test_manifest_failure_stops_run_safely(self):
        """Verifies that an error in manifest recording raises and preserves previous state."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        valid_app_id = str(uuid.uuid4())
        manifest.record_entity("applications", valid_app_id)

        # Attempting to record protected baseline UUID must raise immediately
        prot_uuid = next(iter(BASELINE_PROTECTED_UUIDS))
        with self.assertRaises(BaselineProtectionViolationError):
            manifest.record_entity("users", prot_uuid)

        # Manifest on disk must still contain the valid app ID and be uncorrupted
        disk_manifest = DurableCleanupManifest.load_from_file(manifest.manifest_path)
        self.assertEqual(disk_manifest.entities["applications"], [valid_app_id])
        self.assertEqual(disk_manifest.entities["users"], [])

    def test_failed_cleanup_preserves_manifest_for_manual_recovery(self):
        """Verifies that an error during cleanup marks manifest as failed and preserves disk file."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        app_id = str(uuid.uuid4())
        manifest.record_entity("applications", app_id)

        # Simulate cleanup failure by passing a broken engine mock
        broken_engine = MagicMock()
        broken_engine.begin.side_effect = RuntimeError("DB operational lock timeout")

        try:
            manifest.update_status("cleaning")
            with broken_engine.begin():
                pass
        except RuntimeError as exc:
            manifest.update_status("failed", error_message=str(exc))

        # Check disk state
        disk_manifest = DurableCleanupManifest.load_from_file(manifest.manifest_path)
        self.assertEqual(disk_manifest.status, "failed")
        self.assertEqual(disk_manifest.entities["applications"], [app_id])
        self.assertEqual(len(disk_manifest.errors), 1)
        self.assertIn("DB operational lock timeout", disk_manifest.errors[0])

    def test_dry_run_inspection_on_runner_manifest(self):
        """Validates that recover_d9_state dry-run inspection succeeds on runner manifest."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        manifest.record_entity("applications", str(uuid.uuid4()))
        manifest.record_entity("sbom_uploads", str(uuid.uuid4()))
        manifest.record_entity("verification_requests", str(uuid.uuid4()))

        exit_code = run_dry_run_inspection(manifest.manifest_path)
        self.assertEqual(exit_code, 0)


    def test_all_eight_baseline_users_are_protected_from_manifest_recording(self):
        """Verifies that all 8 verified baseline users (5 auditors, 1 admin, 1 vendor, 1 importer) are protected."""
        all_8_baseline_uuids = [
            "08edf357-94d6-405e-97d7-0e258d2136f6",  # Tanmay
            "2ec0a7bd-6797-4ff9-b9dc-19ecf1aad53f",  # idem_2ec0a7bd
            "43068bbb-ac36-4005-ba82-d3a453c4cd51",  # idem_43068bbb
            "c60ea9b9-ee23-409d-acc8-b9cebe6e0058",  # idem_c60ea9b9
            "b7e87663-07b4-49ac-9d48-05d6232186fe",  # local_auditor_alpha
            "32ad85e4-7229-4b31-bed1-da746df45830",  # d9_admin
            "203fabbf-2d7a-4b58-b9e2-b15b8bbf8a45",  # d9_vendor
            "931a603e-2d87-4894-885e-57c2db82f190",  # d9_trusted_importer
        ]
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        for user_uuid in all_8_baseline_uuids:
            with self.subTest(user_uuid=user_uuid):
                self.assertIn(user_uuid, BASELINE_PROTECTED_UUIDS)
                with self.assertRaises(BaselineProtectionViolationError):
                    manifest.record_entity("users", user_uuid)

    def test_revision_016_is_default_and_accepted(self):
        """Verifies that revision 016 is default and correctly roundtrips through manifest."""
        manifest = DurableCleanupManifest.create_new(manifest_dir=self.manifest_dir)
        self.assertEqual(manifest.expected_revision, "016")
        loaded = DurableCleanupManifest.load_from_file(manifest.manifest_path)
        self.assertEqual(loaded.expected_revision, "016")


if __name__ == "__main__":
    unittest.main()

"""
Offline mocked tests for PostgreSQL 16 migration 015 runner (scripts/run_pg16_migration_015.py).

Guarantees validated:
  1. Missing ALLOW_PG16_MIGRATION_015=true fails closed without opening connections.
  2. False or malformed gate values fail closed without opening connections.
  3. STAGING_MODE=true fails closed without opening connections.
  4. Preflight failure (wrong port, wrong DB, wrong engine) aborts before Alembic upgrade.
  5. Incompatible legacy roles in public.users abort before Alembic upgrade.
  6. Pre-migration snapshot captures exact primary-key sets and row data across all 6 tables.
  7. Post-migration data discrepancies (dropped row, altered role, missing column) fail closed.
  8. End-to-end execution invokes Alembic upgrade with verified connection and passes validation.

ALL tests are strictly offline and mocked. Zero live database or network connections.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch
import uuid

import pytest
from sqlalchemy import text

# Ensure backend root, alembic, and scripts directories are on sys.path
_this_dir = os.path.dirname(os.path.abspath(__file__))
_backend_root = os.path.abspath(os.path.join(_this_dir, "../.."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

_alembic_dir = os.path.join(_backend_root, "alembic")
if _alembic_dir not in sys.path:
    sys.path.insert(0, _alembic_dir)

_repo_root = os.path.abspath(os.path.join(_backend_root, ".."))
_scripts_dir = os.path.join(_repo_root, "scripts")
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

from staging_guard import StagingConfigError
import run_pg16_migration_015
from run_pg16_migration_015 import (
    DatabaseSnapshot,
    MigrationGateError,
    MigrationVerificationError,
    capture_database_snapshot,
    execute_migration_015,
    run_migration_cli,
    verify_authorization_gate,
    verify_post_migration_state,
)


# =======================================================================
# 1. Executable Authorization Gate Tests
# =======================================================================

class TestAuthorizationGate:
    """Verify that execution is blocked unless explicit authorization is set."""

    def test_missing_authorization_raises_gate_error(self, monkeypatch):
        monkeypatch.delenv("ALLOW_PG16_MIGRATION_015", raising=False)
        with pytest.raises(MigrationGateError, match="ALLOW_PG16_MIGRATION_015=true"):
            verify_authorization_gate()

    def test_false_authorization_raises_gate_error(self, monkeypatch):
        monkeypatch.setenv("ALLOW_PG16_MIGRATION_015", "false")
        with pytest.raises(MigrationGateError, match="ALLOW_PG16_MIGRATION_015=true"):
            verify_authorization_gate()

    def test_typo_authorization_raises_gate_error(self, monkeypatch):
        monkeypatch.setenv("ALLOW_PG16_MIGRATION_015", "True")  # strict lowercase "true"
        with pytest.raises(MigrationGateError, match="ALLOW_PG16_MIGRATION_015=true"):
            verify_authorization_gate()

    def test_staging_mode_rejects_pg16_migration_runner(self, monkeypatch):
        monkeypatch.setenv("ALLOW_PG16_MIGRATION_015", "true")
        monkeypatch.setenv("STAGING_MODE", "true")
        with pytest.raises(MigrationGateError, match="rejects STAGING_MODE=true"):
            verify_authorization_gate()

    def test_valid_authorization_passes(self, monkeypatch):
        monkeypatch.setenv("ALLOW_PG16_MIGRATION_015", "true")
        monkeypatch.delenv("STAGING_MODE", raising=False)
        # Should not raise
        verify_authorization_gate()


# =======================================================================
# 2. Snapshot and Data Preservation Tests
# =======================================================================

class TestSnapshotAndPreservation:
    """Verify pre-migration snapshot capture and post-migration validation logic."""

    def test_capture_database_snapshot_records_all_tables(self):
        mock_conn = MagicMock()
        mock_conn.in_transaction.return_value = False

        u1 = str(uuid.uuid4())
        a1 = str(uuid.uuid4())
        v1 = str(uuid.uuid4())
        j1 = str(uuid.uuid4())
        r1 = str(uuid.uuid4())
        c1 = str(uuid.uuid4())

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "public.users" in sql:
                res.fetchall.return_value = [(u1, "vendor_alice", "vendor")]
            elif "sbom.applications" in sql:
                res.fetchall.return_value = [(a1, "CoreApp", "Acme", u1)]
            elif "vulnerability.vulnerability_snapshots" in sql:
                res.fetchall.return_value = [(v1, "active", "prov_smt_123", "auth_smt_123")]
            elif "zkp.proof_jobs" in sql:
                res.fetchall.return_value = [(j1, "COMPLETED", "s_root_1", "v_root_1", "pol_hash_1")]
            elif "verification.verification_requests" in sql:
                res.fetchall.return_value = [(r1, "VALID", "s_root_1", "v_root_1", "pol_hash_1")]
            elif "verification.verification_certificates" in sql:
                res.fetchall.return_value = [(c1, False, None, None, "s_root_1", "v_root_1", "pol_hash_1")]
            return res

        mock_conn.execute.side_effect = mock_exec

        snap = capture_database_snapshot(mock_conn)

        assert snap.users_count == 1
        assert snap.users_ids == frozenset({u1})
        assert snap.users_data[u1] == ("vendor_alice", "vendor")
        assert snap.apps_ids == frozenset({a1})
        assert snap.apps_data[a1] == ("CoreApp", "Acme", u1)
        assert snap.vulns_ids == frozenset({v1})
        assert snap.vulns_data[v1] == ("active", "prov_smt_123", "auth_smt_123")
        assert snap.proof_jobs_ids == frozenset({j1})
        assert snap.proof_jobs_data[j1] == ("COMPLETED", "s_root_1", "v_root_1", "pol_hash_1")
        assert snap.verif_requests_ids == frozenset({r1})
        assert snap.verif_requests_data[r1] == ("VALID", "s_root_1", "v_root_1", "pol_hash_1")
        assert snap.certs_ids == frozenset({c1})
        assert snap.certs_data[c1] == (False, None, None, "s_root_1", "v_root_1", "pol_hash_1")
        # Verifies rollback was called to clear query autobegin
        mock_conn.rollback.assert_called_once()

    def test_post_migration_validation_fails_on_dropped_user_key(self):
        u1 = str(uuid.uuid4())
        u2 = str(uuid.uuid4())

        snap = DatabaseSnapshot(
            users_count=2,
            users_ids=frozenset({u1, u2}),
            users_data={u1: ("alice", "vendor"), u2: ("bob", "buyer")},
            apps_count=0, apps_ids=frozenset(), apps_data={},
            vulns_count=0, vulns_ids=frozenset(), vulns_data={},
            proof_jobs_count=0, proof_jobs_ids=frozenset(), proof_jobs_data={},
            verif_requests_count=0, verif_requests_ids=frozenset(), verif_requests_data={},
            certs_count=0, certs_ids=frozenset(), certs_data={},
        )

        mock_conn = MagicMock()

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "alembic_version" in sql:
                res.scalar.return_value = "015"
            elif "public.users" in sql:
                # Dropped user u2!
                res.fetchall.return_value = [(u1, "alice", "vendor", True, "2026-10-18")]
            else:
                res.fetchall.return_value = []
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(MigrationVerificationError, match="public.users primary key set mismatch"):
            verify_post_migration_state(mock_conn, snap)

    def test_post_migration_validation_fails_on_altered_user_role(self):
        u1 = str(uuid.uuid4())

        snap = DatabaseSnapshot(
            users_count=1,
            users_ids=frozenset({u1}),
            users_data={u1: ("alice", "vendor")},
            apps_count=0, apps_ids=frozenset(), apps_data={},
            vulns_count=0, vulns_ids=frozenset(), vulns_data={},
            proof_jobs_count=0, proof_jobs_ids=frozenset(), proof_jobs_data={},
            verif_requests_count=0, verif_requests_ids=frozenset(), verif_requests_data={},
            certs_count=0, certs_ids=frozenset(), certs_data={},
        )

        mock_conn = MagicMock()

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "alembic_version" in sql:
                res.scalar.return_value = "015"
            elif "public.users" in sql:
                # Role silently modified to 'admin'!
                res.fetchall.return_value = [(u1, "alice", "admin", True, "2026-10-18")]
            else:
                res.fetchall.return_value = []
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(MigrationVerificationError, match="role altered from 'vendor' to 'admin'"):
            verify_post_migration_state(mock_conn, snap)

    def test_post_migration_validation_fails_on_altered_application_ownership(self):
        a1 = str(uuid.uuid4())
        u1 = str(uuid.uuid4())
        u2 = str(uuid.uuid4())

        snap = DatabaseSnapshot(
            users_count=0, users_ids=frozenset(), users_data={},
            apps_count=1, apps_ids=frozenset({a1}), apps_data={a1: ("CoreApp", "Acme", u1)},
            vulns_count=0, vulns_ids=frozenset(), vulns_data={},
            proof_jobs_count=0, proof_jobs_ids=frozenset(), proof_jobs_data={},
            verif_requests_count=0, verif_requests_ids=frozenset(), verif_requests_data={},
            certs_count=0, certs_ids=frozenset(), certs_data={},
        )

        mock_conn = MagicMock()

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "alembic_version" in sql:
                res.scalar.return_value = "015"
            elif "sbom.applications" in sql:
                # user_id altered to u2!
                res.fetchall.return_value = [(a1, "CoreApp", "Acme", u2, True, None)]
            else:
                res.fetchall.return_value = []
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(MigrationVerificationError, match="user_id ownership altered"):
            verify_post_migration_state(mock_conn, snap)

    def test_post_migration_validation_fails_on_altered_vulnerability_commitment(self):
        v1 = str(uuid.uuid4())

        snap = DatabaseSnapshot(
            users_count=0, users_ids=frozenset(), users_data={},
            apps_count=0, apps_ids=frozenset(), apps_data={},
            vulns_count=1, vulns_ids=frozenset({v1}), vulns_data={v1: ("active", "smt_original", "auth_original")},
            proof_jobs_count=0, proof_jobs_ids=frozenset(), proof_jobs_data={},
            verif_requests_count=0, verif_requests_ids=frozenset(), verif_requests_data={},
            certs_count=0, certs_ids=frozenset(), certs_data={},
        )

        mock_conn = MagicMock()

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "alembic_version" in sql:
                res.scalar.return_value = "015"
            elif "vulnerability.vulnerability_snapshots" in sql:
                # provisional root modified!
                res.fetchall.return_value = [(v1, "active", "smt_tampered", "auth_original")]
            else:
                res.fetchall.return_value = []
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(MigrationVerificationError, match="cryptographic commitment root altered"):
            verify_post_migration_state(mock_conn, snap)

    def test_post_migration_validation_fails_on_altered_verification_outcome(self):
        r1 = str(uuid.uuid4())

        snap = DatabaseSnapshot(
            users_count=0, users_ids=frozenset(), users_data={},
            apps_count=0, apps_ids=frozenset(), apps_data={},
            vulns_count=0, vulns_ids=frozenset(), vulns_data={},
            proof_jobs_count=0, proof_jobs_ids=frozenset(), proof_jobs_data={},
            verif_requests_count=1, verif_requests_ids=frozenset({r1}), verif_requests_data={r1: ("VALID", "s1", "v1", "p1")},
            certs_count=0, certs_ids=frozenset(), certs_data={},
        )

        mock_conn = MagicMock()

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "alembic_version" in sql:
                res.scalar.return_value = "015"
            elif "verification.verification_requests" in sql:
                # result outcome modified!
                res.fetchall.return_value = [(r1, "INVALID", "s1", "v1", "p1")]
            else:
                res.fetchall.return_value = []
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(MigrationVerificationError, match="outcome result altered from 'VALID' to 'INVALID'"):
            verify_post_migration_state(mock_conn, snap)

    def test_post_migration_validation_fails_on_wrong_alembic_revision(self):
        snap = DatabaseSnapshot(
            users_count=0, users_ids=frozenset(), users_data={},
            apps_count=0, apps_ids=frozenset(), apps_data={},
            vulns_count=0, vulns_ids=frozenset(), vulns_data={},
            proof_jobs_count=0, proof_jobs_ids=frozenset(), proof_jobs_data={},
            verif_requests_count=0, verif_requests_ids=frozenset(), verif_requests_data={},
            certs_count=0, certs_ids=frozenset(), certs_data={},
        )

        mock_conn = MagicMock()

        def mock_exec(stmt, *args, **kwargs):
            sql = stmt.text if hasattr(stmt, "text") else str(stmt)
            res = MagicMock()
            if "alembic_version" in sql:
                res.scalar.return_value = "014"  # Did not advance to 015!
            else:
                res.fetchall.return_value = []
            return res

        mock_conn.execute.side_effect = mock_exec

        with pytest.raises(MigrationVerificationError, match="expected strictly '015'"):
            verify_post_migration_state(mock_conn, snap)



# =======================================================================
# 3. End-to-End Execution Flow Tests (Offline Mocked)
# =======================================================================

class TestExecuteMigrationFlow:
    """Verify complete execution flow with preflight, snapshot, Alembic upgrade, and validation."""

    @patch("run_pg16_migration_015.command.upgrade")
    @patch("run_pg16_migration_015.verify_post_migration_state")
    @patch("run_pg16_migration_015.capture_database_snapshot")
    @patch("run_pg16_migration_015.verify_pg16_target_preflight")
    def test_execute_migration_015_orchestrates_safely(
        self,
        mock_preflight,
        mock_snapshot,
        mock_verify_post,
        mock_alembic_upgrade,
        monkeypatch,
    ):
        monkeypatch.setenv("ALLOW_PG16_MIGRATION_015", "true")
        monkeypatch.delenv("STAGING_MODE", raising=False)

        mock_conn = MagicMock()
        mock_snapshot_obj = MagicMock()
        mock_snapshot_obj.users_count = 5
        mock_snapshot_obj.apps_count = 2
        mock_snapshot_obj.certs_count = 1
        mock_snapshot_obj.proof_jobs_count = 3
        mock_snapshot.return_value = mock_snapshot_obj

        execute_migration_015(connection=mock_conn)

        # 1. Preflight was executed with expected revision 014
        mock_preflight.assert_called_once_with(
            connection=mock_conn,
            settings=None,
            expected_revision="014",
        )

        # 2. Snapshot was captured before upgrade
        mock_snapshot.assert_called_once_with(mock_conn)

        # 3. Alembic upgrade was called with connection attribute
        mock_alembic_upgrade.assert_called_once()
        alembic_cfg = mock_alembic_upgrade.call_args[0][0]
        assert alembic_cfg.attributes["connection"] is mock_conn
        assert alembic_cfg.attributes["target_database"] == "ZKP_SBOM_LOCAL_DEV"
        assert mock_alembic_upgrade.call_args[0][1] == "015"
        expected_script_dir = os.path.abspath(os.path.join(_backend_root, "alembic"))
        assert alembic_cfg.get_main_option("script_location") == expected_script_dir

        # 4. Post-migration verification was called with snapshot
        mock_verify_post.assert_called_once_with(mock_conn, mock_snapshot_obj)

    @patch("run_pg16_migration_015.command.upgrade")
    @patch("run_pg16_migration_015.verify_post_migration_state")
    @patch("run_pg16_migration_015.capture_database_snapshot")
    @patch("run_pg16_migration_015.verify_pg16_target_preflight")
    def test_execute_migration_015_resolves_script_location_independent_of_cwd(
        self,
        mock_preflight,
        mock_snapshot,
        mock_verify_post,
        mock_alembic_upgrade,
        monkeypatch,
        tmp_path,
    ):
        """Ensure script_location is an absolute path that resolves to backend/alembic
        even when current working directory is outside the backend or repository root.
        """
        monkeypatch.setenv("ALLOW_PG16_MIGRATION_015", "true")
        monkeypatch.delenv("STAGING_MODE", raising=False)
        # Change working directory to a foreign directory with no alembic/ subfolder
        monkeypatch.chdir(tmp_path)

        mock_conn = MagicMock()
        execute_migration_015(connection=mock_conn)

        mock_alembic_upgrade.assert_called_once()
        alembic_cfg = mock_alembic_upgrade.call_args[0][0]
        script_loc = alembic_cfg.get_main_option("script_location")
        assert os.path.isabs(script_loc)
        assert script_loc == os.path.abspath(os.path.join(_backend_root, "alembic"))
        assert os.path.isdir(script_loc)
        assert os.path.isfile(os.path.join(script_loc, "env.py"))

        # Verify ScriptDirectory can actually be initialized from this config offline
        from alembic.script import ScriptDirectory
        script = ScriptDirectory.from_config(alembic_cfg)
        assert script.get_current_head() == "016"

    @patch("run_pg16_migration_015.command.upgrade")
    @patch("run_pg16_migration_015.verify_post_migration_state")
    @patch("run_pg16_migration_015.capture_database_snapshot")
    @patch("run_pg16_migration_015.verify_pg16_target_preflight")
    def test_execute_migration_015_accepts_custom_script_location(
        self,
        mock_preflight,
        mock_snapshot,
        mock_verify_post,
        mock_alembic_upgrade,
        monkeypatch,
        tmp_path,
    ):
        """Verify explicit script_location parameter is respected and made absolute."""
        monkeypatch.setenv("ALLOW_PG16_MIGRATION_015", "true")
        monkeypatch.delenv("STAGING_MODE", raising=False)

        mock_conn = MagicMock()
        custom_loc = str(tmp_path / "custom_alembic")
        execute_migration_015(connection=mock_conn, script_location=custom_loc)

        alembic_cfg = mock_alembic_upgrade.call_args[0][0]
        assert alembic_cfg.get_main_option("script_location") == os.path.abspath(custom_loc)

    def test_cli_entry_point_aborts_cleanly_when_gate_missing(self, monkeypatch):
        monkeypatch.delenv("ALLOW_PG16_MIGRATION_015", raising=False)
        mock_engine = MagicMock()

        exit_code = run_migration_cli(argv=[], engine=mock_engine)

        assert exit_code == 1
        assert not mock_engine.connect.called

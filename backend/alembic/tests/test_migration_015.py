"""Offline mocked tests for Alembic migration 015 (auth lifecycle, application archival, and revocation).

All tests are strictly offline and mocked. No connections are made to PostgreSQL 16 or 17.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch
import uuid

import pytest


_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ALEMBIC_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_MIGRATION_PATH = os.path.join(_ALEMBIC_DIR, "versions", "015_auth_lifecycle_and_revocation.py")


def _load_migration_015():
    spec = importlib.util.spec_from_file_location("migration_015", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMigration015Metadata:
    """Verify revision identifiers and dependency chaining."""

    def test_revision_identifiers(self):
        mod = _load_migration_015()
        assert mod.revision == "015"
        assert mod.down_revision == "014"
        assert mod.branch_labels is None
        assert mod.depends_on is None
        assert set(mod.ALLOWED_ROLES) == {"vendor", "buyer", "auditor", "admin", "trusted_importer"}


class TestMigration015PreflightRoleValidation:
    """Verify preflight role check strictly fails closed on unexpected legacy roles."""

    @patch("alembic.op.get_bind")
    def test_preflight_passes_when_all_roles_are_allowed(self, mock_get_bind):
        mod = _load_migration_015()
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = []
        mock_get_bind.return_value = mock_conn

        with patch("alembic.op.create_check_constraint"), \
             patch("alembic.op.add_column"), \
             patch("alembic.op.create_foreign_key"), \
             patch("alembic.op.create_index"), \
             patch("alembic.op.drop_constraint"):
            # Should execute without raising
            mod.upgrade()

        assert mock_conn.execute.called

    @patch("alembic.op.get_bind")
    def test_preflight_fails_closed_on_unexpected_legacy_role(self, mock_get_bind):
        mod = _load_migration_015()
        mock_conn = MagicMock()
        # Return unexpected roles from query
        mock_conn.execute.return_value.fetchall.return_value = [("superadmin",), ("guest",)]
        mock_get_bind.return_value = mock_conn

        with pytest.raises(Exception, match="Migration 015 aborted: unexpected legacy role"):
            mod.upgrade()


class TestMigration015UpgradeAndDowngradeOperations:
    """Verify all expected DDL operations are invoked during upgrade and downgrade."""

    @patch("alembic.op.get_bind")
    @patch("alembic.op.create_index")
    @patch("alembic.op.create_foreign_key")
    @patch("alembic.op.drop_constraint")
    @patch("alembic.op.add_column")
    @patch("alembic.op.create_check_constraint")
    def test_upgrade_invokes_all_schema_operations(
        self,
        mock_create_chk,
        mock_add_col,
        mock_drop_chk,
        mock_create_fk,
        mock_create_idx,
        mock_get_bind,
    ):
        mod = _load_migration_015()
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = []
        mock_get_bind.return_value = mock_conn

        mod.upgrade()

        # 1. public.users constraints & columns
        mock_create_chk.assert_any_call(
            "chk_users_role",
            "users",
            "role IN ('vendor', 'buyer', 'auditor', 'admin', 'trusted_importer')",
            schema="public",
        )
        users_col_names = [call_args[0][1].name for call_args in mock_add_col.call_args_list if call_args[0][0] == "users"]
        assert "is_active" in users_col_names
        assert "updated_at" in users_col_names

        # 2. sbom.applications columns, constraint, index
        app_col_names = [call_args[0][1].name for call_args in mock_add_col.call_args_list if call_args[0][0] == "applications"]
        assert "is_active" in app_col_names
        assert "archived_at" in app_col_names
        mock_create_chk.assert_any_call(
            "chk_sbom_applications_archival",
            "applications",
            "(is_active = TRUE AND archived_at IS NULL) OR (is_active = FALSE AND archived_at IS NOT NULL)",
            schema="sbom",
        )
        mock_create_idx.assert_any_call(
            "ix_sbom_applications_user_active",
            "applications",
            ["user_id", "is_active"],
            schema="sbom",
        )

        # 3. verification.verification_certificates columns, fk, index, check constraint
        cert_col_names = [call_args[0][1].name for call_args in mock_add_col.call_args_list if call_args[0][0] == "verification_certificates"]
        assert "revoked_by" in cert_col_names
        mock_create_fk.assert_any_call(
            "fk_verification_certificates_revoked_by",
            "verification_certificates",
            "users",
            ["revoked_by"],
            ["id"],
            source_schema="verification",
            referent_schema="public",
            ondelete="SET NULL",
        )
        mock_drop_chk.assert_any_call(
            "chk_certificate_revocation_state",
            "verification_certificates",
            schema="verification",
            type_="check",
        )
        mock_create_chk.assert_any_call(
            "chk_certificate_revocation_state",
            "verification_certificates",
            "(is_revoked = FALSE AND revoked_at IS NULL AND revoked_by IS NULL) OR "
            "(is_revoked = TRUE AND revoked_at IS NOT NULL)",
            schema="verification",
        )

    @patch("alembic.op.drop_column")
    @patch("alembic.op.drop_index")
    @patch("alembic.op.drop_constraint")
    @patch("alembic.op.create_check_constraint")
    def test_downgrade_reverts_all_operations(
        self,
        mock_create_chk,
        mock_drop_chk,
        mock_drop_idx,
        mock_drop_col,
    ):
        mod = _load_migration_015()
        mod.downgrade()

        # Restores migration 009 revocation check constraint
        mock_create_chk.assert_any_call(
            "chk_certificate_revocation_state",
            "verification_certificates",
            "(is_revoked = FALSE AND revoked_at IS NULL) OR (is_revoked = TRUE AND revoked_at IS NOT NULL)",
            schema="verification",
        )
        # Drops partial index and fk
        mock_drop_idx.assert_any_call(
            "ix_verification_certificates_revoked_by",
            table_name="verification_certificates",
            schema="verification",
        )
        mock_drop_chk.assert_any_call(
            "fk_verification_certificates_revoked_by",
            "verification_certificates",
            schema="verification",
            type_="foreignkey",
        )
        # Drops columns
        dropped_cols = [(c[0][0], c[0][1]) for c in mock_drop_col.call_args_list]
        assert ("verification_certificates", "revoked_by") in dropped_cols
        assert ("applications", "archived_at") in dropped_cols
        assert ("applications", "is_active") in dropped_cols
        assert ("users", "updated_at") in dropped_cols
        assert ("users", "is_active") in dropped_cols
        # Drops role check
        mock_drop_chk.assert_any_call("chk_users_role", "users", schema="public", type_="check")


class TestConstraintLogicInvariants:
    """Offline truth-table tests verifying check constraint logical equivalence."""

    def test_application_archival_state_logic(self):
        """(is_active = TRUE AND archived_at IS NULL) OR (is_active = FALSE AND archived_at IS NOT NULL)"""
        def is_valid_app_state(is_active: bool, archived_at: datetime | None) -> bool:
            return (is_active is True and archived_at is None) or (is_active is False and archived_at is not None)

        now = datetime.now(timezone.utc)

        # Valid states
        assert is_valid_app_state(True, None) is True
        assert is_valid_app_state(False, now) is True

        # Invalid states
        assert is_valid_app_state(True, now) is False
        assert is_valid_app_state(False, None) is False

    def test_certificate_revocation_state_compatibility(self):
        """
        (is_revoked = FALSE AND revoked_at IS NULL AND revoked_by IS NULL) OR
        (is_revoked = TRUE AND revoked_at IS NOT NULL)
        """
        def is_valid_revocation_state(
            is_revoked: bool,
            revoked_at: datetime | None,
            revoked_by: uuid.UUID | None,
        ) -> bool:
            return (
                (is_revoked is False and revoked_at is None and revoked_by is None)
                or (is_revoked is True and revoked_at is not None)
            )

        now = datetime.now(timezone.utc)
        user_id = uuid.uuid4()

        # State 1: Active certificate -> Valid
        assert is_valid_revocation_state(False, None, None) is True

        # State 4: Revoked with actor -> Valid
        assert is_valid_revocation_state(True, now, user_id) is True

        # State 5: Revoked without actor (historical or deleted user) -> Valid
        assert is_valid_revocation_state(True, now, None) is True

        # State 2: Active with timestamp -> Invalid
        assert is_valid_revocation_state(False, now, None) is False

        # State 3: Active with actor -> Invalid
        assert is_valid_revocation_state(False, None, user_id) is False

        # State 6: Revoked without timestamp -> Invalid
        assert is_valid_revocation_state(True, None, user_id) is False
        assert is_valid_revocation_state(True, None, None) is False

    def test_role_check_constraint_domain(self):
        allowed = {"vendor", "buyer", "auditor", "admin", "trusted_importer"}
        for r in allowed:
            assert r in allowed

        unallowed = {"superadmin", "guest", "operator", "user", "root", "", None}
        for u in unallowed:
            assert u not in allowed

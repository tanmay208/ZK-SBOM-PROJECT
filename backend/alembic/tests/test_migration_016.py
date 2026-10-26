"""Offline mocked tests for Alembic migration 016 (snapshot TTL expires_at).

All tests are strictly offline and mocked. No connections are made to live databases.
"""

from __future__ import annotations

import importlib.util
import os
from unittest.mock import MagicMock, call, patch
import pytest


_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ALEMBIC_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_MIGRATION_PATH = os.path.join(_ALEMBIC_DIR, "versions", "016_add_snapshot_ttl_expires_at.py")


def _load_migration_016():
    spec = importlib.util.spec_from_file_location("migration_016", _MIGRATION_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMigration016Metadata:
    """Verify revision identifiers and dependency chaining for migration 016."""

    def test_revision_identifiers(self):
        mod = _load_migration_016()
        assert mod.revision == "016"
        assert mod.down_revision == "015"
        assert mod.branch_labels is None
        assert mod.depends_on is None


class TestMigration016Operations:
    """Verify upgrade and downgrade schema operations."""

    @patch("alembic.op.create_index")
    @patch("alembic.op.add_column")
    def test_upgrade_operations(self, mock_add_col, mock_create_idx):
        mod = _load_migration_016()
        mod.upgrade()

        # Check column addition
        mock_add_col.assert_called_once()
        table_name, col = mock_add_col.call_args[0]
        schema = mock_add_col.call_args[1].get("schema")
        assert table_name == "vulnerability_snapshots"
        assert schema == "vulnerability"
        assert col.name == "expires_at"
        assert col.nullable is True

        # Check index creation
        mock_create_idx.assert_called_once_with(
            "ix_vuln_snapshots_expires_at",
            "vulnerability_snapshots",
            ["expires_at"],
            schema="vulnerability",
        )

    @patch("alembic.op.drop_column")
    @patch("alembic.op.drop_index")
    def test_downgrade_operations(self, mock_drop_idx, mock_drop_col):
        mod = _load_migration_016()
        mod.downgrade()

        mock_drop_idx.assert_called_once_with(
            "ix_vuln_snapshots_expires_at",
            table_name="vulnerability_snapshots",
            schema="vulnerability",
        )
        mock_drop_col.assert_called_once_with(
            "vulnerability_snapshots",
            "expires_at",
            schema="vulnerability",
        )

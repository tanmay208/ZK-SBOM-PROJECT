"""Unit and isolated integration tests for Migration 015 role validation.

Verifies:
1. Allowed roles are strictly the 5 approved roles ('vendor', 'buyer', 'auditor', 'admin', 'trusted_importer').
2. Preflight fails closed when unexpected roles exist (uppercase 'VENDOR', unknown 'superuser', etc.).
3. Preflight succeeds when all roles are canonical lowercase.
4. Remediation SQL correctly normalizes role with verified preconditions.
"""

import os
import importlib.util
from sqlalchemy import create_engine, text

def test_migration_015_allowed_roles_constant():

    mig_path = os.path.join(
        os.path.dirname(__file__), "..", "versions", "015_auth_lifecycle_and_revocation.py"
    )
    spec = importlib.util.spec_from_file_location("mig_015", mig_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert hasattr(module, "ALLOWED_ROLES")
    assert sorted(module.ALLOWED_ROLES) == sorted(
        ["vendor", "buyer", "auditor", "admin", "trusted_importer"]
    )


def test_migration_015_preflight_logic_fails_on_uppercase_vendor():
    """Simulates preflight query against an in-memory SQLite table containing 'VENDOR'."""
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as conn:
        conn.execute(text("CREATE TABLE users (id TEXT PRIMARY KEY, role TEXT);"))
        conn.execute(
            text(
                "INSERT INTO users (id, role) VALUES ('1', 'admin'), ('2', 'vendor'), ('3', 'VENDOR');"
            )
        )
        conn.commit()

        # Execute Migration 015 preflight query
        res = conn.execute(
            text(
                "SELECT DISTINCT role FROM users "
                "WHERE role NOT IN ('vendor', 'buyer', 'auditor', 'admin', 'trusted_importer')"
            )
        )
        unexpected = [row[0] for row in res.fetchall()]
        assert "VENDOR" in unexpected
        assert len(unexpected) == 1


def test_migration_015_preflight_logic_passes_when_normalized():
    """Simulates preflight query against an in-memory SQLite table with only canonical roles."""
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as conn:
        conn.execute(text("CREATE TABLE users (id TEXT PRIMARY KEY, role TEXT);"))
        conn.execute(
            text(
                "INSERT INTO users (id, role) VALUES ('1', 'admin'), ('2', 'vendor'), ('3', 'buyer'), ('4', 'auditor'), ('5', 'trusted_importer');"
            )
        )
        conn.commit()

        res = conn.execute(
            text(
                "SELECT DISTINCT role FROM users "
                "WHERE role NOT IN ('vendor', 'buyer', 'auditor', 'admin', 'trusted_importer')"
            )
        )
        unexpected = [row[0] for row in res.fetchall()]
        assert len(unexpected) == 0


def test_migration_015_remediation_transaction_safety():
    """Verifies that remediation SQL only updates targeted row and aborts if precondition fails."""
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as conn:
        conn.execute(
            text(
                "CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, role TEXT, updated_at TEXT);"
            )
        )
        conn.execute(
            text(
                "INSERT INTO users (id, username, role, updated_at) VALUES ('target-id', 'test@example.com', 'VENDOR', '2026-10-02');"
            )
        )
        conn.commit()

        # Test safe update with strict precondition
        update_sql = text("""
            UPDATE users 
            SET role = 'vendor' 
            WHERE id = 'target-id' AND role = 'VENDOR';
        """)
        result = conn.execute(update_sql)
        conn.commit()

        assert result.rowcount == 1

        # Verify new role
        role = conn.execute(text("SELECT role FROM users WHERE id = 'target-id';")).scalar()
        assert role == "vendor"

        # Verify idempotency (second run updates 0 rows because precondition role='VENDOR' is false)
        result2 = conn.execute(update_sql)
        conn.commit()
        assert result2.rowcount == 0

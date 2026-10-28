"""Focused offline unit tests for shared.models.user.User ORM metadata and lifecycle fields (D2.1).

These tests run strictly offline with zero live database connections,
zero network I/O, and zero dependency on PostgreSQL 16 or PostgreSQL 17.
"""

from datetime import datetime, timezone
import socket
import uuid
import pytest
from sqlalchemy import Boolean, DateTime, String, Uuid
from sqlalchemy.dialects import postgresql, sqlite

from shared.models.user import User


@pytest.fixture(autouse=True)
def disallow_network_and_db(monkeypatch):
    """Enforce strict offline execution: any network or DB connection attempt fails closed."""
    def _blocked_connect(*args, **kwargs):
        raise RuntimeError("Database/network connection attempted in offline test suite!")

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)


def test_user_table_name_and_schema():
    """Verify table name and schema binding."""
    table = User.__table__
    assert table.name == "users"


def test_is_active_column_metadata():
    """Verify is_active column type, non-nullability, and defaults (migration 015 alignment)."""
    table = User.__table__
    assert "is_active" in table.columns, "Column 'is_active' missing from User.__table__"

    col = table.columns["is_active"]
    assert isinstance(col.type, Boolean), f"Expected Boolean type, got {type(col.type)}"
    assert col.nullable is False, "Column 'is_active' must be non-nullable (nullable=False)"

    # Python-side lifecycle default must be True
    assert col.default is not None, "Column 'is_active' must have a Python-side default"
    assert col.default.arg is True, f"Expected Python default True, got {col.default.arg}"

    # Server-side default must be present and compile to 'true' in PostgreSQL
    assert col.server_default is not None, "Column 'is_active' must have a server_default"
    pg_compiled = str(col.server_default.arg.compile(dialect=postgresql.dialect()))
    assert pg_compiled.lower() == "true", f"Expected server default 'true', got '{pg_compiled}'"


def test_updated_at_column_metadata():
    """Verify updated_at column type, non-nullability, creation default, update hook, and server default."""
    table = User.__table__
    assert "updated_at" in table.columns, "Column 'updated_at' missing from User.__table__"

    col = table.columns["updated_at"]
    assert isinstance(col.type, DateTime), f"Expected DateTime type, got {type(col.type)}"
    assert col.nullable is False, "Column 'updated_at' must be non-nullable (nullable=False)"

    # Python-side creation default: callable returning datetime
    assert col.default is not None, "Column 'updated_at' must have a creation default"
    assert col.default.is_callable, "Column 'updated_at' creation default must be callable"
    sample_dt = col.default.arg(None)
    assert isinstance(sample_dt, datetime), f"Expected datetime from default callable, got {type(sample_dt)}"

    # Python-side update hook (onupdate): callable returning datetime
    assert col.onupdate is not None, "Column 'updated_at' must have an onupdate hook"
    assert col.onupdate.is_callable, "Column 'updated_at' onupdate hook must be callable"
    sample_update_dt = col.onupdate.arg(None)
    assert isinstance(sample_update_dt, datetime), f"Expected datetime from onupdate callable, got {type(sample_update_dt)}"

    # Server-side default: CURRENT_TIMESTAMP matching migration 015
    assert col.server_default is not None, "Column 'updated_at' must have a server_default"
    server_default_text = str(col.server_default.arg.text if hasattr(col.server_default.arg, "text") else col.server_default.arg)
    assert "CURRENT_TIMESTAMP" in server_default_text.upper(), (
        f"Expected 'CURRENT_TIMESTAMP' in server default, got '{server_default_text}'"
    )


def test_existing_columns_unbroken():
    """Verify existing User columns (id, username, hashed_password, role, created_at) are preserved."""
    table = User.__table__
    expected_cols = {"id", "username", "hashed_password", "role", "created_at", "is_active", "updated_at"}
    actual_cols = set(table.columns.keys())
    assert actual_cols == expected_cols, f"Column set mismatch: expected {expected_cols}, got {actual_cols}"

    # id: Uuid primary key with callable default
    id_col = table.columns["id"]
    assert isinstance(id_col.type, Uuid)
    assert id_col.primary_key is True
    assert id_col.default is not None and id_col.default.is_callable
    generated_id = id_col.default.arg(None)
    assert isinstance(generated_id, uuid.UUID)

    # username: String(255), unique, non-nullable, indexed
    uname_col = table.columns["username"]
    assert isinstance(uname_col.type, String)
    assert uname_col.type.length >= 255
    assert uname_col.unique is True
    assert uname_col.nullable is False
    assert uname_col.index is True

    # hashed_password: String(255), non-nullable
    pw_col = table.columns["hashed_password"]
    assert isinstance(pw_col.type, String)
    assert pw_col.type.length >= 255
    assert pw_col.nullable is False

    # role: String(50), non-nullable, default is 'buyer' in Roadmap V3 Stage G2 (consolidated primary role)
    role_col = table.columns["role"]
    assert isinstance(role_col.type, String)
    assert role_col.type.length >= 50
    assert role_col.nullable is False
    assert role_col.default is not None
    assert role_col.default.arg == "buyer", (
        f"Roadmap V3 Stage G2 invariant: role default must be 'buyer' (got '{role_col.default.arg}')"
    )

    # created_at: DateTime with callable default
    created_col = table.columns["created_at"]
    assert isinstance(created_col.type, DateTime)
    assert created_col.default is not None and created_col.default.is_callable
    sample_created = created_col.default.arg(None)
    assert isinstance(sample_created, datetime)


def test_five_role_compatibility():
    """Verify all 5 authorized roles can be held by User instances without truncation or error."""
    authorized_roles = ("vendor", "buyer", "auditor", "admin", "trusted_importer")
    for role in authorized_roles:
        u = User(username=f"user_{role}", hashed_password="dummy_hash", role=role)
        assert u.role == role
        assert len(u.role) <= User.__table__.columns["role"].type.length


def test_stage_g2_primary_and_legacy_roles():
    """Verify Stage G2 primary and legacy roles are properly defined on user model."""
    from shared.models.user import PRIMARY_ROLES, LEGACY_ROLES, ALL_SUPPORTED_ROLES
    assert PRIMARY_ROLES == ("vendor", "buyer", "admin")
    assert LEGACY_ROLES == ("auditor", "trusted_importer")
    assert set(ALL_SUPPORTED_ROLES) == {"vendor", "buyer", "admin", "auditor", "trusted_importer"}


def test_user_instance_lifecycle_attributes():
    """Verify pure Python instantiation with lifecycle attributes without database access."""
    # Instantiation with explicit lifecycle values
    u1 = User(
        username="active_user",
        hashed_password="pw1",
        is_active=True,
    )
    assert u1.is_active is True
    assert u1.username == "active_user"

    # Instantiation with deactivated status
    u2 = User(
        username="deactivated_user",
        hashed_password="pw2",
        is_active=False,
    )
    assert u2.is_active is False

    # Instantiation with explicit timestamps
    now = datetime.now(timezone.utc)
    u3 = User(
        username="timestamped_user",
        hashed_password="pw3",
        created_at=now,
        updated_at=now,
    )
    assert u3.created_at == now
    assert u3.updated_at == now

import pytest
import re
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from policy_service.app.models.policy_models import Base, SecurityPolicy
from policy_service.app.services.policy_service import create_policy, activate_policy, POLICY_MUTATION_LOCK_ID
from shared.crypto.poseidon_bn254 import poseidon_hash

class MockSession:
    def query(self, *args, **kwargs):
        class MockQuery:
            def update(self, *args, **kwargs): pass
            def filter_by(self, *args, **kwargs): return self
            def first(self): return None
        return MockQuery()
    def add(self, *args, **kwargs): pass
    def commit(self, *args, **kwargs): pass
    def refresh(self, obj, *args, **kwargs):
        obj.id = "mock-id"

@pytest.fixture(scope="function")
def db_session():
    return MockSession()

def test_policy_hash_canonicalization(db_session):
    # Test valid cvss
    max_cvss = 7.0
    policy = create_policy(db_session, max_cvss)
    
    # 1. Verify exactly 66 characters
    assert len(policy.policy_hash) == 66, f"Expected length 66, got {len(policy.policy_hash)}"
    
    # 2. Verify begins with 0x and has 64 hex digits
    assert re.match(r"^0x[a-fA-F0-9]{64}$", policy.policy_hash), "Hash does not match strict 64-hex-digit format"
    
    # 3. Verify underlying integer value is preserved
    expected_int = poseidon_hash([int(round(max_cvss * 10))])
    stored_int = int(policy.policy_hash, 16)
    assert stored_int == expected_int, "Stored hash integer does not match original Poseidon hash"
    
    # 4. (Skipped DB persistence check since using mock session)

def test_policy_creation_invalid_value(db_session):
    # 5. Invalid or out-of-range values fail safely
    with pytest.raises(ValueError, match="between 0.0 and 10.0"):
        create_policy(db_session, -1.0)
    
    with pytest.raises(ValueError, match="between 0.0 and 10.0"):
        create_policy(db_session, 11.0)


def test_policy_creation_rollback_on_error():
    """Regression test: verify atomicity and rollback invocation on unexpected failure."""
    class FailingSession:
        def __init__(self):
            self.rolled_back = False
        def query(self, *args, **kwargs):
            class MockQuery:
                def update(self, *args, **kwargs):
                    raise RuntimeError("Simulated DB write failure during policy deactivation")
            return MockQuery()
        def rollback(self):
            self.rolled_back = True

    session = FailingSession()
    with pytest.raises(RuntimeError, match="Simulated DB write failure"):
        create_policy(session, 7.5)

    assert session.rolled_back is True, "Expected session.rollback() to be called on failure"


def test_policy_creation_advisory_lock_on_postgresql():
    """Regression test: verify advisory lock is dispatched when dialect is PostgreSQL."""
    class MockDialect:
        name = "postgresql"

    class MockBind:
        dialect = MockDialect()

    class PostgresSession:
        def __init__(self):
            self.bind = MockBind()
            self.executed_sql = []
        def execute(self, statement, params=None):
            self.executed_sql.append((str(statement), params))
        def query(self, *args, **kwargs):
            class MockQuery:
                def update(self, *args, **kwargs): pass
            return MockQuery()
        def add(self, obj): pass
        def commit(self): pass
        def refresh(self, obj):
            obj.id = "mock-pg-id"

    session = PostgresSession()
    policy = create_policy(session, 8.0)
    assert any("pg_advisory_xact_lock" in sql for sql, _ in session.executed_sql), (
        "Expected pg_advisory_xact_lock to be executed for PostgreSQL connections"
    )


def test_activate_policy_advisory_lock_and_single_active():
    """Verify activate_policy dispatches pg_advisory_xact_lock and deactivates others."""
    class MockDialect:
        name = "postgresql"

    class MockBind:
        dialect = MockDialect()

    target_policy = SecurityPolicy(name="Target", max_allowed_cvss=5.0, is_active=0)
    target_policy.id = "target-uuid"

    class PostgresSession:
        def __init__(self):
            self.bind = MockBind()
            self.executed_sql = []
            self.updated = []

        def execute(self, statement, params=None):
            self.executed_sql.append((str(statement), params))

        def query(self, *args, **kwargs):
            session_self = self
            class MockQuery:
                def filter(self, *f_args, **f_kwargs):
                    return self
                def first(self):
                    return target_policy
                def update(self, values):
                    session_self.updated.append(values)
            return MockQuery()

        def commit(self): pass
        def refresh(self, obj): pass

    session = PostgresSession()
    activated = activate_policy(session, "target-uuid")

    assert activated.is_active == 1
    assert any("pg_advisory_xact_lock" in sql for sql, _ in session.executed_sql)
    assert any(u == {"is_active": 0} for u in session.updated)


def test_activate_policy_rollback_on_failure():
    """Verify activate_policy rolls back on unexpected database failure."""
    target_policy = SecurityPolicy(name="Target", max_allowed_cvss=5.0, is_active=0)
    target_policy.id = "target-uuid"

    class FailingSession:
        def __init__(self):
            self.rolled_back = False

        def query(self, *args, **kwargs):
            class MockQuery:
                def filter(self, *f_args, **f_kwargs):
                    return self
                def first(self):
                    return target_policy
                def update(self, values):
                    raise RuntimeError("Simulated DB failure during deactivation")
            return MockQuery()

        def rollback(self):
            self.rolled_back = True

    session = FailingSession()
    with pytest.raises(RuntimeError, match="Simulated DB failure"):
        activate_policy(session, "target-uuid")

    assert session.rolled_back is True



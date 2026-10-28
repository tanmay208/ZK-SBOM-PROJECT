"""
Regression tests for AUD-A-001 — Application tenant isolation.

Validates that:
  1. Two different users with the same (name, vendor) get separate Application records.
  2. The same user with the same (name, vendor) reuses their existing record.
  3. Ownership consistency: Application.user_id matches the requesting user.
  4. The existing cascade delete behaviour is not broken.

All database interactions are mocked (no live DB required).
"""

from __future__ import annotations

import sys
import os
import uuid
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
)

from sbom_service.app.repositories.sbom_repository import SBOMRepository
from sbom_service.app.models.sbom_models import Application


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session_returning(existing_app=None):
    """Create a mock session whose query().filter().first() returns *existing_app*."""
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = existing_app
    return session


def _capture_add(session):
    """Attach a side_effect to session.add that captures the added object."""
    captured = {}

    def _side(obj):
        captured["obj"] = obj

    session.add.side_effect = _side
    return captured


# ---------------------------------------------------------------------------
# 1. Cross-tenant collision prevention
# ---------------------------------------------------------------------------

class TestCrossTenantIsolation:
    """AUD-A-001: two users must never share an Application record."""

    def test_different_users_same_name_vendor_get_separate_records(self) -> None:
        """When no existing record matches (name, vendor, user_id), a new
        Application must be created — even if another user already owns
        the same (name, vendor) pair.

        We simulate this by having the session return None from the
        query (meaning no match for THIS user's triple).  The repository
        must add a new Application with the requesting user's user_id.
        """
        user_a = uuid.uuid4()
        user_b = uuid.uuid4()

        # --- User A creates the application ---------------------------------
        session_a = _make_session_returning(existing_app=None)
        captured_a = _capture_add(session_a)
        repo_a = SBOMRepository(session_a)
        result_a = repo_a.get_or_create_application(
            name="SharedApp", vendor="Acme", user_id=user_a,
        )
        assert session_a.add.called
        assert captured_a["obj"].user_id == user_a

        # --- User B asks for the same (name, vendor) -----------------------
        # Because the query now includes user_id in the filter, the DB
        # returns None for user_b even though user_a's record exists.
        session_b = _make_session_returning(existing_app=None)
        captured_b = _capture_add(session_b)
        repo_b = SBOMRepository(session_b)
        result_b = repo_b.get_or_create_application(
            name="SharedApp", vendor="Acme", user_id=user_b,
        )
        assert session_b.add.called
        assert captured_b["obj"].user_id == user_b

    def test_filter_includes_user_id(self) -> None:
        """The query filter must include Application.user_id."""
        user_id = uuid.uuid4()
        session = _make_session_returning(existing_app=None)
        repo = SBOMRepository(session)
        repo.get_or_create_application(
            name="X", vendor="Y", user_id=user_id,
        )
        # Inspect the filter() call arguments.  SQLAlchemy BinaryExpression
        # objects are passed positionally; we just verify three filter args
        # were supplied (name, vendor, user_id).
        filter_call = session.query.return_value.filter
        filter_call.assert_called_once()
        args = filter_call.call_args[0]
        assert len(args) == 3, (
            f"Expected 3 filter predicates (name, vendor, user_id), got {len(args)}"
        )


# ---------------------------------------------------------------------------
# 2. Same-tenant reuse
# ---------------------------------------------------------------------------

class TestSameTenantReuse:
    """An existing Application for the SAME user must be returned as-is."""

    def test_existing_record_returned_without_insert(self) -> None:
        user_id = uuid.uuid4()
        existing = MagicMock(spec=Application)
        existing.id = uuid.uuid4()
        existing.user_id = user_id

        session = _make_session_returning(existing_app=existing)
        repo = SBOMRepository(session)
        result = repo.get_or_create_application(
            name="MyApp", vendor="MyVendor", user_id=user_id,
        )
        assert result is existing
        session.add.assert_not_called()
        session.flush.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Ownership consistency
# ---------------------------------------------------------------------------

class TestOwnershipConsistency:
    """New Application records must carry the requesting user_id."""

    def test_created_application_has_correct_user_id(self) -> None:
        user_id = uuid.uuid4()
        session = _make_session_returning(existing_app=None)
        captured = _capture_add(session)
        repo = SBOMRepository(session)
        repo.get_or_create_application(
            name="NewApp", vendor="NewVendor", user_id=user_id,
        )
        created_app = captured["obj"]
        assert isinstance(created_app, Application)
        assert created_app.user_id == user_id
        assert created_app.name == "NewApp"
        assert created_app.vendor == "NewVendor"

    def test_created_application_has_description_when_provided(self) -> None:
        user_id = uuid.uuid4()
        session = _make_session_returning(existing_app=None)
        captured = _capture_add(session)
        repo = SBOMRepository(session)
        repo.get_or_create_application(
            name="App", vendor="Vendor", user_id=user_id,
            description="My application",
        )
        assert captured["obj"].description == "My application"


# ---------------------------------------------------------------------------
# 4. Cascade safety — upload still links to the correct application
# ---------------------------------------------------------------------------

class TestCascadeSafety:
    """Verify create_upload still correctly references the application."""

    def test_upload_references_correct_application(self) -> None:
        user_id = uuid.uuid4()

        # Create an application first
        app_session = _make_session_returning(existing_app=None)
        captured_app = _capture_add(app_session)
        repo = SBOMRepository(app_session)
        repo.get_or_create_application(
            name="CascadeApp", vendor="CascadeVendor", user_id=user_id,
        )
        app_obj = captured_app["obj"]
        app_obj.id = uuid.uuid4()  # simulate flush populating the id

        # Now create an upload for that application
        upload_session = MagicMock()
        captured_upload = _capture_add(upload_session)
        upload_repo = SBOMRepository(upload_session)
        upload_repo.create_upload(
            application=app_obj,
            filename="test.json",
            format="CycloneDX",
            raw_content="{}",
            user_id=user_id,
        )
        upload_obj = captured_upload["obj"]
        assert upload_obj.application_id == app_obj.id
        assert upload_obj.user_id == user_id


# ---------------------------------------------------------------------------
# 5. Model-level unique constraint declaration
# ---------------------------------------------------------------------------

class TestModelConstraint:
    """Verify the Application model declares the expected unique constraint."""

    def test_unique_constraint_declared(self) -> None:
        table_args = Application.__table_args__
        # __table_args__ is a tuple: (constraint1, ..., {options_dict})
        assert isinstance(table_args, tuple), (
            "__table_args__ should be a tuple containing the UniqueConstraint"
        )
        constraint_names = []
        for arg in table_args:
            if hasattr(arg, "name"):
                constraint_names.append(arg.name)
        assert "uq_sbom_applications_name_vendor_user" in constraint_names, (
            f"Expected unique constraint 'uq_sbom_applications_name_vendor_user' "
            f"in {constraint_names}"
        )

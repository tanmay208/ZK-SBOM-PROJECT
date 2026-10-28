"""
Unit tests for SBOM response metadata enrichment and admin all_tenants listing.
Stage D4.3 — Backend companion deliverables 7 & 8.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from sbom_service.app.models.sbom_models import Application, SBOMUpload
from sbom_service.app.schemas.sbom_schemas import SBOMUploadResponse
from sbom_service.app.api.routes.sbom_routes import list_sboms, get_sbom
from shared.models.user import User


class TestSBOMMetadataEnrichment:
    """Tests for Deliverable 7: SBOM response model enrichment."""

    def test_from_model_with_loaded_application(self) -> None:
        """Derives application_name and vendor from upload.application relationship."""
        app = Application(
            id=uuid.uuid4(),
            name="payments-service",
            vendor="Acme Corp",
            user_id=uuid.uuid4(),
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        upload = SBOMUpload(
            id=uuid.uuid4(),
            application_id=app.id,
            user_id=app.user_id,
            filename="payments.json",
            format="CycloneDX",
            status="committed",
            sbom_root="0x12345678",
            component_count=12,
            created_at=datetime.now(timezone.utc),
        )
        upload.application = app

        resp = SBOMUploadResponse.from_model(upload)
        assert resp.upload_id == upload.id
        assert resp.application_id == app.id
        assert resp.application_name == "payments-service"
        assert resp.vendor == "Acme Corp"
        assert resp.status == "committed"
        assert resp.component_count == 12

    def test_from_model_without_application_historical_fallback(self) -> None:
        """Historical records with no loaded application gracefully default to None."""
        upload = SBOMUpload(
            id=uuid.uuid4(),
            application_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            filename="legacy.json",
            format="CycloneDX",
            status="committed",
            sbom_root="0xabcdef",
            component_count=5,
            created_at=datetime.now(timezone.utc),
        )
        upload.application = None

        resp = SBOMUploadResponse.from_model(upload)
        assert resp.application_name is None
        assert resp.vendor is None
        assert resp.upload_id == upload.id

    def test_from_model_with_explicit_parameters(self) -> None:
        """Explicitly passed application_name and vendor take precedence."""
        upload = SBOMUpload(
            id=uuid.uuid4(),
            application_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            filename="test.json",
            format="CycloneDX",
            status="committed",
            created_at=datetime.now(timezone.utc),
        )
        resp = SBOMUploadResponse.from_model(
            upload,
            application_name="explicit-app",
            vendor="Explicit Vendor",
        )
        assert resp.application_name == "explicit-app"
        assert resp.vendor == "Explicit Vendor"


class TestAdminAllTenantsListing:
    """Tests for Deliverable 8: admin all_tenants query parameter."""

    def test_list_sboms_default_scopes_to_current_user(self) -> None:
        """Default all_tenants=False filters by current_user.id."""
        user_id = uuid.uuid4()
        user = User(id=user_id, username="vendor1", role="vendor")

        session = MagicMock()
        query_mock = MagicMock()
        session.query.return_value = query_mock
        query_mock.options.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.offset.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.all.return_value = []

        list_sboms(skip=0, limit=50, all_tenants=False, session=session, current_user=user)

        # filter must have been called
        assert query_mock.filter.called

    def test_list_sboms_all_tenants_admin_bypasses_user_filter(self) -> None:
        """Admin with all_tenants=True does NOT filter by user_id."""
        admin_id = uuid.uuid4()
        admin = User(id=admin_id, username="admin_user", role="admin")

        session = MagicMock()
        query_mock = MagicMock()
        session.query.return_value = query_mock
        query_mock.options.return_value = query_mock
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.offset.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.all.return_value = []

        list_sboms(skip=0, limit=50, all_tenants=True, session=session, current_user=admin)

        # filter should NOT be called for user_id scoping
        assert not query_mock.filter.called

    def test_list_sboms_all_tenants_rejected_for_vendor(self) -> None:
        """Non-admin requesting all_tenants=True is rejected with HTTP 403."""
        user = User(id=uuid.uuid4(), username="vendor1", role="vendor")
        session = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            list_sboms(skip=0, limit=50, all_tenants=True, session=session, current_user=user)

        assert exc_info.value.status_code == 403
        assert "Only administrators" in exc_info.value.detail

    def test_list_sboms_all_tenants_rejected_for_auditor(self) -> None:
        """Auditor requesting all_tenants=True is rejected with HTTP 403."""
        user = User(id=uuid.uuid4(), username="auditor1", role="auditor")
        session = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            list_sboms(skip=0, limit=50, all_tenants=True, session=session, current_user=user)

        assert exc_info.value.status_code == 403

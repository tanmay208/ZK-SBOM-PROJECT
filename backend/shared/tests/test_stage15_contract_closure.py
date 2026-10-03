"""Focused Stage 1.5 contract-closure tests."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from shared.auth import get_current_user
from shared.database import get_session
from shared.models.user import User
from verification_service.app.main import app
from zkp_service.app.schemas.zkp_schemas import ProofJobResponse


CLIENT = TestClient(app, raise_server_exceptions=False)


def _user(role: str) -> User:
    return User(id=uuid4(), username=f"{role}-test", role=role)


def test_auditor_cannot_mutate_vendor_or_admin_resources():
    app.dependency_overrides[get_current_user] = lambda: _user("auditor")
    try:
        sbom_response = CLIENT.post(
            "/api/v1/sbom/upload",
            json={
                "application_name": "app",
                "vendor": "vendor",
                "format": "CycloneDX",
                "content": "{}",
            },
        )
        policy_response = CLIENT.post(
            "/api/v1/policy",
            json={"max_cvss_score": 7.0},
        )
        proof_response = CLIENT.post(
            "/api/v1/zkp/generate",
            json={
                "sbom_upload_id": str(uuid4()),
                "snapshot_id": str(uuid4()),
                "policy_id": str(uuid4()),
            },
        )

        assert sbom_response.status_code == 403
        assert policy_response.status_code == 403
        assert proof_response.status_code == 403
        assert sbom_response.json()["code"] == "FORBIDDEN"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_certificate_detail_is_public_metadata_only():
    certificate_id = uuid4()
    app.dependency_overrides[get_session] = lambda: iter([MagicMock()])
    app.dependency_overrides[get_current_user] = lambda: _user("auditor")
    try:
        with patch(
            "verification_service.app.api.routes.verification_routes.VerificationService"
        ) as service_class:
            service_class.return_value.get_certificate.return_value = None
            response = CLIENT.get(
                f"/api/v1/verification/certificates/{certificate_id}"
            )

        assert response.status_code == 404
        assert service_class.return_value.get_certificate.called
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_current_user, None)


def test_proof_job_response_sanitizes_internal_error():
    response = ProofJobResponse(
        id=uuid4(),
        sbom_upload_id=uuid4(),
        snapshot_id=uuid4(),
        policy_id=uuid4(),
        status="failed",
        error_message="Command failed at C:\\private\\Prover.toml: secret stderr",
        created_at="2026-09-25T00:00:00Z",
    )

    assert response.error_message == "Proof generation failed"
    assert "Prover.toml" not in response.model_dump_json()
    assert "secret stderr" not in response.model_dump_json()


def test_protected_http_errors_use_stable_codes():
    response = CLIENT.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"
    assert response.headers["www-authenticate"] == "Bearer"

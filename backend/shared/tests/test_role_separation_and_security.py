import uuid
from datetime import datetime, timezone, timedelta
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from shared.models.user import User
from shared.auth import get_password_hash, create_access_token
from shared.database import Base, get_session
from sbom_service.app.models.sbom_models import Application, SBOMUpload
from zkp_service.app.models.zkp_models import ProofJob
from verification_service.app.models.verification_models import ProofShare, VerificationCertificate, VerificationRequest
from policy_service.app.models.policy_models import SecurityPolicy
from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot
from verification_service.app.main import app


@pytest.fixture(scope="module")
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Strip PostgreSQL schemas for SQLite compatibility
    saved_schemas = {table: table.schema for table in Base.metadata.tables.values()}
    for table in Base.metadata.tables.values():
        table.schema = None
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        for table, schema in saved_schemas.items():
            table.schema = schema


@pytest.fixture
def db_session(db_engine) -> Generator:
    TestingSession = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.rollback()
        session.query(ProofShare).delete()
        session.query(VerificationCertificate).delete()
        session.query(VerificationRequest).delete()
        session.query(ProofJob).delete()
        session.query(SBOMUpload).delete()
        session.query(Application).delete()
        session.query(SecurityPolicy).delete()
        session.query(VulnerabilitySnapshot).delete()
        session.query(User).delete()
        session.commit()
        session.close()


@pytest.fixture
def client(db_session) -> Generator:
    app.dependency_overrides[get_session] = lambda: db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.pop(get_session, None)


def create_user(db: Session, username: str, role: str = "vendor", is_active: bool = True) -> User:
    u = User(
        id=uuid.uuid4(),
        username=username,
        hashed_password=get_password_hash("SecretPassword123!"),
        role=role,
        is_active=is_active,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def get_headers(user: User) -> dict:
    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


def test_1_vendor_isolation(client: TestClient, db_session: Session):
    """1. Vendor A cannot read or mutate Vendor B's applications, SBOMs, proof jobs, shares."""
    v_a = create_user(db_session, f"vendor_a_{uuid.uuid4().hex[:6]}", "vendor")
    v_b = create_user(db_session, f"vendor_b_{uuid.uuid4().hex[:6]}", "vendor")
    h_a = get_headers(v_a)
    h_b = get_headers(v_b)

    # Vendor B creates application
    app_b = Application(id=uuid.uuid4(), name="App B", vendor=v_b.username, user_id=v_b.id, is_active=True)
    db_session.add(app_b)
    db_session.commit()

    # Vendor A attempts to read Vendor B's app -> 404 non-disclosing
    resp = client.get(f"/api/v1/applications/{app_b.id}", headers=h_a)
    assert resp.status_code == 404

    # Vendor A attempts to update Vendor B's app -> 404 non-disclosing
    resp_patch = client.patch(f"/api/v1/applications/{app_b.id}", json={"name": "Hacked"}, headers=h_a)
    assert resp_patch.status_code == 404

    # Vendor B creates SBOM upload
    sbom_b = SBOMUpload(
        id=uuid.uuid4(),
        application_id=app_b.id,
        user_id=v_b.id,
        filename="bom.json",
        format="CycloneDX",
        status="committed",
        sbom_root="0x123",
    )
    db_session.add(sbom_b)
    db_session.commit()

    # Vendor A attempts to read Vendor B's SBOM -> 404 non-disclosing
    resp_sbom = client.get(f"/api/v1/sbom/{sbom_b.id}", headers=h_a)
    assert resp_sbom.status_code == 404

    # Vendor B creates proof job
    job_b = ProofJob(
        id=uuid.uuid4(),
        user_id=v_b.id,
        sbom_upload_id=sbom_b.id,
        snapshot_id=uuid.uuid4(),
        policy_id=uuid.uuid4(),
        status="completed",
        sbom_root="0x123",
        vulnerability_db_root="0x456",
        policy_hash="0x789",
    )
    db_session.add(job_b)
    db_session.commit()

    # Vendor A attempts to read Vendor B's proof job -> 404 non-disclosing
    resp_job = client.get(f"/api/v1/zkp/jobs/{job_b.id}", headers=h_a)
    assert resp_job.status_code == 404


def test_2_buyer_cannot_mutate_vendor_resources(client: TestClient, db_session: Session):
    """2. Buyer cannot upload SBOMs, create applications, generate proofs, or create/revoke vendor shares."""
    buyer = create_user(db_session, f"buyer_{uuid.uuid4().hex[:6]}", "buyer")
    h_b = get_headers(buyer)

    # Buyer create app -> 403
    resp_app = client.post("/api/v1/applications", json={"name": "Buyer App", "vendor": "Buyer Co"}, headers=h_b)
    assert resp_app.status_code == 403

    # Buyer upload SBOM -> 403
    resp_sbom = client.post(
        "/api/v1/sbom/upload",
        json={"application_name": "App", "vendor": "Vendor", "format": "CycloneDX", "content": "{}"},
        headers=h_b,
    )
    assert resp_sbom.status_code == 403

    # Buyer generate proof -> 403
    resp_zkp = client.post(
        "/api/v1/zkp/generate",
        json={"sbom_upload_id": str(uuid.uuid4()), "snapshot_id": str(uuid.uuid4()), "policy_id": str(uuid.uuid4())},
        headers=h_b,
    )
    assert resp_zkp.status_code == 403

    # Buyer create share -> 403
    resp_share = client.post("/api/v1/verification/shares", json={"proof_job_id": str(uuid.uuid4())}, headers=h_b)
    assert resp_share.status_code == 403


def test_3_admin_cannot_perform_routine_vendor_buyer_actions(client: TestClient, db_session: Session):
    """3. Admin cannot register applications, upload SBOMs, generate proof jobs, or submit routine proof verification."""
    admin = create_user(db_session, f"admin_{uuid.uuid4().hex[:6]}", "admin")
    h_a = get_headers(admin)

    # Admin cannot create app -> 403
    resp_app = client.post("/api/v1/applications", json={"name": "Admin App", "vendor": "Admin Co"}, headers=h_a)
    assert resp_app.status_code == 403

    # Admin cannot upload SBOM -> 403
    resp_sbom = client.post(
        "/api/v1/sbom/upload",
        json={"application_name": "App", "vendor": "Admin", "format": "CycloneDX", "content": "{}"},
        headers=h_a,
    )
    assert resp_sbom.status_code == 403

    # Admin cannot generate proof -> 403
    resp_zkp = client.post(
        "/api/v1/zkp/generate",
        json={"sbom_upload_id": str(uuid.uuid4()), "snapshot_id": str(uuid.uuid4()), "policy_id": str(uuid.uuid4())},
        headers=h_a,
    )
    assert resp_zkp.status_code == 403

    # Admin cannot submit routine verification -> 403
    resp_verif = client.post(
        "/api/v1/verification/verify",
        json={"sbom_root": "0x1", "vulnerability_db_root": "0x2", "policy_hash": "0x3"},
        headers=h_a,
    )
    assert resp_verif.status_code == 403

    # Admin cannot create share -> 403
    resp_share = client.post(
        "/api/v1/verification/shares",
        json={"proof_job_id": str(uuid.uuid4())},
        headers=h_a,
    )
    assert resp_share.status_code == 403


def test_4_admin_governance_and_platform_aggregates(client: TestClient, db_session: Session):
    """4. Admin can read authorized platform-wide dashboard aggregates and governance registries."""
    admin = create_user(db_session, f"admin_gov_{uuid.uuid4().hex[:6]}", "admin")
    h_a = get_headers(admin)

    resp_gov = client.get("/api/v1/metrics/governance", headers=h_a)
    assert resp_gov.status_code == 200
    data = resp_gov.json()
    assert "users" in data
    assert "applications" in data
    assert "sboms" in data
    assert "proof_jobs" in data
    assert "verifications" in data
    assert "certificates" in data
    assert "policies" in data
    assert "vulnerabilities" in data


def test_5_vendor_and_buyer_dashboards_scoped(client: TestClient, db_session: Session):
    """5. Vendor and buyer dashboards remain correctly scoped."""
    vendor = create_user(db_session, f"vendor_dash_{uuid.uuid4().hex[:6]}", "vendor")
    buyer = create_user(db_session, f"buyer_dash_{uuid.uuid4().hex[:6]}", "buyer")

    h_v = get_headers(vendor)
    h_b = get_headers(buyer)

    # Vendor query without all_tenants -> 200 OK (scoped)
    resp_v = client.get("/api/v1/metrics", headers=h_v)
    assert resp_v.status_code == 200

    # Vendor attempts all_tenants=true -> 403
    resp_v_all = client.get("/api/v1/metrics?all_tenants=true", headers=h_v)
    assert resp_v_all.status_code == 403

    # Buyer attempts all_tenants=true -> 403
    resp_b_all = client.get("/api/v1/metrics?all_tenants=true", headers=h_b)
    assert resp_b_all.status_code == 403


def test_6_admin_inspect_without_vendor_mutation(client: TestClient, db_session: Session):
    """6. Admin can inspect application/SBOM inventories without obtaining vendor mutation privileges."""
    admin = create_user(db_session, f"admin_insp_{uuid.uuid4().hex[:6]}", "admin")
    vendor = create_user(db_session, f"vendor_src_{uuid.uuid4().hex[:6]}", "vendor")
    h_a = get_headers(admin)

    app = Application(id=uuid.uuid4(), name="Vendor App", vendor=vendor.username, user_id=vendor.id, is_active=True)
    db_session.add(app)
    db_session.commit()

    # Admin inspects application -> 200 OK
    resp_read = client.get(f"/api/v1/applications/{app.id}", headers=h_a)
    assert resp_read.status_code == 200
    assert resp_read.json()["name"] == "Vendor App"

    # Admin attempts metadata mutation -> 403 Forbidden
    resp_mut = client.patch(f"/api/v1/applications/{app.id}", json={"name": "Admin Rename"}, headers=h_a)
    assert resp_mut.status_code == 403

    # Admin can perform lifecycle governance (archive / reactivate) -> 200 OK
    resp_arch = client.post(f"/api/v1/applications/{app.id}/archive", headers=h_a)
    assert resp_arch.status_code == 200
    assert resp_arch.json()["is_active"] is False


def test_7_admin_policy_governance(client: TestClient, db_session: Session):
    """7. Admin can create/manage policies and use authorized vulnerability intelligence workflows."""
    admin = create_user(db_session, f"admin_pol_{uuid.uuid4().hex[:6]}", "admin")
    buyer = create_user(db_session, f"buyer_pol_{uuid.uuid4().hex[:6]}", "buyer")

    h_a = get_headers(admin)
    h_b = get_headers(buyer)

    # Admin creates policy -> 200 OK
    resp_pol = client.post(
        "/api/v1/policy",
        json={"name": "Strict CVSS", "max_cvss_score": 7.0, "description": "High security policy"},
        headers=h_a,
    )
    assert resp_pol.status_code == 200
    pol_id = resp_pol.json()["id"]

    # Admin activates policy -> 200 OK
    resp_act = client.post(f"/api/v1/policy/{pol_id}/activate", headers=h_a)
    assert resp_act.status_code == 200
    assert resp_act.json()["active"] is True

    # Buyer attempts to create policy -> 403 Forbidden
    resp_b = client.post(
        "/api/v1/policy",
        json={"name": "Buyer Policy", "max_cvss_score": 9.0},
        headers=h_b,
    )
    assert resp_b.status_code == 403


def test_8_user_deletion_safeguards(client: TestClient, db_session: Session):
    """8-10. User deletion safeguards: admin rejection, self-deletion guard, session invalidation."""
    admin1 = create_user(db_session, f"admin_boss_{uuid.uuid4().hex[:6]}", "admin")
    admin2 = create_user(db_session, f"admin_sub_{uuid.uuid4().hex[:6]}", "admin")
    vendor = create_user(db_session, f"vendor_del_{uuid.uuid4().hex[:6]}", "vendor")

    h_a1 = get_headers(admin1)
    h_v = get_headers(vendor)

    # Admin cannot delete another admin -> 400
    resp_del_admin = client.delete(f"/api/v1/admin/users/{admin2.id}", headers=h_a1)
    assert resp_del_admin.status_code == 400

    # Admin cannot delete self -> 400
    resp_del_self = client.delete(f"/api/v1/admin/users/{admin1.id}", headers=h_a1)
    assert resp_del_self.status_code == 400

    # Admin deletes vendor -> 200 OK
    resp_del_v = client.delete(f"/api/v1/admin/users/{vendor.id}", headers=h_a1)
    assert resp_del_v.status_code == 200
    assert resp_del_v.json()["deleted"] is True

    # Deleted vendor credentials rejected -> 401
    resp_post = client.get("/api/v1/applications", headers=h_v)
    assert resp_post.status_code == 401

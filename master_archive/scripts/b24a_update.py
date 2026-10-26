import sys
import re

# 1. Update Models
models_path = 'backend/vulnerability_service/app/models/vulnerability_models.py'
with open(models_path, 'r', encoding='utf-8') as f:
    content = f.read()

model_addition = '''    frozen_at = Column(DateTime(timezone=True), nullable=True)
    frozen_by = Column(Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approved_by = Column(Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    revocation_reason = Column(String(512), nullable=True)'''

content = content.replace('    frozen_at = Column(DateTime(timezone=True), nullable=True)', model_addition)

with open(models_path, 'w', encoding='utf-8') as f:
    f.write(content)

# 2. Update Schemas
schemas_path = 'backend/vulnerability_service/app/schemas/vulnerability_schemas.py'
with open(schemas_path, 'r', encoding='utf-8') as f:
    content = f.read()

schema_addition = '''    authoritative_smt_root: str | None = Field(default=None, description="The final frozen SMT root")
    frozen_at: str | None = Field(default=None, description="Timestamp when frozen")
    frozen_by: str | None = None
    approved_at: str | None = None
    approved_by: str | None = None
    revoked_at: str | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None'''

content = content.replace(
    '''    authoritative_smt_root: str | None = Field(default=None, description="The final frozen SMT root")
    frozen_at: str | None = Field(default=None, description="Timestamp when frozen")''',
    schema_addition
)

from_model_addition = '''            authoritative_smt_root=getattr(s, "authoritative_smt_root", None),
            frozen_at=str(s.frozen_at) if getattr(s, "frozen_at", None) else None,
            frozen_by=str(s.frozen_by) if getattr(s, "frozen_by", None) else None,
            approved_at=str(s.approved_at) if getattr(s, "approved_at", None) else None,
            approved_by=str(s.approved_by) if getattr(s, "approved_by", None) else None,
            revoked_at=str(s.revoked_at) if getattr(s, "revoked_at", None) else None,
            revoked_by=str(s.revoked_by) if getattr(s, "revoked_by", None) else None,
            revocation_reason=getattr(s, "revocation_reason", None),'''

content = content.replace(
    '''            authoritative_smt_root=getattr(s, "authoritative_smt_root", None),
            frozen_at=str(s.frozen_at) if getattr(s, "frozen_at", None) else None,''',
    from_model_addition
)

# Add a RevocationRequest schema
revocation_schema = '''
class RevocationRequest(BaseModel):
    reason: str | None = Field(default=None, description="Reason for revocation")
'''
content = content + revocation_schema

with open(schemas_path, 'w', encoding='utf-8') as f:
    f.write(content)

# 3. Update Routes
routes_path = 'backend/vulnerability_service/app/api/routes/vulnerability_routes.py'
with open(routes_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Add to approve
approve_search = '''    snap.status = 'approved'
    db.commit()'''
approve_replace = '''    from datetime import datetime, timezone
    snap.status = 'approved'
    snap.approved_at = datetime.now(timezone.utc)
    snap.approved_by = current_user.id
    db.commit()'''
content = content.replace(approve_search, approve_replace)

# Add to revoke
revoke_search = '''def revoke_snapshot(snapshot_id: UUID, db: Session = Depends(get_session), current_user: User = Depends(get_current_user)):'''
revoke_replace = '''from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest # Just to appease static checks, wait we need to import RevocationRequest
from vulnerability_service.app.schemas.vulnerability_schemas import RevocationRequest

@router.post('/snapshots/{snapshot_id}/revoke', response_model=VulnerabilitySnapshotResponse)
def revoke_snapshot(snapshot_id: UUID, req: RevocationRequest | None = None, db: Session = Depends(get_session), current_user: User = Depends(get_current_user)):'''
content = re.sub(r"@router\.post\('/snapshots/\{snapshot_id\}/revoke', response_model=VulnerabilitySnapshotResponse\)\ndef revoke_snapshot\(snapshot_id: UUID, db: Session = Depends\(get_session\), current_user: User = Depends\(get_current_user\)\):", revoke_replace.strip(), content)

revoke_status_search = '''    snap.status = 'revoked'
    db.commit()'''
revoke_status_replace = '''    from datetime import datetime, timezone
    snap.status = 'revoked'
    snap.revoked_at = datetime.now(timezone.utc)
    snap.revoked_by = current_user.id
    if req and req.reason:
        snap.revocation_reason = req.reason
    db.commit()'''
content = content.replace(revoke_status_search, revoke_status_replace)

# Add to freeze
freeze_search = '''    snap.frozen_at = datetime.now(timezone.utc)
    snap.status = 'frozen'
    
    db.commit()'''
freeze_replace = '''    snap.frozen_at = datetime.now(timezone.utc)
    snap.frozen_by = current_user.id
    snap.status = 'frozen'
    
    db.commit()'''
content = content.replace(freeze_search, freeze_replace)

with open(routes_path, 'w', encoding='utf-8') as f:
    f.write(content)

# 4. Update Mocks in Tests
tests_path = 'backend/vulnerability_service/tests/test_vulnerability_ingestion.py'
with open(tests_path, 'r', encoding='utf-8') as f:
    content = f.read()

mock_search = '''    mock_snapshot.authoritative_smt_root = None
    mock_snapshot.frozen_at = None'''
mock_replace = '''    mock_snapshot.authoritative_smt_root = None
    mock_snapshot.frozen_at = None
    mock_snapshot.frozen_by = None
    mock_snapshot.approved_at = None
    mock_snapshot.approved_by = None
    mock_snapshot.revoked_at = None
    mock_snapshot.revoked_by = None
    mock_snapshot.revocation_reason = None'''
content = content.replace(mock_search, mock_replace)

# 5. Add focused tests
new_tests = '''
    def test_audit_fields_on_approve(self):
        mock_session, mock_snapshot, override = _get_mock_db()
        mock_snapshot.status = "pending"
        # Avoid SoD violation
        mock_snapshot.created_by = "00000000-0000-0000-0000-000000000002"
        
        app.dependency_overrides[get_current_user] = lambda: type("User", (), {"id": "11111111-1111-1111-1111-111111111111", "role": "admin", "username": "admin"})()
        app.dependency_overrides[
            __import__("backend.shared.database", fromlist=["get_session"]).get_session
        ] = override
        client = TestClient(app)

        mock_session.query.return_value.filter.return_value.first.return_value = mock_snapshot
        
        response = client.post(f"/api/v1/vulnerability/snapshots/{mock_snapshot.id}/approve")
        
        app.dependency_overrides.clear()
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "approved"
        assert mock_snapshot.approved_by == "11111111-1111-1111-1111-111111111111"
        assert mock_snapshot.approved_at is not None

    def test_audit_fields_on_freeze(self):
        mock_session, mock_snapshot, override = _get_mock_db()
        mock_snapshot.status = "approved"
        mock_mapping = type("Mapping", (), {"component_hash": "0000000000000000000000000000000000000000000000000000000000000123", "max_cvss": 5})()
        mock_snapshot.mappings = [mock_mapping]
        
        app.dependency_overrides[get_current_user] = lambda: type("User", (), {"id": "22222222-2222-2222-2222-222222222222", "role": "admin", "username": "admin"})()
        app.dependency_overrides[
            __import__("backend.shared.database", fromlist=["get_session"]).get_session
        ] = override
        client = TestClient(app)

        mock_session.query.return_value.filter.return_value.first.return_value = mock_snapshot
        
        response = client.post(f"/api/v1/vulnerability/snapshots/{mock_snapshot.id}/freeze")
        
        app.dependency_overrides.clear()
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "frozen"
        assert mock_snapshot.frozen_by == "22222222-2222-2222-2222-222222222222"
        assert mock_snapshot.frozen_at is not None

    def test_audit_fields_on_revoke_with_reason(self):
        mock_session, mock_snapshot, override = _get_mock_db()
        mock_snapshot.status = "frozen"
        
        app.dependency_overrides[get_current_user] = lambda: type("User", (), {"id": "33333333-3333-3333-3333-333333333333", "role": "admin", "username": "admin"})()
        app.dependency_overrides[
            __import__("backend.shared.database", fromlist=["get_session"]).get_session
        ] = override
        client = TestClient(app)

        mock_session.query.return_value.filter.return_value.first.return_value = mock_snapshot
        
        response = client.post(f"/api/v1/vulnerability/snapshots/{mock_snapshot.id}/revoke", json={"reason": "Compromised importer"})
        
        app.dependency_overrides.clear()
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "revoked"
        assert mock_snapshot.revoked_by == "33333333-3333-3333-3333-333333333333"
        assert mock_snapshot.revoked_at is not None
        assert mock_snapshot.revocation_reason == "Compromised importer"
'''

content += new_tests

with open(tests_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Update script completed successfully.")

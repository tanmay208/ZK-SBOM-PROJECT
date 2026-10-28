import sys

# 1. Update schemas
schema_path = 'backend/vulnerability_service/app/schemas/vulnerability_schemas.py'
with open(schema_path, 'r', encoding='utf-8') as f:
    content = f.read()

old_schema = '''class VulnerabilitySnapshotResponse(BaseModel):
    id: str = Field(..., description="Snapshot UUID")
    snapshot_label: str = Field(..., description="Label or version of snapshot")
    record_count: int = Field(..., description="Total vulnerability records processed")
    status: str = Field(..., description="Processing status")

    @classmethod
    def from_model(cls, s: object) -> "VulnerabilitySnapshotResponse":
        return cls(
            id=str(getattr(s, "id", "")),
            snapshot_label=str(getattr(s, "snapshot_label", "")),
            record_count=int(getattr(s, "record_count", 0)),
            status=str(getattr(s, "status", "completed")),
        )'''

new_schema = '''class VulnerabilitySnapshotResponse(BaseModel):
    id: str = Field(..., description="Snapshot UUID")
    snapshot_label: str = Field(..., description="Label or version of snapshot")
    record_count: int = Field(..., description="Total vulnerability records processed")
    status: str = Field(..., description="Processing status")
    authoritative_smt_root: str | None = Field(default=None, description="The final frozen SMT root")
    frozen_at: str | None = Field(default=None, description="Timestamp when frozen")

    @classmethod
    def from_model(cls, s: object) -> "VulnerabilitySnapshotResponse":
        return cls(
            id=str(getattr(s, "id", "")),
            snapshot_label=str(getattr(s, "snapshot_label", "")),
            record_count=int(getattr(s, "record_count", 0)),
            status=str(getattr(s, "status", "completed")),
            authoritative_smt_root=getattr(s, "authoritative_smt_root", None),
            frozen_at=str(s.frozen_at) if getattr(s, "frozen_at", None) else None,
        )'''

new_content = content.replace(old_schema, new_schema)
with open(schema_path, 'w', encoding='utf-8') as f:
    f.write(new_content)

# 2. Update tests
test_path = 'backend/vulnerability_service/tests/test_vulnerability_ingestion.py'
with open(test_path, 'r', encoding='utf-8') as f:
    content = f.read()

new_tests = '''
    def test_freeze_snapshot_success(self):
        mock_session, mock_snapshot, override = _get_mock_db()
        mock_snapshot.status = "approved"
        # Setup mock_snapshot.mappings for the SMT logic
        mock_mapping = type("Mapping", (), {"component_hash": "0000000000000000000000000000000000000000000000000000000000000123", "max_cvss": 5})()
        mock_snapshot.mappings = [mock_mapping]
        
        app.dependency_overrides[get_current_user] = lambda: type("User", (), {"id": "1", "role": "admin", "username": "admin"})()
        app.dependency_overrides[
            __import__("backend.shared.database", fromlist=["get_session"]).get_session
        ] = override
        client = TestClient(app)

        mock_session.query.return_value.filter.return_value.first.return_value = mock_snapshot
        
        response = client.post(f"/api/v1/vulnerability/snapshots/{mock_snapshot.id}/freeze")
        
        app.dependency_overrides.clear()
        assert response.status_code == 200
        assert mock_snapshot.status == "frozen"
        assert mock_snapshot.authoritative_smt_root is not None
        assert mock_snapshot.frozen_at is not None

    def test_freeze_snapshot_not_approved(self):
        mock_session, mock_snapshot, override = _get_mock_db()
        mock_snapshot.status = "pending"
        
        app.dependency_overrides[get_current_user] = lambda: type("User", (), {"id": "1", "role": "admin", "username": "admin"})()
        app.dependency_overrides[
            __import__("backend.shared.database", fromlist=["get_session"]).get_session
        ] = override
        client = TestClient(app)

        mock_session.query.return_value.filter.return_value.first.return_value = mock_snapshot
        
        response = client.post(f"/api/v1/vulnerability/snapshots/{mock_snapshot.id}/freeze")
        
        app.dependency_overrides.clear()
        assert response.status_code == 400
        assert "frozen from approved state" in response.text
'''

with open(test_path, 'a', encoding='utf-8') as f:
    f.write(new_tests)

print("Done updating schemas and tests")

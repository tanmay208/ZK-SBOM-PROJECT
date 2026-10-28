import sys

tests_path = 'backend/vulnerability_service/tests/test_vulnerability_ingestion.py'
with open(tests_path, 'r', encoding='utf-8') as f:
    content = f.read()

new_test = '''
    def test_re_revocation_rejected(self):
        mock_session, mock_snapshot, override = _get_mock_db()
        mock_snapshot.status = "revoked"
        
        app.dependency_overrides[get_current_user] = lambda: type("User", (), {"id": "44444444-4444-4444-4444-444444444444", "role": "admin", "username": "admin"})()
        app.dependency_overrides[
            __import__("backend.shared.database", fromlist=["get_session"]).get_session
        ] = override
        client = TestClient(app)

        mock_session.query.return_value.filter.return_value.first.return_value = mock_snapshot
        
        response = client.post(f"/api/v1/vulnerability/snapshots/{mock_snapshot.id}/revoke")
        
        app.dependency_overrides.clear()
        assert response.status_code == 400
        assert "Snapshot is already revoked" in response.text
'''

if 'test_re_revocation_rejected' not in content:
    content += new_test
    with open(tests_path, 'w', encoding='utf-8') as f:
        f.write(content)

print("Test appended.")

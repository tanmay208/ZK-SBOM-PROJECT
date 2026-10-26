import sys

test_path = 'backend/vulnerability_service/tests/test_vulnerability_ingestion.py'

new_test = '''
    def test_unauthorized_role_freeze_rejected(self):
        app.dependency_overrides[get_current_user] = lambda: type("User", (), {"id": "1", "role": "trusted_importer", "username": "importer"})()
        client = TestClient(app)
        response = client.post("/api/v1/vulnerability/snapshots/00000000-0000-0000-0000-000000000000/freeze")
        assert response.status_code == 403
        assert "Admin role required for freezing" in response.text
        app.dependency_overrides.pop(get_current_user, None)
'''

with open(test_path, 'a', encoding='utf-8') as f:
    f.write(new_test)

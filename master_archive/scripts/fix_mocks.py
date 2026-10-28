import sys

test_path = 'backend/vulnerability_service/tests/test_vulnerability_ingestion.py'
with open(test_path, 'r', encoding='utf-8') as f:
    content = f.read()

old_mock = '''    mock_snapshot.provisional_smt_root = "0x00000000000000000000000000000000"
    mock_snapshot.created_by = "00000000-0000-0000-0000-000000000002"'''

new_mock = '''    mock_snapshot.provisional_smt_root = "0x00000000000000000000000000000000"
    mock_snapshot.created_by = "00000000-0000-0000-0000-000000000002"
    mock_snapshot.authoritative_smt_root = None
    mock_snapshot.frozen_at = None'''

new_content = content.replace(old_mock, new_mock)

with open(test_path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print("Updated mocks")

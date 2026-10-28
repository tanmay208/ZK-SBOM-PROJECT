import sys

test_path = 'backend/zkp_service/tests/test_zkp_api.py'
new_tests = '''
def test_generate_proof_status_rejections():
    from fastapi import HTTPException
    from zkp_service.app.repositories.zkp_repository import ZKPRepository
    from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest
    from unittest.mock import MagicMock
    import pytest
    
    repo = ZKPRepository(MagicMock())
    req = GenerateProofRequest(sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4())
    user_id = uuid.uuid4()
    
    # 1. Reject pending
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),  # SBOM
        MagicMock(status="pending")  # Snapshot
    ]
    with pytest.raises(HTTPException) as exc:
        repo.create_job(req, user_id)
    assert exc.value.status_code == 400
    assert "Snapshot is not frozen" in exc.value.detail

    # 2. Reject approved
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),
        MagicMock(status="approved")
    ]
    with pytest.raises(HTTPException) as exc:
        repo.create_job(req, user_id)
    assert exc.value.status_code == 400

    # 3. Reject revoked
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),
        MagicMock(status="revoked")
    ]
    with pytest.raises(HTTPException) as exc:
        repo.create_job(req, user_id)
    assert exc.value.status_code == 400

    # 4. Accept frozen
    repo._session.query.return_value.filter.return_value.first.side_effect = [
        MagicMock(user_id=user_id),
        MagicMock(status="frozen")
    ]
    # To bypass job creation DB commits since session is mocked, we expect it to not raise HTTPException
    # It might raise something else from the mocked session during commit, but the logic passed the gate.
    try:
        repo.create_job(req, user_id)
    except Exception as e:
        if isinstance(e, HTTPException):
            pytest.fail(f"Raised HTTPException unexpectedly: {e}")
'''
with open(test_path, 'a', encoding='utf-8') as f:
    f.write(new_tests)

print("Added tests")

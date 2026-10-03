import pytest
import subprocess
from unittest.mock import patch, MagicMock
from uuid import uuid4
from verification_service.app.core.verifier import NoirVerifier

def test_verifier_fails_closed_on_missing_inputs():
    verifier = NoirVerifier()
    proof = uuid4()
    
    with pytest.raises(ValueError, match="Missing expected public inputs"):
        verifier.verify(proof, None, expected_sbom_root=None, expected_vulnerability_db_root="abc", expected_policy_hash="def")
        
    with pytest.raises(ValueError, match="Missing expected public inputs"):
        verifier.verify(proof, None, expected_sbom_root="abc", expected_vulnerability_db_root=None, expected_policy_hash="def")
        
    with pytest.raises(ValueError, match="Missing expected public inputs"):
        verifier.verify(proof, None, expected_sbom_root="abc", expected_vulnerability_db_root="def", expected_policy_hash="")

def test_verifier_verification_unavailable():
    verifier = NoirVerifier()
    res = verifier.verify(None, None)
    assert res == "verification_unavailable"

@pytest.fixture
def mock_db_session():
    session = MagicMock()
    job = MagicMock()
    job.id = uuid4()
    session.query.return_value.filter.return_value.first.return_value = job
    
    # We won't fully mock out the 32x8 loops here because that's complex, 
    # but we can patch the subprocess.run directly.
    return session

@patch("subprocess.run")
@patch("verification_service.app.core.verifier.os.makedirs")
@patch("verification_service.app.core.verifier.os.path.exists", return_value=True)
@patch("verification_service.app.core.verifier.open")
@patch("verification_service.app.core.verifier.get_crypto_profile")
@patch("base64.b64decode", return_value=b"\x00"*2304)
def test_bb_timeout(mock_b64, mock_get_profile, mock_open, mock_exists, mock_makedirs, mock_run):
    verifier = NoirVerifier()
    
    # Mocking timeout
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="bb verify", timeout=300)
    
    session = MagicMock()
    job = MagicMock(id=uuid4())
    session.query.return_value.filter.return_value.first.return_value = job
    
    # Setup mock chunks and segments to get past topology checks
    chunks = [MagicMock(id=uuid4(), chunk_index=i, status="completed", components_commit="0x0", proof_job_id=job.id, total_chunks=32, component_start=i*32, component_count=32) for i in range(32)]
    
    def query_mock(model):
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ChunkProofSet":
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: chunks)))
        if model.__name__ == "SegmentProof":
            segs = []
            for j in range(8):
                s = MagicMock(segment_index=j, chunk_index=0, total_chunks=32, status="completed", components_commit="0x0", proof_artifact="base64==", proof_artifact_hash="hash", hash_in_commit="0x0", hash_out_commit="0x0")
                if j == 0:
                    s.global_sbom_root = "0x0"
                    s.policy_hash = "0x0"
                if j == 7:
                    s.vulnerability_db_root = "vuln"
                segs.append(s)
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: segs)))
        return MagicMock()

    session.query.side_effect = query_mock
    
    mock_profile = MagicMock()
    mock_profile.decomposed_artifacts = {
        "segment_init_32": {"vk_hash": "hash"},
        "segment_mid_32": {"vk_hash": "hash"},
        "segment_final_32": {"vk_hash": "hash"}
    }
    mock_profile.max_proof_size_bytes = 5000
    mock_profile.proof_timeout_seconds = 300
    mock_profile.get_artifact_paths.return_value = ("vk", "json", "C:\\root")
    mock_get_profile.return_value = mock_profile
    
    # Mock reading VK hash matching the mock profile
    file_mock = MagicMock()
    file_mock.read.return_value = b"vkdata"
    mock_open.return_value.__enter__.return_value = file_mock
    
    with patch("hashlib.sha256") as mock_sha:
        mock_sha.return_value.hexdigest.return_value = "hash"
        
        res = verifier.verify(job.id, session, expected_sbom_root="0x0", expected_vulnerability_db_root="0x0", expected_policy_hash="0x0")
        
    assert res == "invalid_proof"
    mock_run.assert_called_once()
    
@patch("subprocess.run")
@patch("verification_service.app.core.verifier.os.makedirs")
@patch("verification_service.app.core.verifier.os.path.exists", return_value=True)
@patch("verification_service.app.core.verifier.open")
@patch("verification_service.app.core.verifier.get_crypto_profile")
@patch("base64.b64decode", return_value=b"\x00"*2304)
def test_bb_nonzero_exit(mock_b64, mock_get_profile, mock_open, mock_exists, mock_makedirs, mock_run):
    verifier = NoirVerifier()
    
    mock_run.return_value = MagicMock(returncode=1, stderr=b"Error")
    
    session = MagicMock()
    job = MagicMock(id=uuid4())
    session.query.return_value.filter.return_value.first.return_value = job
    
    chunks = []
    for i in range(32):
        chunk = MagicMock(id=uuid4(), chunk_index=i, status="completed", components_commit="0x0", proof_job_id=job.id, total_chunks=32, component_start=i*32, component_count=32)
        chunks.append(chunk)
    
    def query_mock(model):
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ChunkProofSet":
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: chunks)))
        if model.__name__ == "SegmentProof":
            segs = []
            for j in range(8):
                s = MagicMock(segment_index=j, chunk_index=0, total_chunks=32, status="completed", components_commit="0x0", proof_artifact="base64==", proof_artifact_hash="hash", hash_in_commit="0x0", hash_out_commit="0x0")
                if j == 0:
                    s.global_sbom_root = "0x0"
                    s.policy_hash = "0x0"
                if j == 7:
                    s.vulnerability_db_root = "0x0"
                segs.append(s)
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: segs)))
        return MagicMock()

    session.query.side_effect = query_mock
    
    mock_profile = MagicMock()
    mock_profile.decomposed_artifacts = {
        "segment_init_32": {"vk_hash": "hash"},
        "segment_mid_32": {"vk_hash": "hash"},
        "segment_final_32": {"vk_hash": "hash"}
    }
    mock_profile.max_proof_size_bytes = 5000
    mock_profile.proof_timeout_seconds = 300
    mock_profile.get_artifact_paths.return_value = ("vk", "json", "C:\\root")
    mock_get_profile.return_value = mock_profile
    
    file_mock = MagicMock()
    file_mock.read.return_value = b"vkdata"
    mock_open.return_value.__enter__.return_value = file_mock
    
    with patch("hashlib.sha256") as mock_sha:
        mock_sha.return_value.hexdigest.return_value = "hash"
        
        res = verifier.verify(job.id, session, expected_sbom_root="0x0", expected_vulnerability_db_root="0x0", expected_policy_hash="0x0")
        
    assert res == "invalid_proof"
    mock_run.assert_called_once()
    
@patch("subprocess.run")
@patch("verification_service.app.core.verifier.os.makedirs")
@patch("verification_service.app.core.verifier.os.path.exists", return_value=True)
@patch("verification_service.app.core.verifier.open")
@patch("verification_service.app.core.verifier.get_crypto_profile")
@patch("base64.b64decode", return_value=b"\x00"*2304)
def test_bb_subprocess_exception(mock_b64, mock_get_profile, mock_open, mock_exists, mock_makedirs, mock_run):
    verifier = NoirVerifier()
    
    mock_run.side_effect = FileNotFoundError("bb not found")
    
    session = MagicMock()
    job = MagicMock(id=uuid4())
    session.query.return_value.filter.return_value.first.return_value = job
    
    chunks = [MagicMock(id=uuid4(), chunk_index=i, status="completed", components_commit="0x0", proof_job_id=job.id, total_chunks=32, component_start=i*32, component_count=32) for i in range(32)]
    
    def query_mock(model):
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ChunkProofSet":
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: chunks)))
        if model.__name__ == "SegmentProof":
            segs = []
            for j in range(8):
                s = MagicMock(segment_index=j, chunk_index=0, total_chunks=32, status="completed", components_commit="0x0", proof_artifact="base64==", proof_artifact_hash="hash", hash_in_commit="0x0", hash_out_commit="0x0")
                if j == 0:
                    s.global_sbom_root = "0x0"
                    s.policy_hash = "0x0"
                if j == 7:
                    s.vulnerability_db_root = "0x0"
                segs.append(s)
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: segs)))
        return MagicMock()

    session.query.side_effect = query_mock
    
    mock_profile = MagicMock()
    mock_profile.decomposed_artifacts = {
        "segment_init_32": {"vk_hash": "hash"},
        "segment_mid_32": {"vk_hash": "hash"},
        "segment_final_32": {"vk_hash": "hash"}
    }
    mock_profile.max_proof_size_bytes = 5000
    mock_profile.proof_timeout_seconds = 300
    mock_profile.get_artifact_paths.return_value = ("vk", "json", "C:\\root")
    mock_get_profile.return_value = mock_profile
    
    file_mock = MagicMock()
    file_mock.read.return_value = b"vkdata"
    mock_open.return_value.__enter__.return_value = file_mock
    
    with patch("hashlib.sha256") as mock_sha:
        mock_sha.return_value.hexdigest.return_value = "hash"
        
        res = verifier.verify(job.id, session, expected_sbom_root="0x0", expected_vulnerability_db_root="0x0", expected_policy_hash="0x0")
        
    assert res == "invalid_proof"
    mock_run.assert_called_once()

def test_archive_integrity_failure(mock_db_session):
    verifier = NoirVerifier()
    
    session = MagicMock()
    job = MagicMock(id=uuid4(), proof_archive_hash="expected_hash")
    session.query.return_value.filter.return_value.first.return_value = job
    
    chunks = [MagicMock() for _ in range(32)]
    session.query.return_value.filter.return_value.order_by.return_value.all.return_value = chunks
    
    with patch("verification_service.app.core.verifier.get_crypto_profile") as mock_get_profile:
        mock_profile = MagicMock()
        mock_profile.validate_proof_archive.side_effect = ValueError("Archive hash mismatch")
        mock_get_profile.return_value = mock_profile
        
        res = verifier.verify(job.id, session, expected_sbom_root="0x0", expected_vulnerability_db_root="0x0", expected_policy_hash="0x0")
        
    assert res == "invalid_proof"
    mock_profile.validate_proof_archive.assert_called_once()
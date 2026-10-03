import sys
import os
import uuid
import pytest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from zkp_service.app.services.prover_service import ProverService
from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof


@pytest.fixture
def mock_repo():
    return MagicMock()

@pytest.fixture
def mock_session():
    return MagicMock()

@pytest.fixture
def mock_crypto_profile():
    with patch("shared.crypto.config.get_crypto_profile") as mock_get_profile:
        mock_profile = MagicMock()
        mock_get_profile.return_value = mock_profile
        yield mock_profile

def test_component_chunking(mock_repo, mock_session, mock_crypto_profile):
    """
    Test Phase 2: Component chunking
    - exactly 1024 components
    - exactly 32 chunks
    - deterministic ordering
    """
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    
    # Mock dependencies for chunk derivation
    job_id = uuid.uuid4()
    job_mock = ProofJob(id=job_id, sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending")
    mock_repo.get_job.return_value = job_mock
    
    sbom = MagicMock()
    sbom.sbom_root = "0xsbomroot"
    
    snapshot = MagicMock()
    snapshot.provisional_smt_root = "0xsnapshotroot"
    
    policy = MagicMock()
    policy.policy_hash = "0xpolicyhash"
    policy.max_allowed_cvss_int = 50
    
    def query_side_effect(model):
        q = MagicMock()
        if model.__name__ == "SBOMUpload":
            q.filter.return_value.first.return_value = sbom
        elif model.__name__ == "VulnerabilitySnapshot":
            q.filter.return_value.first.return_value = snapshot
        elif model.__name__ == "SecurityPolicy":
            q.filter.return_value.first.return_value = policy
        elif model.__name__ == "Component":
            comps = []
            for i in range(50):
                c = MagicMock()
                c.component_hash = f"{i:064x}"
                comps.append(c)
            q.filter.return_value.order_by.return_value.all.return_value = comps
        elif model.__name__ == "ComponentVulnerabilityMapping":
            q.filter.return_value.all.return_value = []
        return q
        
    mock_session.query.side_effect = query_side_effect
    
    mock_repo.update_job_status.return_value = job_mock
    
    # Mock orchestrator to prevent actually running all chunks
    with patch.object(prover, "generate_all_chunk_proofs") as mock_generate_all:
        mock_generate_all.return_value = job_mock
        prover.process_job(job_id)
        
    # Verify exactly 32 chunks created
    assert mock_repo.create_chunk.call_count == 32
    
    # Verify exactly 32 * 8 = 256 segments created
    assert mock_repo.create_segment.call_count == 256
    
    # Verify deterministic ordering
    first_chunk_call = mock_repo.create_chunk.call_args_list[0]
    assert first_chunk_call.kwargs["chunk_index"] == 0
    assert first_chunk_call.kwargs["component_start"] == 0
    assert first_chunk_call.kwargs["component_count"] == 32
    
    last_chunk_call = mock_repo.create_chunk.call_args_list[31]
    assert last_chunk_call.kwargs["chunk_index"] == 31
    assert last_chunk_call.kwargs["component_start"] == 992
    assert last_chunk_call.kwargs["component_count"] == 32


def test_chunk_integrity_reject_oversized(mock_repo, mock_session, mock_crypto_profile):
    """
    Test Phase 2: Reject if components > 1024
    """
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    
    job_id = uuid.uuid4()
    job_mock = ProofJob(id=job_id, sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending")
    mock_repo.get_job.return_value = job_mock
    
    def query_side_effect(model):
        q = MagicMock()
        if model.__name__ == "Component":
            q.filter.return_value.order_by.return_value.all.return_value = [MagicMock()] * 1025
        else:
            q.filter.return_value.first.return_value = MagicMock()
            q.filter.return_value.all.return_value = []
        return q
        
    mock_session.query.side_effect = query_side_effect
    
    prover.process_job(job_id)
    
    # Verify rejection
    mock_repo.update_job_status.assert_any_call(job_id, "failed", error_message="Component count exceeds 1024")


def test_segment_execution_and_concurrency(mock_repo, mock_session, mock_crypto_profile):
    """
    Test Phase 2: Segment execution exactly 8 segments sequentially
    """
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    
    chunk = MagicMock()
    chunk.component_start = 0
    
    seg0, seg7 = MagicMock(), MagicMock()
    seg0.segment_index = 0
    seg7.segment_index = 7
    chunk.segments = [MagicMock(segment_index=i) for i in range(8)]
    
    padded = [{"hash": 0, "score": 0, "presence": 0} for _ in range(32)]
    smt = MagicMock()
    smt.get_path.return_value = [0] * 256
    
    # Verify that `generate_segment_proof` is called exactly 8 times sequentially
    with patch.object(prover, "generate_segment_proof") as mock_gen_seg:
        mock_gen_seg.return_value = True
        
        merkle_paths_all = [[[0]*10] for _ in range(32)]
        
        result = prover.generate_chunk_proofs(chunk, padded, smt, "0xsbom", "0xvuln", "0xpol", 50, merkle_paths_all)
        assert result is True
        assert mock_gen_seg.call_count == 8
        
        # Verify indices 0..7
        for i in range(8):
            args = mock_gen_seg.call_args_list[i].args
            assert args[6] == i  # seg_idx is 7th argument


def test_artifact_handling_and_crypto_boundary(mock_repo, mock_session, mock_crypto_profile):
    """
    Test Phase 2: Artifact handling and boundary verification
    Ensure clean temporary unique paths and immediate verification
    """
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    prover.circuit_dir = "/tmp/fake_circuits"
    
    seg_db = MagicMock()
    seg_db.id = uuid.uuid4()
    
    chunk_comps = [{"hash": 0, "score": 0, "presence": 0} for _ in range(32)]
    smt = MagicMock()
    smt.get_path.return_value = [0] * 256
    
    # We mock subprocess to pretend Nargo and BB succeed
    with patch("zkp_service.app.services.prover_service.subprocess.run") as mock_run, \
         patch("builtins.open", new_callable=MagicMock) as mock_open, \
         patch("zkp_service.app.services.prover_service.os.path.exists") as mock_exists, \
         patch("zkp_service.app.services.prover_service.os.remove") as mock_remove, \
         patch("zkp_service.app.services.prover_service.os.makedirs") as mock_makedirs:
         
        # Make run succeed
        mock_run.return_value = MagicMock(returncode=0)
        
        # Mock file read for base64 encode
        # Must be exactly 2304 bytes for segment_init_32 to pass the structural length check (ST21A-009)
        mock_file = MagicMock()
        mock_file.read.return_value = b"x" * 2304
        mock_open.return_value.__enter__.return_value = mock_file
        
        mock_exists.return_value = True
        mock_crypto_profile.decomposed_artifacts = {
            "segment_init_32": {
                "circuit_artifact_hash": "b7393cd49d8b09955d5d7eb531180d6c32d4ab688fd786b3520b2e4e230f617e",
                "vk_hash": "b7393cd49d8b09955d5d7eb531180d6c32d4ab688fd786b3520b2e4e230f617e"
            }
        }
        mock_crypto_profile.get_artifact_paths.return_value = ("vk", "json", "C:\\root")
        
        result = prover.generate_segment_proof(
            seg_db, "segment_init_32", chunk_comps, [[0]*10], smt, 0, 0, 0x1, 0x2, [0x0]*32, "0xsbom", "0xvuln", "0xpol", 50
        )
        
        assert result is True
        
        # Check subprocess calls (exactly 3: witness gen, bb prove, bb verify)
        assert mock_run.call_count == 3
        
        # Verify cleanup was called on the unique ID files
        uid = str(seg_db.id).replace("-", "")
        expected_prover_path = os.path.join("C:\\root", "segment_init_32", f"Prover_{uid}.toml")
        expected_target_gz = os.path.join("C:\\root", "segment_init_32", "target", f"witness_{uid}.gz")
        expected_proof_path = os.path.join("C:\\root", "segment_init_32", "proofs", f"proof_{uid}.proof")
        
        mock_remove.assert_any_call(expected_prover_path)
        mock_remove.assert_any_call(expected_target_gz)
        mock_remove.assert_any_call(expected_proof_path)
        
        mock_repo.update_segment_artifact.assert_called_once()
        args = mock_repo.update_segment_artifact.call_args.args
        assert args[0] == seg_db.id
        assert args[1] == "completed"

def test_archive_proofs_negative_incomplete(mock_repo, mock_session, mock_crypto_profile):
    """
    Test Phase 2: Archive creation fails if proofs are missing
    """
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    
    job = MagicMock()
    job.id = uuid.uuid4()
    job.sbom_upload_id = uuid.uuid4()
    job.snapshot_id = uuid.uuid4()
    job.sbom_root = "0xsbom"
    job.vulnerability_db_root = "0xvuln"
    job.policy_hash = "0xpol"
    job.user_id = uuid.uuid4()
    
    # Create chunks but only 255 segments have proof_artifact
    chunks = []
    for c_idx in range(32):
        chunk = MagicMock()
        chunk.chunk_index = c_idx
        chunk.component_start = c_idx * 32
        chunk.component_count = 32
        chunk.components_commit = "0xcommit"
        segments = []
        for s_idx in range(8):
            seg = MagicMock()
            seg.segment_index = s_idx
            seg.hash_in_commit = "0xin"
            seg.hash_out_commit = "0xout"
            
            # Missing proof artifact for the very last segment
            if c_idx == 31 and s_idx == 7:
                seg.proof_artifact = None
            else:
                import base64
                seg.proof_artifact = base64.b64encode(b"fake_proof_data").decode("utf-8")
                
            segments.append(seg)
        chunk.segments = segments
        chunks.append(chunk)
        
    job.chunks = chunks
    
    mock_crypto_profile.nargo_version = "0.32.0"
    mock_crypto_profile.profile_name = "test_profile"
    mock_crypto_profile.decomposed_artifacts = {}
    mock_crypto_profile.get_artifact_paths.return_value = ("vk", "json", "root")
    
    with pytest.raises(ValueError, match="Incomplete proof set: Missing proof artifacts"):
        prover._archive_proofs(job)


def test_resource_control_limits(mock_repo, mock_session, mock_crypto_profile):
    """
    Test Phase 2: Prover resource limits (ST21A-011)
    """
    from zkp_service.app.services.prover_service import ProverService, _global_prover_lock, _user_lock, _user_active_jobs
    
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    job_id = uuid.uuid4()
    
    # 1. Test global lock limit
    _global_prover_lock.acquire()
    try:
        prover.process_job(job_id)
        mock_repo.update_job_status.assert_called_with(job_id, "failed", error_message="Server is at capacity. Only one proof job can run concurrently.")
    finally:
        _global_prover_lock.release()
        
    # 2. Test user quota limit
    job = MagicMock()
    job.user_id = uuid.uuid4()
    mock_repo.get_job.return_value = job
    
    with _user_lock:
        _user_active_jobs[str(job.user_id)] = 1
        
    try:
        prover.process_job(job_id)
        mock_repo.update_job_status.assert_called_with(job_id, "failed", error_message="Per-user quota exceeded")
    finally:
        with _user_lock:
            del _user_active_jobs[str(job.user_id)]

def test_prover_lock_released_on_missing_job(mock_repo, mock_session, mock_crypto_profile):
    from zkp_service.app.services.prover_service import ProverService, _global_prover_lock
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    mock_repo.get_job.return_value = None
    job_id = uuid.uuid4()
    
    assert prover.process_job(job_id) is None
    
    # Assert lock is released (we can acquire it without blocking)
    acquired = _global_prover_lock.acquire(blocking=False)
    assert acquired
    if acquired: _global_prover_lock.release()

def test_prover_lock_released_on_repo_exception(mock_repo, mock_session, mock_crypto_profile):
    from zkp_service.app.services.prover_service import ProverService, _global_prover_lock
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    mock_repo.get_job.side_effect = Exception("DB error")
    job_id = uuid.uuid4()
    
    prover.process_job(job_id)
    
    acquired = _global_prover_lock.acquire(blocking=False)
    assert acquired
    if acquired: _global_prover_lock.release()

def test_prover_lock_released_on_validation_exception(mock_repo, mock_session, mock_crypto_profile):
    from zkp_service.app.services.prover_service import ProverService, _global_prover_lock
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    
    job_id = uuid.uuid4()
    job_mock = ProofJob(id=job_id, sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending", user_id=uuid.uuid4())
    mock_repo.get_job.return_value = job_mock
    
    # Mock missing upstream data (validation exception)
    mock_session.query.side_effect = Exception("Query error")
    
    prover.process_job(job_id)
    
    acquired = _global_prover_lock.acquire(blocking=False)
    assert acquired
    if acquired: _global_prover_lock.release()

def test_prover_lock_released_on_proof_exception(mock_repo, mock_session, mock_crypto_profile):
    from zkp_service.app.services.prover_service import ProverService, _global_prover_lock
    prover = ProverService(mock_session)
    prover._repo = mock_repo
    
    job_id = uuid.uuid4()
    job_mock = ProofJob(id=job_id, sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending", user_id=uuid.uuid4())
    mock_repo.get_job.return_value = job_mock
    
    def query_side_effect(model):
        q = MagicMock()
        q.filter.return_value.first.return_value = MagicMock()
        q.filter.return_value.all.return_value = []
        return q
    mock_session.query.side_effect = query_side_effect
    
    with patch.object(prover, "generate_all_chunk_proofs", side_effect=Exception("Proof error")):
        prover.process_job(job_id)
        
    acquired = _global_prover_lock.acquire(blocking=False)
    assert acquired
    if acquired: _global_prover_lock.release()

def test_archive_validation_oversized(mock_repo, mock_session, mock_crypto_profile):
    from shared.crypto.config import CryptoProfile
    import os
    
    # Use real CryptoProfile
    profile = CryptoProfile("test", {"max_proof_size_bytes": 5000})
    
    with patch('os.path.exists', return_value=True), \
         patch('os.path.getsize', return_value=52428801): # > 50MB
        with pytest.raises(ValueError, match="Archive size 52428801 exceeds 50MB bound"):
            profile.validate_proof_archive("fake_path.zip")
            
def test_archive_validation_missing(mock_repo, mock_session, mock_crypto_profile):
    from shared.crypto.config import CryptoProfile
    profile = CryptoProfile("test", {"max_proof_size_bytes": 5000})
    with patch('os.path.exists', return_value=False):
        with pytest.raises(ValueError, match="Archive does not exist"):
            profile.validate_proof_archive("fake_path.zip")



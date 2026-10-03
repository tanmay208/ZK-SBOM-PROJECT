import pytest
from unittest.mock import MagicMock
from uuid import uuid4
from verification_service.app.core.verifier import NoirVerifier

def _make_verifier_session(chunks_list, segments_list):
    session = MagicMock()
    job = MagicMock(id=uuid4())
    
    def query_mock(model):
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ChunkProofSet":
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: chunks_list)))
        if model.__name__ == "SegmentProof":
            # Just return all for any chunk, simplifies mock
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: segments_list)))
        return MagicMock()
    
    session.query.side_effect = query_mock
    return session, job.id

def test_missing_chunk():
    verifier = NoirVerifier()
    chunks = [MagicMock(chunk_index=i, status="completed") for i in range(31)] # Missing 31
    session, job_id = _make_verifier_session(chunks, [])
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_duplicate_chunk():
    verifier = NoirVerifier()
    chunks = [MagicMock(chunk_index=i, status="completed") for i in range(32)]
    chunks.append(MagicMock(chunk_index=0, status="completed")) # Duplicate 0
    session, job_id = _make_verifier_session(chunks, [])
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_reordered_chunk():
    verifier = NoirVerifier()
    chunks = [MagicMock(chunk_index=i, status="completed") for i in range(32)]
    chunks[0], chunks[1] = chunks[1], chunks[0]
    session, job_id = _make_verifier_session(chunks, [])
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_wrong_total_chunks():
    verifier = NoirVerifier()
    job_id = uuid4()
    chunks = [MagicMock(chunk_index=i, status="completed", proof_job_id=job_id, total_chunks=31) for i in range(32)]
    session, _ = _make_verifier_session(chunks, [])
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_wrong_component_start():
    verifier = NoirVerifier()
    job_id = uuid4()
    chunks = [MagicMock(chunk_index=i, status="completed", proof_job_id=job_id, total_chunks=32, component_start=i*32+1, component_count=32) for i in range(32)]
    session, _ = _make_verifier_session(chunks, [])
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_wrong_component_count():
    verifier = NoirVerifier()
    job_id = uuid4()
    chunks = [MagicMock(chunk_index=i, status="completed", proof_job_id=job_id, total_chunks=32, component_start=i*32, component_count=31) for i in range(32)]
    session, _ = _make_verifier_session(chunks, [])
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_missing_segment():
    verifier = NoirVerifier()
    job_id = uuid4()
    chunks = [MagicMock(chunk_index=i, status="completed", proof_job_id=job_id, total_chunks=32, component_start=i*32, component_count=32) for i in range(32)]
    segments = [MagicMock(segment_index=i) for i in range(7)] # Missing 7
    session, _ = _make_verifier_session(chunks, segments)
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_duplicate_segment():
    verifier = NoirVerifier()
    job_id = uuid4()
    chunks = [MagicMock(chunk_index=i, status="completed", proof_job_id=job_id, total_chunks=32, component_start=i*32, component_count=32) for i in range(32)]
    segments = [MagicMock(segment_index=i) for i in range(8)]
    segments.append(MagicMock(segment_index=0)) # Duplicate 0
    session, _ = _make_verifier_session(chunks, segments)
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_reordered_segment():
    verifier = NoirVerifier()
    job_id = uuid4()
    chunks = [MagicMock(chunk_index=i, status="completed", proof_job_id=job_id, total_chunks=32, component_start=i*32, component_count=32) for i in range(32)]
    segments = [MagicMock(segment_index=i) for i in range(8)]
    segments[0], segments[1] = segments[1], segments[0]
    session, _ = _make_verifier_session(chunks, segments)
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

def test_segment_from_another_job():
    verifier = NoirVerifier()
    job_id = uuid4()
    other_job_id = uuid4()
    chunks = [MagicMock(chunk_index=i, status="completed", proof_job_id=job_id if i > 0 else other_job_id, total_chunks=32, component_start=i*32, component_count=32) for i in range(32)]
    session, _ = _make_verifier_session(chunks, [])
    assert verifier.verify(job_id, session, "a", "b", "c") == "invalid_proof"

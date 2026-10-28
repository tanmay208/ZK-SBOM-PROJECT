import pytest
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from sqlalchemy.ext.compiler import compiles
from shared.database import Base

@compiles(UNIQUEIDENTIFIER, 'sqlite')
def compile_uniqueidentifier(type_, compiler, **kw):
    return "VARCHAR(36)"

# Import models so they are attached to Base
from shared.models.user import User
from sbom_service.app.models.sbom_models import SBOMUpload
from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot
from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
from policy_service.app.models.policy_models import SecurityPolicy
from verification_service.app.models.verification_models import VerificationRequest, VerificationCertificate

@pytest.fixture
def memory_db_session():
    # Use SQLite memory DB for constraint testing
    engine = create_engine("sqlite:///:memory:")
    
    from sqlalchemy import event, text
    from datetime import datetime, timezone
    
    @event.listens_for(engine, "connect")
    def receive_connect(dbapi_connection, connection_record):
        dbapi_connection.create_function("getutcdate", 0, lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    
    with engine.connect() as conn:
        conn.execute(text("ATTACH DATABASE ':memory:' AS sbom"))
        conn.execute(text("ATTACH DATABASE ':memory:' AS vulnerability"))
        conn.execute(text("ATTACH DATABASE ':memory:' AS policy"))
        conn.execute(text("ATTACH DATABASE ':memory:' AS zkp"))
        conn.execute(text("ATTACH DATABASE ':memory:' AS verification"))
    
    # SQLite enforces CHECK constraints if we just let it create tables.
    Base.metadata.create_all(engine)
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    yield session
    session.close()

def test_chunk_index_bounds(memory_db_session):
    job = ProofJob(sbom_upload_id=uuid.UUID("11111111-1111-1111-1111-111111111111"), snapshot_id=uuid.UUID("11111111-1111-1111-1111-111111111111"), policy_id=uuid.UUID("11111111-1111-1111-1111-111111111111"))
    memory_db_session.add(job)
    memory_db_session.commit()
    
    # Valid chunk
    chunk_valid = ChunkProofSet(proof_job_id=job.id, chunk_index=0, total_chunks=32, component_start=0, component_count=32)
    memory_db_session.add(chunk_valid)
    memory_db_session.commit()
    
    # Invalid chunk index (>= 32)
    chunk_invalid = ChunkProofSet(proof_job_id=job.id, chunk_index=32, total_chunks=32, component_start=32*32, component_count=32)
    memory_db_session.add(chunk_invalid)
    with pytest.raises(IntegrityError):
        memory_db_session.commit()
    memory_db_session.rollback()

def test_segment_index_bounds(memory_db_session):
    job = ProofJob(sbom_upload_id=uuid.UUID("11111111-1111-1111-1111-111111111111"), snapshot_id=uuid.UUID("11111111-1111-1111-1111-111111111111"), policy_id=uuid.UUID("11111111-1111-1111-1111-111111111111"))
    memory_db_session.add(job)
    memory_db_session.commit()
    
    chunk = ChunkProofSet(proof_job_id=job.id, chunk_index=1, total_chunks=32, component_start=32, component_count=32)
    memory_db_session.add(chunk)
    memory_db_session.commit()
    
    # Valid segment
    seg_valid = SegmentProof(chunk_id=chunk.id, chunk_index=1, total_chunks=32, segment_index=0)
    memory_db_session.add(seg_valid)
    memory_db_session.commit()
    
    # Invalid segment index (>= 8)
    seg_invalid = SegmentProof(chunk_id=chunk.id, chunk_index=1, total_chunks=32, segment_index=8)
    memory_db_session.add(seg_invalid)
    with pytest.raises(IntegrityError):
        memory_db_session.commit()
    memory_db_session.rollback()
    
def test_certificate_1_to_1_verification(memory_db_session):
    req = VerificationRequest(proof_job_id=uuid.UUID("11111111-1111-1111-1111-111111111111"), sbom_root="a", vulnerability_db_root="b", policy_hash="c", result="verified")
    memory_db_session.add(req)
    memory_db_session.commit()
    
    cert1 = VerificationCertificate(verification_request_id=req.id, certificate_data="data1", sbom_root="a", vulnerability_db_root="b", policy_hash="c")
    memory_db_session.add(cert1)
    memory_db_session.commit()
    
    # Duplicate cert for same request should fail unique constraint
    cert2 = VerificationCertificate(verification_request_id=req.id, certificate_data="data2", sbom_root="a", vulnerability_db_root="b", policy_hash="c")
    memory_db_session.add(cert2)
    with pytest.raises(IntegrityError):
        memory_db_session.commit()
    memory_db_session.rollback()


def test_certificate_revocation_state_constraint(memory_db_session):
    req = VerificationRequest(
        proof_job_id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
        sbom_root="a",
        vulnerability_db_root="b",
        policy_hash="c",
        result="verified",
    )
    memory_db_session.add(req)
    memory_db_session.commit()

    invalid = VerificationCertificate(
        verification_request_id=req.id,
        certificate_data="data",
        sbom_root="a",
        vulnerability_db_root="b",
        policy_hash="c",
        is_revoked=True,
    )
    memory_db_session.add(invalid)
    with pytest.raises(IntegrityError):
        memory_db_session.commit()
    memory_db_session.rollback()

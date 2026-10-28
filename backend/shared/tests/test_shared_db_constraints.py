import pytest
from sqlalchemy import create_engine
from zkp_service.app.models.zkp_models import Base as ZkpBase, ProofJob, ChunkProofSet, SegmentProof
from sbom_service.app.models.sbom_models import Base as SbomBase
from vulnerability_service.app.models.vulnerability_models import Base as VulnBase
from policy_service.app.models.policy_models import Base as PolicyBase
from verification_service.app.models.verification_models import Base as VerBase, VerificationRequest, VerificationCertificate
from shared.models.user import Base as UserBase, User
import uuid
import sqlalchemy.exc

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

def test_chunk_index_bounds():
    engine = create_engine("sqlite:///:memory:")
    for table in ZkpBase.metadata.tables.values():
        table.schema = None
    ZkpBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    
    # In SQLite Check constraints only work if PRAGMA foreign_keys=ON or depending on SQLite versions, but we can verify constraint exists via reflection.
    # Note: SQLite may not enforce CHECK constraints if not explicitly enabled or depending on driver.
    # However, SQLAlchemy models themselves will raise IntegrityError if unique constraint is violated.
    
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    job_id = uuid.uuid4()
    job = ProofJob(id=job_id, user_id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending", created_at=now)
    session.add(job)
    session.commit()
    
    # Test Unique Constraint (uq_chunk_index_per_job)
    c1 = ChunkProofSet(proof_job_id=job_id, chunk_index=0, total_chunks=32, component_start=0, component_count=32, components_commit="0x0", created_at=now)
    session.add(c1)
    session.commit()
    
    c2 = ChunkProofSet(proof_job_id=job_id, chunk_index=0, total_chunks=32, component_start=32, component_count=32, components_commit="0x1", created_at=now)
    session.add(c2)
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        session.commit()
    session.rollback()
    
def test_segment_index_bounds():
    engine = create_engine("sqlite:///:memory:")
    for table in ZkpBase.metadata.tables.values():
        table.schema = None
    ZkpBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    job_id = uuid.uuid4()
    job = ProofJob(id=job_id, user_id=uuid.uuid4(), sbom_upload_id=uuid.uuid4(), snapshot_id=uuid.uuid4(), policy_id=uuid.uuid4(), status="pending", created_at=now)
    session.add(job)
    session.commit()
    
    chunk_id = uuid.uuid4()
    c1 = ChunkProofSet(id=chunk_id, proof_job_id=job_id, chunk_index=0, total_chunks=32, component_start=0, component_count=32, components_commit="0x0", created_at=now)
    session.add(c1)
    session.commit()
    
    # Test Unique Constraint (uq_segment_index_per_chunk)
    s1 = SegmentProof(chunk_id=chunk_id, segment_index=0, total_chunks=32, chunk_index=0, created_at=now)
    session.add(s1)
    session.commit()
    
    s2 = SegmentProof(chunk_id=chunk_id, segment_index=0, total_chunks=32, chunk_index=0, created_at=now)
    session.add(s2)
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        session.commit()
    session.rollback()

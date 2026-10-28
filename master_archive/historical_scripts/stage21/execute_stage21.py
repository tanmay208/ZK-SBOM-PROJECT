import os
import sys
import json
import traceback
import subprocess
from uuid import uuid4

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from shared.database import Base
from shared.models.user import User

import sbom_service.app.models.sbom_models
import vulnerability_service.app.models.vulnerability_models
import policy_service.app.models.policy_models
import zkp_service.app.models.zkp_models
import verification_service.app.models.verification_models

from sbom_service.app.services.sbom_intake_service import SBOMIntakeService
from sbom_service.app.schemas.sbom_schemas import SBOMUploadRequest

from policy_service.app.services.policy_service import create_policy
from policy_service.app.schemas.policy_schemas import PolicyCreateRequest
from zkp_service.app.services.prover_service import ProverService
from zkp_service.app.repositories.zkp_repository import ZKPRepository
from zkp_service.app.schemas.zkp_schemas import GenerateProofRequest
from verification_service.app.services.verification_service import VerificationService

def main():
    print("STAGE 21 — FULL 1024-COMPONENT E2E CRYPTOGRAPHIC VALIDATION")
    
    import tempfile
    
    # Set up test profile with decomposed artifacts
    profile_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "shared", "crypto", "profile.json"))
    with open(profile_path, "r") as f:
        manifest = json.load(f)
        
    manifest["profiles"]["prod"]["decomposed_artifacts"] = {
        "segment_init_32": {
            "circuit_artifact_hash": "3d529f2528d1adc77d6085e94b7da2287a3ab460159586b4add3c62c5c18e535",
            "vk_hash": "3fa91fd9f1e797000b3f773774f697621c1b7ed3f1eebd99e4f65f2a4c3a6480"
        },
        "segment_mid_32": {
            "circuit_artifact_hash": "c45a306d8f3d143577baa880356213575d9c339dd2905ccfb779b0a5f2fb9eab",
            "vk_hash": "820a2ac24f2f5baa0a674cdb4a4b99dd011c5645fe96c3cd3b628fcbe579d247"
        },
        "segment_final_32": {
            "circuit_artifact_hash": "60289dda7350161f37cfaf6b8519f07b221009b08ddd45a4f1337bf77c62fe41",
            "vk_hash": "5faba2640b5f32d96099e1d133aa2c74402cb346db9597bcaaf301e5c2fe9910"
        }
    }
    
    fd, temp_profile_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(manifest, f)
        
    os.environ["CRYPTO_PROFILE_PATH"] = temp_profile_path
    os.environ["CRYPTO_PROFILE"] = "prod"

    print("Setting up isolated SQLite test environment...")
    
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    
    # Fix UNIQUEIDENTIFIER for SQLite
    from sqlalchemy.ext.compiler import compiles
    from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
    @compiles(UNIQUEIDENTIFIER, 'sqlite')
    def compile_uniqueidentifier(element, compiler, **kw):
        return "CHAR(36)"
        
    # Fix getutcdate for SQLite via UDF
    from sqlalchemy import event
    from datetime import datetime
    import sqlite3
    
    @event.listens_for(engine, "connect")
    def do_connect(dbapi_connection, connection_record):
        if isinstance(dbapi_connection, sqlite3.Connection):
            dbapi_connection.create_function("getutcdate", 0, lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        
    from sqlalchemy import text
    with engine.connect() as conn:
        for schema in ['sbom', 'vulnerability', 'policy', 'zkp', 'verification']:
            conn.execute(text(f"ATTACH DATABASE ':memory:' AS {schema}"))
            
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db: Session = TestingSession()
    
    # Create test user
    user = User(id=uuid4(), username="admin", hashed_password="hashed", role="admin")
    db.add(user)
    db.commit()
    
    # Load payload
    print("Loading deterministic 1024-component dataset...")
    with open("scripts/stage21_payload.json", "r") as f:
        payload = json.load(f)
        
    try:
        # Phase 1: SBOM Ingestion
        print("PHASE 1: Authoritative SBOM Ingestion...")
        sbom_svc = SBOMIntakeService(db)
        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": payload["components"]
        }
        sbom_resp = sbom_svc.ingest(
            application_name="Stage 21 App",
            vendor="Stage 21 Vendor",
            filename="stage21_bom.json",
            format="CycloneDX",
            content=json.dumps(cyclonedx),
            user_id=user.id
        )
        print(f"  -> SBOM Root: {sbom_resp.sbom_root}")
        assert sbom_resp.sbom_root is not None
        
        # Phase 2: Vulnerability Ingestion
        print("PHASE 2: Authoritative Vulnerability Snapshot...")
        from vulnerability_service.app.services.vulnerability_service import ingest_vulnerabilities
        from vulnerability_service.app.schemas.vulnerability_schemas import VulnerabilityIngestionRequest, VulnerabilityIngestionItem
        vul_req = VulnerabilityIngestionRequest(
            vulnerabilities=[VulnerabilityIngestionItem(**v) for v in payload["vulnerabilities"]]
        )
        vul_resp = ingest_vulnerabilities(db, vul_req, user.id)
        
        # Get the actual snapshot from DB to get provisional_smt_root
        import uuid
        from vulnerability_service.app.api.routes.vulnerability_routes import approve_snapshot
        snapshot_uuid = uuid.UUID(vul_resp.snapshot_id)
        snap_resp = approve_snapshot(snapshot_uuid, db, user)
        
        snapshot_model = db.query(vulnerability_service.app.models.vulnerability_models.VulnerabilitySnapshot).filter_by(id=snapshot_uuid).first()
        print(f"  -> Provisional SMT Root: {snapshot_model.provisional_smt_root}")
        assert snapshot_model.provisional_smt_root is not None
        
        # Phase 3: Policy Ingestion
        print("PHASE 3: Authoritative Policy Evaluation...")
        from policy_service.app.api.routes.policy_routes import add_policy
        pol_req = PolicyCreateRequest(
            name="Stage 21 Max CVSS 5.0",
            max_cvss_score=payload["policy"]["max_cvss_score"]
        )
        pol_resp = add_policy(pol_req, db, user)
        print(f"  -> Policy Hash: {pol_resp.policy_hash}")
        assert pol_resp.policy_hash is not None
        
        # Phase 4: ZKP Orchestration (THE BIG ONE)
        print("PHASE 4: Cryptographic Proof Generation (256 proofs)...")
        print("  WARNING: This will take several hours to complete. Using Nargo & Barretenberg via WSL.")
        
        # Validate that `nargo` exists in WSL
        res = subprocess.run(["wsl", "-d", "kali-linux", "--", "bash", "-c", "ls ~/.nargo/bin/nargo"], capture_output=True, text=True)
        if res.returncode != 0:
            print("  ERROR: nargo not found in WSL. Cannot proceed with real proofs.")
            sys.exit(1)
            
        prover_repo = ZKPRepository(db)
        job_req = GenerateProofRequest(
            sbom_upload_id=sbom_resp.id,
            snapshot_id=vul_resp.snapshot_id,
            policy_id=pol_resp.id
        )
        job = prover_repo.create_job(job_req, user.id)
        print(f"  -> Created ProofJob: {job.id}")
        
        # Run prover synchronously
        prover = ProverService(db)
        prover.circuit_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        print(f"  -> Circuit Dir: {prover.circuit_dir}")
        
        final_job = prover.process_job(job.id)
        if final_job.status != "completed":
            print(f"  -> Proof Job FAILED: {final_job.error_message}")
            sys.exit(1)
            
        print("  -> Proof Job COMPLETED! 256 proofs generated and structurally bound.")
        
        # Phase 5: Verification
        print("PHASE 5: Backend Cryptographic Verification...")
        from verification_service.app.schemas.verification_schemas import VerifyProofRequest
        verifier = VerificationService(db)
        verify_req = VerifyProofRequest(
            sbom_root=sbom_resp.sbom_root,
            vulnerability_db_root=snapshot_model.provisional_smt_root,
            policy_hash=pol_resp.policy_hash,
            proof_job_id=final_job.id
        )
        verify_resp = verifier.process_verification(verify_req, user.id)
        
        if verify_resp.result == "verified":
            print(f"  -> Verification SUCCESS! Certificate Request ID: {verify_resp.id}")
        else:
            print(f"  -> Verification FAILED: {verify_resp.result}")
            sys.exit(1)
            
        print("\nSTAGE 21 COMPLETION: Authoritative cryptographic validation has succeeded!")
        
    except Exception as e:
        print(f"Error during execution: {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    main()

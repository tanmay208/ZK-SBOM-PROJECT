import abc
import logging
from uuid import UUID
import base64
import tempfile
import subprocess
import os
import uuid
import hashlib
from shared.crypto.config import get_crypto_profile

logger = logging.getLogger(__name__)


class AbstractVerifier(abc.ABC):
    @abc.abstractmethod
    def verify(
        self,
        proof_job_id: UUID | None,
        session,
        expected_sbom_root: str | None = None,
        expected_vulnerability_db_root: str | None = None,
        expected_policy_hash: str | None = None,
    ) -> str:
        """
        Verify the 256-proof set structurally.
        """
        pass


class NoirVerifier(AbstractVerifier):
    def __init__(self):
        pass

    def verify(
        self,
        proof_job_id: UUID | None,
        session,
        expected_sbom_root: str | None = None,
        expected_vulnerability_db_root: str | None = None,
        expected_policy_hash: str | None = None,
    ) -> str:
        if not proof_job_id:
            return "verification_unavailable"

        if not expected_sbom_root or not expected_vulnerability_db_root or not expected_policy_hash:
            raise ValueError("Missing expected public inputs for ZK-002 binding")

        from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
        
        try:
            job = session.query(ProofJob).filter(ProofJob.id == proof_job_id).first()
            if not job:
                return "invalid_proof"
                
            chunks = session.query(ChunkProofSet).filter(ChunkProofSet.proof_job_id == job.id).order_by(ChunkProofSet.chunk_index).all()
            if len(chunks) != 32:
                logger.error(f"Expected 32 chunks, found {len(chunks)}")
                return "invalid_proof"
                
            # Archive Integrity Check with Semantic Binding (Finding D)
            if job.proof_archive_hash:
                import os
                project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
                archive_path = os.path.join(project_root, "archives", "proofs", f"{job.id}.zip")
                
                # Gather authoritative hashes from DB for cross-reference
                expected_member_hashes = {}
                for chunk in chunks:
                    segs = session.query(SegmentProof).filter(SegmentProof.chunk_id == chunk.id).all()
                    for seg in segs:
                        expected_member_hashes[f"chunk_{chunk.chunk_index}_segment_{seg.segment_index}.proof"] = seg.proof_artifact_hash

                try:
                    profile = get_crypto_profile()
                    expected_manifest = {
                        "job_id": str(job.id),
                        "sbom_upload_id": str(job.sbom_upload_id),
                        "snapshot_id": str(job.snapshot_id),
                        "sbom_root": expected_sbom_root,
                        "vulnerability_db_root": expected_vulnerability_db_root,
                        "policy_hash": expected_policy_hash,
                        "profile_identity": profile.profile_name,
                        "total_chunks": 32,
                        "total_segments": 256,
                    }
                    profile.validate_proof_archive(
                        archive_path, 
                        expected_hash=job.proof_archive_hash, 
                        expected_proof_count=256,
                        expected_member_hashes=expected_member_hashes,
                        expected_manifest=expected_manifest,
                    )
                except Exception as e:
                    logger.error(f"Archive integrity validation failed: {e}")
                    # If the archive is missing or corrupted, we fail the verification because the integrity of the forensic record is compromised.
                    return "invalid_proof"
                
            chunk_indices = [c.chunk_index for c in chunks]
            if chunk_indices != list(range(32)):
                logger.error("Chunk indices are not exactly 0..31 or are duplicated/reordered")
                return "invalid_proof"
                
            for chunk in chunks:
                if chunk.proof_job_id != job.id:
                    return "invalid_proof"
                if chunk.total_chunks != 32:
                    return "invalid_proof"
                if chunk.component_start != chunk.chunk_index * 32:
                    return "invalid_proof"
                if chunk.component_count != 32:
                    return "invalid_proof"
                    
                if chunk.status != "completed":
                    logger.error(f"Chunk {chunk.chunk_index} is not completed")
                    return "invalid_proof"
                    
                segments = session.query(SegmentProof).filter(SegmentProof.chunk_id == chunk.id).order_by(SegmentProof.segment_index).all()
                if len(segments) != 8:
                    logger.error(f"Expected 8 segments for chunk {chunk.chunk_index}, found {len(segments)}")
                    return "invalid_proof"
                    
                segment_indices = [s.segment_index for s in segments]
                if segment_indices != list(range(8)):
                    logger.error(f"Segment indices in chunk {chunk.chunk_index} are not exactly 0..7")
                    return "invalid_proof"
                
                # Check components_commit equality and cross-reference constraints
                c_commit = chunk.components_commit
                for seg in segments:
                    if seg.chunk_index != chunk.chunk_index:
                        logger.error(f"Segment chunk_index ({seg.chunk_index}) mismatch parent ({chunk.chunk_index})")
                        return "invalid_proof"
                    if seg.total_chunks != chunk.total_chunks:
                        logger.error(f"Segment total_chunks ({seg.total_chunks}) mismatch parent ({chunk.total_chunks})")
                        return "invalid_proof"
                    if seg.components_commit != c_commit:
                        logger.error(f"Components commit mismatch in chunk {chunk.chunk_index} segment {seg.segment_index}")
                        return "public_input_mismatch"
                        
                    if seg.status != "completed":
                        logger.error(f"Segment {seg.segment_index} not completed")
                        return "invalid_proof"
                        
                    # Cryptographic verification using bb verify
                    segment_name = "segment_init_32" if seg.segment_index == 0 else ("segment_final_32" if seg.segment_index == 7 else "segment_mid_32")
                    
                    profile = get_crypto_profile()
                    vk_path_win, _, project_root_win = profile.get_artifact_paths(segment_name)
                    
                    pass
                        
                    if not seg.proof_artifact:
                        logger.error(f"Proof artifact missing for segment {seg.segment_index}")
                        return "invalid_proof"
                        
                    proof_bytes = base64.b64decode(seg.proof_artifact)
                    
                    actual_proof_hash = hashlib.sha256(proof_bytes).hexdigest()
                    if actual_proof_hash != seg.proof_artifact_hash:
                        logger.error(f"Proof artifact hash mismatch for segment {seg.segment_index}")
                        return "invalid_proof"
                        
                    try:
                        profile.validate_segment_proof(segment_name, proof_bytes)
                    except ValueError as e:
                        logger.error(f"Segment proof validation failed: {e}")
                        return "invalid_proof"
                        
                    def parse_hex(val) -> int:
                        if isinstance(val, str):
                            return int(val, 16)
                        return int(val)
                        
                    def extract_pi(index: int) -> int:
                        # RUNTIME VALIDATION PENDING: BB proof format serialization order (Public Inputs offset)
                        return int.from_bytes(proof_bytes[index*32:(index+1)*32], "big")
                        
                    if seg.segment_index == 0:
                        if extract_pi(0) != parse_hex(expected_sbom_root): return "public_input_mismatch"
                        if extract_pi(1) != parse_hex(expected_policy_hash): return "public_input_mismatch"
                        if extract_pi(2) != chunk.chunk_index: return "public_input_mismatch"
                        if extract_pi(3) != parse_hex(chunk.components_commit): return "public_input_mismatch"
                        if extract_pi(4) != parse_hex(seg.hash_out_commit): return "public_input_mismatch"
                    elif seg.segment_index == 7:
                        if extract_pi(0) != parse_hex(expected_vulnerability_db_root): return "public_input_mismatch"
                        if extract_pi(1) != parse_hex(chunk.components_commit): return "public_input_mismatch"
                        if extract_pi(2) != parse_hex(seg.hash_in_commit): return "public_input_mismatch"
                    else:
                        if extract_pi(0) != seg.segment_index: return "public_input_mismatch"
                        if extract_pi(1) != parse_hex(chunk.components_commit): return "public_input_mismatch"
                        if extract_pi(2) != parse_hex(seg.hash_in_commit): return "public_input_mismatch"
                        if extract_pi(3) != parse_hex(seg.hash_out_commit): return "public_input_mismatch"

                    uid = uuid.uuid4().hex
                    proofs_dir_win = os.path.join(project_root_win, segment_name, "proofs")
                    os.makedirs(proofs_dir_win, exist_ok=True)
                    temp_proof_path = os.path.join(proofs_dir_win, f"verify_{uid}.proof")
                    
                    try:
                        with open(temp_proof_path, "wb") as f:
                            f.write(proof_bytes)
                            
                        # WSL paths mapping
                        drive, tail = os.path.splitdrive(project_root_win)
                        project_root_linux = f"/mnt/{drive.lower()[0]}{tail.replace(os.sep, '/')}"
                        vk_path_linux = f"{project_root_linux}/{segment_name}/target/vk"
                        temp_proof_linux = f"{project_root_linux}/{segment_name}/proofs/verify_{uid}.proof"
                        
                        cmd = [
                            "wsl", "-d", "kali-linux", "--", "bash", "-c",
                            f"~/.bb/bb verify -k '{vk_path_linux}' -p '{temp_proof_linux}'"
                        ]
                        try:
                            res = subprocess.run(cmd, capture_output=True, check=False, timeout=profile.proof_timeout_seconds)
                            if res.returncode != 0:
                                logger.error(f"bb verify failed for segment {seg.segment_index} of chunk {chunk.chunk_index}: {res.stderr.decode('utf-8', errors='replace')}")
                                return "invalid_proof"
                        except subprocess.TimeoutExpired:
                            logger.error(f"bb verify timed out for segment {seg.segment_index} of chunk {chunk.chunk_index}")
                            return "invalid_proof"
                        except Exception as e:
                            logger.error(f"bb verify subprocess error for segment {seg.segment_index} of chunk {chunk.chunk_index}: {e}")
                            return "invalid_proof"
                    finally:
                        if os.path.exists(temp_proof_path):
                            os.remove(temp_proof_path)
                        
                # Check hash linkage
                for i in range(7):
                    if segments[i].hash_out_commit != segments[i+1].hash_in_commit:
                        logger.error(f"Hash linkage broken between {i} and {i+1} in chunk {chunk.chunk_index}")
                        return "public_input_mismatch"

            return "verified"
            
        except Exception:
            logger.exception("Verification failed with exception")
            return "invalid_proof"

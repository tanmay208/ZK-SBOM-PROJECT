import abc
import logging
from uuid import UUID
import base64
import os
import hashlib
from shared.crypto.config import get_crypto_profile
from verification_service.app.core.legacy_acir import (
    LegacyAcirVerificationError,
    LegacyAcirRuntimeError,
    StructuralRejectionError,
    RuntimeFailureError,
    EnvironmentFailureError,
    CryptographicFalseError,
    verify_bound_proof,
)

logger = logging.getLogger(__name__)

# Verifier Error Taxonomy (CRYPTOGRAPHY_RULES.md §7)
VERIFIED = "verified"
STRUCTURAL_REJECTION = "structural_rejection"
RUNTIME_FAILURE = "runtime_failure"
ENVIRONMENT_FAILURE = "environment_failure"
CRYPTOGRAPHIC_FALSE = "cryptographic_false"
PUBLIC_INPUT_MISMATCH = "public_input_mismatch"
RECORD_MISMATCH = "record_mismatch"
VERIFICATION_UNAVAILABLE = "verification_unavailable"


def _field_value(value: str | int) -> int:
    """Normalize persisted/requested field values for semantic comparison."""
    if isinstance(value, str):
        return int(value, 16) if value.startswith(("0x", "0X")) else int(value)
    return int(value)


def _public_inputs_match(
    segment,
    chunk,
    expected_sbom_root: str,
    expected_vulnerability_db_root: str,
    expected_policy_hash: str,
) -> bool:
    """Bind requested public inputs to persisted metadata, not proof-byte offsets."""
    try:
        if segment.segment_index == 0:
            return (
                _field_value(segment.global_sbom_root) == _field_value(expected_sbom_root)
                and _field_value(segment.policy_hash) == _field_value(expected_policy_hash)
            )
        if segment.segment_index == 7:
            return _field_value(segment.vulnerability_db_root) == _field_value(
                expected_vulnerability_db_root
            )
        return True
    except (TypeError, ValueError):
        logger.error(
            "Persisted public-input metadata is malformed for chunk %s segment %s",
            chunk.chunk_index,
            segment.segment_index,
        )
        return False


def _public_input_values(segment, chunk) -> list[str]:
    """Build the circuit-declared public-input vector from persisted metadata."""
    if segment.segment_index == 0:
        values = (
            segment.global_sbom_root,
            segment.policy_hash,
            chunk.chunk_index,
            chunk.components_commit,
            segment.hash_out_commit,
        )
    elif segment.segment_index == 7:
        values = (
            segment.vulnerability_db_root,
            chunk.components_commit,
            segment.hash_in_commit,
        )
    else:
        values = (
            segment.segment_index,
            chunk.components_commit,
            segment.hash_in_commit,
            segment.hash_out_commit,
        )

    try:
        return [hex(_field_value(value)) for value in values]
    except (TypeError, ValueError):
        raise ValueError(
            f"Malformed public-input metadata for chunk {chunk.chunk_index} "
            f"segment {segment.segment_index}"
        ) from None


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
            return VERIFICATION_UNAVAILABLE

        if not expected_sbom_root or not expected_vulnerability_db_root or not expected_policy_hash:
            raise ValueError("Missing expected public inputs for ZK-002 binding")

        from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
        
        try:
            job = session.query(ProofJob).filter(ProofJob.id == proof_job_id).first()
            if not job:
                logger.error(f"Job not found: {proof_job_id}")
                return STRUCTURAL_REJECTION
                
            chunks = session.query(ChunkProofSet).filter(ChunkProofSet.proof_job_id == job.id).order_by(ChunkProofSet.chunk_index).all()
            if len(chunks) != 32:
                logger.error(f"Expected 32 chunks, found {len(chunks)}")
                return STRUCTURAL_REJECTION
                
            # Archive Integrity Check with Semantic Binding (Finding D)
            if job.proof_archive_hash:
                import os
                project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
                archive_path = os.path.join(project_root, "archive", "proofs", f"{job.id}.zip")
                if not os.path.exists(archive_path):
                    legacy_path = os.path.join(project_root, "archives", "proofs", f"{job.id}.zip")
                    if os.path.exists(legacy_path):
                        archive_path = legacy_path

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
                except FileNotFoundError as e:
                    logger.error(f"Proof archive missing from filesystem: {e}")
                    return ENVIRONMENT_FAILURE
                except ValueError as e:
                    logger.error(f"Archive integrity validation failed (structural): {e}")
                    return STRUCTURAL_REJECTION
                except Exception as e:
                    logger.error(f"Archive validation unexpected error: {e}")
                    return STRUCTURAL_REJECTION
                
            chunk_indices = [c.chunk_index for c in chunks]
            if chunk_indices != list(range(32)):
                logger.error("Chunk indices are not exactly 0..31 or are duplicated/reordered")
                return STRUCTURAL_REJECTION
                
            for chunk in chunks:
                if chunk.proof_job_id != job.id:
                    logger.error(f"chunk proof_job_id mismatch: {chunk.proof_job_id} != {job.id}")
                    return STRUCTURAL_REJECTION
                if chunk.total_chunks != 32:
                    logger.error(f"chunk total_chunks mismatch: {chunk.total_chunks} != 32")
                    return STRUCTURAL_REJECTION
                if chunk.component_start != chunk.chunk_index * 32:
                    logger.error(f"chunk component_start mismatch: {chunk.component_start} != {chunk.chunk_index * 32}")
                    return STRUCTURAL_REJECTION
                if chunk.component_count != 32:
                    logger.error(f"chunk component_count mismatch: {chunk.component_count} != 32")
                    return STRUCTURAL_REJECTION
                    
                if chunk.status != "completed":
                    logger.error(f"Chunk {chunk.chunk_index} is not completed")
                    return STRUCTURAL_REJECTION
                    
                segments = session.query(SegmentProof).filter(SegmentProof.chunk_id == chunk.id).order_by(SegmentProof.segment_index).all()
                if len(segments) != 8:
                    logger.error(f"Expected 8 segments for chunk {chunk.chunk_index}, found {len(segments)}")
                    return STRUCTURAL_REJECTION
                    
                segment_indices = [s.segment_index for s in segments]
                if segment_indices != list(range(8)):
                    logger.error(f"Segment indices in chunk {chunk.chunk_index} are not exactly 0..7")
                    return STRUCTURAL_REJECTION
                
                # Check components_commit equality and cross-reference constraints
                c_commit = chunk.components_commit
                for seg in segments:
                    if seg.chunk_index != chunk.chunk_index:
                        logger.error(f"Segment chunk_index ({seg.chunk_index}) mismatch parent ({chunk.chunk_index})")
                        return STRUCTURAL_REJECTION
                    if seg.total_chunks != chunk.total_chunks:
                        logger.error(f"Segment total_chunks ({seg.total_chunks}) mismatch parent ({chunk.total_chunks})")
                        return STRUCTURAL_REJECTION
                    if seg.components_commit != c_commit:
                        logger.error(f"Components commit mismatch in chunk {chunk.chunk_index} segment {seg.segment_index}")
                        return PUBLIC_INPUT_MISMATCH
                        
                    if seg.status != "completed":
                        logger.error(f"Segment {seg.segment_index} not completed")
                        return STRUCTURAL_REJECTION
                        
                    segment_name = "segment_init_32" if seg.segment_index == 0 else ("segment_final_32" if seg.segment_index == 7 else "segment_mid_32")
                    
                    profile = get_crypto_profile()
                    vk_path_win, _, _project_root_win = profile.get_artifact_paths(segment_name)
                    expected_vk_hash = profile.decomposed_artifacts[segment_name]["vk_hash"]
                        
                    if not seg.proof_artifact:
                        logger.error(f"Proof artifact missing for segment {seg.segment_index}")
                        return STRUCTURAL_REJECTION
                        
                    try:
                        proof_bytes = base64.b64decode(seg.proof_artifact, validate=True)
                    except Exception as e:
                        logger.error(f"Proof artifact base64 decode failed for segment {seg.segment_index}: {e}")
                        return STRUCTURAL_REJECTION
                    
                    actual_proof_hash = hashlib.sha256(proof_bytes).hexdigest()
                    if actual_proof_hash != seg.proof_artifact_hash:
                        logger.error(f"Proof artifact hash mismatch for segment {seg.segment_index}")
                        return STRUCTURAL_REJECTION
                        
                    try:
                        profile.validate_segment_proof(segment_name, proof_bytes)
                    except ValueError as e:
                        logger.error(f"Segment proof validation failed: {e}")
                        return STRUCTURAL_REJECTION
                        
                    if not _public_inputs_match(
                        seg,
                        chunk,
                        expected_sbom_root,
                        expected_vulnerability_db_root,
                        expected_policy_hash,
                    ):
                        return PUBLIC_INPUT_MISMATCH

                    try:
                        with open(vk_path_win, "rb") as vk_file:
                            verification_key = vk_file.read()
                    except (OSError, FileNotFoundError) as exc:
                        logger.error(f"Cannot read verification key {vk_path_win}: {exc}")
                        return ENVIRONMENT_FAILURE

                    try:
                        accepted = verify_bound_proof(
                            circuit_id=segment_name,
                            verification_key=verification_key,
                            expected_verification_key_sha256=expected_vk_hash,
                            complete_proof=proof_bytes,
                            expected_public_inputs=_public_input_values(seg, chunk),
                            timeout_seconds=profile.proof_timeout_seconds,
                        )
                    except EnvironmentFailureError as exc:
                        logger.error(
                            "Environment failure for segment %s of chunk %s: %s",
                            seg.segment_index,
                            chunk.chunk_index,
                            exc,
                        )
                        return ENVIRONMENT_FAILURE
                    except RuntimeFailureError as exc:
                        logger.error(
                            "Runtime failure for segment %s of chunk %s: %s",
                            seg.segment_index,
                            chunk.chunk_index,
                            exc,
                        )
                        return RUNTIME_FAILURE
                    except StructuralRejectionError as exc:
                        logger.error(
                            "Structural rejection for segment %s of chunk %s: %s",
                            seg.segment_index,
                            chunk.chunk_index,
                            exc,
                        )
                        return STRUCTURAL_REJECTION
                    except (LegacyAcirRuntimeError, OSError) as exc:
                        logger.error(
                            "Verifier runtime error for segment %s of chunk %s: %s",
                            seg.segment_index,
                            chunk.chunk_index,
                            exc,
                        )
                        if "timed out" in str(exc).lower():
                            return RUNTIME_FAILURE
                        return ENVIRONMENT_FAILURE
                    except (LegacyAcirVerificationError, ValueError) as exc:
                        logger.error(
                            "Bound proof verification failed structurally for segment %s of chunk %s: %s",
                            seg.segment_index,
                            chunk.chunk_index,
                            exc,
                        )
                        return STRUCTURAL_REJECTION

                    if accepted is not True:
                        logger.error(
                            "Official verifier mathematically rejected segment %s of chunk %s",
                            seg.segment_index,
                            chunk.chunk_index,
                        )
                        return CRYPTOGRAPHIC_FALSE
                        
                # Check hash linkage
                for i in range(7):
                    if segments[i].hash_out_commit != segments[i+1].hash_in_commit:
                        logger.error(f"Hash linkage broken between {i} and {i+1} in chunk {chunk.chunk_index}")
                        return PUBLIC_INPUT_MISMATCH

            return VERIFIED
            
        except Exception as exc:
            logger.exception("Verification failed with unexpected exception: %s", exc)
            return RUNTIME_FAILURE

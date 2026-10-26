import logging
import os
import shlex
import subprocess
import base64
import threading
from uuid import UUID

from sqlalchemy.orm import Session

from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
from zkp_service.app.repositories.zkp_repository import ZKPRepository
from sbom_service.app.models.sbom_models import SBOMUpload, Component
from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot, ComponentVulnerabilityMapping
from policy_service.app.models.policy_models import SecurityPolicy

from shared.crypto.poseidon_bn254 import poseidon_hash
from shared.crypto.smt import SparseMerkleTree, hash_2


logger = logging.getLogger(__name__)

# ST21A-011: Proof-generation resource controls
# Deployment scope: PROCESS-LOCAL ONLY.
# This system is designed strictly for single-instance container deployments where process-local 
# locking is sufficient to prevent out-of-memory crashes. If deployed with multiple replicas,
# Redis or a database-backed distributed lock MUST be implemented to prevent resource exhaustion.
# It does NOT currently provide deployment-wide rate limits, quotas, queueing, or multi-worker limits.
_global_prover_lock = threading.Lock()
_user_active_jobs = {} # dict mapping user_id to active job count
_user_lock = threading.Lock()


def hash_32(elements):
    """Array hashing matching the Noir `hash_32` implementation."""
    current = elements[0]
    for i in range(1, 32):
        current = hash_2(current, elements[i])
    return current


def build_toolchain_command(
    tool: str,
    subcmd_args: list[str],
    *,
    os_name: str | None = None,
    wsl_distro: str | None = None,
) -> list[str]:
    """
    Construct command line for executing Nargo or Barretenberg.

    Supported runtimes:
    - POSIX (Linux/Docker): executes tool directly via PATH.
    - Windows: executes tool inside WSL (using WSL_DISTRIBUTION if set, or system default WSL distribution).

    Args:
        tool: "nargo" or "bb"
        subcmd_args: argument list for the tool (e.g. ["execute", "-p", ...])
        os_name: Override for OS detection (defaults to os.name)
        wsl_distro: Override for WSL distribution name (defaults to WSL_DISTRIBUTION env var)

    Returns:
        Command list suitable for subprocess.run
    """
    if tool not in ("nargo", "bb", "node", "acvm"):
        raise ValueError(f"Unsupported tool: {tool}")

    target_os = os_name if os_name is not None else os.name
    if target_os == "posix":
        if tool in ("node", "acvm"):
            from zkp_service.crypto_runtime.acvm_adapter import resolve_node_command
            cmd_base, _ = resolve_node_command()
            node_exe = cmd_base[0] if cmd_base else "node"
            return [node_exe] + list(subcmd_args)
        return [tool] + list(subcmd_args)

    # Windows / non-POSIX runtime: route through WSL
    distro = wsl_distro if wsl_distro is not None else os.environ.get("WSL_DISTRIBUTION")
    if tool == "nargo":
        binary_path = "~/.nargo/bin/nargo"
    elif tool == "bb":
        binary_path = "~/.bb/bb"
    else:
        binary_path = "~/.bin/node"
    args_str = " ".join(shlex.quote(str(arg)) for arg in subcmd_args)
    inner_cmd = f"{binary_path} {args_str}".strip()

    cmd = ["wsl"]
    if distro and distro.strip():
        cmd.extend(["-d", distro.strip()])
    cmd.extend(["--", "bash", "-c", inner_cmd])
    return cmd


def run_toolchain_command(
    cmd: list[str],
    cwd: str,
    timeout: int | float,
) -> subprocess.CompletedProcess | None:
    """
    Execute toolchain command with bounded timeout and safe error handling.
    Returns CompletedProcess on execution, or None if the binary is missing, timed out, or failed to start.
    """
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        logger.error("Runtime toolchain unavailable: executable '%s' not found: %s", cmd[0], exc)
        return None
    except subprocess.TimeoutExpired as exc:
        logger.error("Toolchain execution timed out after %ss for '%s': %s", exc.timeout, cmd[0], exc)
        return None
    except OSError as exc:
        logger.error("Toolchain execution failed for '%s': %s", cmd[0], exc)
        return None


class ProverService:
    """
    Handles witness extraction, SMT recomputation, deterministic chunking,
    bounded execution, and proof orchestration for the 256-proof architecture.
    """

    def __init__(self, session: Session):
        from shared.crypto.config import get_crypto_profile
        self._session = session
        self._repo = ZKPRepository(session)
        self._profile = get_crypto_profile()
        self.MAX_COMPONENTS = 1024
        self.CHUNK_SIZE = 32
        self.SEGMENTS_PER_CHUNK = 8
        self.TOTAL_CHUNKS = self.MAX_COMPONENTS // self.CHUNK_SIZE
        # Ensure we point to the correct split circuits
        self.circuit_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

    def process_job(self, job_id: UUID, user_id: UUID | None = None) -> ProofJob | None:
        """
        Process the proof job. Derives the 32 chunks and executes them sequentially.

        When invoked for an authenticated request, ``user_id`` is mandatory
        for the repository lookup so a job from another tenant cannot be
        processed by ID.
        """
        if not _global_prover_lock.acquire(blocking=False):
            logger.warning(f"Proof job {job_id} blocked: Server is at capacity.")
            return self._repo.update_job_status(job_id, "failed", error_message="Server is at capacity. Only one proof job can run concurrently.")
            
        requested_user_id = user_id
        active_user_id = None
        quota_acquired = False
        try:
            job = self._repo.get_job(job_id, user_id=requested_user_id)
            if not job:
                return None
                
            with _user_lock:
                active_user_id = str(job.user_id) if job.user_id is not None else None
                if active_user_id is not None:
                    if _user_active_jobs.get(active_user_id, 0) >= 1:
                        logger.warning(f"User {active_user_id} exceeded process-local quota")
                        return self._repo.update_job_status(job_id, "failed", error_message="Per-user quota exceeded")
                    _user_active_jobs[active_user_id] = _user_active_jobs.get(active_user_id, 0) + 1
                    quota_acquired = True
                
            self._repo.update_job_status(job_id, "assembling_witness")

            # 1. Fetch upstream data securely
            sbom = self._session.query(SBOMUpload).filter(SBOMUpload.id == job.sbom_upload_id).first()

            snapshot = self._session.query(VulnerabilitySnapshot).filter(VulnerabilitySnapshot.id == job.snapshot_id).first()
            policy = self._session.query(SecurityPolicy).filter(SecurityPolicy.id == job.policy_id).first()

            if not sbom or not snapshot or not policy:
                return self._repo.update_job_status(job_id, "failed", error_message="Missing upstream data references")

            # Recheck snapshot eligibility immediately before witness assembly and proving begins
            from vulnerability_service.app.core.snapshot_expiry import is_snapshot_usable_for_proving
            usable, reason = is_snapshot_usable_for_proving(snapshot)
            if not usable:
                logger.warning(f"Proof job {job_id} aborted before proving: {reason}")
                return self._repo.update_job_status(job_id, "failed", error_message=f"Snapshot ineligible: {reason}")

            components = self._session.query(Component).filter(
                Component.sbom_upload_id == sbom.id
            ).order_by(Component.position).all()
            
            mappings = self._session.query(ComponentVulnerabilityMapping).filter(
                ComponentVulnerabilityMapping.snapshot_id == snapshot.id
            ).all()
            
            mapping_dict = {m.component_hash: m.max_cvss for m in mappings}

            # 2. Build SMT to extract payload
            smt = SparseMerkleTree(256)
            for m in mappings:
                comp_hash_int = int(m.component_hash, 16)
                leaf_payload = poseidon_hash([comp_hash_int, m.max_cvss])
                smt.insert(comp_hash_int, leaf_payload)

            # 3. Derive global values
            active_count = len(components)
            if active_count > self.MAX_COMPONENTS:
                return self._repo.update_job_status(job_id, "failed", error_message="Component count exceeds 1024")

            # Pad components to 1024
            padded_components = []
            for i in range(self.MAX_COMPONENTS):
                if i < active_count:
                    c = components[i]
                    padded_components.append({
                        "hash": int(c.component_hash, 16),
                        "score": mapping_dict.get(c.component_hash, 0),
                        "presence": 1 if c.component_hash in mapping_dict else 0
                    })
                else:
                    padded_components.append({"hash": poseidon_hash([0]), "score": 0, "presence": 0})

            # 4. Create chunks and segments atomically in a single transaction
            chunks_data = []
            for chunk_idx in range(self.TOTAL_CHUNKS):
                start = chunk_idx * self.CHUNK_SIZE
                chunk_comps = padded_components[start:start+self.CHUNK_SIZE]
                comp_hashes = [c["hash"] for c in chunk_comps]
                components_commit_val = hex(hash_32(comp_hashes))
                chunks_data.append({
                    "chunk_index": chunk_idx,
                    "total_chunks": self.TOTAL_CHUNKS,
                    "component_start": start,
                    "component_count": self.CHUNK_SIZE,
                    "components_commit": components_commit_val,
                })

            self._repo.create_chunks_and_segments_batch(
                proof_job_id=job.id,
                chunks_data=chunks_data,
                segments_per_chunk=self.SEGMENTS_PER_CHUNK,
            )

            # 5. Execute all chunks (Bounded Concurrency: sequential)
            job = self._repo.update_job_status(
                job_id, "running", 
                sbom_root=sbom.sbom_root, 
                vulnerability_db_root=snapshot.authoritative_smt_root,
                policy_hash=policy.policy_hash
            )
            
            job = self.generate_all_chunk_proofs(job.id, padded_components, smt, sbom.sbom_root, snapshot.authoritative_smt_root, policy.policy_hash, policy.max_allowed_cvss_int)
            return job

        except Exception as e:
            logger.error("Failed to process proof job (%s)", type(e).__name__)
            return self._repo.update_job_status(job_id, "failed", error_message="Proof generation orchestration failed")
        finally:
            if quota_acquired and active_user_id is not None:
                with _user_lock:
                    remaining = max(0, _user_active_jobs.get(active_user_id, 0) - 1)
                    if remaining == 0:
                        _user_active_jobs.pop(active_user_id, None)
                    else:
                        _user_active_jobs[active_user_id] = remaining
            _global_prover_lock.release()

    def _compute_merkle_paths(self, padded_components):
        from shared.crypto.merkle import EMPTY_HASHES, hash_2
        leaves = [c["hash"] for c in padded_components]
        tree = [leaves]
        for level in range(self._profile.merkle_depth):
            current_level = tree[-1]
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1]
                next_level.append(hash_2(left, right))
            tree.append(next_level)
            
        paths = []
        for i in range(len(leaves)):
            path = []
            idx = i
            for level in range(self._profile.merkle_depth):
                sibling_idx = idx ^ 1
                path.append(tree[level][sibling_idx])
                idx //= 2
            paths.append(path)
        return paths

    def generate_all_chunk_proofs(self, job_id: UUID, padded_components, smt, sbom_root, vul_db_root, policy_hash, policy_max_cvss) -> ProofJob:
        job = self._repo.get_job_with_chunks(job_id)
        if not job:
            return None
            
        merkle_paths_all = self._compute_merkle_paths(padded_components)
            
        for chunk in job.chunks:
            self._repo.update_chunk_status(chunk.id, "running")
            success = self.generate_chunk_proofs(chunk, padded_components, smt, sbom_root, vul_db_root, policy_hash, policy_max_cvss, merkle_paths_all)
            if not success:
                self._repo.update_chunk_status(chunk.id, "failed")
                return self._repo.update_job_status(job_id, "failed", error_message=f"Chunk {chunk.chunk_index} failed")
            self._repo.update_chunk_status(chunk.id, "completed")
            
        archive_hash = self._archive_proofs(job)
        return self._repo.update_job_status(job_id, "completed", proof_archive_hash=archive_hash)

    def _archive_proofs(self, job):
        """Export all 256 segment proofs to an independent filesystem archive (ST21A-004)."""
        import os
        import base64
        import shutil
        import hashlib
        import json
        
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
        archive_dir_name = "archive" if os.path.exists(os.path.join(project_root, "archive")) or not os.path.exists(os.path.join(project_root, "archives")) else "archives"
        # Create a temporary directory for atomic assembly
        archive_tmp_dir = os.path.join(project_root, archive_dir_name, "proofs", f"{job.id}_tmp")
        archive_final_dir = os.path.join(project_root, archive_dir_name, "proofs", str(job.id))
        
        # Clean up any previous temp state
        if os.path.exists(archive_tmp_dir):
            shutil.rmtree(archive_tmp_dir)
            
        os.makedirs(archive_tmp_dir, exist_ok=True)
        
        try:
            from datetime import datetime, timezone
            manifest = {
                "job_id": str(job.id),
                "sbom_upload_id": str(job.sbom_upload_id),
                "snapshot_id": str(job.snapshot_id),
                "policy_id": str(job.policy_id),
                "sbom_root": job.sbom_root,
                "vulnerability_db_root": job.vulnerability_db_root,
                "policy_hash": job.policy_hash,
                "total_chunks": 32,
                "total_segments": 256,
                "components_per_chunk": 32,
                # Proof generation is not cryptographic verification. The
                # verifier may later return "verified" after BB verification,
                # but this archive records the honest pre-verification state.
                "cryptographic_verification_status": "pending",
                "tool_versions": {
                    "nargo": self._profile.nargo_version,
                    "barretenberg": "0.46.1"
                },
                "profile_identity": self._profile.profile_name,
                "retention_policy": "365_days",
                "disk_bound_bytes": 52428800,
                "archive_owner": str(job.user_id),
                "creation_timestamp": datetime.now(timezone.utc).isoformat(),
                "archive_status": "complete",
                "segments": []
            }

            missing_proofs = [
                (chunk.chunk_index, seg.segment_index)
                for chunk in job.chunks
                for seg in chunk.segments
                if not seg.proof_artifact
            ]
            if missing_proofs:
                raise ValueError(
                    f"Incomplete proof set: Missing proof artifacts {missing_proofs}"
                )

            for chunk in job.chunks:
                for seg in chunk.segments:
                    if seg.proof_artifact:
                        proof_bytes = base64.b64decode(seg.proof_artifact)
                        filename = f"chunk_{chunk.chunk_index}_segment_{seg.segment_index}.proof"
                        path = os.path.join(archive_tmp_dir, filename)
                        with open(path, "wb") as f:
                            f.write(proof_bytes)
                    
                    seg_data = {
                        "chunk_index": chunk.chunk_index,
                        "segment_index": seg.segment_index,
                        "component_start": chunk.component_start,
                        "component_count": chunk.component_count,
                        "components_commit": chunk.components_commit,
                        "hash_in_commit": seg.hash_in_commit,
                        "hash_out_commit": seg.hash_out_commit,
                        "circuit_identity": f"segment_{'init' if seg.segment_index == 0 else 'final' if seg.segment_index == 7 else 'mid'}_32",
                        "filename": filename,
                        "proof_hash": None,
                    }
                    
                    if seg.proof_artifact:
                        proof_bytes = base64.b64decode(seg.proof_artifact)
                        proof_hash = hashlib.sha256(proof_bytes).hexdigest()
                        if not seg.proof_artifact_hash or proof_hash != seg.proof_artifact_hash:
                            raise ValueError(
                                f"Persisted proof hash mismatch for chunk {chunk.chunk_index}, "
                                f"segment {seg.segment_index}"
                            )
                        seg_data["proof_hash"] = seg.proof_artifact_hash
                        
                    circuit_id = seg_data["circuit_identity"]
                    if hasattr(self._profile, "decomposed_artifacts") and circuit_id in self._profile.decomposed_artifacts:
                        seg_data["vk_hash"] = self._profile.decomposed_artifacts[circuit_id].get("vk_hash")
                        
                    manifest["segments"].append(seg_data)

            # Validate completeness
            if len(manifest["segments"]) != 256:
                raise ValueError("Incomplete proof set: Expected exactly 256 proofs.")
            
            if any(s["proof_hash"] is None for s in manifest["segments"]):
                raise ValueError("Incomplete proof set: Missing proof artifacts.")

            # Copy VKs and profile
            for segment_name in ["segment_init_32", "segment_mid_32", "segment_final_32"]:
                vk_src, _, _ = self._profile.get_artifact_paths(segment_name)
                if os.path.exists(vk_src):
                    shutil.copy2(vk_src, os.path.join(archive_tmp_dir, f"{segment_name}.vk"))
                    
            profile_src = os.path.join(project_root, "backend", "shared", "crypto", "profile.json")
            if os.path.exists(profile_src):
                shutil.copy2(profile_src, os.path.join(archive_tmp_dir, "profile.json"))

            with open(os.path.join(archive_tmp_dir, "manifest.json"), "w") as f:
                json.dump(manifest, f, indent=2)

            # Atomically finalize the archive zip
            zip_path_base = os.path.join(project_root, archive_dir_name, "proofs", f"{job.id}")
            zip_tmp_base = os.path.join(project_root, archive_dir_name, "proofs", f"{job.id}_zip_tmp")
            
            # Zip it directly from the tmp dir
            shutil.make_archive(zip_tmp_base, 'zip', archive_tmp_dir)
            
            # Atomic rename of the zip file
            os.rename(f"{zip_tmp_base}.zip", f"{zip_path_base}.zip")
            
            # Clean up the unzipped temporary directory
            shutil.rmtree(archive_tmp_dir)
            
            zip_file = f"{zip_path_base}.zip"
            if os.path.exists(zip_file):
                try:
                    expected_member_hashes = {
                        f"chunk_{chunk.chunk_index}_segment_{seg.segment_index}.proof": seg.proof_artifact_hash
                        for chunk in job.chunks
                        for seg in chunk.segments
                    }
                    expected_manifest = {
                        "job_id": str(job.id),
                        "sbom_upload_id": str(job.sbom_upload_id),
                        "snapshot_id": str(job.snapshot_id),
                        "policy_id": str(job.policy_id),
                        "sbom_root": job.sbom_root,
                        "vulnerability_db_root": job.vulnerability_db_root,
                        "policy_hash": job.policy_hash,
                        "profile_identity": self._profile.profile_name,
                        "total_chunks": 32,
                        "total_segments": 256,
                        "components_per_chunk": 32,
                    }
                    self._profile.validate_proof_archive(
                        zip_file,
                        expected_proof_count=256,
                        expected_member_hashes=expected_member_hashes,
                        expected_manifest=expected_manifest,
                    )
                except ValueError as e:
                    logger.error(f"Archive validation failed: {e}")
                    raise
                    
                with open(zip_file, "rb") as f:
                    return hashlib.sha256(f.read()).hexdigest()
                    
            return None
            
        except Exception as e:
            logger.error(f"Archive creation failed: {e}")
            if os.path.exists(archive_tmp_dir):
                shutil.rmtree(archive_tmp_dir)
            raise

    def generate_chunk_proofs(self, chunk, padded_components, smt, sbom_root, vul_db_root, policy_hash, policy_max_cvss, merkle_paths_all) -> bool:
        start = chunk.component_start
        chunk_comps = padded_components[start:start+self.CHUNK_SIZE]
        chunk_merkle_paths = merkle_paths_all[start:start+self.CHUNK_SIZE]
        
        # Calculate intermediate hashes for all 32 components at all 256 levels
        intermediates = [] # [component_idx][segment_idx]
        for i in range(self.CHUNK_SIZE):
            c = chunk_comps[i]
            path = smt.get_path(c["hash"])
            leaf = poseidon_hash([c["hash"], c["score"]]) if c["presence"] == 1 else 0
            current_hash = leaf
            
            key_bits = [(c["hash"] >> b) & 1 for b in range(256)]
            comp_intermediates = [current_hash]
            
            for b in range(256):
                is_right = key_bits[b]
                sibling = path[b]
                left = sibling if is_right else current_hash
                right = current_hash if is_right else sibling
                from shared.crypto.poseidon_bn254 import poseidon_hash as ph
                current_hash = ph([left, right])
                if (b + 1) % 32 == 0:
                    comp_intermediates.append(current_hash)
            intermediates.append(comp_intermediates)
            
        commits = []
        for seg_idx in range(9):
            arr = [intermediates[i][seg_idx] for i in range(32)]
            commits.append(hash_32(arr))

        for seg_idx in range(self.SEGMENTS_PER_CHUNK):
            seg_db = next(s for s in chunk.segments if s.segment_index == seg_idx)
            
            if seg_idx == 0:
                circuit_name = "segment_init_32"
            elif seg_idx == 7:
                circuit_name = "segment_final_32"
            else:
                circuit_name = f"segment_mid_32_{seg_idx}"
                
            hash_in = commits[seg_idx]
            hash_out = commits[seg_idx + 1]
            hash_in_array = [intermediates[i][seg_idx] for i in range(32)]
            
            success = self.generate_segment_proof(
                seg_db, circuit_name, chunk_comps, chunk_merkle_paths, smt, chunk.chunk_index,
                seg_idx, hash_in, hash_out, hash_in_array, sbom_root, vul_db_root, policy_hash, policy_max_cvss
            )
            if not success:
                return False
                
        return True

    def generate_segment_proof(self, seg_db, circuit_name, chunk_comps, chunk_merkle_paths, smt, chunk_index, seg_idx, hash_in, hash_out, hash_in_array, sbom_root, vul_db_root, policy_hash, policy_max_cvss) -> bool:
        prover_content = []
        
        def hex_fmt(val: int) -> str:
            if isinstance(val, str) and val.startswith("0x"):
                return f'"{val}"'
            return f'"{hex(val)}"'
        def array_fmt(arr) -> str:
            return "[" + ", ".join(hex_fmt(v) for v in arr) + "]"
            
        components_hashes = [c["hash"] for c in chunk_comps]
        comp_commit = hash_32(components_hashes)
        
        prover_content.append(f'components_commit = {hex_fmt(comp_commit)}')
        prover_content.append(f'components = {array_fmt(components_hashes)}')
        
        if seg_idx == 0:
            prover_content.append(f'global_sbom_root = "{sbom_root}"')
            prover_content.append(f'policy_hash = "{policy_hash}"')
            prover_content.append(f'chunk_index = "{chunk_index}"')
            prover_content.append(f'hash_out_commit = {hex_fmt(hash_out)}')
            prover_content.append(f'scores = ["' + '", "'.join(str(c["score"]) for c in chunk_comps) + '"]')
            prover_content.append(f'presence = ["' + '", "'.join(str(c["presence"]) for c in chunk_comps) + '"]')
            prover_content.append(f'policy_max_cvss = "{policy_max_cvss}"')
            
            prover_content.append('merkle_paths = [')
            for path in chunk_merkle_paths:
                prover_content.append(f'  {array_fmt(path)},')
            prover_content.append(']')
            
        elif seg_idx == 7:
            prover_content.append(f'vulnerability_db_root = "{vul_db_root}"')
            prover_content.append(f'hash_in_commit = {hex_fmt(hash_in)}')
            prover_content.append(f'hash_in_array = {array_fmt(hash_in_array)}')
            
        else:
            prover_content.append(f'segment_index = "{seg_idx}"')
            prover_content.append(f'hash_in_commit = {hex_fmt(hash_in)}')
            prover_content.append(f'hash_out_commit = {hex_fmt(hash_out)}')
            prover_content.append(f'hash_in_array = {array_fmt(hash_in_array)}')

        prover_content.append('path_segments = [')
        for c in chunk_comps:
            path = smt.get_path(c["hash"])
            segment_path = path[seg_idx*32 : (seg_idx+1)*32]
            prover_content.append(f'  {array_fmt(segment_path)},')
        prover_content.append(']')

        prover_str = "\n".join(prover_content)

        artifact_name = "segment_mid_32" if "segment_mid_32" in circuit_name else circuit_name
        vk_src, json_src, project_root = self._profile.get_artifact_paths(artifact_name)
            
        source_cwd = os.path.join(project_root, artifact_name)
        uid = str(seg_db.id).replace("-", "")
        prover_name = f"Prover_{uid}"
        
        import tempfile
        import shutil
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                prover_path = os.path.join(tmpdir, f"{prover_name}.toml")
                with open(prover_path, "w") as f:
                    f.write(prover_str)
                
                # Copy immutable circuit assets into tmpdir workspace
                shutil.copy(os.path.join(source_cwd, "Nargo.toml"), tmpdir)
                shutil.copytree(os.path.join(source_cwd, "src"), os.path.join(tmpdir, "src"))
                
                os.makedirs(os.path.join(tmpdir, "target"), exist_ok=True)
                shutil.copy(json_src, os.path.join(tmpdir, "target", f"{artifact_name}.json"))
                shutil.copy(vk_src, os.path.join(tmpdir, "target", "vk"))
                
                os.makedirs(os.path.join(tmpdir, "proofs"), exist_ok=True)
                
                # Witness Gen
                target_json = os.path.join(tmpdir, "target", f"{artifact_name}.json")
                target_witness = os.path.join(tmpdir, "target", f"witness_{uid}.gz")

                witness_solved = False
                try:
                    import json
                    try:
                        import tomllib
                    except ImportError:
                        import tomli as tomllib

                    raw_toml = tomllib.loads(prover_str)
                    clean_inputs = {}
                    for k, v in raw_toml.items():
                        if k in ('chunk_index', 'policy_max_cvss', 'segment_index'):
                            clean_inputs[k] = int(v) if isinstance(v, str) else v
                        elif k in ('scores', 'presence'):
                            clean_inputs[k] = [int(x) if isinstance(x, str) else x for x in v]
                        else:
                            clean_inputs[k] = v

                    inputs_json_path = os.path.join(tmpdir, f"inputs_{uid}.json")
                    with open(inputs_json_path, "w", encoding="utf-8") as f:
                        json.dump(clean_inputs, f, indent=2)

                    from zkp_service.crypto_runtime.acvm_adapter import EXECUTE_SCRIPT, to_node_path, resolve_node_command
                    cmd_base, is_win_node = resolve_node_command()

                    if cmd_base:
                        script_arg = to_node_path(EXECUTE_SCRIPT, is_win_node)
                        circuit_arg = to_node_path(target_json, is_win_node)
                        inputs_arg = to_node_path(inputs_json_path, is_win_node)
                        witness_arg = to_node_path(target_witness, is_win_node)

                        acvm_args = [script_arg, circuit_arg, inputs_arg, witness_arg]
                        cmd = build_toolchain_command("node", acvm_args)
                        res = run_toolchain_command(cmd, cwd=tmpdir, timeout=self._profile.proof_timeout_seconds)

                        if (
                            res is not None
                            and res.returncode == 0
                            and os.path.isfile(target_witness)
                            and os.path.getsize(target_witness) > 100
                        ):
                            with open(target_witness, "rb") as wf:
                                if wf.read(2) == b"\x1f\x8b":
                                    witness_solved = True
                except Exception as acvm_exc:
                    logger.warning("ACVM adapter encountered error: %s. Falling back to Nargo CLI.", acvm_exc)
                    witness_solved = False

                if not witness_solved:
                    logger.info("Using controlled fallback: nargo execute for segment %d", seg_idx)
                    witness_args = ["execute", "-p", prover_name, f"witness_{uid}"]
                    cmd = build_toolchain_command("nargo", witness_args)
                    res = run_toolchain_command(cmd, cwd=tmpdir, timeout=self._profile.proof_timeout_seconds)
                    if res is None:
                        logger.error(f"Witness generation failed to launch for segment {seg_idx}")
                        return False
                    if res.returncode != 0:
                        logger.error(f"Witness generation failed for segment {seg_idx}: {res.stderr}")
                        return False
                    
                # Prove
                prove_args = ["prove", "-b", f"./target/{artifact_name}.json", "-w", f"./target/witness_{uid}.gz", "-o", f"./proofs/proof_{uid}.proof"]
                cmd = build_toolchain_command("bb", prove_args)
                res = run_toolchain_command(cmd, cwd=tmpdir, timeout=self._profile.proof_timeout_seconds)
                if res is None:
                    logger.error(f"Prove failed to launch for segment {seg_idx}")
                    return False
                if res.returncode != 0:
                    logger.error(f"Prove failed for segment {seg_idx}: code={res.returncode}")
                    return False
                    
                # Verify immediately (Phase 8)
                verify_args = ["verify", "-k", "./target/vk", "-p", f"./proofs/proof_{uid}.proof"]
                cmd = build_toolchain_command("bb", verify_args)
                res = run_toolchain_command(cmd, cwd=tmpdir, timeout=self._profile.proof_timeout_seconds)
                if res is None:
                    logger.error(f"Verification failed to launch for segment {seg_idx}")
                    return False
                if res.returncode != 0:
                    logger.error(f"Verification failed for segment {seg_idx}: {res.stderr}")
                    return False
                    
                proof_path = os.path.join(tmpdir, "proofs", f"proof_{uid}.proof")
                with open(proof_path, "rb") as f:
                    proof_bytes = f.read()
                
            expected_len = 2304 if seg_idx == 0 else (2240 if seg_idx == 7 else 2272)
            if len(proof_bytes) != expected_len:
                logger.error(f"Invalid proof length for segment {seg_idx}. Expected {expected_len}, got {len(proof_bytes)}")
                return False
                
            proof_artifact = base64.b64encode(proof_bytes).decode("utf-8")
                
            from hashlib import sha256
            proof_hash = sha256(proof_bytes).hexdigest()
            
            comp_commit = hex(hash_32(components_hashes))
            
            self._repo.update_segment_artifact(
                seg_db.id, "completed", proof_artifact, proof_hash, 
                comp_commit, hex(hash_in), hex(hash_out), 
                sbom_root if seg_idx == 0 else None, 
                vul_db_root if seg_idx == 7 else None, 
                policy_hash if seg_idx == 0 else None
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Segment execution error: {e}")
            return False

import json
import logging
import os
import hashlib

logger = logging.getLogger(__name__)

class CryptoProfileConfigError(Exception):
    pass

class CryptoProfile:
    def __init__(self, profile_name: str, config: dict):
        self.profile_name = profile_name
        self.circuit_dir = config.get("circuit_dir")
        self.circuit_artifact_hash = config.get("circuit_artifact_hash")
        self.vk_hash = config.get("vk_hash")
        self.max_components = config.get("max_components")
        self.merkle_depth = config.get("merkle_depth")
        self.smt_depth = config.get("smt_depth")
        self.nargo_version = config.get("nargo_version")
        self.max_proof_size_bytes = config.get("max_proof_size_bytes", 5000)
        self.proof_timeout_seconds = config.get("proof_timeout_seconds", 300)
        
        self.decomposed_artifacts = config.get("decomposed_artifacts")

        self._validate_artifacts()

    def _validate_artifacts(self):
        """
        Fail fast if artifacts are missing or do not match the expected hashes.
        """
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        
        # Validate monolithic artifacts if explicitly configured
        if self.circuit_artifact_hash and self.circuit_artifact_hash != "UNUSED_IN_DECOMPOSED_TOPOLOGY":
            circuit_path = os.path.join(project_root, self.circuit_dir)
            target_dir = os.path.join(circuit_path, "target")
            sbom_zkp_json_path = os.path.join(target_dir, "sbom_zkp.json")
            vk_path = os.path.join(target_dir, "vk")

            if not os.path.exists(sbom_zkp_json_path):
                raise CryptoProfileConfigError(f"Missing required artifact: {sbom_zkp_json_path}")
            
            with open(sbom_zkp_json_path, "rb") as f:
                actual_circuit_hash = hashlib.sha256(f.read()).hexdigest()
                if actual_circuit_hash != self.circuit_artifact_hash:
                    raise CryptoProfileConfigError(f"Circuit artifact hash mismatch. Expected {self.circuit_artifact_hash}, got {actual_circuit_hash}")

            if self.vk_hash is None:
                raise CryptoProfileConfigError(f"Profile '{self.profile_name}' is not fully configured (missing vk_hash)")

            if not os.path.exists(vk_path):
                raise CryptoProfileConfigError(f"Missing required artifact: {vk_path}")

            with open(vk_path, "rb") as f:
                actual_vk_hash = hashlib.sha256(f.read()).hexdigest()
                if actual_vk_hash != self.vk_hash:
                    raise CryptoProfileConfigError(f"VK hash mismatch. Expected {self.vk_hash}, got {actual_vk_hash}")

        # Validate decomposed artifacts if required by topology (prod/1024 components)
        if self.max_components == 1024:
            if not self.decomposed_artifacts:
                raise CryptoProfileConfigError(f"Profile '{self.profile_name}' requires decomposed_artifacts but none were configured.")
                
            required_segments = ["segment_init_32", "segment_mid_32", "segment_final_32"]
            for seg in required_segments:
                seg_config = self.decomposed_artifacts.get(seg)
                if not seg_config:
                    raise CryptoProfileConfigError(f"Missing decomposed artifact config for {seg}")
                    
                expected_circuit_hash = seg_config.get("circuit_artifact_hash")
                expected_vk_hash = seg_config.get("vk_hash")
                
                if not expected_circuit_hash:
                    raise CryptoProfileConfigError(f"Missing expected circuit_artifact_hash for {seg}")
                if not expected_vk_hash:
                    raise CryptoProfileConfigError(f"Missing expected vk_hash for {seg}")
                    
                circuit_path = os.path.join(project_root, seg)
                target_dir = os.path.join(circuit_path, "target")
                json_path = os.path.join(target_dir, f"{seg}.json")
                vk_path = os.path.join(target_dir, "vk")
                
                if not os.path.exists(json_path):
                    raise CryptoProfileConfigError(f"Missing required decomposed artifact: {json_path}")
                with open(json_path, "rb") as f:
                    actual = hashlib.sha256(f.read()).hexdigest()
                    if actual != expected_circuit_hash:
                        raise CryptoProfileConfigError(f"Decomposed circuit hash mismatch for {seg}. Expected {expected_circuit_hash}, got {actual}")
                        
                if not os.path.exists(vk_path):
                    raise CryptoProfileConfigError(f"Missing required decomposed VK: {vk_path}")
                with open(vk_path, "rb") as f:
                    actual = hashlib.sha256(f.read()).hexdigest()
                    if actual != expected_vk_hash:
                        raise CryptoProfileConfigError(f"Decomposed VK hash mismatch for {seg}. Expected {expected_vk_hash}, got {actual}")
                        
                # Save authoritative paths
                seg_config["authoritative_vk_path"] = vk_path
                seg_config["authoritative_json_path"] = json_path
                seg_config["authoritative_project_root"] = project_root

    def get_artifact_paths(self, segment_name: str) -> tuple[str, str, str]:
        """Returns (vk_path, json_path, project_root) for a segment."""
        if not self.decomposed_artifacts or segment_name not in self.decomposed_artifacts:
            raise CryptoProfileConfigError(f"Segment {segment_name} not configured in profile {self.profile_name}")
        seg_config = self.decomposed_artifacts[segment_name]
        return (
            seg_config["authoritative_vk_path"],
            seg_config["authoritative_json_path"],
            seg_config["authoritative_project_root"]
        )

    def validate_segment_proof(self, segment_name: str, proof_bytes: bytes) -> None:
        """Centralized proof format, size and integrity validation."""
        if len(proof_bytes) > self.max_proof_size_bytes:
            raise ValueError(f"Proof size {len(proof_bytes)} exceeds maximum {self.max_proof_size_bytes}")
            
        if proof_bytes.startswith(b"\x1f\x8b"):
            raise ValueError("Proof is a gzip witness, not a proof")
            
        # Structure constraints (UltraPlonk = Public Inputs + 2144 bytes proof)
        if segment_name == "segment_init_32":
            expected_length = (5 * 32) + 2144
        elif segment_name == "segment_final_32":
            expected_length = (3 * 32) + 2144
        elif segment_name.startswith("segment_mid_32"):
            expected_length = (4 * 32) + 2144
        else:
            raise ValueError(f"Unknown segment topology: {segment_name}")
            
        if len(proof_bytes) != expected_length:
            raise ValueError(f"Structural format rejection: expected {expected_length} bytes, got {len(proof_bytes)}")

    def validate_proof_archive(
        self,
        archive_path: str,
        expected_hash: str = None,
        expected_proof_count: int = 256,
        expected_member_hashes: dict = None,
        expected_manifest: dict = None,
    ) -> None:
        """Validate archive bytes, names, manifest binding, and persisted proof hashes."""
        import zipfile
        from datetime import datetime, timezone
        
        if not os.path.exists(archive_path):
            raise ValueError("Archive does not exist")
            
        size = os.path.getsize(archive_path)
        # Bounded at 50MB
        if size > 52428800:
            raise ValueError(f"Archive size {size} exceeds 50MB bound")
        if size == 0:
            raise ValueError("Archive is empty")
            
        if expected_hash:
            with open(archive_path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()
            if actual_hash != expected_hash:
                raise ValueError(f"Archive hash mismatch. Expected {expected_hash}, got {actual_hash}")
                
        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                names = zf.namelist()
                if len(names) != len(set(names)):
                    raise ValueError("Archive contains duplicate member names")

                # Path traversal protection and exact, flat member names.
                for member in names:
                    if (
                        '..' in member
                        or member.startswith('/')
                        or os.path.isabs(member)
                        or os.path.basename(member) != member
                    ):
                        raise ValueError(f"Invalid archive member path: {member}")

                proof_files = [m for m in names if m.endswith('.proof')]
                if len(proof_files) != expected_proof_count:
                    raise ValueError(f"Expected {expected_proof_count} proof files, found {len(proof_files)}")
                
                if 'manifest.json' not in names:
                    raise ValueError("Archive is missing manifest.json")
                
                manifest = json.loads(zf.read('manifest.json').decode('utf-8'))
                
                # Semantic structural validation of manifest
                if not manifest.get("job_id"):
                    raise ValueError("Manifest missing job_id")
                if manifest.get("total_chunks") != 32 or manifest.get("total_segments") != 256:
                    raise ValueError("Manifest topology incorrect")
                if manifest.get("components_per_chunk", 32) != 32:
                    raise ValueError("Manifest component topology incorrect")
                if not isinstance(manifest.get("segments"), list) or len(manifest["segments"]) != expected_proof_count:
                    raise ValueError("Manifest segment topology incorrect")
                try:
                    ts_str = manifest["creation_timestamp"]
                    if ts_str != "timestamp_marker":
                        timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if timestamp.tzinfo is None or timestamp > datetime.now(timezone.utc):
                            raise ValueError("Manifest creation timestamp is not a real event")
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError("Manifest creation timestamp is invalid") from exc
                if manifest.get("archive_status") != "complete":
                    raise ValueError("Manifest archive status is not complete")
                if manifest.get("cryptographic_verification_status") not in {
                    "pending",
                    "verified",
                }:
                    raise ValueError("Manifest cryptographic status is invalid")

                manifest_segments = manifest["segments"]
                manifest_names = []
                for segment in manifest_segments:
                    try:
                        filename = f"chunk_{segment['chunk_index']}_segment_{segment['segment_index']}.proof"
                        if "filename" in segment and segment["filename"] != filename:
                            raise ValueError("Manifest proof filename mismatch")
                        segment["filename"] = filename
                        if segment.get("proof_hash") is None:
                            raise ValueError("Manifest proof hash is missing")
                        manifest_names.append(filename)
                    except KeyError as exc:
                        raise ValueError("Manifest segment metadata is incomplete") from exc
                if len(manifest_names) != len(set(manifest_names)) or set(manifest_names) != set(proof_files):
                    raise ValueError("Manifest proof filenames do not exactly match archive members")

                # Cross-reference with DB hashes if provided
                if expected_member_hashes:
                    if set(expected_member_hashes) != set(proof_files):
                        raise ValueError("Archive proof filenames do not exactly match persisted segments")
                    for filename, exp_hash in expected_member_hashes.items():
                        if not exp_hash or filename not in names:
                            raise ValueError(f"Missing expected proof member: {filename}")
                        member_bytes = zf.read(filename)
                        member_hash = hashlib.sha256(member_bytes).hexdigest()
                        if member_hash != exp_hash:
                            raise ValueError(f"Archive member hash mismatch for {filename}")
                        segment = next(s for s in manifest_segments if s["filename"] == filename)
                        if segment["proof_hash"] != exp_hash:
                            raise ValueError(f"Manifest proof hash mismatch for {filename}")

                if expected_manifest:
                    for key, expected in expected_manifest.items():
                        actual = manifest.get(key)
                        if isinstance(expected, str) and expected.startswith("0x") and isinstance(actual, str) and actual.startswith("0x"):
                            if int(expected, 16) != int(actual, 16):
                                raise ValueError(f"Manifest binding mismatch for {key}")
                        elif actual != expected:
                            raise ValueError(f"Manifest binding mismatch for {key}")

                allowed_names = set(proof_files) | {"manifest.json", "profile.json"}
                allowed_names.update(f"{name}.vk" for name in ("segment_init_32", "segment_mid_32", "segment_final_32"))
                if set(names) - allowed_names:
                    raise ValueError("Archive contains unexpected members")
                            
        except zipfile.BadZipFile:
            raise ValueError("Archive is not a valid ZIP file")


def get_crypto_profile() -> CryptoProfile:
    config_path = os.environ.get("CRYPTO_PROFILE_PATH", os.path.join(os.path.dirname(__file__), "profile.json"))
    with open(config_path, "r") as f:
        manifest = json.load(f)

    active_profile_name = os.environ.get("CRYPTO_PROFILE")
    if not active_profile_name:
        raise CryptoProfileConfigError("CRYPTO_PROFILE environment variable is required")

    if active_profile_name not in manifest["profiles"]:
        raise CryptoProfileConfigError(f"Invalid CRYPTO_PROFILE specified: {active_profile_name}")

    profile_config = manifest["profiles"][active_profile_name]
    return CryptoProfile(active_profile_name, profile_config)

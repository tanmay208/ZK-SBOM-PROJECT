import os
import sys
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from unittest.mock import MagicMock
from backend.zkp_service.app.services.prover_service import ProverService
from backend.shared.crypto.smt import SparseMerkleTree
from backend.shared.crypto.poseidon_bn254 import poseidon_hash

def main():
    print("Running C=32 Focused Backend Smoke Test...")
    
    # 1. Prepare dummy components (1024 components)
    padded_components = []
    for i in range(1024):
        padded_components.append({
            "hash": i + 1,
            "score": i % 100,
            "presence": 1
        })
        
    # 2. Build SMT
    smt = SparseMerkleTree()
    for c in padded_components:
        leaf = poseidon_hash([c["hash"], c["score"]]) if c["presence"] == 1 else 0
        smt.insert(c["hash"], leaf)
        
    # 3. Merkle Paths all (fake, just need 32 leaves)
    # The ProverService now computes this itself using _compute_merkle_paths!
    
    # 4. Mock DB and chunk
    mock_session = MagicMock()
    
    chunk = MagicMock()
    chunk.component_start = 0
    chunk.chunk_index = 0
    
    segments = []
    for i in range(8):
        seg = MagicMock()
        seg.segment_index = i
        import uuid
        seg.id = uuid.uuid4()
        segments.append(seg)
    chunk.segments = segments
    
    # We must patch os.environ to use dev or test profile with actual hashes?
    # No, execute_stage21 creates the profile. We can do it here too.
    import tempfile
    profile_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "shared", "crypto", "profile.json"))
    with open(profile_path, "r") as f:
        manifest = json.load(f)
        
    import hashlib
    segments_config = ["segment_init_32", "segment_mid_32", "segment_final_32"]
    out = {}
    for seg_name in segments_config:
        try:
            with open(f"E:/Main Project/{seg_name}/target/{seg_name}.json", "rb") as f:
                c_hash = hashlib.sha256(f.read()).hexdigest()
            with open(f"E:/Main Project/{seg_name}/target/vk", "rb") as f:
                v_hash = hashlib.sha256(f.read()).hexdigest()
            out[seg_name] = {"circuit_artifact_hash": c_hash, "vk_hash": v_hash}
        except:
            print(f"Skipping hash {seg_name}")
            
    manifest["profiles"]["prod"]["decomposed_artifacts"] = out
    
    fd, temp_profile_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(manifest, f)
        
    os.environ["CRYPTO_PROFILE_PATH"] = temp_profile_path
    os.environ["CRYPTO_PROFILE"] = "prod"
    
    # Re-init prover to pick up the profile
    prover = ProverService(mock_session)
    prover._repo = MagicMock()
    prover.circuit_dir = "E:/Main Project"
    
    merkle_paths_all = prover._compute_merkle_paths(padded_components)
    
    policy_max_cvss = 50
    policy_hash = "0x" + hex(poseidon_hash([policy_max_cvss]))[2:]
    
    # We also need a valid sbom_root.
    from backend.shared.crypto.merkle import compute_merkle_root
    leaves = [c["hash"] for c in padded_components]
    sbom_root = "0x" + hex(compute_merkle_root(leaves))[2:]
    
    vul_db_root = "0x" + hex(smt.get_root())[2:]
    
    success = prover.generate_chunk_proofs(
        chunk, padded_components, smt, sbom_root, vul_db_root, policy_hash, policy_max_cvss, merkle_paths_all
    )
    
    print(f"Smoke Test Result: {'PASSED' if success else 'FAILED'}")
    
    if not success:
        sys.exit(1)
        
if __name__ == "__main__":
    main()

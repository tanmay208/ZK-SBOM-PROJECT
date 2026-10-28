import os
import sys

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.shared.crypto.smt import SparseMerkleTree, hash_2, EMPTY_HASHES
from backend.shared.crypto.poseidon_bn254 import poseidon_hash
from backend.shared.crypto.merkle import hash_1, hash_2, EMPTY_HASHES

def get_merkle_path(leaves, index):
    current_level = leaves + [EMPTY_HASHES[0]] * (1024 - len(leaves))
    path = []
    
    current_index = index
    for level in range(10):
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1]
            next_level.append(hash_2(left, right))
            
            if i == current_index or i + 1 == current_index:
                sibling_index = i if (current_index % 2 == 1) else i + 1
                path.append(current_level[sibling_index])
                
        current_level = next_level
        current_index = current_index // 2
        
    return path, current_level[0]

def main():
    # 1. Setup global Merkle Tree
    # 1024 components, depth 10
    leaves = [poseidon_hash([i]) for i in range(1024)]
    
    chunk_index = 0
    component = leaves[chunk_index]
    merkle_path, global_sbom_root = get_merkle_path(leaves, chunk_index)
    
    # Policy
    policy_max_cvss = 5
    policy_hash = poseidon_hash([policy_max_cvss])
    
    # Vulnerability score/presence
    score = 4
    presence = 1
    
    leaf = poseidon_hash([component, score]) * presence
    
    # 2. Setup SMT
    smt = SparseMerkleTree(256)
    smt.insert(component, leaf)
    vulnerability_db_root = smt.get_root()
    path = smt.get_path(component)
    
    # 3. Generate intermediate hashes
    current_hash = leaf
    key_bits = [(component >> i) & 1 for i in range(256)]
    
    intermediates = [current_hash]
    for i in range(256):
        is_right = key_bits[i]
        sibling = path[i]
        
        left = sibling if is_right else current_hash
        right = current_hash if is_right else sibling
        
        current_hash = hash_2(left, right)
        if (i + 1) % 32 == 0:
            intermediates.append(current_hash)
            
    assert current_hash == vulnerability_db_root
    
    print(f"global_sbom_root: {global_sbom_root}")
    print(f"policy_hash: {policy_hash}")
    print(f"component: {component}")
    print(f"leaf: {leaf}")
    print(f"vulnerability_db_root: {vulnerability_db_root}")
    
    # Generate Prover.toml for segment_init
    with open("segment_init/Prover.toml", "w") as f:
        f.write(f'global_sbom_root = "{hex(global_sbom_root)}"\n')
        f.write(f'policy_hash = "{hex(policy_hash)}"\n')
        f.write(f'chunk_index = "{chunk_index}"\n')
        components_commit = poseidon_hash([component])
        f.write(f'components_commit = "{hex(components_commit)}"\n')
        hash_out_commit = poseidon_hash([intermediates[1]])
        f.write(f'hash_out_commit = "{hex(hash_out_commit)}"\n')
        f.write(f'component = "{hex(component)}"\n')
        f.write(f'score = "{score}"\n')
        f.write(f'presence = "{presence}"\n')
        
        path_seg0 = '", "'.join([hex(p) for p in path[0:32]])
        f.write(f'path_segment = ["{path_seg0}"]\n')
        
        mpath_str = '", "'.join([hex(p) for p in merkle_path])
        f.write(f'merkle_path = ["{mpath_str}"]\n')
        f.write(f'policy_max_cvss = "{policy_max_cvss}"\n')

    # Generate Prover.toml for segment_mid (segment 1)
    with open("segment_mid/Prover.toml", "w") as f:
        f.write(f'segment_index = "1"\n')
        f.write(f'components_commit = "{hex(components_commit)}"\n')
        hash_in_commit = poseidon_hash([intermediates[1]])
        f.write(f'hash_in_commit = "{hex(hash_in_commit)}"\n')
        hash_out_commit_mid = poseidon_hash([intermediates[2]])
        f.write(f'hash_out_commit = "{hex(hash_out_commit_mid)}"\n')
        f.write(f'component = "{hex(component)}"\n')
        f.write(f'hash_in = "{hex(intermediates[1])}"\n')
        
        path_seg1 = '", "'.join([hex(p) for p in path[32:64]])
        f.write(f'path_segment = ["{path_seg1}"]\n')
        
    # Generate Prover.toml for segment_final
    with open("segment_final/Prover.toml", "w") as f:
        f.write(f'vulnerability_db_root = "{hex(vulnerability_db_root)}"\n')
        f.write(f'components_commit = "{hex(components_commit)}"\n')
        hash_in_commit_final = poseidon_hash([intermediates[7]])
        f.write(f'hash_in_commit = "{hex(hash_in_commit_final)}"\n')
        f.write(f'component = "{hex(component)}"\n')
        f.write(f'hash_in = "{hex(intermediates[7])}"\n')
        
        path_seg7 = '", "'.join([hex(p) for p in path[224:256]])
        f.write(f'path_segment = ["{path_seg7}"]\n')

    print("Generated Prover.toml for all 3 segments.")

if __name__ == "__main__":
    main()

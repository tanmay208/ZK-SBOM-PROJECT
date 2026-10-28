import os
import sys
import json

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.shared.crypto.smt import SparseMerkleTree, hash_2, EMPTY_HASHES
from backend.shared.crypto.poseidon_bn254 import poseidon_hash

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

def hash_32(elements):
    current = elements[0]
    for i in range(1, 32):
        current = hash_2(current, elements[i])
    return current

def format_array(elements):
    return '", "'.join([hex(x) for x in elements])

def main():
    print("Generating deterministic C=32 witnesses...")

    # 1. Setup 1024 components
    all_components = [poseidon_hash([i]) for i in range(1024)]
    
    # 2. Select chunk 0 (components 0-31)
    chunk_index = 0
    components_32 = all_components[0:32]

    # Policy
    policy_max_cvss = 5
    policy_hash = poseidon_hash([policy_max_cvss])

    # 3. Setup vulnerability DB
    # Let's make:
    # Component 0: vulnerable, score 4, presence 1
    # Component 1: non-vulnerable, score 0, presence 0
    # Component 2: CVSS 0 vulnerable, score 0, presence 1
    # Component 3-31: non-vulnerable, score 0, presence 0
    
    scores = [0] * 32
    presence = [0] * 32
    
    scores[0] = 4; presence[0] = 1
    scores[1] = 0; presence[1] = 0
    scores[2] = 0; presence[2] = 1
    
    smt = SparseMerkleTree(256)
    
    leaves = []
    paths = []
    intermediates = [] # intermediates[component_idx][segment_idx]
    
    for i in range(32):
        if presence[i] == 1:
            leaf = poseidon_hash([components_32[i], scores[i]])
        else:
            leaf = 0
        leaves.append(leaf)
        smt.insert(components_32[i], leaf)

    vulnerability_db_root = smt.get_root()

    merkle_paths = []
    global_sbom_root = None
    
    for i in range(32):
        comp_idx = chunk_index * 32 + i
        m_path, root = get_merkle_path(all_components, comp_idx)
        merkle_paths.append(m_path)
        global_sbom_root = root

        # SMT paths & intermediates
        path = smt.get_path(components_32[i])
        paths.append(path)
        
        current_hash = leaves[i]
        key = components_32[i]
        key_bits = [(key >> b) & 1 for b in range(256)]
        
        comp_intermediates = [current_hash]
        for b in range(256):
            is_right = key_bits[b]
            sibling = path[b]
            left = sibling if is_right else current_hash
            right = current_hash if is_right else sibling
            current_hash = hash_2(left, right)
            
            if (b + 1) % 32 == 0:
                comp_intermediates.append(current_hash)
        
        assert current_hash == vulnerability_db_root
        intermediates.append(comp_intermediates)

    # 4. Generate Commitments
    components_commit = hash_32(components_32)
    hash_out_commit_0 = hash_32([intermediates[i][1] for i in range(32)])
    hash_out_commit_1 = hash_32([intermediates[i][2] for i in range(32)])
    hash_out_commit_2 = hash_32([intermediates[i][3] for i in range(32)])
    hash_out_commit_3 = hash_32([intermediates[i][4] for i in range(32)])
    hash_out_commit_4 = hash_32([intermediates[i][5] for i in range(32)])
    hash_out_commit_5 = hash_32([intermediates[i][6] for i in range(32)])
    hash_out_commit_6 = hash_32([intermediates[i][7] for i in range(32)])
    hash_out_commit_7 = hash_32([intermediates[i][8] for i in range(32)])
    
    hash_out_commits = [
        hash_out_commit_0, hash_out_commit_1, hash_out_commit_2, hash_out_commit_3,
        hash_out_commit_4, hash_out_commit_5, hash_out_commit_6, hash_out_commit_7
    ]

    # --- Generate Prover.toml for segment_init_32 ---
    with open("segment_init_32/Prover.toml", "w") as f:
        f.write(f'global_sbom_root = "{hex(global_sbom_root)}"\n')
        f.write(f'policy_hash = "{hex(policy_hash)}"\n')
        f.write(f'chunk_index = "{chunk_index}"\n')
        f.write(f'components_commit = "{hex(components_commit)}"\n')
        f.write(f'hash_out_commit = "{hex(hash_out_commits[0])}"\n')
        
        f.write(f'components = ["{format_array(components_32)}"]\n')
        f.write(f'scores = [{", ".join(map(str, scores))}]\n')
        f.write(f'presence = [{", ".join(map(str, presence))}]\n')
        
        # Array of arrays for paths
        f.write("path_segments = [\n")
        for i in range(32):
            seg_path = paths[i][0:32]
            f.write(f'  ["{format_array(seg_path)}"]')
            f.write(",\n" if i < 31 else "\n")
        f.write("]\n")

        # Merkle paths
        f.write("merkle_paths = [\n")
        for i in range(32):
            f.write(f'  ["{format_array(merkle_paths[i])}"]')
            f.write(",\n" if i < 31 else "\n")
        f.write("]\n")
        
        f.write(f'policy_max_cvss = "{policy_max_cvss}"\n')

    # --- Generate Prover.toml for segment_mid_32 (all 6 segments 1..6) ---
    for seg_idx in range(1, 7):
        dir_name = f"segment_mid_32_{seg_idx}"
        if not os.path.exists(dir_name):
            import shutil
            shutil.copytree("segment_mid_32", dir_name)
            
        with open(f"{dir_name}/Prover.toml", "w") as f:
            f.write(f'segment_index = "{seg_idx}"\n')
            f.write(f'components_commit = "{hex(components_commit)}"\n')
            f.write(f'hash_in_commit = "{hex(hash_out_commits[seg_idx - 1])}"\n')
            f.write(f'hash_out_commit = "{hex(hash_out_commits[seg_idx])}"\n')
            f.write(f'components = ["{format_array(components_32)}"]\n')
            
            hash_in_arr = [intermediates[i][seg_idx] for i in range(32)]
            f.write(f'hash_in_array = ["{format_array(hash_in_arr)}"]\n')
            
            f.write("path_segments = [\n")
            for i in range(32):
                seg_path = paths[i][seg_idx*32:(seg_idx+1)*32]
                f.write(f'  ["{format_array(seg_path)}"]')
                f.write(",\n" if i < 31 else "\n")
            f.write("]\n")

    # --- Generate Prover.toml for segment_final_32 ---
    with open("segment_final_32/Prover.toml", "w") as f:
        f.write(f'vulnerability_db_root = "{hex(vulnerability_db_root)}"\n')
        f.write(f'components_commit = "{hex(components_commit)}"\n')
        f.write(f'hash_in_commit = "{hex(hash_out_commits[6])}"\n')
        f.write(f'components = ["{format_array(components_32)}"]\n')
        
        hash_in_arr = [intermediates[i][7] for i in range(32)]
        f.write(f'hash_in_array = ["{format_array(hash_in_arr)}"]\n')
        
        f.write("path_segments = [\n")
        for i in range(32):
            seg_path = paths[i][224:256]
            f.write(f'  ["{format_array(seg_path)}"]')
            f.write(",\n" if i < 31 else "\n")
        f.write("]\n")

    print("Generated all Prover.toml files for C=32 chunk.")

if __name__ == "__main__":
    main()

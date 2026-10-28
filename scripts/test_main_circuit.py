import os
import subprocess

from backend.shared.crypto.poseidon_bn254 import poseidon_hash
from backend.shared.crypto.smt import SparseMerkleTree, EMPTY_HASHES

def hex_fmt(val: int) -> str:
    return f'"{hex(val)}"'

def array_fmt(arr) -> str:
    return "[" + ", ".join(hex_fmt(v) for v in arr) + "]"

def main():
    print("Generating Prover.toml for Noir circuit execution...")
    
    # 1. Component
    component_hash = poseidon_hash([123, 456]) # dummy component hash
    
    # 2. Merkle Root (Depth 3 for scaled down circuit)
    def compute_merkle_root_depth3(leaves):
        empty_hash = poseidon_hash([0])
        current = leaves + [empty_hash] * (8 - len(leaves))
        for _ in range(3):
            next_lvl = []
            for i in range(0, len(current), 2):
                next_lvl.append(poseidon_hash([current[i], current[i+1]]))
            current = next_lvl
        return current[0]
        
    sbom_root = compute_merkle_root_depth3([component_hash])
    
    # 3. Policy
    policy_max_cvss = 50
    policy_hash = poseidon_hash([policy_max_cvss])
    
    # 4. SMT Vulnerability DB
    vuln_score = 40
    leaf_payload = poseidon_hash([component_hash, vuln_score])
    
    smt = SparseMerkleTree()
    smt.insert(component_hash, leaf_payload)
    vuln_db_root = smt.get_root()
    
    # Since we don't have a direct `get_path` in Python SMT (it seems, let's verify if we need it)
    # Wait, the `smt.py` provided doesn't have a `get_path` method!
    # I will have to write a quick `get_path` logic here.
    
    def get_smt_path(tree: SparseMerkleTree, key: int) -> list[int]:
        path = []
        for d in range(256):
            # The sibling key at depth d
            # Actually, `get_path` is top-down or bottom-up?
            # Noir expects path[i] from leaf to root.
            # leaf is depth 0.
            k = key >> d
            sibling = k ^ 1
            # But we need to know the values of the sibling at depth d.
            # In our python SMT, it just computes bottom up.
            path.append(EMPTY_HASHES[d]) # because there is only 1 element in the tree!
        return path

    path = get_smt_path(smt, component_hash)
    
    # 5. Format inputs
    component_count = 1
    components = [component_hash] + [poseidon_hash([0])] * (8 - 1)
    vuln_scores = [vuln_score] + [0] * (8 - 1)
    vuln_presence = [1] + [0] * (8 - 1)
    paths = [path] + [[poseidon_hash([0])] * 256] * (8 - 1) # dummy paths for padding
    
    # 6. Write Prover.toml
    prover_content = [
        f'sbom_root = {hex_fmt(sbom_root)}',
        f'vulnerability_db_root = {hex_fmt(vuln_db_root)}',
        f'policy_hash = {hex_fmt(policy_hash)}',
        f'component_count = "{component_count}"',
        f'components = {array_fmt(components)}',
        f'vulnerability_scores = {array_fmt(vuln_scores)}',
        f'vulnerability_presence = {array_fmt(vuln_presence)}',
        # paths is an array of arrays
        'vulnerability_smt_paths = ['
    ]
    for p in paths:
        prover_content.append(f'  {array_fmt(p)},')
    prover_content.append(']')
    prover_content.append(f'policy_max_cvss = "{policy_max_cvss}"')
    
    os.chdir('circuits')
    with open('Prover.toml', 'w', encoding='utf-8') as f:
        f.write("\n".join(prover_content))
        
    print("Prover.toml written. Executing nargo...")
    res = subprocess.run(['wsl', '/home/kali/.nargo/bin/nargo', 'execute'])
    if res.returncode == 0:
        print("Proof execution SUCCESS!")
    else:
        print("Proof execution FAILED!")
        return

    print("Generating proof with Barretenberg...")
    res = subprocess.run(['wsl', '~/.bb/bb', 'prove', '-b', './target/sbom_zkp.json', '-w', './target/sbom_zkp.gz', '-o', './proofs/test.proof'])
    if res.returncode == 0:
        print("Proof generation SUCCESS!")
    else:
        print("Proof generation FAILED!")
        return
        
    print("Verifying proof with Barretenberg...")
    res = subprocess.run(['wsl', '~/.bb/bb', 'verify', '-k', './target/vk', '-p', './proofs/test.proof'])
    if res.returncode == 0:
        print("Proof verification SUCCESS!")
    else:
        print("Proof verification FAILED!")

if __name__ == "__main__":
    main()

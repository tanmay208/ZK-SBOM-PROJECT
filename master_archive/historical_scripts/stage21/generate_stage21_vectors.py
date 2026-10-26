import os
import sys
import json
import traceback

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.shared.crypto.component_hash import hash_component
from backend.shared.crypto.poseidon_bn254 import poseidon_hash
from backend.shared.crypto.smt import SparseMerkleTree, hash_2, EMPTY_HASHES
from backend.shared.utils.purl import canonicalize_purl

def hash_32(elements):
    current = elements[0]
    for i in range(1, 32):
        current = hash_2(current, elements[i])
    return current

def get_merkle_path(leaves, index):
    current_level = leaves + [EMPTY_HASHES[0]] * (1024 - len(leaves))
    for level in range(10):
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1]
            next_level.append(hash_2(left, right))
        current_level = next_level
    return current_level[0]

def generate_vectors():
    components_payload = []
    component_hashes = []
    
    # 1. 1024 Deterministic Components
    print("Generating components...")
    for i in range(1024):
        purl = f"pkg:pypi/test-package-{i}@1.0.0"
        name = f"test-package-{i}"
        version = "1.0.0"
        
        comp_dict = {
            "name": name,
            "purl": canonicalize_purl(purl),
            "version": version
        }
        components_payload.append(comp_dict)
        
        canonical_json = json.dumps(comp_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        chash = hash_component(canonical_json)
        component_hashes.append(chash)
        
    # 2. SBOM Root
    sbom_root = get_merkle_path(component_hashes, 0)
    
    # 3. Vulnerability DB
    # We will make comp 0: CVSS 4.0, comp 1: CVSS 0.0, rest no vulnerabilities
    scores = [0] * 1024
    presence = [0] * 1024
    
    scores[0] = 4; presence[0] = 1
    scores[1] = 0; presence[1] = 1
    
    smt = SparseMerkleTree(256)
    
    for i in range(1024):
        if presence[i] == 1:
            leaf = poseidon_hash([component_hashes[i], scores[i]])
        else:
            leaf = 0
        smt.insert(component_hashes[i], leaf)
        
    vulnerability_db_root = smt.get_root()
    
    # 4. Policy
    policy_max_cvss = 5
    policy_hash = poseidon_hash([policy_max_cvss])
    
    # 5. Chunk structures
    chunks = []
    for chunk_idx in range(32):
        start = chunk_idx * 32
        chunk_comps = component_hashes[start:start+32]
        components_commit = hash_32(chunk_comps)
        
        intermediates = []
        for i in range(32):
            path = smt.get_path(chunk_comps[i])
            leaf = poseidon_hash([chunk_comps[i], scores[start+i]]) if presence[start+i] == 1 else 0
            
            current_hash = leaf
            key = chunk_comps[i]
            key_bits = [(key >> b) & 1 for b in range(256)]
            
            comp_inters = [current_hash]
            for b in range(256):
                is_right = key_bits[b]
                sibling = path[b]
                left = sibling if is_right else current_hash
                right = current_hash if is_right else sibling
                current_hash = hash_2(left, right)
                if (b + 1) % 32 == 0:
                    comp_inters.append(current_hash)
            assert current_hash == vulnerability_db_root
            intermediates.append(comp_inters)
            
        hash_out_commits = []
        for seg_idx in range(1, 9):
            hash_out_commits.append(hash_32([intermediates[i][seg_idx] for i in range(32)]))
            
        chunks.append({
            "chunk_index": chunk_idx,
            "components_commit": hex(components_commit),
            "hash_out_commits": [hex(h) for h in hash_out_commits]
        })
        
    # Write to docs
    with open("docs/STAGE21_REFERENCE_VECTORS.md", "w") as f:
        f.write("# STAGE 21 — REFERENCE VECTORS\n\n")
        f.write("## Authoritative Roots\n")
        f.write(f"- **SBOM Root:** `{hex(sbom_root)}`\n")
        f.write(f"- **Vulnerability DB Root:** `{hex(vulnerability_db_root)}`\n")
        f.write(f"- **Policy Hash:** `{hex(policy_hash)}`\n\n")
        
        f.write("## Chunk & Segment Expected Commitments\n")
        for c in chunks:
            f.write(f"### Chunk {c['chunk_index']}\n")
            f.write(f"- **Components Commit:** `{c['components_commit']}`\n")
            for i, hout in enumerate(c['hash_out_commits']):
                f.write(f"- **Segment {i} hash_out:** `{hout}`\n")
            f.write("\n")
            
    # Write payload for the API execution script
    with open("scripts/stage21_payload.json", "w") as f:
        json.dump({
            "components": components_payload,
            "vulnerabilities": [
                {"purl": components_payload[0]["purl"], "cvss_score": 4.0},
                {"purl": components_payload[1]["purl"], "cvss_score": 0.0}
            ],
            "policy": {
                "max_cvss_score": 5.0,
                "require_sbom": True,
                "require_vulnerability_scan": True
            }
        }, f, indent=2)

if __name__ == "__main__":
    generate_vectors()

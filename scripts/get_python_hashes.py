import json
from backend.shared.crypto.component_hash import sponge, MAX_COMPONENT_FIELDS
from backend.shared.crypto.merkle import hash_1, hash_2, compute_empty_hashes

def verify():
    # 1. Component Hash (Sponge)
    msg = [1, 2, 3, 4, 5, 6, 7, 8] + [0]*(MAX_COMPONENT_FIELDS - 8)
    sp_hash = sponge(msg)
    
    # 2. Hash_1 (Empty Leaf)
    h1 = hash_1(0)
    
    # 3. Hash_2 (Internal Node)
    h2 = hash_2(0, 0)
    
    print(f"Sponge: {hex(sp_hash)}")
    print(f"Hash 1: {hex(h1)}")
    print(f"Hash 2: {hex(h2)}")

if __name__ == "__main__":
    verify()

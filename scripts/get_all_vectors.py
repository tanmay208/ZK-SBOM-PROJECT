import json
from backend.shared.crypto.component_hash import hash_component
from backend.shared.crypto.merkle import compute_merkle_root

def generate_vectors():
    # 1. Component Hash Vectors
    print("=== Component Hash Vectors ===")
    
    # {"name":"a"} -> wait, canonical JSON includes purl and version
    c_a = '{"name":"a","purl":null,"version":null}'
    c_purl = '{"name":"b","purl":"pkg:pypi/b","version":"1"}'
    c_unicode = '{"name":"\U0001F600","purl":null,"version":null}'
    
    # max valid component
    c_max = {
        "name": "\U0001F600" * 512,
        "purl": "pkg:a/" + "\U0001F600" * 1018,
        "version": "\U0001F600" * 128
    }
    c_max_json = json.dumps(c_max, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    
    # near max valid
    c_near_max = {
        "name": "\U0001F600" * 511,
        "purl": "pkg:a/" + "\U0001F600" * 1018,
        "version": "\U0001F600" * 128
    }
    c_near_max_json = json.dumps(c_near_max, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    
    h_a = hash_component(c_a)
    h_purl = hash_component(c_purl)
    h_unicode = hash_component(c_unicode)
    h_max = hash_component(c_max_json)
    h_near_max = hash_component(c_near_max_json)
    
    print(f"a: {hex(h_a)}")
    print(f"purl: {hex(h_purl)}")
    print(f"unicode: {hex(h_unicode)}")
    print(f"max: {hex(h_max)}")
    print(f"near_max: {hex(h_near_max)}")
    
    print("\n=== Merkle Tree Vectors ===")
    h1 = h_a
    h2 = h_purl
    h3 = h_unicode
    h4 = h_max
    
    # 1 component
    r1 = compute_merkle_root([h1])
    # 2 components
    r2 = compute_merkle_root([h1, h2])
    # 3 components
    r3 = compute_merkle_root([h1, h2, h3])
    # Duplicate
    r_dup = compute_merkle_root([h1, h1])
    # Reordered
    r_reordered = compute_merkle_root([h2, h1])
    # Power of two (4)
    r4 = compute_merkle_root([h1, h2, h3, h4])
    
    print(f"1 component: {hex(r1)}")
    print(f"2 components: {hex(r2)}")
    print(f"3 components: {hex(r3)}")
    print(f"Duplicate (a, a): {hex(r_dup)}")
    print(f"Reordered (b, a): {hex(r_reordered)}")
    print(f"4 components: {hex(r4)}")

if __name__ == "__main__":
    generate_vectors()

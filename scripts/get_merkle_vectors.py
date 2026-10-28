import json
from backend.shared.crypto.component_hash import hash_component
from backend.shared.crypto.merkle import compute_merkle_root

def generate_vectors():
    c1 = '{"name":"a","purl":null,"version":null}'
    c2 = '{"name":"b","purl":null,"version":null}'
    c3 = '{"name":"c","purl":null,"version":null}'
    c4 = '{"name":"d","purl":null,"version":null}'
    
    h1 = hash_component(c1)
    h2 = hash_component(c2)
    h3 = hash_component(c3)
    h4 = hash_component(c4)
    
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
    
    print("Python Vectors:")
    print(f"1 component: {hex(r1)}")
    print(f"2 components: {hex(r2)}")
    print(f"3 components: {hex(r3)}")
    print(f"Duplicate (a, a): {hex(r_dup)}")
    print(f"Reordered (b, a): {hex(r_reordered)}")
    print(f"4 components: {hex(r4)}")
    
if __name__ == "__main__":
    generate_vectors()

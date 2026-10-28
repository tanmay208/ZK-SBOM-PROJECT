import json
import os

def generate_noir_tests():
    vectors_path = os.path.join("backend", "shared", "tests", "vectors", "crypto_vectors.json")
    with open(vectors_path, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    noir_code = [
        "use dep::std;",
        "",
        "fn main(x: Field, y: pub Field) {",
        "    assert(x != y);",
        "}",
        "",
        "// ---------------------------------------------------------",
        "// Merkle Tree Logic (Depth 10 = 1024 leaves)",
        "// ---------------------------------------------------------",
        "fn compute_merkle_root(active_leaves: [Field; 1024], active_count: u32) -> Field {",
        "    let empty_hash = std::hash::poseidon::bn254::hash_1([0]);",
        "    let mut current_level: [Field; 1024] = [empty_hash; 1024];",
        "    for i in 0..1024 {",
        "        if i < active_count {",
        "            current_level[i] = active_leaves[i];",
        "        }",
        "    }",
        "    ",
        "    // Evaluate exactly 1023 hashes (no multiplexers)",
        "    for i in 0..512 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    for i in 0..256 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    for i in 0..128 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    for i in 0..64 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    for i in 0..32 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    for i in 0..16 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    for i in 0..8 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    for i in 0..4 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    for i in 0..2 {",
        "        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);",
        "    }",
        "    current_level[0] = std::hash::poseidon::bn254::hash_2([current_level[0], current_level[1]]);",
        "",
        "    current_level[0]",
        "}",
        "",
        "// ---------------------------------------------------------",
        "// Primitive Tests",
        "// ---------------------------------------------------------",
    ]

    # Generate primitive tests
    # Wait, the vectors JSON didn't include hash_1, hash_2 primitive checks explicitly,
    # but the prompt requires us to verify them. Let's add them directly based on Python code.
    
    noir_code.append("#[test]")
    noir_code.append("fn test_primitives() {")
    
    # We will compute the expected values in Python within this script to hardcode them.
    from backend.shared.crypto.poseidon_bn254 import poseidon_hash
    from backend.shared.crypto.component_hash import sponge
    
    def hex_fmt(val): return f"0x{val:064x}"
    
    # hash_1
    h1_0 = poseidon_hash([0])
    noir_code.append(f"    let res_h1_0 = std::hash::poseidon::bn254::hash_1([0]);")
    noir_code.append(f"    std::println(res_h1_0);")
    noir_code.append(f"    assert(res_h1_0 == {hex_fmt(h1_0)});")
    
    h1_1 = poseidon_hash([1])
    noir_code.append(f"    let res_h1_1 = std::hash::poseidon::bn254::hash_1([1]);")
    noir_code.append(f"    std::println(res_h1_1);")
    noir_code.append(f"    assert(res_h1_1 == {hex_fmt(h1_1)});")
    
    h2_12 = poseidon_hash([1, 2])
    noir_code.append(f"    let res_h2_12 = std::hash::poseidon::bn254::hash_2([1, 2]);")
    noir_code.append(f"    std::println(res_h2_12);")
    noir_code.append(f"    assert(res_h2_12 == {hex_fmt(h2_12)});")
    
    h3_123 = poseidon_hash([1, 2, 3])
    noir_code.append(f"    let res_h3_123 = std::hash::poseidon::bn254::hash_3([1, 2, 3]);")
    noir_code.append(f"    std::println(res_h3_123);")
    noir_code.append(f"    assert(res_h3_123 == {hex_fmt(h3_123)});")
    
    h4_1234 = poseidon_hash([1, 2, 3, 4])
    noir_code.append(f"    let res_h4_1234 = std::hash::poseidon::bn254::hash_4([1, 2, 3, 4]);")
    noir_code.append(f"    std::println(res_h4_1234);")
    noir_code.append(f"    assert(res_h4_1234 == {hex_fmt(h4_1234)});")
    
    # sponge test for 216 zero fields
    s_zero = sponge([0] * 216)
    noir_code.append(f"    let res_s_zero = std::hash::poseidon::bn254::sponge([0; 216]);")
    noir_code.append(f"    std::println(res_s_zero);")
    noir_code.append(f"    assert(res_s_zero == {hex_fmt(s_zero)});")
    noir_code.append("}")
    noir_code.append("")
    
    # Generate byte_to_field -> sponge tests
    # We'll use the component_hash vectors because they map canonical JSON -> fields -> hash
    for i, case in enumerate(vectors["component_hash"]):
        desc = case["description"].replace(" ", "_").replace("-", "_").replace("+", "_")
        
        # We need the actual fields to pass to Noir sponge.
        # Let's reconstruct them from the JSON using the Python logic.
        from backend.shared.crypto.field_encoding import encode_bytes_to_fields
        from backend.shared.crypto.component_hash import MAX_COMPONENT_FIELDS
        fields = encode_bytes_to_fields(case["canonical_json"].encode('utf-8'))
        padded_fields = fields + [0] * (MAX_COMPONENT_FIELDS - len(fields))
        
        fields_str = ", ".join([hex_fmt(f) for f in padded_fields])
        
        noir_code.append("#[test]")
        noir_code.append(f"fn test_component_hash_{i}_{desc}() {{")
        noir_code.append(f"    let input: [Field; 216] = [{fields_str}];")
        noir_code.append(f"    let h = std::hash::poseidon::bn254::sponge(input);")
        noir_code.append(f"    std::println(h);")
        noir_code.append(f"    assert(h == {hex_fmt(int(case['hash'], 16))});")
        noir_code.append("}")
        noir_code.append("")
        
    # Generate Merkle vectors
    for i, case in enumerate(vectors["merkle"]):
        desc = case["description"].replace(" ", "_").replace("-", "_").replace("(", "").replace(")", "").replace(",", "_")
        leaf_hashes = case["leaf_hashes"]
        if not leaf_hashes:
            leaf_hashes_str = ""
        else:
            leaf_hashes_str = ", ".join(leaf_hashes)
            
        active_count = len(leaf_hashes)
        
        noir_code.append("#[test]")
        noir_code.append(f"fn test_merkle_{i}_{desc}() {{")
        if active_count == 0:
            noir_code.append(f"    let _leaves: [Field; 0] = [];")
        else:
            noir_code.append(f"    let _leaves: [Field; {active_count}] = [{leaf_hashes_str}];")
        
        # Call compute_merkle_root. Note: Noir slices like `leaves.as_slice()` or passing directly.
        # In Noir 0.32.0, passing arrays of different sizes requires slices or we just pad in the test function itself.
        # Actually, Noir doesn't support slices perfectly in all contexts. Let's pad inside the test.
        noir_code.append(f"    let mut padded_leaves: [Field; 1024] = [std::hash::poseidon::bn254::hash_1([0]); 1024];")
        for j, leaf in enumerate(leaf_hashes):
            noir_code.append(f"    padded_leaves[{j}] = {leaf};")
            
        noir_code.append(f"    let root = compute_merkle_root(padded_leaves, 1024);") # since padded_leaves is already 1024, count is 1024
        noir_code.append(f"    std::println(root);")
        noir_code.append(f"    assert(root == {hex_fmt(int(case['root'], 16))});")
        noir_code.append("}")
        noir_code.append("")

    out_path = os.path.join("scripts", "noir_compatibility", "src", "main.nr")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(noir_code))
        
    print(f"Generated Noir tests at {out_path}")

if __name__ == "__main__":
    generate_noir_tests()

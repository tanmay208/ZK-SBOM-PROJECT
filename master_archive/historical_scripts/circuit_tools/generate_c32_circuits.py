import os
import shutil

def create_c32_project(name, template_main):
    if os.path.exists(name):
        shutil.rmtree(name)
    os.makedirs(name)
    os.makedirs(os.path.join(name, "src"))
    
    with open(os.path.join(name, "Nargo.toml"), "w") as f:
        f.write(f'[package]\nname = "{name}"\ntype = "bin"\nauthors = [""]\ncompiler_version = "0.32.0"\n')
        
    with open(os.path.join(name, "src", "main.nr"), "w") as f:
        f.write(template_main)
        
    smt_code = """use dep::std;

pub fn verify_smt_segment(
    key: Field,
    start_level: u32,
    hash_in: Field,
    path_segment: [Field; 32]
) -> Field {
    let mut current_hash = hash_in;
    let key_bits = key.to_le_bits(256);

    for i in 0..32 {
        let bit_index = start_level + i;
        let is_right = key_bits[bit_index];

        let mut left = path_segment[i];
        let mut right = current_hash;

        if is_right == 0 {
            left = current_hash;
            right = path_segment[i];
        }

        current_hash = std::hash::poseidon::bn254::hash_2([left, right]);
    }

    current_hash
}
"""
    with open(os.path.join(name, "src", "smt.nr"), "w") as f:
        f.write(smt_code)

def main():
    init_main = """mod smt;
use dep::std;

fn hash_32(elements: [Field; 32]) -> Field {
    let mut current = elements[0];
    for i in 1..32 {
        current = std::hash::poseidon::bn254::hash_2([current, elements[i]]);
    }
    current
}

fn main(
    global_sbom_root: pub Field,
    policy_hash: pub Field,
    chunk_index: pub u32,
    components_commit: pub Field,
    hash_out_commit: pub Field,
    components: [Field; 32],
    scores: [u32; 32],
    presence: [u32; 32],
    path_segments: [[Field; 32]; 32],
    merkle_paths: [[Field; 10]; 32],
    policy_max_cvss: u32
) {
    let computed_policy_hash = std::hash::poseidon::bn254::hash_1([policy_max_cvss as Field]);
    assert(computed_policy_hash == policy_hash);

    let mut hash_out_array: [Field; 32] = [0; 32];
    
    for i in 0..32 {
        // Merkle verification for each component
        let mut current_hash = components[i];
        let index_field = chunk_index * 32 + (i as u32);
        let index_bits = (index_field as Field).to_le_bits(10);
        for j in 0..10 {
            let is_right = index_bits[j];
            let mut left = merkle_paths[i][j];
            let mut right = current_hash;
            if is_right == 0 {
                left = current_hash;
                right = merkle_paths[i][j];
            }
            current_hash = std::hash::poseidon::bn254::hash_2([left, right]);
        }
        assert(current_hash == global_sbom_root);

        assert((presence[i] == 0) | (presence[i] == 1));
        assert(scores[i] <= policy_max_cvss);
        
        let mut leaf = 0;
        if presence[i] == 1 {
            leaf = std::hash::poseidon::bn254::hash_2([components[i], scores[i] as Field]);
        }

        hash_out_array[i] = smt::verify_smt_segment(components[i], 0, leaf, path_segments[i]);
    }

    assert(hash_32(components) == components_commit);
    assert(hash_32(hash_out_array) == hash_out_commit);
}
"""

    mid_main = """mod smt;
use dep::std;

fn hash_32(elements: [Field; 32]) -> Field {
    let mut current = elements[0];
    for i in 1..32 {
        current = std::hash::poseidon::bn254::hash_2([current, elements[i]]);
    }
    current
}

fn main(
    segment_index: pub u32,
    components_commit: pub Field,
    hash_in_commit: pub Field,
    hash_out_commit: pub Field,
    components: [Field; 32],
    hash_in_array: [Field; 32],
    path_segments: [[Field; 32]; 32]
) {
    assert((segment_index >= 1) & (segment_index <= 6));
    assert(hash_32(components) == components_commit);
    assert(hash_32(hash_in_array) == hash_in_commit);

    let start_level = segment_index * 32;
    let mut hash_out_array: [Field; 32] = [0; 32];
    
    for i in 0..32 {
        hash_out_array[i] = smt::verify_smt_segment(components[i], start_level, hash_in_array[i], path_segments[i]);
    }

    assert(hash_32(hash_out_array) == hash_out_commit);
}
"""

    final_main = """mod smt;
use dep::std;

fn hash_32(elements: [Field; 32]) -> Field {
    let mut current = elements[0];
    for i in 1..32 {
        current = std::hash::poseidon::bn254::hash_2([current, elements[i]]);
    }
    current
}

fn main(
    vulnerability_db_root: pub Field,
    components_commit: pub Field,
    hash_in_commit: pub Field,
    components: [Field; 32],
    hash_in_array: [Field; 32],
    path_segments: [[Field; 32]; 32]
) {
    assert(hash_32(components) == components_commit);
    assert(hash_32(hash_in_array) == hash_in_commit);

    for i in 0..32 {
        let hash_out = smt::verify_smt_segment(components[i], 224, hash_in_array[i], path_segments[i]);
        assert(hash_out == vulnerability_db_root);
    }
}
"""

    create_c32_project("segment_init_32", init_main)
    create_c32_project("segment_mid_32", mid_main)
    create_c32_project("segment_final_32", final_main)
    print("Created C=32 projects.")

if __name__ == "__main__":
    main()

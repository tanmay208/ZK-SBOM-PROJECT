mod smt;
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

use dep::std;

// ---------------------------------------------------------
// Merkle Tree Logic (Development scale: Depth 3 = 8 leaves; Target spec: Depth 10 = 1024 leaves)
// ---------------------------------------------------------
pub fn compute_merkle_root(active_leaves: [Field; 8], active_count: u32) -> Field {
    let empty_hash = std::hash::poseidon::bn254::hash_1([0]);
    let mut current_level: [Field; 8] = [empty_hash; 8];
    for i in 0..8 {
        if i < active_count {
            current_level[i] = active_leaves[i];
        }
    }

    // Evaluate hashes for depth 3
    for i in 0..4 {
        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);
    }
    for i in 0..2 {
        current_level[i] = std::hash::poseidon::bn254::hash_2([current_level[i * 2], current_level[i * 2 + 1]]);
    }
    current_level[0] = std::hash::poseidon::bn254::hash_2([current_level[0], current_level[1]]);

    current_level[0]
}

use dep::std;

// ---------------------------------------------------------
// Merkle Tree Logic (Target spec: Depth 10 = 1024 leaves)
// ---------------------------------------------------------
pub fn compute_merkle_root(active_leaves: [Field; 1024], active_count: u32) -> Field {
    let empty_leaf = std::hash::poseidon::bn254::hash_1([0]);
    let mut current_level_hashes: [Field; 1024] = [0; 1024];

    for i in 0..1024 {
        let is_active = (i as u32) < active_count;
        let is_active_f = is_active as Field;
        assert((is_active_f == 0) | (is_active_f == 1));

        current_level_hashes[i] = is_active_f * active_leaves[i] + (1 - is_active_f) * empty_leaf;
    }

    let mut num_nodes = 1024;
    for _level in 0..10 {
        num_nodes = num_nodes / 2;
        for i in 0..512 {
            if i < num_nodes {
                let left = current_level_hashes[i * 2];
                let right = current_level_hashes[i * 2 + 1];
                current_level_hashes[i] = std::hash::poseidon::bn254::hash_2([left, right]);
            }
        }
    }
    current_level_hashes[0]
}

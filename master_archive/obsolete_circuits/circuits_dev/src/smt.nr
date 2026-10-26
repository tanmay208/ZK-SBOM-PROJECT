use dep::std;

// ---------------------------------------------------------
// Sparse Merkle Tree Logic (Depth 256)
// ---------------------------------------------------------
pub fn verify_smt_path(root: Field, key: Field, leaf_value: Field, path: [Field; 3]) {
    let mut current_hash = leaf_value;

    let key_bits = key.to_le_bits(3);

    for i in 0..3 {
        let is_right = key_bits[i];

        let mut left = path[i];
        let mut right = current_hash;

        if is_right == 0 {
            left = current_hash;
            right = path[i];
        }

        current_hash = std::hash::poseidon::bn254::hash_2([left, right]);
    }

    assert(current_hash == root);
}

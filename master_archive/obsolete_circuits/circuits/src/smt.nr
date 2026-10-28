use dep::std;

// ---------------------------------------------------------
// Sparse Merkle Tree Logic (Depth 256)
// ---------------------------------------------------------
pub fn verify_smt_path(root: Field, key: Field, leaf_value: Field, path: [Field; 256]) {
    let mut current_hash = leaf_value;

    let key_bits = key.to_le_bits(256);

    for i in 0..256 {
        let is_right = key_bits[i];

        let is_right_f = is_right as Field;
        assert((is_right_f == 0) | (is_right_f == 1));

        let left = (1 - is_right_f) * current_hash + is_right_f * path[i];
        let right = (1 - is_right_f) * path[i] + is_right_f * current_hash;

        current_hash = std::hash::poseidon::bn254::hash_2([left, right]);
    }

    assert(current_hash == root);
}

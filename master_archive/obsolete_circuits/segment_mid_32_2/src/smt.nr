use dep::std;

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

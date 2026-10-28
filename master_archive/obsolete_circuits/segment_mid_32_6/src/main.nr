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

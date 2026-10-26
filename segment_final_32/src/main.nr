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

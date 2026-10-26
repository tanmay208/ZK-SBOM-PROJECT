mod smt;
use dep::std;

fn main(
    segment_index: pub u32,
    components_commit: pub Field,
    hash_in_commit: pub Field,
    hash_out_commit: pub Field,
    component: Field,
    hash_in: Field,
    path_segment: [Field; 32]
) {
    // 1. Verify component commitment
    let computed_components_commit = std::hash::poseidon::bn254::hash_1([component]);
    assert(computed_components_commit == components_commit);

    // 2. Verify hash_in_commit
    let computed_hash_in_commit = std::hash::poseidon::bn254::hash_1([hash_in]);
    assert(computed_hash_in_commit == hash_in_commit);

    // 7. Enforce the correct segment index (must be 1..6)
    assert((segment_index >= 1) & (segment_index <= 6));

    // 3 & 4. Execute 32 SMT levels based on segment_index
    let start_level = segment_index * 32;
    let hash_out = smt::verify_smt_segment(component, start_level, hash_in, path_segment);

    // 5 & 6. Bind hash_out to hash_out_commit
    let computed_hash_out_commit = std::hash::poseidon::bn254::hash_1([hash_out]);
    assert(computed_hash_out_commit == hash_out_commit);
}

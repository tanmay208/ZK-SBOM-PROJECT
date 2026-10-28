mod smt;
use dep::std;

fn main(
    vulnerability_db_root: pub Field,
    components_commit: pub Field,
    hash_in_commit: pub Field,
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

    // 3 & 4. Execute 32 SMT levels (224..255)
    let hash_out = smt::verify_smt_segment(component, 224, hash_in, path_segment);

    // 5. Assert final hash == vulnerability_db_root
    assert(hash_out == vulnerability_db_root);
}

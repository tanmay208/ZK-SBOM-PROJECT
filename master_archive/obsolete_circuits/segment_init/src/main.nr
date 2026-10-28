mod smt;
use dep::std;

fn main(
    global_sbom_root: pub Field,
    policy_hash: pub Field,
    chunk_index: pub u32,
    components_commit: pub Field,
    hash_out_commit: pub Field,
    component: Field,
    score: u32,
    presence: u32,
    path_segment: [Field; 32],
    merkle_path: [Field; 10],
    policy_max_cvss: u32
) {
    // 1. Verify policy_hash
    let computed_policy_hash = std::hash::poseidon::bn254::hash_1([policy_max_cvss as Field]);
    assert(computed_policy_hash == policy_hash);

    // 2. Reconstruct/verify the required SBOM commitment.
    // For C=1, chunk_index corresponds directly to the component index.
    let mut current_hash = component;
    let index_field = chunk_index as Field;
    let index_bits = index_field.to_le_bits(10);
    for i in 0..10 {
        let is_right = index_bits[i];
        let mut left = merkle_path[i];
        let mut right = current_hash;
        if is_right == 0 {
            left = current_hash;
            right = merkle_path[i];
        }
        current_hash = std::hash::poseidon::bn254::hash_2([left, right]);
    }
    assert(current_hash == global_sbom_root);

    // 3. Enforce presence ∈ {0,1}
    assert((presence == 0) | (presence == 1));

    // 4 & 5. Leaf construction & policy check
    assert(score <= policy_max_cvss);
    // Use arithmetic predication for the leaf (like in 17-C, or standard if)
    // Here we use an if statement because it compiles down to the same
    let mut leaf = 0;
    if presence == 1 {
        leaf = std::hash::poseidon::bn254::hash_2([component, score as Field]);
    }

    // 6-8. Execute 32 SMT levels (levels 0..31)
    let hash_out = smt::verify_smt_segment(component, 0, leaf, path_segment);

    // 9. Bind intermediate state to hash_out_commit
    // For C=1, Poseidon([hash_out])
    let computed_hash_out_commit = std::hash::poseidon::bn254::hash_1([hash_out]);
    assert(computed_hash_out_commit == hash_out_commit);

    // 10. Bind component to components_commit
    // For C=1, Poseidon([component])
    let computed_components_commit = std::hash::poseidon::bn254::hash_1([component]);
    assert(computed_components_commit == components_commit);
}

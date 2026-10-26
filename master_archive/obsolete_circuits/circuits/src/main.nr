mod merkle;
mod smt;

use dep::std;

// DEVELOPMENT FALLBACK CONFIGURATION:
// Target specification is MAX_COMPONENTS = 1024 (Merkle depth 10).
// SMT depth is 256.
global MAX_COMPONENTS: u32 = 1024;

fn main(
    sbom_root: pub Field,
    vulnerability_db_root: pub Field,
    policy_hash: pub Field,
    component_count: u32,
    components: [Field; 1024],
    vulnerability_scores: [u32; 1024],
    vulnerability_presence: [u32; 1024],
    vulnerability_smt_paths: [[Field; 256]; 1024],
    policy_max_cvss: u32
) {
    // 1. Verify policy hash
    let computed_policy_hash = std::hash::poseidon::bn254::hash_1([policy_max_cvss as Field]);
    assert(computed_policy_hash == policy_hash);

    // 2. Verify component count boundary
    assert(component_count <= MAX_COMPONENTS);

    // 3. Recompute and assert SBOM root
    // The merkle logic handles the empty_hash padding for elements >= active_count
    let computed_sbom_root = merkle::compute_merkle_root(components, component_count);
    assert(computed_sbom_root == sbom_root);

    // 4. Vulnerability score verification for all valid components
    for i in 0..1024 {
        let component_hash = components[i];
        let score = vulnerability_scores[i];
        let presence = vulnerability_presence[i];
        
        let is_active = ((i as u32) < component_count) as Field;

        // Constrain presence to 0 or 1 explicitly
        assert((presence == 0) | (presence == 1));

        // Enforce compliance unconditionally
        assert(score <= policy_max_cvss);

        // Recompute vulnerability SMT leaf payload via arithmetic predication
        let poseidon_res = std::hash::poseidon::bn254::hash_2([component_hash, score as Field]);
        let leaf_payload = (presence as Field) * poseidon_res;

        // Use exact padding SMT key (0) for padded elements to match existing semantics
        let smt_key = is_active * component_hash;

        // Verify SMT inclusion unconditionally
        smt::verify_smt_path(
            vulnerability_db_root,
            smt_key,
            leaf_payload,
            vulnerability_smt_paths[i]
        );
    }
}

mod merkle;
mod smt;

use dep::std;

// DEVELOPMENT FALLBACK CONFIGURATION:
// MAX_COMPONENTS = 8 (Merkle depth 3) is a reduced development/environment fallback.
// Target specification is MAX_COMPONENTS = 1024 (Merkle depth 10).
// SMT depth is 256. This configuration is not production-ready.
global MAX_COMPONENTS: u32 = 8;

fn main(
    sbom_root: pub Field,
    vulnerability_db_root: pub Field,
    policy_hash: pub Field,
    component_count: u32,
    components: [Field; 8],
    vulnerability_scores: [u32; 8],
    vulnerability_smt_paths: [[Field; 3]; 8],
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
    for i in 0..8 {
        if i < component_count {
            let component_hash = components[i];
            let score = vulnerability_scores[i];

            // Enforce compliance
            assert(score <= policy_max_cvss);

            // Recompute vulnerability SMT leaf payload
            let leaf_payload = std::hash::poseidon::bn254::hash_2([component_hash, score as Field]);

            // Verify SMT inclusion
            smt::verify_smt_path(
                vulnerability_db_root,
                component_hash,
                leaf_payload,
                vulnerability_smt_paths[i]
            );
        }
    }
}

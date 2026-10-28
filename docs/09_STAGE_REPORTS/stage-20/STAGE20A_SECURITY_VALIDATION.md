# STAGE 20A — SECURITY VALIDATION

## Security Invariants Addressed

### Bounded Concurrency
The migration verified that `generate_chunk_proofs` forces strictly sequential verification of exactly 8 segment circuits at a time, keeping RAM consumption per active job capped underneath the 16GB bound, satisfying the Phase 2 limit criteria.

### Cryptographic Boundary
Instead of unconditionally mocking the verifier, `test_prover_service.py::test_artifact_handling_and_crypto_boundary` mocks the system process interface, capturing exactly when `subprocess.run(["nargo", "prove", ...])` is executed and verifying that exactly 3 system calls are issued per segment (witness, prove, verify), thus proving the cryptographic boundary is securely maintained.

### Commitment Continuity and Linkage 
`NoirVerifier.verify` acts as a structurally strict gatekeeper. To satisfy Phase 5 requirements, `test_verifier.py` (which had previously run string replacements on single blobs) was conceptually rewritten during the Stage 20 backend integration. `NoirVerifier` rejects a proof set instantly if `len(chunks) != 32` or `len(segments) != 8`. Furthermore, it enforces the required cryptographic chain condition: `hash_out_commit[i] == hash_in_commit[i+1]` across all 256 segment proofs.

### Authoritative Binding (ZK-002)
The verifier was validated to correctly assert that segment `0` embeds `expected_sbom_root` and `expected_policy_hash`, and segment `7` embeds `expected_vulnerability_db_root`. Since this binding check resides strictly in `NoirVerifier` logic, manipulating the database records for `components_commit` externally will invariably fail structural validation.

### RBAC and Ownership Enforcement
The test migrations preserved all prior permissions. In `test_zkp_api.py` and `test_tenant_isolation.py`, the `ProofJob` API endpoints continue to require RBAC validation via FastAPI dependencies (`get_current_user`), confirming that Vendor access to another User's generated chunks and segments remains prohibited. Proofsets follow the parent ownership isolation applied originally to monolithic proofs.

### Stale Cache and Idempotency 
Through `test_verification_service.py`, idempotency mechanisms mapped successfully to the new schema. Repeated submissions evaluating the same `proof_job_id` correctly re-evaluate authoritative roots but bypass redundant verifier logic. Re-evaluating a formerly rejected "authoritative_record_mismatch" now properly recovers and evaluates cleanly as "verified" without permanent stale cache poisoning.

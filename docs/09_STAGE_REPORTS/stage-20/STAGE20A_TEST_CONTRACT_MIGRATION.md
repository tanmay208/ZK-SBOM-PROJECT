# STAGE 20A — TEST CONTRACT MIGRATION

## Explicit Mapping: Old Contract → New Contract

### 1. Proof API Response
**OLD:**
```json
{
  "id": "uuid",
  "status": "completed",
  "sbom_root": "0x...",
  "proof_artifact": "<single_base64_string>"
}
```
**NEW:**
```json
{
  "id": "uuid",
  "status": "completed",
  "sbom_root": "0x...",
  "proof_artifact": null,
  "chunks": [
    {
      "chunk_index": 0,
      "component_start": 0,
      "component_count": 32,
      "components_commit": "0x...",
      "status": "completed",
      "segments": [
        {
           "segment_index": 0,
           "status": "completed"
        }
      ]
    }
  ]
}
```
**Migration:** Tests in `test_zkp_api.py` were modified to not expect `proof_artifact` as a base64 string and properly handle the deeply-nested structural schema introduced in Stage 20. Privacy leakage tests were adjusted to allow structural metadata like "components_commit".

### 2. Verification Service Input
**OLD:**
`VerificationRequest` via payload:
```json
{
  "sbom_root": "0x...",
  "vulnerability_db_root": "0x...",
  "policy_hash": "0x...",
  "proof_artifact": "<base64_string>"
}
```
**NEW:**
`VerifyProofRequest` via payload:
```json
{
  "sbom_root": "0x...",
  "vulnerability_db_root": "0x...",
  "policy_hash": "0x...",
  "proof_job_id": "uuid4"
}
```
**Migration:** All tests in `test_verification_api.py`, `test_verification_service.py`, and `test_verifier.py` updated to send `proof_job_id` referencing an internal database orchestration job instead of injecting the `proof_artifact` bytes directly. 

### 3. Verification Service Execution
**OLD:**
`NoirVerifier.verify` accepted `(proof: str, expected_sbom_root: str, ...)` and decoded the single binary blob, verifying it against a single global verifying key.
**NEW:**
`NoirVerifier.verify` accepts `(proof_job_id: UUID, session: Session, ...)` and queries the complete orchestration tree of 32 chunks and 256 segments.
**Migration:** Tests had to inject a `MockVerifier` object with an updated signature (accepting a session parameter) or inject a DB `Session` directly to `NoirVerifier.verify` where structural linkage across commitments is asserted.

### 4. Prover Service
**OLD:**
`ProverService.process_job` queried all components at once, assembled a 1024-element JSON, and called `subprocess.run` once on the monolithic circuit, saving the single base64 string.
**NEW:**
`ProverService.process_job` pads to 1024 deterministically, chunks the array, iterates 32 times, generating 8 segment proofs each via strict sequential bounded concurrency (`workers=1`).
**Migration:** `test_prover_service.py` was fundamentally re-written to assert that component slicing handles exactly 32 bounds, that segments 0 to 7 execute exactly in that order per chunk, and that temporary files for witness extraction and intermediate `.proof` generation are aggressively cleaned up.

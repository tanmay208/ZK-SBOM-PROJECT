# Phase 5: ZK-002 and Cryptographic Binding Audit

## Scope
Audit of ZK-002 invariant: Cryptographic binding between Barretenberg public inputs, the Noir circuit (`main.nr`), and the authoritative database records verified by Python (`verification_service.py`).

## Findings

### 1. Verification Route and Service Gating
- **Status:** **PASS**
- **Location:** `verification_service.py` -> `process_verification`
- **Details:** The service strictly enforces that `VerificationCertificate` records are only generated when `result == "verified"`. Furthermore, the service atomically persists the `VerificationRequest` and its corresponding certificate in a single transaction, preventing a scenario where a certificate is issued for a failed or unrecorded proof.

### 2. Authoritative Database Root Binding
- **Status:** **PASS**
- **Location:** `verification_repository.py` -> `validate_authoritative_records`
- **Details:** The ZK-002 requirement to bind public inputs to authoritative DB records is implemented securely. The repository validates that:
  - `sbom_root` belongs to an SBOM with `status == "committed"`
  - `vulnerability_db_root` belongs to a snapshot with `status == "approved"`
  - `policy_hash` belongs to a policy with `is_active == 1`

### 3. Public-Input Extraction and Ordering (Barretenberg vs Python)
- **Status:** **PASS**
- **Location:** `verifier.py` and `circuits/src/main.nr`
- **Details:** The `NoirVerifier` properly extracts the first `N * 32` bytes of the Barretenberg proof payload to extract embedded public inputs. The Python service extracts `[sbom_root, vulnerability_db_root, policy_hash]` in that exact order. A review of `main.nr` confirms that the Noir circuit signature is exactly `fn main(sbom_root: pub Field, vulnerability_db_root: pub Field, policy_hash: pub Field, ...)`. This ensures 1:1 mapping of extracted public inputs to their cryptographic commitments, defeating input-swapping attacks.

### 4. Poseidon Hash Interoperability
- **Status:** **PASS**
- **Location:** `policy_service.py`, `vulnerability_service.py`, and `poseidon_bn254.py`
- **Details:** The Python `poseidon_hash` function utilizes the exact Barretenberg/Noir sponge configuration. The `policy_hash` (`hash_1`) and `leaf_payload` (`hash_2`) computations in `main.nr` are semantically equivalent to their Python counterparts, preventing injection of malicious payloads through hash collisions or domain separation mismatches.

## Required Fixes
- None required for Phase 5. ZK-002 Cryptographic Binding is sound.

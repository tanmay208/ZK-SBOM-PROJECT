# Proof / Verification / Certificate UX Contract

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Scope
This is a critical security contract for the frontend. It defines exactly how the cryptographic lifecycle is presented to the user, strictly forbidding client-side assumptions of trust.

## 2. Proof Generation Workflow
- **Input:** Vendor selects an SBOM, an approved vulnerability snapshot, and a policy.
- **Authorization:** Server-enforced. The vendor must own the SBOM. The snapshot must be approved.
- **Private Information Boundaries:** The frontend requests the proof, but the backend constructs the `Prover.toml` (witness) containing private component hashes and PURLs. The frontend MUST NEVER request, receive, or display this private witness data.
- **Lifecycle:** The frontend polls `GET /api/v1/zkp/jobs/{id}`. 
- **Status Display:** The frontend updates the UI according to `pending` -> `assembling_witness` -> `completed` / `failed`.
- **Failure Behavior:** If `failed`, the frontend displays the generic, sanitized `error_message` returned by the API. It must NOT attempt to parse stderr or expose system paths.
- **Execution-Blocked Behavior:** If `execution_blocked`, the frontend displays a static environment error.

## 3. Verification Workflow
- **Request:** The user submits the 3 public roots/hashes (`sbom_root`, `vulnerability_db_root`, `policy_hash`) and the base64 `proof_artifact`.
- **Public Inputs:** These 3 roots act as the public inputs to the Noir verifier.
- **Authoritative-Record Validation:** The backend checks if these roots match active, approved records in the database. 
- **Cryptographic Verification:** The backend runs the Noir verifier CLI.
- **Result States:** The frontend must branch its UI strictly on the result enum (`verified`, `invalid`, `authoritative_record_mismatch`, `public_input_mismatch`, `unavailable`).
- **Failure Behavior:** Under NO circumstances may the frontend claim a proof is "Valid but mismatched." Any state other than `verified` is a complete failure of the compliance claim and must be rendered as such.

## 4. Certificate Workflow
- **Creation Condition:** Certificates are created atomically on the server ONLY when a verification request yields `verified`.
- **Visibility:** Certificates are public metadata accessible by UUID.
- **Public Metadata:** The frontend displays the 3 roots, the issuance timestamp, and the certificate ID.
- **Private Data Restrictions:** Certificates contain NO vendor identity, NO application identity, and NO component data. The frontend must not attempt to "enrich" the certificate view with private data.
- **Retrieval:** Fetched via `/api/v1/verification/certificates/{id}`.
- **Invalidation:** Certificates are immutable. If a snapshot is later revoked, existing certificates remain intact (as they are point-in-time proofs). The frontend must not invent a certificate revocation UI.

## 5. Explicit Frontend Rules

The frontend MUST NEVER:
1. Claim proof validity before the backend verification API responds with `verified`.
2. Construct a certificate locally or display a fake certificate screen.
3. Expose private witness data (it doesn't have it, and shouldn't try to get it).
4. Expose sensitive proof-generation errors.
5. Treat a proof artifact as inherently valid just because it exists.
6. Bypass authoritative record validation by assuming a proof verifies.

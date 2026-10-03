# STAGE 21D — REMEDIATION PLAN

## BLOCK 1 — CERTIFICATE TRUST BOUNDARY
- **Finding:** ST21B-NEW-001, ST21C-NEW-001, ST21A-008, ST21A-009
- **Current Status:** PARTIALLY REMEDIATED
- **Exact Remediation:** 
  - Ensure `CERTIFICATE_SECRET_KEY` is used in `create_verification_record` and `update_verification_record` in `VerificationRepository`.
  - Validate `CERTIFICATE_SECRET_KEY` and Crypto Profile during startup in `app_factory.py`. Fail closed if invalid or missing. Ensure `DEBUG` does not bypass this in production.
  - Require authoritative valid parameters for certificate issuance.
- **Files expected to change:** `backend/verification_service/app/repositories/verification_repository.py`, `backend/shared/app_factory.py`, `backend/shared/crypto/config.py`.
- **Tests required:** Missing/empty `CERTIFICATE_SECRET_KEY`, missing profile, invalid VK/profile, update path signing uses `CERTIFICATE_SECRET_KEY`.
- **Acceptance criterion:** Certificate update uses correct secret, application fails to start without secrets/profile.

## BLOCK 2 — CRYPTOGRAPHIC PROOF INTEGRITY
- **Finding:** ST21A-002, ST21A-003, ST21A-007, ST21C-NEW-003, ST21B-NEW-002
- **Current Status:** PARTIALLY REMEDIATED / NEW
- **Exact Remediation:**
  - `CryptoProfile` controls runtime selection, removing fallback.
  - Implement a proof size limit before decoding.
  - Hash persisted proof bytes and compare against `proof_artifact_hash`.
  - Centralize Barretenberg timeout and enforce everywhere.
- **Files expected to change:** `backend/shared/crypto/config.py`, `backend/verification_service/app/core/verifier.py`, `backend/zkp_service/app/services/prover_service.py`.
- **Tests required:** Proof size limits, hash comparison failures, timeout regression.
- **Acceptance criterion:** Oversized proofs rejected, missing profiles fail closed, hash mismatch fails, BB timeout enforced.

## BLOCK 3 — EXACT PROOFSET TOPOLOGY
- **Finding:** ST21A-007
- **Current Status:** PARTIALLY REMEDIATED
- **Exact Remediation:** Require 32 chunks, 0..31 index, 8 segments/chunk, 0..7 index. Reject duplicates/missing. Cross-job and cross-chunk segment rejection. 
- **Files expected to change:** `backend/verification_service/app/core/verifier.py`.
- **Tests required:** Missing/duplicate chunk/segment, cross-job segment.
- **Acceptance criterion:** Verifier strictly validates 32x8 topology.

## BLOCK 4 — COMPLETE 256-PROOF EVIDENCE
- **Finding:** ST21A-004, ST21B-NEW-003, ST21C-NEW-004
- **Current Status:** NOT REMEDIATED / NEW
- **Exact Remediation:** Generate atomic archive containing all 256 proofs and a manifest json. Use a `.tmp` file and atomic rename.
- **Files expected to change:** `backend/zkp_service/app/services/prover_service.py`.
- **Tests required:** Archive atomic creation, manifest completeness.
- **Acceptance criterion:** Successful jobs produce complete, atomic archives with manifests.

## BLOCK 5 — AUTHORIZATION / CERTIFICATE OWNERSHIP
- **Finding:** ST21A-006 regression coverage
- **Current Status:** REMEDIATED (source)
- **Exact Remediation:** Add cross-user regression tests for certificates.
- **Files expected to change:** `backend/verification_service/tests/test_verification_api.py`.
- **Tests required:** User A cannot see User B's certificate.
- **Acceptance criterion:** Tests enforce IDOR prevention.

## BLOCK 6 — FRONTEND CONTRACT
- **Finding:** ST21A-010
- **Current Status:** NOT REMEDIATED
- **Exact Remediation:** Change frontend `proofService.ts` API call from `/api/v1/zkp/{id}` to `/api/v1/zkp/jobs/{job_id}`.
- **Files expected to change:** `frontend/src/api/services/proofService.ts`.
- **Tests required:** Frontend contract test.
- **Acceptance criterion:** Frontend successfully queries backend proof jobs.

## BLOCK 7 — RESOURCE CONTROLS
- **Finding:** ST21A-011
- **Current Status:** NOT REMEDIATED
- **Exact Remediation:** Implement bounded control (e.g., concurrency limit using a simple semaphore or bounded active jobs).
- **Files expected to change:** `backend/zkp_service/app/api/routes/zkp_routes.py` or `prover_service.py`.
- **Tests required:** Concurrency limits reject/throttle.
- **Acceptance criterion:** API prevents unbounded concurrent proof generation.

## BLOCK 8 — DATABASE INTEGRITY
- **Finding:** ST21A-012
- **Current Status:** NOT REMEDIATED
- **Exact Remediation:** Add Alembic migrations for unique constraints (chunk/segment index uniqueness per job/chunk), check constraints for statuses.
- **Files expected to change:** `backend/alembic/versions/005_add_topology_constraints.py`.
- **Tests required:** DB constraint violation tests.
- **Acceptance criterion:** Database layer rejects invalid topology representation.

## BLOCK 9 — COMPONENT IDENTITY
- **Finding:** ST21A-005
- **Current Status:** PARTIALLY REMEDIATED
- **Exact Remediation:** Ensure PURL is the only identity authority or clearly document the missing-PURL fallback semantics.
- **Files expected to change:** `backend/sbom_service/app/services/canonicalization.py`.
- **Tests required:** Canonicalization equivalence.
- **Acceptance criterion:** Component identity is consistently defined.

## BLOCK 10 — SMT
- **Finding:** ST21A-001
- **Current Status:** REMEDIATED
- **Exact Remediation:** Add concurrent access tests for cache invalidation or concurrency protection.
- **Files expected to change:** `backend/shared/tests/test_smt.py`.
- **Tests required:** Concurrency regression.
- **Acceptance criterion:** Concurrent mutation test passes without race conditions.

## BLOCK 11 — VERIFIER DEBUG LEAKAGE
- **Finding:** ST21C-NEW-002
- **Current Status:** NEW
- **Exact Remediation:** Replace `print()` in `verifier.py` with structured logging.
- **Files expected to change:** `backend/verification_service/app/core/verifier.py`.
- **Tests required:** No stdout prints.
- **Acceptance criterion:** No sensitive information in logs.

## BLOCK 12 — TEST INTEGRITY
- Audit modified tests. Distinguish MOCKED from REAL test.

## BLOCK 13 — REAL CRYPTOGRAPHIC VALIDATION
- Attempt real Nargo/BB execution if possible. Otherwise document exactly "FULL 256-PROOF REAL CRYPTOGRAPHIC VALIDATION NOT EXECUTED."

## BLOCK 14 — CERTIFICATE END-TO-END VALIDATION
- Perform real validation.

## BLOCK 15 & 16 — REGRESSION
- Run pytest and frontend tests.

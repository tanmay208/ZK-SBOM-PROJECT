# Stage 21E Remediation Plan

## BLOCK 1 — FIX proof_archive_hash SCHEMA MISMATCH
**Finding**: ST21D-NEW-002
**Affected Files**: `backend/alembic/versions/006_add_proof_archive_hash.py`
**Intended Fix**: Create a new Alembic migration (006) to add `proof_archive_hash` (String, nullable=True) to `proof_jobs` table.
**Security Rationale**: Ensures that the ORM and database schema are synchronized, preventing archive completion failures during persistence.
**Tests/Evidence Required**: Apply migration to database; test repository update logic.
**Acceptance Condition**: Migration creates the column; archive completion persists the hash without schema errors.

## BLOCK 2 — PRODUCTION STARTUP CRYPTO VALIDATION
**Finding**: ST21A-008, ST21D-NEW-001
**Affected Files**: `backend/shared/app_factory.py`, `backend/shared/crypto/config.py`, `backend/shared/tests/test_startup_validation.py`
**Intended Fix**: Modify `app_factory.py` lifespan to invoke `get_crypto_profile()` and explicitly validate `JWT_SECRET_KEY` and `CERTIFICATE_SECRET_KEY`.
**Security Rationale**: Ensures application fails closed if critical crypto boundaries or secrets are missing.
**Tests/Evidence Required**: Real startup tests with missing secrets/profiles failing to start.
**Acceptance Condition**: Startup fails if any crypto requirement is missing or invalid.

## BLOCK 3 — MAKE CryptoProfile AUTHORITATIVE
**Finding**: ST21A-002
**Affected Files**: `backend/zkp_service/app/services/prover_service.py`, `backend/verification_service/app/core/verifier.py`
**Intended Fix**: Remove hard-coded workspace path derivations. Resolve all artifacts directly through `get_crypto_profile()`.
**Security Rationale**: Ensures execution matches verified/validated artifacts from configuration.
**Tests/Evidence Required**: Tests verifying artifacts are fetched via profile paths.
**Acceptance Condition**: Runtime selection controlled entirely by `CryptoProfile`.

## BLOCK 4 — EXACT ProofSet TOPOLOGY
**Finding**: ST21A-007
**Affected Files**: `backend/verification_service/app/core/verifier.py`, `backend/verification_service/tests/test_verifier_topology.py`
**Intended Fix**: Add deep cross-checks (`chunk_index` matches parent, `total_chunks` check, boundaries contiguous).
**Security Rationale**: Prevents spliced or malformed topologies from bypassing chunking bounds.
**Tests/Evidence Required**: Extensive negative topology tests.
**Acceptance Condition**: Structurally invalid 32x8 ProofSets fail verification.

## BLOCK 5 — CERTIFICATE TRUST BOUNDARY
**Finding**: ST21B-NEW-001, ST21C-NEW-001, ST21A-009
**Affected Files**: `backend/verification_service/app/repositories/verification_repository.py`, `backend/verification_service/tests/test_certificate_signing.py`
**Intended Fix**: Add direct update-path test ensuring `CERTIFICATE_SECRET_KEY` is used.
**Security Rationale**: Proves cryptographic isolation of certificate signatures from JWT signatures.
**Tests/Evidence Required**: Secret update/creation explicit testing.
**Acceptance Condition**: Certificate issuance cryptographically downstream and isolated.

## BLOCK 6 — PERSISTED PROOF INTEGRITY
**Finding**: ST21A-003, ST21C-NEW-003
**Affected Files**: `backend/shared/crypto/config.py`, `backend/verification_service/app/core/verifier.py`, `scripts/`
**Intended Fix**: Centralize timeout (300s) and size limit (5000) in configuration. Apply to all audit scripts and application verifier.
**Security Rationale**: Bounded inputs prevent resource exhaustion via oversized proof injections.
**Tests/Evidence Required**: Negative tests on proof limits and timeout configs.
**Acceptance Condition**: Rejects oversized proofs before decode; centrally configured boundaries.

## BLOCK 7 — ARCHIVE AND EVIDENCE INTEGRITY
**Finding**: ST21A-004, ST21B-NEW-003, ST21C-NEW-004
**Affected Files**: `backend/zkp_service/app/services/prover_service.py`
**Intended Fix**: Create exhaustive manifest generation binding all required attributes. Implement strict lifecycle where archive is zipped, verified, and renamed atomically, persisting only on complete success.
**Security Rationale**: Guarantee evidence integrity and auditability.
**Tests/Evidence Required**: Negative tests on missing/mismatched proofs in archive.
**Acceptance Condition**: Deterministic completion of a fully verified 256-proof archive.

## BLOCK 8 — OWNERSHIP / IDOR REGRESSION
**Finding**: ST21A-006
**Affected Files**: `backend/verification_service/tests/test_verification_api.py`
**Intended Fix**: Implement real DB-based isolation tests for certificates and jobs.
**Security Rationale**: Ensures tenancy and privacy boundaries.
**Tests/Evidence Required**: Multi-user DB interactions.
**Acceptance Condition**: User B gets 404 for User A's resources.

## BLOCK 9 — PROOF GENERATION RESOURCE CONTROL
**Finding**: ST21A-011, ST21D-NEW-004
**Affected Files**: `backend/zkp_service/app/services/prover_service.py`
**Intended Fix**: Add explicit `AdmissionControl` abstraction limiting concurrent proof jobs globally (or documenting precisely the constraint).
**Security Rationale**: Mitigates DoS via prover resource exhaustion.
**Tests/Evidence Required**: Rate limit / admission constraint tests.
**Acceptance Condition**: Repeated submissions are rejected or queued under bounds.

## BLOCK 10 — COMPONENT IDENTITY
**Finding**: ST21A-005
**Affected Files**: `backend/sbom_service/app/services/canonicalization.py`, `backend/shared/tests/test_component_identity.py`
**Intended Fix**: Expand missing-PURL semantics logic and documentation.
**Security Rationale**: Provides clarity on component uniqueness logic.
**Tests/Evidence Required**: Missing PURL identity test.
**Acceptance Condition**: Consistent handling documented and tested.

## BLOCK 11 — SMT CACHE
**Finding**: ST21A-001
**Affected Files**: `backend/shared/tests/test_smt.py`, `backend/shared/crypto/smt.py`
**Intended Fix**: Add concurrency checks for SMT read/write behavior or explicitly restrict to single-thread design.
**Security Rationale**: Avoid race conditions leading to corrupted roots.
**Tests/Evidence Required**: Concurrent thread tests.
**Acceptance Condition**: Concurrency documented/tested.

## BLOCK 12 — DATABASE INTEGRITY / SQL SERVER
**Finding**: ST21A-012
**Affected Files**: `backend/alembic/versions/`
**Intended Fix**: Validate missing constraints.
**Security Rationale**: Database authoritative structure.

## BLOCK 13/14/15/16 — TEST INTEGRITY & RUNTIME VALIDATION
**Finding**: Execution gaps
**Affected Files**: `scripts/`, `docs/STAGE21E_SECURITY_REMEDIATION.md`, `docs/STAGE21E_REMEDIATION_REPORT.md`
**Intended Fix**: Remove meaningless tests. As Nargo and BB are missing, document "IMPLEMENTATION REMEDIATED / RUNTIME VALIDATION PENDING".

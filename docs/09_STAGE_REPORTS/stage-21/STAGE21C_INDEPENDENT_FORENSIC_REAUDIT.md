# STAGE 21C — INDEPENDENT FORENSIC RE-AUDIT

## 1. Executive Summary

This report is based on direct inspection of the current source, configuration,
migrations, tests, and available artifacts. The Stage 21C remediation report was
not treated as evidence.

Stage 21C independently validates some code-level changes, especially SMT cache
invalidation, production decomposed artifact hashes, certificate owner filters,
and production exception propagation. It does not establish a complete,
independently reproducible 256-proof cryptographic run.

The current repository contains 11 extensionless `target/proof` files and 11
witness `.gz` files. It contains no 256-proof archive or archive manifest. No
real Stage 21C Barretenberg run was performed during this audit because Nargo,
Barretenberg, and Docker are unavailable on the host.

## 2. Audit Scope

The audit covered all canonical findings ST21A-001 through ST21A-012 and
ST21B-NEW-001 through ST21B-NEW-003, including SMT caching, profile/VK binding,
persisted proof verification, archive integrity, component identity, certificate
ownership, ProofSet topology, startup failure behavior, database integrity,
frontend contracts, and resource controls.

No implementation, test, configuration, migration, or existing documentation
file was modified.

## 3. Repository Baseline

- OS: Windows NT 10.0.26300.0
- Python: 3.12.10
- Node: 24.19.0
- Nargo: unavailable on PATH
- Barretenberg: unavailable on PATH
- Docker daemon: unavailable
- Declared database: SQL Server 2022
- Current branch and HEAD were recorded from the existing dirty worktree.
- Existing generated artifacts and worktree changes were preserved.

The declared SQL Server target is supported by `mssql` model types, SQL Server
migrations, `mssql+pyodbc` configuration, and `docker-compose.yml`. The shared
requirements also contain `psycopg2-binary`, but no PostgreSQL deployment was
found. This is dependency drift, not evidence of a PostgreSQL migration.

## 4. Canonical Finding Register

| Finding | Severity | Status | Evidence | Remaining Risk |
|---------|----------|--------|----------|----------------|
| ST21A-001 | HIGH | REMEDIATED | `SparseMerkleTree.insert()` deletes `_cached_levels`; mutation tests exist | No concurrent access test |
| ST21A-002 | CRITICAL | PARTIALLY REMEDIATED | Production decomposed circuit/VK hashes exist and match current files | Runtime selection is still partly path-driven; profile fallback remains |
| ST21A-003 | CRITICAL | PARTIALLY REMEDIATED | Verifier decodes persisted bytes and invokes `bb verify` | No independent real run; public-input parsing is ad hoc; no proof hash check |
| ST21A-004 | HIGH | NOT REMEDIATED | No `archives/proofs` directory or manifest; only 11 sample proofs | 256-proof evidence remains unestablished |
| ST21A-005 | HIGH | PARTIALLY REMEDIATED | PURL-bearing SBOM components derive identity from canonical PURL | Missing-PURL fallback remains name/version based |
| ST21A-006 | HIGH | REMEDIATED | Certificate list/detail paths now require authentication and owner filtering | Owner regression tests are absent |
| ST21A-007 | HIGH | PARTIALLY REMEDIATED | Exact chunk and segment index checks were added | Segment cross-job/index metadata is not fully checked; no DB uniqueness |
| ST21A-008 | HIGH | PARTIALLY REMEDIATED | Production startup rethrows initialization failures | Crypto profile and certificate secret are not startup-validated; DEBUG bypass remains |
| ST21A-009 | HIGH | PARTIALLY REMEDIATED | Certificate is issued only after verifier returns `verified` | Complete real cryptographic certificate chain is not independently established |
| ST21A-010 | MEDIUM | NOT REMEDIATED | Frontend uses `/api/v1/zkp/{id}`; backend uses `/api/v1/zkp/jobs/{job_id}` | Proof retrieval remains broken |
| ST21A-011 | HIGH | NOT REMEDIATED | Synchronous proof generation remains; no queue, quota, or rate limit | Authenticated resource exhaustion remains possible |
| ST21A-012 | MEDIUM | NOT REMEDIATED | Migrations/models lack topology FKs and uniqueness/check constraints | Database can represent invalid ProofSets |
| ST21B-NEW-001 | HIGH | PARTIALLY REMEDIATED | Create path requires `CERTIFICATE_SECRET_KEY` and has no literal default | Update path uses `JWT_SECRET_KEY`; startup does not require certificate secret |
| ST21B-NEW-002 | HIGH | PARTIALLY REMEDIATED | Service BB calls have 300-second timeout and catch `TimeoutExpired` | No proof size limit; audit scripts have unbounded BB calls; no independent runtime test |
| ST21B-NEW-003 | MEDIUM | NOT REMEDIATED | `_archive_proofs()` writes files only after success, with no manifest | No archive exists; no atomicity, retention, ownership, or disk protection |

## 5. Finding-by-Finding Analysis

### ST21A-001 — SMT cache invalidation

**Status: REMEDIATED**

**Source:** [backend/shared/crypto/smt.py](../../../backend/shared/crypto/smt.py#L20-L28),
`SparseMerkleTree.insert`.

`insert()` removes `_cached_levels` after both new insertion and replacement.
`get_root()` and `get_path()` rebuild levels on the next access.

**Tests:** [backend/shared/tests/test_smt.py](../../../backend/shared/tests/test_smt.py#L52-L82)
tests root mutation, replacement mutation, path mutation, and separate instances.

**Runtime evidence:** No live runtime execution was performed. The behavior is
code-verified and test-verified with local unit tests inspected, not independently
re-executed.

**Remaining weakness:** The cache is not synchronized for concurrent mutation
and reads. No concurrency test or request-lifetime test exists.

### ST21A-002 — Production profile and VK binding

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/shared/crypto/config.py](../../../backend/shared/crypto/config.py#L24-L108),
[backend/shared/crypto/profile.json](../../../backend/shared/crypto/profile.json#L12-L29).

The production profile now includes hashes for `segment_init_32`,
`segment_mid_32`, and `segment_final_32`. Independent SHA-256 calculation showed
that all three JSON artifacts and VK files match the configured hashes. All six
mid directories also matched the same mid artifact/VK hash.

**Remaining issues:** `get_crypto_profile()` still falls back to the manifest's
`active_profile` when `CRYPTO_PROFILE` is absent. `ProverService` and
`NoirVerifier` construct circuit/VK paths directly rather than receiving an
immutable artifact path from the profile. The monolithic fields use the sentinel
`UNUSED_IN_DECOMPOSED_TOPOLOGY`, so no monolithic production artifact is bound.

**Tests:** [backend/shared/tests/test_crypto_profile.py](../../../backend/shared/tests/test_crypto_profile.py#L55-L70)
still contains an unfinished successful-profile test with `pass`.

**Conclusion:** Hash equality is independently verified; complete runtime
selection and fail-closed profile enforcement are not.

### ST21A-003 — Verification of persisted proof bytes

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/verification_service/app/core/verifier.py](../../../backend/verification_service/app/core/verifier.py#L50-L185),
`NoirVerifier.verify`.

The verifier now decodes persisted base64, rejects gzip signatures, checks the
selected VK hash, writes a temporary proof, and invokes Barretenberg with a
timeout. A timeout or nonzero exit returns `invalid_proof`.

**Trust-chain weaknesses:**

- `proof_artifact_hash` is stored but never compared to the decoded bytes.
- Public inputs are extracted by treating the first 32-byte blocks of the raw
  proof as public inputs; no Barretenberg proof-format parser is used.
- The selected circuit identity is inferred only from `segment_index`.
- No complete real 256-proof execution was available.
- The verifier tests do not exercise real Barretenberg; successful service tests
  use `MockVerifier`.

**Result:** The original metadata-only defect is not present in the source, but
independent cryptographic verification of persisted artifacts remains
NOT DEMONSTRATED.

### ST21A-004 — Complete 256-proof evidence

**Status: NOT REMEDIATED**

**Source:** [backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L125-L149),
`_archive_proofs`.

The implementation would iterate over 32 chunks and 8 segments after a
successful job, but it only writes an archive at runtime. The current repository
has no `archives/proofs` directory, no archive manifest, and no 256 proof files.
It has 11 extensionless sample proofs and 11 witness files.

No evidence identifies the exact circuit, VK, profile, proof hash, chunk, and
segment for 256 persisted proofs. The 1024-component claim is therefore not
independently established.

### ST21A-005 — Component identity consistency

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/sbom_service/app/services/canonicalization.py](../../../backend/sbom_service/app/services/canonicalization.py#L150-L164),
[backend/vulnerability_service/app/services/vulnerability_service.py](../../../backend/vulnerability_service/app/services/vulnerability_service.py#L45-L58).

When a PURL exists, SBOM canonicalization extracts the canonical PURL name and
version. Vulnerability ingestion also derives name and version from the PURL.
Tests cover differing display names and benign display names paired with a
vulnerable PURL in [backend/shared/tests/test_component_identity.py](../../../backend/shared/tests/test_component_identity.py#L19-L56).

Missing-PURL components still fall back to name/version identity. The fallback
is not PURL-authoritative and remains a distinct identity regime.

### ST21A-006 — Certificate IDOR

**Status: REMEDIATED**

**Source:** [backend/verification_service/app/api/routes/verification_routes.py](../../../backend/verification_service/app/api/routes/verification_routes.py#L94-L125),
`list_certificates` and `get_certificate`.

Listing filters by `VerificationRequest.user_id == current_user.id`. Detail now
requires authentication and passes the caller ID to
`VerificationService._validate_cert_job`, which rejects another user's request.

This is distinct from the former intentionally public endpoint: the current
executable route is no longer public.

**Test gap:** Existing tests do not exercise User A/User B certificate access;
the source enforcement is present, but regression coverage is incomplete.

### ST21A-007 — ProofSet topology

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/verification_service/app/core/verifier.py](../../../backend/verification_service/app/core/verifier.py#L36-L86).

The verifier now requires chunk indices exactly `0..31`, segment indices exactly
`0..7`, `total_chunks == 32`, component starts equal to `chunk_index * 32`, and
component count `32`. It checks component commitments and hash linkage.

**Remaining gaps:** It does not check `SegmentProof.chunk_index` against the
parent chunk, `SegmentProof.total_chunks`, or segment proof ownership beyond the
`chunk_id` query. It does not compare persisted proof hashes. Database uniqueness
constraints are absent.

Duplicate/missing top-level indices are rejected by current list comparisons;
cross-job and inconsistent child metadata are not fully rejected.

### ST21A-008 — Startup fail-closed behavior

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/shared/app_factory.py](../../../backend/shared/app_factory.py#L40-L56).

In non-debug mode, database/configuration exceptions are re-raised. This fixes
the former unconditional startup continuation.

**Remaining gaps:** Startup does not call `get_crypto_profile()`, does not check
`CERTIFICATE_SECRET_KEY`, and does not check the existence or hash of the
selected VK before serving. With `DEBUG=true`, initialization errors are still
suppressed and the application starts.

Therefore missing JWT/database configuration fails in production mode, but
missing certificate configuration and invalid crypto artifacts do not necessarily
fail startup.

### ST21A-009 — Certificate cryptographic gating

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/verification_service/app/services/verification_service.py](../../../backend/verification_service/app/services/verification_service.py#L35-L66),
[backend/verification_service/app/repositories/verification_repository.py](../../../backend/verification_service/app/repositories/verification_repository.py#L31-L91).

Certificates are created only when the verifier returns exactly `verified`.
Incomplete topology, failed BB exit, timeout, wrong public-input checks, and
gzip-looking artifacts return failure before certificate creation.

**Remaining weaknesses:** No independent 256-proof run exists. Tests use a mock
verifier. The verifier's public-input extraction is not demonstrated to match
the Barretenberg proof format. The persisted proof hash is not checked. A
certificate therefore has a stronger gate than before, but the complete
cryptographic trust chain is not established.

### ST21A-010 — Frontend proof-job route

**Status: NOT REMEDIATED**

**Source:** [frontend/src/api/services/proofService.ts](../../../frontend/src/api/services/proofService.ts#L17-L22)
calls `/api/v1/zkp/{id}`. Executable backend registration in
[backend/zkp_service/app/api/routes/zkp_routes.py](../../../backend/zkp_service/app/api/routes/zkp_routes.py#L57-L75)
uses `/api/v1/zkp/jobs/{job_id}`.

The frontend route still does not match the backend route.

### ST21A-011 — Proof-generation resource controls

**Status: NOT REMEDIATED**

**Source:** [backend/zkp_service/app/api/routes/zkp_routes.py](../../../backend/zkp_service/app/api/routes/zkp_routes.py#L35-L54),
[backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L105-L130).

Per-subprocess timeout exists in the prover, and execution is sequential. There
is no job queue, per-user admission control, rate limit, quota, cancellation,
global worker bound, disk quota, or proof-retention policy. An authenticated
vendor can repeatedly hold an API worker while triggering expensive proving.

The verifier now adds up to 256 BB subprocesses per request, increasing the
resource surface.

### ST21A-012 — Database integrity

**Status: NOT REMEDIATED**

**Source:** [backend/alembic/versions/003_add_chunk_proof_models.py](../../../backend/alembic/versions/003_add_chunk_proof_models.py#L16-L80),
[backend/alembic/versions/004_update_verification_model.py](../../../backend/alembic/versions/004_update_verification_model.py#L15-L27),
[backend/verification_service/app/models/verification_models.py](../../../backend/verification_service/app/models/verification_models.py#L37-L66).

Proof and verification tables still lack complete foreign keys, uniqueness
constraints for chunk/segment indices, status check constraints, and a unique
certificate-per-request constraint. SQL Server behavior was not independently
executed.

### ST21B-NEW-001 — Certificate secret fallback/isolation

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/verification_service/app/repositories/verification_repository.py](../../../backend/verification_service/app/repositories/verification_repository.py#L31-L91).

The initial creation path requires `CERTIFICATE_SECRET_KEY` and has no literal
default or generated ephemeral secret. Repository-wide search found no
`default_secret` certificate fallback in the current file.

However, `update_verification_record()` signs with `JWT_SECRET_KEY`, not
`CERTIFICATE_SECRET_KEY`. Thus certificate signing is not isolated from JWT
authentication. The update path also does not require the certificate secret.

Startup does not validate `CERTIFICATE_SECRET_KEY`. Existing successful tests use
mock verification and do not exercise the real configuration path.

### ST21B-NEW-002 — Unbounded Barretenberg verification

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/verification_service/app/core/verifier.py](../../../backend/verification_service/app/core/verifier.py#L151-L185)
and [backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L300-L335).

Production prover and verifier BB calls use a 300-second timeout. `TimeoutExpired`
returns `invalid_proof`, and verifier temporary proof cleanup is protected by a
`finally` block.

**Remaining gaps:** The timeout is hard-coded rather than centrally configured.
The verifier accepts arbitrarily large persisted base64 proof text and decodes it
before execution. Audit scripts such as `run_c32_negative_tests.py` use BB calls
without timeouts. No real timeout execution test was found.

### ST21B-NEW-003 — Proof archive integrity

**Status: NOT REMEDIATED**

**Source:** [backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L132-L149).

The archive implementation writes one file per segment after the database job is
complete. It provides filenames containing chunk and segment indices, but no
manifest, proof hashes, VK hashes, circuit identity, profile identity, atomic
commit marker, partial-archive marker, ownership metadata, retention policy,
cleanup policy, or disk limit.

No archive exists in the current repository. Witness files are not copied by
this function, but no archive-level control prevents unrelated witness leakage
or disk exhaustion.

## 6. Cryptographic Trust Chain

The intended chain is:

`persisted proof bytes -> base64 decode -> public inputs -> circuit/VK -> BB verify -> ProofSet -> certificate`.

The current code performs each broad step, but the following links are not
independently established:

- raw proof byte public-input offsets are assumed, not parsed using an official
  Barretenberg format;
- persisted `proof_artifact_hash` is not recomputed and compared;
- no complete 256-proof artifact set is available;
- no real certificate-producing run is available;
- successful tests use mocks.

## 7. Authentication and Authorization Analysis

Certificate list and detail routes now require authentication and owner filtering.
Proof-job ownership remains enforced on individual job retrieval. The current
certificate tests do not exercise cross-user access.

Frontend route guards remain non-security controls. Backend authorization is the
relevant control.

## 8. Startup and Configuration Analysis

Production mode now rethrows database/configuration initialization failures in
[backend/shared/app_factory.py](../../../backend/shared/app_factory.py#L40-L56).

It does not validate the certificate signing secret or crypto profile during
startup. Debug mode still suppresses startup failures. Profile absence also
falls back to the manifest default in [backend/shared/crypto/config.py](../../../backend/shared/crypto/config.py#L112-L127).

## 9. Database Integrity Analysis

The current architecture targets SQL Server, not PostgreSQL. Models use
`mssql.UNIQUEIDENTIFIER`, migrations use SQL Server DDL and `GETUTCDATE()`, and
Docker defines `mcr.microsoft.com/mssql/server:2022-latest`.

SQLite remains the Stage 21 harness. SQL Server constraints and transaction
behavior were not independently executed because Docker was unavailable.

## 10. Evidence and Reproducibility Analysis

The current repository has no complete archive or manifest. Existing proof files
are extensionless samples in circuit target directories and are not linked to a
ProofJob/chunk/segment manifest. The current host cannot run Nargo, Barretenberg,
or Docker.

The 1024/256 result is therefore evidence-only and not independently reproducible
from the repository state.

## 11. Test Integrity Analysis

Observed test weaknesses include:

- successful certificate tests inject `MockVerifier`;
- prover subprocess tests mock all subprocess calls;
- the valid crypto-profile test is unfinished;
- no owner-isolation regression covers User A versus User B certificates;
- no SQL Server integration test was observed;
- no full 256-proof test verifies persisted artifacts;
- no archive manifest or atomicity test exists;
- no test executes the real certificate-secret configuration path;
- topology tests, where present, focus on expected list values rather than
  database uniqueness and cross-job contamination.

## 12. New Findings

### ST21C-NEW-001 — Certificate signing uses the JWT secret on update

**Severity: HIGH**

`create_verification_record()` uses `CERTIFICATE_SECRET_KEY`, but
`update_verification_record()` uses `JWT_SECRET_KEY`. A caller that can obtain or
compromise the JWT secret can forge certificates produced by the update path.

Affected function: `VerificationRepository.update_verification_record` in
[backend/verification_service/app/repositories/verification_repository.py](../../../backend/verification_service/app/repositories/verification_repository.py#L60-L91).

### ST21C-NEW-002 — Debug prints expose verifier internals

**Severity: MEDIUM**

`NoirVerifier.verify()` prints job absence, missing VK, VK mismatch, and generic
verification failure to stdout in [backend/verification_service/app/core/verifier.py](../../../backend/verification_service/app/core/verifier.py#L33-L35).
This bypasses structured logging/redaction and may expose internal state in
container logs.

### ST21C-NEW-003 — Persisted proof size is unbounded before BB execution

**Severity: HIGH**

The verifier base64-decodes `seg.proof_artifact` without a size limit before
writing it and launching Barretenberg in [backend/verification_service/app/core/verifier.py](../../../backend/verification_service/app/core/verifier.py#L99-L116).
A large database/API-injected artifact can consume memory, disk, and subprocess
time. The request-size middleware does not bound existing database artifact size.

### ST21C-NEW-004 — Archive creation is non-atomic and lacks completion state

**Severity: MEDIUM**

`_archive_proofs()` creates the directory and writes files one at a time. A disk
failure or process termination leaves a partial archive that has no manifest or
completion marker. [backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L132-L149).

## 13. Evidence Gaps

- No complete 256-proof archive.
- No archive manifest binding proof, circuit, VK, profile, job, chunk, and segment.
- No real Stage 21C Barretenberg execution.
- No SQL Server execution.
- No real certificate-signing configuration test.
- No complete certificate-chain regression using mutated and wrong-VK artifacts.
- No cross-user certificate regression.
- No timeout or disk-exhaustion runtime test.

## 14. Regression Risks

The new verification path may reject valid proofs if the assumed raw proof-byte
public-input layout does not match the actual Barretenberg proof format. The
certificate secret split can also produce inconsistent signatures depending on
whether a record is initially created or later updated.

The archive is runtime-only and can silently remain incomplete because no
manifest or completion marker is persisted.

## 15. Final Security Disposition

1. **Is ST21C independently validated?** No. Some code changes are directly verified, but the complete remediation and cryptographic claims are not.
2. **Is production cryptographic validation established?** No.
3. **Is complete 256-proof evidence established?** No.
4. **Is certificate issuance cryptographically gated?** Partially. It depends on a BB-verification return path, but complete real execution and proof-input parsing are not established.
5. **Is production startup fail-closed?** Partially. Database/configuration failures rethrow outside debug mode, but crypto profile and certificate-secret validation are absent.
6. **Is certificate signing isolated from JWT authentication?** No. The update path uses `JWT_SECRET_KEY`.
7. **Is SQL Server integrity established?** No. SQL Server is the declared target, but it was not independently executed or validated.
8. **Are all 15 canonical findings remediated?** No. The register contains several partial and unresolved findings.
9. **Are there new findings?** Yes: certificate-secret inconsistency, verifier debug leakage, unbounded persisted proof input, and non-atomic archive creation.
10. **Is the repository ready for the next project stage?** No. Release freeze and architectural progression should remain blocked pending the unresolved trust-chain, archive, ownership, startup, resource, and database findings.
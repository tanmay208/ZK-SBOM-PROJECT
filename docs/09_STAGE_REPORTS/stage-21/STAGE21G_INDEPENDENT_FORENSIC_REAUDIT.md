# STAGE 21G - FINAL INDEPENDENT FORENSIC RE-AUDIT

**Audit date:** 2026-10-02  
**Role:** Independent security auditor  
**Authoritative baseline:** `docs/STAGE21F_INDEPENDENT_FORENSIC_REAUDIT.md`  
**Final disposition:** Stage 22 remains BLOCKED.

## 1. Executive Summary

The Stage 21G implementation closes the specific Stage 21F lock-release defect at the source level and adds focused regression tests for missing-job, repository-exception, validation-exception, and proof-exception paths. The full backend test claim is also independently reproducible: the suite collected and executed 513 tests with 513 passed and 63 warnings. `packageurl-python==0.16.0` is declared through the shared dependency file included by each backend service, and the active virtual environment imports it.

Stage 21G does not close the security release gate. The requested `svgstage_21G_remediation_summary.md` is absent, so there is no remediation summary or changed-file manifest to validate. No complete 256-proof archive or manifest is present. Nargo and Barretenberg are unavailable, SQL Server 2022 is unreachable, and no real certificate has been produced from a real cryptographically verified ProofSet. The public-input parser still uses fixed byte offsets marked `RUNTIME VALIDATION PENDING`. Base64 decoding is not strict, and the archive validation helper checks only existence, zero size, and file size; it does not validate archive contents, archive hash, manifest, or 256-entry topology.

Observed positive evidence:

- Full backend suite: `513 passed, 63 warnings`.
- Frontend typecheck, lint, and build completed; lint reported 19 warnings and 0 errors.
- Actual production `CryptoProfile` loaded and validated the checked-in Init, Mid, and Final circuit/VK hashes.
- All six `segment_mid_32*` directories currently contain identical circuit and VK hashes.
- Stage 21F lock-release regression tests pass and the cleanup variables are present in source.

Observed blocking evidence gaps:

- No Nargo runtime.
- No Barretenberg runtime.
- No SQL Server runtime.
- No 256 real proofs, complete ProofSet, archive, or independent archive inspection.
- No real certificate trust-chain execution.
- No real proof-format/public-input serialization validation.

## 2. Audit Scope and Evidence Rules

Inspected the Stage 21F report, current source, migrations, models, tests, dependency metadata, profile/artifacts, frontend, deployment configuration, and repository filesystem. The exact Stage 21G summary named by the request does not exist anywhere under the workspace. No source code, test, migration, configuration, frontend file, artifact, or prior report was modified. The only intended repository addition is this report.

Evidence classifications used here:

- **SOURCE VERIFIED:** directly observed in current source/configuration.
- **TEST VERIFIED:** an executable test passed; mocks may be present.
- **INTEGRATION VERIFIED:** real components and persisted records were exercised in a test environment. SQLite is explicitly not SQL Server evidence.
- **REAL RUNTIME VERIFIED:** actual repository artifacts or external runtime tools executed.
- **NOT VERIFIED:** required evidence was absent or unavailable.
- **PARTIALLY VERIFIED:** some boundary is demonstrated, but the complete security property is not.

A remediation statement is not evidence. A mocked subprocess is not BB evidence. A SQLite constraint or ownership test is not SQL Server evidence. Code capable of generating 256 proofs is not evidence that 256 proofs were generated.

## 3. Repository Baseline

| Item | Independent observation |
|---|---|
| Branch | `chore/final-project-cleanup` |
| Worktree | Pre-existing dirty worktree with extensive added/deleted/renamed files; no unrelated changes reverted |
| Python | `3.12.10` |
| Node | `v24.19.0` |
| packageurl metadata | Declared as `packageurl-python==0.16.0` in `backend/shared/requirements.txt`; service requirements include that file |
| packageurl runtime | Importable from `.venv`, version `0.16.0` |
| Docker CLI | `29.8.1` available |
| Docker daemon | Unavailable; Docker API connection failed |
| SQL Server | `localhost:1433` unreachable |
| Nargo | Not available on PATH or in WSL `kali-linux` |
| Barretenberg | `bb` not available on PATH or in WSL `kali-linux` |
| CRYPTO_PROFILE | Explicit `CRYPTO_PROFILE=prod` probe succeeded; no inherited profile was assumed |
| Production profile | `prod`, 1024 components, 32 chunks, 8 segments per chunk |
| Actual profile artifacts | Init, Mid, Final circuit/VK hashes matched profile values |
| Proof evidence | 11 standalone extensionless proof files |
| Witness evidence | 11 `.gz` witness files |
| Archive evidence | `archives/proofs` exists but is empty; no zip or manifest |
| Secrets | No project `.env`, private key, or certificate key artifact found outside dependency certificate bundles |
| Stage 21G summary | `svgstage_21G_remediation_summary.md` absent |

The full test suite executed successfully despite an earlier metadata probe reporting no packageurl package. Direct import and `pip list` confirmed the package is installed in the same `.venv` used by pytest. The dependency is reproducible from each service's `-r ../shared/requirements.txt` chain, although `pyproject.toml` itself does not declare backend dependencies.

## 4. Stage 21F -> Stage 21G Delta

| Stage 21F finding | Current Stage 21G observation |
|---|---|
| ST21F-NEW-001 lock/quota release | `user_id=None`, `quota_acquired=False`, and guarded cleanup are present. Focused regression tests cover missing job, repository exception, validation exception, and proof exception. |
| ST21F-NEW-002 full suite dependency evidence | packageurl is declared through the shared requirements chain, imports successfully, and the full suite executes 513 tests. |
| Proof validation | `CryptoProfile.validate_segment_proof()` exists and is called after decode/hash; it checks decoded length, gzip rejection, and deterministic structural lengths. |
| Archive validation | `CryptoProfile.validate_proof_archive()` exists but checks only path existence, file size <= 50 MB, and nonzero size. It does not validate archive hash, manifest, entries, or topology. |
| Public inputs | Fixed offsets remain in `NoirVerifier.extract_pi()` with an explicit `RUNTIME VALIDATION PENDING` comment. |
| Real runtime | Still no Nargo, BB, SQL Server, complete proof set, archive, or certificate E2E. |

The requested Stage 21G remediation summary is missing. Consequently, claims about the complete Stage 21G change set cannot be accepted beyond what is independently visible in the repository.

## 5. Canonical Finding Register

| ID | Severity | Stage 21F status | Stage 21G claim/current change | Independent result | Evidence | Tests executed | Runtime evidence | Remaining gap | Final classification |
|---|---:|---|---|---|---|---|---|---|---|
| ST21A-001 | HIGH | PARTIALLY REMEDIATED | SMT locking retained | Lock protects insert/cache construction; empty-root read remains outside lock and race-free path/root behavior is not established | Source + TEST VERIFIED | Full suite includes SMT tests; no strong race oracle | No concurrent production run | Shared-state read semantics and race behavior remain unproven | PARTIALLY REMEDIATED |
| ST21A-002 | CRITICAL | PARTIALLY REMEDIATED | CryptoProfile authoritative paths | Real profile/file hashes validate; runtime prover/verifier and all profile bindings not executed | SOURCE VERIFIED + REAL RUNTIME VERIFIED for file validation | Profile tests include mocks | Profile probe only; no Nargo/BB | Real cryptographic artifact use and complete authority chain absent | PARTIALLY REMEDIATED |
| ST21A-003 | CRITICAL | PARTIALLY REMEDIATED | Central proof validation helper | Decoded size/gzip/structural checks added; hash and BB call remain source/mock-tested; Base64 validation permissive | SOURCE VERIFIED + TEST VERIFIED | Verifier/timeout tests mock decode/filesystem/subprocess | No BB verification | Fixed format and public-input semantics not independently proven | PARTIALLY REMEDIATED |
| ST21A-004 | HIGH | NOT REMEDIATED | 256-proof archive generation path | No archive, manifest, or 256-proof evidence exists; only 11 samples | NOT VERIFIED | Archive negative test uses fake/mocked records | No 256 proofs | Complete 32 x 8 evidence absent | NOT REMEDIATED |
| ST21A-005 | HIGH | PARTIALLY REMEDIATED | PURL dependency and fallback tests | Dependency now reproducible; missing-PURL semantics remain synthetic and collision behavior is not security-proven | SOURCE VERIFIED + TEST VERIFIED | Full suite passed identity tests | No production ingestion E2E | Fallback identity equivalence/divergence remains unverified | PARTIALLY REMEDIATED |
| ST21A-006 | HIGH | PARTIALLY REMEDIATED | Ownership tests retained | Two-user persisted SQLite certificate test passes; no SQL Server or full ProofJob/API matrix | INTEGRATION VERIFIED for SQLite | Full suite passed certificate IDOR test | No SQL Server | Database/API production boundary incomplete | PARTIALLY REMEDIATED |
| ST21A-007 | HIGH | PARTIALLY REMEDIATED | Topology negative tests added | Source checks many fields; topology tests use MagicMock query fixtures and do not cover all requested mutations or DB consistency | TEST VERIFIED, mocked | Full suite passed topology tests | No real ProofSet | No complete real topology or DB parent-child enforcement | PARTIALLY REMEDIATED |
| ST21A-008 | HIGH | PARTIALLY REMEDIATED | Startup checks secrets/profile | Real startup against DB/artifacts not run; tests patch `init_engine` and some filesystem/hash paths | SOURCE VERIFIED + TEST VERIFIED | Startup tests passed | No SQL Server startup | Actual fail-closed deployment path remains unverified | PARTIALLY REMEDIATED |
| ST21A-009 | HIGH | PARTIALLY REMEDIATED | Certificate gated by verifier result | Gate exists, but successful tests use MockVerifier and mock sessions | TEST VERIFIED, mocked | Full suite passed service/certificate tests | No real certificate from verified ProofSet | Real trust chain absent | NOT VERIFIED |
| ST21A-010 | MEDIUM | REMEDIATED at source | Frontend/backend proof route aligned | Source matches; typecheck/build pass | SOURCE VERIFIED + TEST VERIFIED | Typecheck and build passed | No live backend/frontend integration | Live integration not executed | PARTIALLY REMEDIATED |
| ST21A-011 | HIGH | PARTIALLY REMEDIATED | Process-local lock/user quota documented | Documentation correctly states process-local scope; no queue, rate limit, persistent quota, disk quota, or deployment-wide control | SOURCE VERIFIED + TEST VERIFIED | Resource test passed | No multi-worker/container execution | Deployment-wide DoS control absent | PARTIALLY REMEDIATED |
| ST21A-012 | MEDIUM | PARTIALLY REMEDIATED | Migrations include archive hash and bounds | Migration source exists; no SQL Server migration/schema execution; status/metadata constraints remain limited | SOURCE VERIFIED | SQLite tests only | SQL Server unavailable | Actual schema consistency unknown | PARTIALLY REMEDIATED |
| ST21B-NEW-001 | HIGH | PARTIALLY REMEDIATED | Certificate secret isolated | Create/update source and tests use `CERTIFICATE_SECRET_KEY`; no real persisted signing | SOURCE VERIFIED + TEST VERIFIED | Certificate signing tests passed | No production signing | Runtime secret isolation/startup evidence absent | PARTIALLY REMEDIATED |
| ST21B-NEW-002 | HIGH | PARTIALLY REMEDIATED | Application timeout retained/profile-driven | Application calls have timeout; multiple audit/development scripts remain without timeout | SOURCE VERIFIED + TEST VERIFIED | Timeout tests mock exception | No actual timeout execution | Scope/classification of every subprocess remains incomplete | PARTIALLY REMEDIATED |
| ST21B-NEW-003 | MEDIUM | PARTIALLY REMEDIATED | Archive helper and manifest retained | Helper is only size/existence check; archive has no real evidence or complete content/hash verification | SOURCE VERIFIED + TEST VERIFIED | Oversized/missing helper tests patch filesystem | No archive runtime | Archive integrity remains unproven | PARTIALLY REMEDIATED |
| ST21C-NEW-001 | HIGH | PARTIALLY REMEDIATED | JWT/certificate signing defect fixed | Repository search confirms certificate create/update use certificate secret only | SOURCE VERIFIED + TEST VERIFIED | Full suite certificate tests passed | No persisted production cert | Runtime trust boundary absent | PARTIALLY REMEDIATED |
| ST21C-NEW-002 | MEDIUM | PARTIALLY REMEDIATED | Debug prints removed | No verifier print path observed; BB stderr is logged and redaction was not runtime-tested | SOURCE VERIFIED | Full suite passed | No production log run | Sensitive log output behavior unverified | PARTIALLY REMEDIATED |
| ST21C-NEW-003 | HIGH | PARTIALLY REMEDIATED | Proof size centralized | Decoded helper check is present, but Base64 decode is non-strict and DB/runtime paths were not SQL Server-tested | SOURCE VERIFIED + TEST VERIFIED | Full suite passed helper/verifier tests | No SQL Server/BB | Strict input validation and deployed schema remain unverified | PARTIALLY REMEDIATED |
| ST21C-NEW-004 | MEDIUM | PARTIALLY REMEDIATED | Archive rename/lifecycle retained | Filesystem rename is separate from DB update; no crash/recovery evidence | SOURCE VERIFIED | Archive tests are mocked/negative | No archive runtime | Durable archive/DB consistency absent | PARTIALLY REMEDIATED |
| ST21F-NEW-001 | MEDIUM | NOT VERIFIED | Guarded lock/quota cleanup added | `quota_acquired` and guarded `finally` prevent the reported unbound-variable lock leak; source and focused tests cover four exception paths | SOURCE VERIFIED + TEST VERIFIED | Missing-job, repo, validation, proof lock tests passed | No deployment concurrency run | Archive/DB-update-specific assertions and cross-thread stress remain absent | REMEDIATED |
| ST21F-NEW-002 | MEDIUM | NOT VERIFIED | Dependency/test reproducibility restored | Shared dependency declaration is included by services; packageurl imports and 513 tests execute | REAL RUNTIME VERIFIED | Full suite: 513 passed, 63 warnings | Same `.venv` runtime verified | Clean isolated install was not created, but metadata chain is present | REMEDIATED |

## 6. Finding-by-Finding Analysis

### ST21A-001 - SMT concurrency

`insert()` invalidates the cache under `_lock`, and `_build_levels()` serializes cache construction. `get_root()` reads `self.leaves` directly for the empty-tree path, while `get_path()` uses the cached level structure without an operation-wide immutable snapshot. The passing suite demonstrates the intended sequential/cache behavior, not a linearizable concurrent root/path contract. **PARTIALLY REMEDIATED.**

### ST21A-002 - CryptoProfile authority

The actual `prod` profile loaded successfully and the Init, Mid, and Final circuit/VK hashes matched. All six `segment_mid_32*` directories currently have identical circuit/VK hashes, which supports shared identity at the filesystem level. The profile explicitly names only `segment_mid_32`; runtime aliases all mid segments to that entry. This is source-consistent but not independently proven by a real Nargo/BB execution or a manifest binding each of the six logical segments. **PARTIALLY REMEDIATED.**

### ST21A-003 - Proof artifact integrity

`validate_segment_proof()` now checks decoded byte length, gzip magic, and expected UltraPlonk lengths. The verifier hashes decoded bytes and then invokes the helper. However, it calls `base64.b64decode()` without `validate=True`, so malformed non-alphabet characters may be discarded instead of being rejected as invalid Base64. The helper does not verify a circuit/VK relationship or BB result. **PARTIALLY REMEDIATED.**

### ST21A-004 - Complete proof evidence

Filesystem inspection found 11 proof files, 11 witness files, no archive, and no manifest. The source still contains the intended 32 x 8 generation path, but there is no evidence that it executed successfully. **NOT REMEDIATED.**

### ST21A-005 - Component identity

`packageurl-python==0.16.0` is declared in shared requirements and inherited by all three relevant services. The full suite now executes PURL tests. The missing-PURL fallback remains a generic synthetic PURL based on name and version, with `unknown` for null version. Tests establish expected outputs, not absence of identity collisions or guaranteed lookup equivalence across ingestion services. **PARTIALLY REMEDIATED.**

### ST21A-006 - Ownership/IDOR

The certificate listing test persists User A and User B records in SQLite and checks each listing plus one cross-user detail denial. Proof-job routes filter detail by current user, and job creation checks SBOM ownership. The requested complete A/B matrix for certificate, ProofJob, verification, list, and detail endpoints was not independently exercised against SQL Server. **PARTIALLY REMEDIATED.**

### ST21A-007 - Exact topology

The verifier checks 32 ordered chunks, 8 ordered segments, totals, chunk/segment indices, component starts/counts, child metadata, commitments, and hash linkage. New topology tests cover missing/duplicate/reordered chunks and segments, wrong totals, component boundaries, and one cross-job chunk. They use MagicMock sessions and do not provide real persistence or all requested root/policy/commitment mutation tests. Database constraints enforce only selected index bounds/uniqueness, not all parent-child metadata. **PARTIALLY REMEDIATED.**

### ST21A-008 - Startup fail-closed

The real path is `create_app -> lifespan -> validate_config -> get_crypto_profile -> init_engine`. Missing JWT/certificate secrets, missing profile, invalid profile, missing artifacts, and wrong hashes have tests, but the tests patch database initialization and some filesystem/hash behavior. No actual production startup reached a live SQL Server. Source has no manifest `active_profile` fallback and requires `CRYPTO_PROFILE`; however complete deployment fail-closed behavior is not runtime verified. **PARTIALLY REMEDIATED.**

### ST21A-009 - Certificate trust chain

`VerificationService` creates a certificate only after the verifier returns `verified`, and authoritative records are checked first. The successful tests inject `MockVerifier` or mock the repository/session. No complete ProofSet, real BB verification, or real certificate was produced. **NOT VERIFIED.**

### ST21A-010 - Frontend route

The frontend proof service calls `/api/v1/zkp/jobs/{id}`, matching the backend route `/api/v1/zkp/jobs/{job_id}`. Typecheck and build completed. Lint completed with warnings only. No live backend integration was run. **PARTIALLY REMEDIATED** as a security evidence classification, despite the source contract being aligned.

### ST21A-011 - Resource control

The global prover lock and per-user counter are explicitly documented as process-local. There is no queue, persistent admission record, rate limit, cancellation, distributed lock, disk quota, or archive retention enforcement. The implementation mitigates one-process simultaneous proving only. **PARTIALLY REMEDIATED.**

### ST21A-012 - SQL Server database integrity

Migrations 005-007 include selected topology uniqueness/checks, `proof_archive_hash`, and proof column length changes. ORM models include foreign keys and some constraints. No SQL Server instance was reachable, no migrations were applied, and no actual schema or constraint behavior was inspected. **PARTIALLY REMEDIATED.**

### ST21B-NEW-001 - Certificate secret isolation

Repository create and update paths read only `CERTIFICATE_SECRET_KEY` and reject an absent value. Repository search found no certificate signing path using `JWT_SECRET_KEY`. Tests verify signatures with the certificate secret and reject the JWT secret, but all use mocked sessions. **PARTIALLY REMEDIATED.**

### ST21B-NEW-002 - BB timeout

Application prover/verifier subprocess calls use profile timeout values. Script paths such as `measure_stage18.py`, `measure_stage19.py`, `run_negative_tests.py`, `test_main_circuit.py`, and compatibility helpers include calls without a timeout. Their production/audit status is not uniformly documented. No real timeout was executed. **PARTIALLY REMEDIATED.**

### ST21B-NEW-003 - Archive integrity

`validate_proof_archive()` enforces only existence, nonzero size, and a 50 MB file-size ceiling. It does not calculate or compare an archive hash, open the ZIP, validate the manifest, require 256 proof files, validate proof hashes/VK hashes/circuit hashes, or enforce compressed/uncompressed expansion limits. No archive exists. **NOT REMEDIATED.**

### ST21C-NEW-001 - Certificate signing regression

Source and tests confirm certificate issuance uses the certificate secret in both creation and update paths. The distinction is not runtime-proven through a real persisted application transaction. **PARTIALLY REMEDIATED.**

### ST21C-NEW-002 - Debug leak

No verifier `print()` path was found. BB stderr is decoded into logger messages on failure, so print removal does not establish that sensitive cryptographic details cannot reach logs. No production log capture or redaction test was run. **PARTIALLY REMEDIATED.**

### ST21C-NEW-003 - Proof input bounds

The decoded proof helper has deterministic size checks, and proof columns are bounded to 5000 characters by migration source. The verifier decodes with permissive Base64 behavior before helper validation. The archive 50 MB check is not a memory/disk bound during assembly and has no content validation. SQL Server execution was not performed. **PARTIALLY REMEDIATED.**

### ST21C-NEW-004 - Archive atomicity

Temporary assembly and ZIP rename provide a filesystem-level atomic rename, but DB completion/hash persistence occurs after archive creation in a separate transaction. A process crash or DB failure can leave filesystem and database states divergent. No crash, disk-full, duplicate, stale-temp, or recovery test exists. **PARTIALLY REMEDIATED.**

### ST21F-NEW-001 - Lock/quota release

The Stage 21F defect is corrected in current source. `user_id` starts as `None`, `quota_acquired` starts false, and quota cleanup is conditional. The global lock is released in `finally` after missing job, repository, validation, and proof exceptions. The tests would fail if the old unbound-variable cleanup were restored for those paths. Archive and DB update failures are covered only indirectly by generic exception handling, and no concurrent stress run was performed. The specific finding is **REMEDIATED** with test/source evidence, not real deployment evidence.

### ST21F-NEW-002 - Dependency/full-suite reproducibility

The package is declared in `backend/shared/requirements.txt`, all relevant services include that file, direct import succeeds, and the full suite reports 513 passed. This closes the previous collection blocker in the current environment. A clean isolated environment was not provisioned, so the classification is based on authoritative metadata plus current runtime execution. **REMEDIATED.**

## 7. Startup Fail-Closed Assessment

The startup chain is present and source-verified:

`create_app -> lifespan -> get_db_settings -> validate_config -> get_crypto_profile -> init_engine`.

Observed behavior and evidence:

- Missing JWT secret: unit/integration-style lifespan test, profile not bypassed in the current test.
- Missing certificate secret: unit/integration-style lifespan test.
- Missing `CRYPTO_PROFILE`: test verifies failure.
- Invalid profile: test verifies failure.
- Missing circuit/VK and wrong hash: tests patch filesystem/hash behavior and verify failure branches.
- Database unavailable: source rethrows initialization errors; no actual SQL Server startup.
- Development fallback: no manifest active-profile fallback was found in current `get_crypto_profile()`.
- Default secrets: no default certificate/JWT signing secret found.

The property is **PARTIALLY VERIFIED**, not REAL RUNTIME VERIFIED, because the tests patch `init_engine`, filesystem, or hashing and no live deployment startup was possible.

## 8. CryptoProfile Authority and Proof Integrity

The profile validates actual Init/Mid/Final circuit and VK hashes. All six logical mid directories currently hash identically to the profile's single `segment_mid_32` entry. This supports, but does not independently prove, intentional shared identity. The prover and verifier derive runtime directory names through profile-returned paths, but the verifier reconstructs the WSL path from `segment_name` and the profile root rather than using the returned VK path directly for the BB command. That is an alternate path derivation inside a profile-controlled root and remains source-only evidence.

Proof processing order is currently:

1. Presence check.
2. Base64 decode.
3. SHA-256 comparison.
4. `validate_segment_proof()` decoded-size/gzip/structural checks.
5. Public-input extraction.
6. Temporary file write.
7. BB verify with timeout.

The requested size-before-decode property is not satisfied for decoded bytes: the verifier does not impose an encoded Base64-length check before decoding, and strict Base64 validation is absent. The database `VARCHAR(5000)` bound limits persisted text, but that is not a substitute for strict decode validation or a runtime SQL Server check.

## 9. Public Input Serialization

`NoirVerifier.extract_pi()` treats the first 32-byte words of the proof bytes as public inputs and uses segment-specific positions for SBOM root, vulnerability root, policy hash, chunk index, commitments, and linkage values. The source explicitly labels the serialization assumption `RUNTIME VALIDATION PENDING`. Nargo and BB are unavailable, so no real proof was generated or inspected and no public-input order was independently established. **NOT VERIFIED.**

## 10. ProofSet Topology

The Python verifier enforces substantial structure. The test suite contains mocked negative tests for missing, duplicate, and reordered chunks/segments, wrong total chunks, wrong component boundaries, and one cross-job chunk. These tests are useful unit evidence but are not real persisted ProofSet tests. The database schema does not enforce `total_chunks=32`, `component_start`, `component_count=32`, segment-parent metadata equality, roots, policy, commitments, or linkage. **PARTIALLY VERIFIED.**

## 11. Certificate Trust Chain and IDOR

Certificate creation requires authoritative records and a verifier result of exactly `verified`, and signing uses `CERTIFICATE_SECRET_KEY` in both create/update paths. The trust chain stops at mocked verification in every successful certificate test. No real proof was verified and no certificate was issued from a complete ProofSet. **NOT VERIFIED** for the cryptographic trust chain.

The persisted SQLite certificate test creates User A and User B, checks A's list, A's denial of B's detail, and B's list. Proof-job detail source checks current user, and job creation checks SBOM ownership. The requested complete two-user matrix for both certificate and ProofJob endpoints was not independently executed against SQL Server. Ownership is **PARTIALLY VERIFIED** as SQLite integration evidence.

## 12. Resource Control and SMT

Resource controls remain process-local. The documentation correctly states that multiple workers, containers, and replicas require a distributed mechanism. The implementation provides no queue, persistent quota, rate limiter, cancellation, disk quota, or archive retention control. **PARTIALLY VERIFIED** for single-process mitigation only.

SMT insertion and cache construction are locked, but direct shared-state reads remain outside a single lock scope. Tests establish deterministic behavior and the Stage 21F suite did not provide a strong concurrent race oracle. **PARTIALLY VERIFIED.**

## 13. SQL Server 2022

The declared database remains SQL Server 2022. Migrations contain `proof_archive_hash`, foreign keys, selected uniqueness, and selected index bounds. There are no SQL Server runtime results because Docker daemon and `localhost:1433` were unavailable. SQLite tests must not be promoted to SQL Server evidence. **SQL SERVER RUNTIME VALIDATION = NOT VERIFIED.**

## 14. Archive and 256-Proof Evidence

Current archive inventory:

- `archives/proofs`: directory only.
- ZIP archives: none.
- Manifest files: none.
- Proof files: 11.
- Witness files: 11.
- Complete job/chunk/segment mapping: none.

The archive source manifest includes job IDs, roots, policy hash, profile identity, runtime version fields, proof hashes, and VK hashes. It does not independently bind a profile SHA-256 or circuit hash per segment, and `creation_timestamp` remains a literal marker. `validate_proof_archive()` does not inspect those fields. No private witness archive was observed, but no completed archive exists to inspect.

**REAL 256-PROOF VALIDATION = NOT VERIFIED.**  
**ARCHIVE EVIDENCE = NOT VERIFIED.**

## 15. Negative Cryptographic Tests

No real proof set exists for mutation testing. Mocked tests cover selected structural rejection paths and mocked BB failures/timeouts. There is no real BB rejection evidence for bit flips, truncation, wrong VK/circuit/profile, swapped or duplicated segments/chunks, wrong commitments, linkage, roots, policy, or component ranges. **NOT VERIFIED.**

## 16. Test Integrity

The full suite is now executable and green, but boundary quality remains mixed:

- Lock regression tests directly control a mocked repository and module-level locks. They are meaningful for the cleanup branch but not deployment stress tests.
- Topology tests use `MagicMock` sessions and simplified query responses. They prove selected Python branches, not actual ORM/database relationships.
- Verifier tests patch `subprocess.run`, `base64.b64decode`, profile, filesystem, and hashing. They are unit tests, not BB tests.
- Startup tests patch `init_engine` and filesystem/hash behavior for failure branches.
- Certificate tests use mocked sessions and `MockVerifier` for successful issuance.
- Archive tests construct fake records and patch filesystem state; no completed archive is opened.
- SQLite IDOR tests use real persisted SQLite rows and are correctly classified only as SQLite integration tests.
- The full suite's `513 passed` result is real test execution evidence, not proof that cryptographic runtime requirements passed.

## 17. Frontend

Executed from `frontend/`:

- `npm run typecheck`: passed.
- `npm run lint`: completed, 0 errors and 19 warnings.
- `npm run build`: passed; Next.js generated the production route set.

The proof route source matches the backend route. `ProofJobResponse` and nested segment response models include `proof_artifact`; this is a public API exposure of persisted proof bytes, though no private witness field is exposed in the reviewed DTO. No live API or authentication/ownership frontend integration was run. **PARTIALLY VERIFIED.**

## 18. Full Repository Security Sweep

Observed:

- Certificate signing source uses `CERTIFICATE_SECRET_KEY`; no JWT-secret signing path found.
- No project default signing secret found.
- No verifier `print()` path found.
- Application prover/verifier subprocess calls have timeouts.
- Several scripts have subprocess calls without timeouts; they include audit/development measurement paths and were not all independently classified as production.
- Proof artifacts are bounded by persisted string length and decoded structural checks, but strict Base64 validation is absent.
- Archive helper's 50 MB check is not a complete archive/resource control.
- No complete generated archive or private key artifact found.
- Docker configuration targets SQL Server 2022 but Docker daemon is unavailable.
- `.env.example` contains empty placeholder DB password, not a credential.

## 19. New Stage 21G Finding

### ST21G-NEW-001 - Proof Base64 and archive validation are incomplete

**Severity:** HIGH  
**Evidence:** SOURCE VERIFIED; selected helper tests TEST VERIFIED; runtime NOT VERIFIED.

`NoirVerifier` calls `base64.b64decode(seg.proof_artifact)` without strict validation and does not enforce the configured maximum before decoding. `CryptoProfile.validate_segment_proof()` checks only the already decoded bytes. `CryptoProfile.validate_proof_archive()` checks only existence, zero size, and a 50 MB file-size limit; it does not verify archive SHA-256, ZIP contents, manifest completeness, proof hashes, VK/circuit/profile hashes, or exactly 256 entries. The helper is not demonstrated as part of successful archive persistence.

**Impact:** malformed or oversized encoded input can reach decode before decoded-size rejection, and an archive can pass the helper without being a valid cryptographic evidence package. This keeps ST21A-003, ST21B-NEW-003, ST21C-NEW-003, and ST21C-NEW-004 from becoming fully remediated.

## 20. Evidence Gaps

1. Real Nargo witness generation.
2. Real Barretenberg proof generation and verification.
3. Public-input serialization/order validation against an actual proof.
4. Complete 1024-component, 32-chunk, 8-segment, 256-proof evidence.
5. Complete ProofSet verification and mutation rejection.
6. Independent ZIP archive inspection with manifest/hash/content checks.
7. SQL Server 2022 migration, schema, relationship, constraint, and persistence execution.
8. Real startup against SQL Server with missing/invalid crypto artifacts.
9. Real certificate issuance from a cryptographically verified ProofSet.
10. Deployment-wide admission/resource control.
11. Strict Base64 and archive-content validation.
12. Clean isolated dependency installation, despite current declared chain and successful suite execution.
13. Full two-user ownership matrix against the target database/API deployment.

## 21. Exact Commands Executed

```text
Get-Location
git status --short --branch
git diff --stat
python --version
node --version
.\.venv\Scripts\python.exe -m pip show packageurl
.\.venv\Scripts\python.exe -c "import packageurl,sys; print(packageurl.__file__); print(sys.executable)"
.\.venv\Scripts\python.exe -m pip list
Get-Command docker,nargo,bb -ErrorAction SilentlyContinue
Test-NetConnection -ComputerName localhost -Port 1433 -InformationLevel Quiet
Get-ChildItem -Recurse -File -Path . | Select-String -Pattern '21G|STAGE21G|svgstage|quota_acquired|validate_segment_proof|validate_proof_archive|513'
Get-Content pyproject.toml
Get-ChildItem backend -Recurse -File -Filter '*requirements*.txt'
.\.venv\Scripts\python.exe -m pytest -q
Push-Location frontend; npm run typecheck; npm run lint; npm run build; Pop-Location
$env:PYTHONPATH='backend'; $env:CRYPTO_PROFILE='prod'; $env:DEBUG='false'; .\.venv\Scripts\python.exe -c "from shared.crypto.config import get_crypto_profile; ..."
Get-ChildItem -Recurse -File -Path . -Include 'proof','*.proof','*.gz','*.zip','manifest.json'
Get-ChildItem archives -Recurse -Force
Get-ChildItem segment_mid_32,segment_mid_32_1,segment_mid_32_2,segment_mid_32_3,segment_mid_32_4,segment_mid_32_5,segment_mid_32_6 -Recurse -File -Include '*.json','vk' | Get-FileHash -Algorithm SHA256
Get-ChildItem backend,scripts,frontend\src -Recurse -File | Select-String -Pattern 'JWT_SECRET_KEY|CERTIFICATE_SECRET_KEY|subprocess\.run|print\(|stdout|stderr|base64|make_archive|proof_archive_hash|ProofJob\.user_id'
docker info --format '{{.ServerVersion}}'
wsl -d kali-linux -- bash -lc 'command -v nargo; command -v bb; nargo --version; bb --version'
```

Observed outcomes:

```text
Backend full suite: 513 passed, 63 warnings in 37.86s
Frontend typecheck: passed
Frontend lint: 0 errors, 19 warnings
Frontend build: passed
packageurl import: successful, packageurl-python 0.16.0
Production profile: prod, max_components=1024, Init/Mid/Final paths returned
Proof inventory: 11 proof files, 11 witness files, no ZIP, no manifest
SQL Server: localhost:1433 unreachable
Docker daemon: unavailable
Nargo: unavailable
Barretenberg: unavailable
```

## 22. Files Inspected

- `docs/STAGE21F_INDEPENDENT_FORENSIC_REAUDIT.md`
- `backend/shared/requirements.txt`
- `backend/sbom_service/requirements.txt`
- `backend/zkp_service/requirements.txt`
- `backend/verification_service/requirements.txt`
- `backend/shared/app_factory.py`
- `backend/shared/config.py`
- `backend/shared/crypto/config.py`
- `backend/shared/crypto/smt.py`
- `backend/zkp_service/app/services/prover_service.py`
- `backend/zkp_service/app/repositories/zkp_repository.py`
- `backend/zkp_service/app/schemas/zkp_schemas.py`
- `backend/zkp_service/app/models/zkp_models.py`
- `backend/zkp_service/app/api/routes/zkp_routes.py`
- `backend/verification_service/app/core/verifier.py`
- `backend/verification_service/app/services/verification_service.py`
- `backend/verification_service/app/repositories/verification_repository.py`
- `backend/verification_service/app/api/routes/verification_routes.py`
- `backend/verification_service/tests/test_prover_service.py`
- `backend/verification_service/tests/test_verifier.py`
- `backend/verification_service/tests/test_verifier_topology.py`
- `backend/verification_service/tests/test_verification_api.py`
- `backend/verification_service/tests/test_db_constraints.py`
- `backend/shared/tests/test_startup_validation.py`
- `backend/shared/tests/test_shared_db_constraints.py`
- `backend/shared/crypto/profile.json`
- `backend/alembic/versions/001_initial_schema.py`
- `backend/alembic/versions/003_add_chunk_proof_models.py`
- `backend/alembic/versions/005_add_topology_constraints.py`
- `backend/alembic/versions/006_add_proof_archive_hash.py`
- `backend/alembic/versions/007_enforce_proof_size.py`
- `frontend/src/api/services/proofService.ts`
- `frontend/src/api/types.ts`
- `docker-compose.yml`
- `.env.example`
- `pyproject.toml`
- `archives/proofs/`
- `segment_init_32/target/`
- `segment_mid_32/target/`
- `segment_mid_32_1/target/` through `segment_mid_32_6/target/`
- `segment_final_32/target/`

## 23. Final Verdict

IMPLEMENTATION:
    Stage 21G implementation is partially verified. The lock/quota cleanup and dependency/full-suite reproducibility claims are supported by source and executable tests. Profile/file validation, startup branches, topology branches, and certificate-secret usage are implemented but remain boundary-limited.

SECURITY:
    High and critical findings remain partially remediated or not verified. A new high-severity proof Base64/archive validation gap is open.

CRYPTOGRAPHIC RUNTIME:
    NOT VERIFIED. Nargo and Barretenberg are unavailable; no real proof verification was performed.

SQL SERVER RUNTIME:
    NOT VERIFIED. SQL Server is unreachable and no migration/schema/persistence execution occurred.

256-PROOF EVIDENCE:
    NOT VERIFIED. No complete 32 x 8 proof set, manifest, or archive exists.

CERTIFICATE TRUST CHAIN:
    NOT VERIFIED. Certificate tests use mocks; no certificate was produced from a real verified ProofSet.

ARCHIVE EVIDENCE:
    NOT VERIFIED. The archive directory is empty and the validation helper does not validate archive contents or hashes.

STAGE 22:
    BLOCKED

The project is not eligible to proceed to Stage 22. Return it to the implementation team for remediation and evidence production. Do not treat the 513 passing tests as proof of the missing cryptographic, database, archive, or certificate runtime boundaries.

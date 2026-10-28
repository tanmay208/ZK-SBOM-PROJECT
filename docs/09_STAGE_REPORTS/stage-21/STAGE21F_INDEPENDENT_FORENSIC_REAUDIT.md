# STAGE 21F - INDEPENDENT FORENSIC RE-AUDIT

**Audit date:** 2026-10-02  
**Role:** Independent security forensic auditor  
**Disposition:** Stage 21E is not independently validated. Previous high and critical findings remain open or only partially demonstrated.

## 1. Executive Summary

Stage 21E contains meaningful implementation changes. The actual source includes profile hash validation, persisted proof hashes, 32-by-8 topology checks, certificate ownership filters, certificate-secret signing, process-local prover admission, archive assembly, and startup configuration checks.

Those changes do not establish the complete security contract. The repository contains no complete 256-proof archive, no 256-proof runtime transcript, no SQL Server execution evidence, and no real certificate trust-chain execution. Most cryptographic, archive, startup, resource-control, and certificate tests use mocks. The full backend suite is not reproducible in the current virtual environment because `packageurl` is missing during collection.

The strongest independently observed results are:

- Production `CryptoProfile` validation succeeded against the actual checked-in circuit and VK files. This is **REAL RUNTIME VERIFIED for profile/file validation only**, not proof generation or BB verification.
- The focused runnable security slice passed `21 passed, 1 warning`.
- Frontend TypeScript typecheck passed.
- The full suite failed collection with 14 `ModuleNotFoundError: packageurl` errors and 1 warning.
- Docker CLI exists, but the Docker daemon is unavailable. SQL Server `localhost:1433` is unreachable.
- `nargo` and `bb` are unavailable on PATH and in the checked WSL Kali distribution.
- Artifact inventory found 11 standalone proof files and 11 witness files, but no complete archive or 256-job manifest.

Stage 21F therefore recommends return to remediation. The project must not advance to Stage 22 on the current evidence.

## 2. Audit Scope

Inspected the Stage 21D authoritative baseline, Stage 21E plan and report, backend source, tests, Alembic migrations, frontend route contract, profile and cryptographic artifacts, archive directory, deployment configuration, and repository status. No source, test, migration, configuration, frontend, documentation, generated artifact, or crypto artifact was modified except creation of this report.

The requested `docs/STAGE21E_SECURITY_REMEDIATION.md` does not exist. The Stage 21E report was therefore audited as the available claim, with the missing document recorded as an evidence/documentation gap.

## 3. Repository Baseline

| Item | Observation |
|---|---|
| Branch | `chore/final-project-cleanup` |
| Worktree | Dirty before audit; extensive pre-existing added/deleted/renamed files. No unrelated changes were reverted. |
| Python | `Python 3.12.10` from the baseline probe; repository `.venv` used for tests |
| Node | `v24.19.0` |
| Nargo | Not available on PATH; not available in WSL `kali-linux` |
| Barretenberg | `bb` not available on PATH; not available in WSL `kali-linux` |
| Docker CLI | `Docker version 29.8.1` |
| Docker daemon | Unavailable: Docker API named pipe could not be opened |
| SQL Server | No reachable listener at `localhost:1433` |
| Declared database | SQL Server 2022 through `mssql+pyodbc` |
| `CRYPTO_PROFILE` | Not present in the inherited shell; explicit probe with `CRYPTO_PROFILE=prod` succeeded |
| Production profile | `prod`, 1024 components, 32 chunks, 8 segments per chunk |
| Profile paths | `segment_init_32`, `segment_mid_32`, `segment_final_32` |
| Profile hash check | Actual circuit/VK hashes matched all three profile entries |
| Proof artifacts | 11 extensionless `target/proof` files, including decomposed samples |
| Witness artifacts | 11 `.gz` files |
| Archives | `archives/proofs` exists but contains no completed archive or manifest |
| Secrets | Only `.env.example` and dependency certificate bundles found; no project private key artifact found |
| Tracked/ignored state | `git status` shows a dirty implementation worktree; generated target files are present, while no complete archive is tracked or present |

The three checked production artifact pairs had these observed SHA-256 prefixes, matching `profile.json`: init circuit `3d529f...`, init VK `3fa91f...`; mid circuit `c45a30...`, mid VK `820a2a...`; final circuit `60289d...`, final VK `5faba2...`.

## 4. Evidence Classification

Evidence labels in this report are intentionally not interchangeable:

- **SOURCE VERIFIED:** behavior is visible in source or configuration; execution was not established.
- **UNIT TEST VERIFIED:** an isolated test passed, generally with mocks or test doubles.
- **INTEGRATION TEST VERIFIED:** multiple real application/database components were exercised in one test environment. SQLite remains SQLite evidence, not SQL Server evidence.
- **REAL RUNTIME VERIFIED:** actual repository artifacts or external runtime tools executed and produced the observed result.
- **NOT VERIFIED:** required evidence was absent, unavailable, or blocked.

A source path that can generate 256 proofs is not evidence that 256 proofs were generated. A mocked `subprocess.run` is not BB evidence. A SQLite constraint test is not SQL Server validation.

## 5. Stage 21D -> Stage 21E Comparison

Stage 21D identified missing concurrency proof, incomplete profile authority, ad hoc proof parsing, no complete 256-proof evidence, mocked ownership testing, incomplete topology enforcement, startup gaps, missing certificate-secret enforcement, process-local resource limits, incomplete SQL schema assurance, and non-atomic archive/database lifecycle.

Stage 21E claims to address these through migrations 006/007, startup validation, profile paths, topology metadata checks, secret isolation, centralized limits, archive manifests, IDOR tests, per-user limits, SMT locks, and SQLite constraints. Source inspection confirms most code exists. Independent validation shows:

- Several claims are source-verified only.
- Several tests are unit tests with mocks, including subprocess, filesystem, profile, verifier, and repository behavior.
- The certificate listing test does create two users and persisted SQLite rows, so that specific boundary is **INTEGRATION TEST VERIFIED for SQLite**.
- No Stage 21E evidence reaches SQL Server, real BB, a complete ProofSet, archive inspection, or certificate creation from a real verified ProofSet.
- The Stage 21E report mislabels findings and omits a consistent finding crosswalk. It also references a missing security-remediation document.

## 6. Canonical Finding Register

| ID | Severity | Stage 21D Status | Stage 21E Claim | Independent Status | Evidence Class | Evidence / Tests / Runtime Evidence | Remaining Risk |
|---|---:|---|---|---|---|---|---|
| ST21A-001 | HIGH | PARTIAL | SMT locking and concurrency | PARTIALLY REMEDIATED | UNIT TEST VERIFIED | Lock protects `insert` and `_build_levels`; focused test passed. No adversarial race oracle or concurrent path correctness test. | Cache/root consistency under concurrent reads and mutation remains incompletely demonstrated. |
| ST21A-002 | CRITICAL | PARTIAL | Profile is authoritative | PARTIALLY REMEDIATED | REAL RUNTIME VERIFIED | Actual `prod` profile validated real circuit/VK hashes and paths. Prover/verifier source uses profile, but no real proving or verification. | Runtime cryptographic binding and all artifact selection remain unproven. |
| ST21A-003 | CRITICAL | PARTIAL | Persisted proof hash, bounds, VK and BB verification | PARTIALLY REMEDIATED | UNIT TEST VERIFIED | Tests mock base64, hashing, file I/O, profile, and `subprocess.run`. Source checks encoded length before decode and hash after decode. | Fixed proof format/public-input offsets and real BB verification are not independently established. |
| ST21A-004 | HIGH | NOT REMEDIATED | Complete archive and 256 proofs | NOT REMEDIATED / EVIDENCE GAP | NOT VERIFIED | 11 sample proofs and 11 witnesses; no 256-proof set, complete manifest, or archive. Negative test only constructs mocked/incomplete data. | The required 32 x 8 cryptographic evidence does not exist in the repository. |
| ST21A-005 | HIGH | PARTIAL | PURL identity and fallback semantics | PARTIALLY REMEDIATED | SOURCE VERIFIED | PURL path is canonicalized; missing PURL falls back to `pkg:generic/<name>@<version-or-unknown>`. Identity tests were not runnable in full suite due missing `packageurl`. | Missing-PURL collisions and vulnerability lookup divergence remain insufficiently proven. |
| ST21A-006 | HIGH | PARTIAL | Ownership/IDOR regression fixed | PARTIALLY REMEDIATED | INTEGRATION TEST VERIFIED | `test_certificate_listing_idor` persists User A/User B rows in SQLite and checks listing/detail isolation. No SQL Server test. | SQL Server behavior and all job/detail/proof ownership paths remain unverified. |
| ST21A-007 | HIGH | PARTIAL | Exact 32 x 8 topology enforced | PARTIALLY REMEDIATED | SOURCE VERIFIED | Verifier checks counts, indices, totals, boundaries, child indices, commitments, and hash linkage. DB checks only index bounds/uniqueness. | Full malformed topology mutation suite and DB parent-child consistency are not proven. |
| ST21A-008 | HIGH | PARTIAL | Startup fails closed | PARTIALLY REMEDIATED | UNIT TEST VERIFIED | `validate_config` and lifespan require secrets and profile; tests patch `get_crypto_profile` for secret cases. Actual startup against real DB/profile was not executed. | Invalid/missing artifacts and DB startup behavior at deployment boundary remain unverified. |
| ST21A-009 | HIGH | PARTIAL | Certificate gated by cryptographic verifier | PARTIALLY REMEDIATED | UNIT TEST VERIFIED | Verification service gates issuance on result; successful tests inject `MockVerifier`. No real ProofSet-to-certificate run. | Certificate trust chain remains unproven. |
| ST21A-010 | MEDIUM | NOT REMEDIATED | Frontend/backend route aligned | REMEDIATED | SOURCE VERIFIED | Frontend calls `/api/v1/zkp/jobs/{id}` and backend registers `/api/v1/zkp/jobs/{job_id}`; frontend typecheck passed. | No live frontend/backend integration test. |
| ST21A-011 | HIGH | NOT REMEDIATED | Global and per-user controls added | PARTIALLY REMEDIATED | UNIT TEST VERIFIED | Process-local nonblocking lock and process-local per-user map; test asserts mocked rejection. | Multiple workers, containers, replicas, repeated submissions, disk, DB, and archive growth are not deployment-wide bounded. |
| ST21A-012 | MEDIUM | NOT REMEDIATED | Constraints and archive hash migration added | PARTIALLY REMEDIATED | SOURCE VERIFIED | Migrations 005-007 and ORM contain several constraints and `proof_archive_hash`; no migration applied to SQL Server. | Status, metadata, parent-child, and SQL Server schema consistency remain unverified/incomplete. |
| ST21B-NEW-001 | HIGH | PARTIAL | Certificate secret isolated | PARTIALLY REMEDIATED | UNIT TEST VERIFIED | Create/update tests decode with certificate secret and reject JWT secret. Startup secret enforcement is source/unit-tested only. | No persisted runtime signing test or secret-rotation runtime test. |
| ST21B-NEW-002 | HIGH | PARTIAL | BB timeout/limits centralized | PARTIALLY REMEDIATED | UNIT TEST VERIFIED | Application prover/verifier calls have profile timeout; timeout tests mock exceptions. Audit scripts still contain unbounded subprocess paths. | Real timeout behavior and scope of all production subprocesses are not verified. |
| ST21B-NEW-003 | MEDIUM | PARTIAL | Archive manifest and atomic zip | PARTIALLY REMEDIATED | UNIT TEST VERIFIED | Source creates temp directory, manifest, zip temp, rename, and SHA-256; negative test uses fake data and checks incomplete rejection. | No complete archive, independent manifest inspection, retention/disk enforcement, or crash recovery. |
| ST21C-NEW-001 | HIGH | PARTIAL | JWT signing defect remains fixed | REMEDIATED at source; runtime gap | SOURCE VERIFIED | Repository create/update paths use `CERTIFICATE_SECRET_KEY`; repository-wide search found no certificate signing path using JWT secret. | No real persisted certificate transaction and startup runtime evidence. |
| ST21C-NEW-002 | MEDIUM | PARTIAL | Debug leak removed | REMEDIATED at source; runtime gap | SOURCE VERIFIED | No verifier `print()` path was found; errors use logger. No stdout/log redaction runtime test. | Sensitive subprocess stderr/log behavior remains untested. |
| ST21C-NEW-003 | HIGH | PARTIAL | 5000 proof bound and DB schema limit | PARTIALLY REMEDIATED | SOURCE VERIFIED | Verifier checks encoded string length before base64 decode; migration 007 changes proof columns to `VARCHAR(5000)`. | Setting is named bytes but application checks encoded characters; DB and alternate ingestion paths were not executed. |
| ST21C-NEW-004 | MEDIUM | NOT REMEDIATED | Atomic archive lifecycle | PARTIALLY REMEDIATED | SOURCE VERIFIED | Zip file rename is atomic within filesystem. DB status/hash update occurs afterward and separately. | Crash, disk-full, zip failure, stale temp, duplicate, and DB/archive divergence remain possible. |

## 7. Finding-by-Finding Analysis

### ST21A-001 - SMT cache

`SparseMerkleTree.insert` invalidates `_cached_levels` while holding a lock, and `_build_levels` serializes cache construction. The runnable SMT test passed. However, `get_root` reads `self.leaves` without the lock on the empty-tree branch, and `get_path` obtains a reference to levels after construction without an explicit operation-wide snapshot. The tests do not establish linearizable concurrent read/mutation behavior. Status: **PARTIALLY REMEDIATED**.

### ST21A-002 - Profile/VK binding

The real profile probe validated actual files and hashes. This is the strongest positive result in the audit. It does not prove Nargo, BB, path selection in a real job, or runtime use of every profile field. `get_artifact_paths` exposes only three profile names; the prover aliases all mid circuits to `segment_mid_32`, while the source also names `_1` through `_6` directories. That may be intentional shared-circuit design, but it is not backed by a complete runtime demonstration. Status: **PARTIALLY REMEDIATED**.

### ST21A-003 - Persisted proof integrity

The verifier checks size before decode, hashes decoded bytes, checks gzip exclusion, uses expected lengths, extracts public inputs, selects a profile VK, and invokes BB with a timeout. Tests replace the costly boundaries with mocks. The fixed byte layout is asserted in source but no independent real Noir/BB format evidence was observed. Status: **PARTIALLY REMEDIATED / UNVERIFIED at cryptographic boundary**.

### ST21A-004 - Complete 256-proof evidence

The source creates 32 chunks and 8 segments each and refuses archive assembly unless it sees 256 segment entries. That is implementation evidence only. Filesystem inspection found 11 proofs and 11 witnesses, no complete archive, no complete job manifest, and no proof-to-job mapping for 256 proofs. Status: **NOT REMEDIATED / EVIDENCE GAP**.

### ST21A-005 - Component identity

PURL-bearing components use the shared PURL canonicalizer for name/version extraction. Missing PURLs are assigned a generic synthetic PURL based on display name and version, with `unknown` for null version. This is deterministic but does not independently establish collision resistance or that vulnerability ingestion resolves exactly the same fallback. Full identity tests were blocked by the missing dependency. Status: **PARTIALLY REMEDIATED**.

### ST21A-006 - Ownership/IDOR

The certificate list filters through `VerificationRequest.user_id`, detail retrieval validates request ownership, and proof jobs have owner-filtered routes. The API test is materially stronger than a mocked query chain: it creates two users, persisted SQLite rows, and checks both listings plus cross-user detail denial. It is still not SQL Server production validation, and no equivalent complete proof-job ownership integration was observed. Status: **PARTIALLY REMEDIATED**.

### ST21A-007 - ProofSet topology

The verifier checks exactly 32 ordered chunks, exact 8 ordered segments per chunk, chunk metadata, child chunk index and total, component boundaries, commitments, and hash linkage. Migrations enforce only index bounds and per-parent uniqueness. There is no broad mutation test demonstrating rejection for every requested swapped, duplicated, cross-job, commitment, root, policy, and linkage mutation. Status: **PARTIALLY REMEDIATED**.

### ST21A-008 - Startup fail-closed

`validate_config` checks DB settings, JWT secret, certificate secret, and calls `get_crypto_profile`; lifespan calls validation, profile retrieval, and DB initialization. The tests patch profile validation in missing-secret cases, so they verify error branching rather than the complete production startup path. No actual SQL Server startup occurred. Status: **PARTIALLY REMEDIATED**.

### ST21A-009 - Certificate trust chain

Certificate creation is conditional on the verifier returning `verified`, and the repository signs with the certificate secret. Tests use `MockVerifier` or mock sessions. No real persisted 256-proof set was verified and no certificate was produced from it. Status: **PARTIALLY REMEDIATED**.

### ST21A-010 - Frontend route

Source contracts match and `npm run typecheck` passed from `frontend/`. No live API integration was run. Status: **REMEDIATED at source contract; runtime integration not verified**.

### ST21A-011 - Resource controls

The global lock and per-user counter are process-local and synchronous. The test holds the lock or manually seeds the counter; it does not create concurrent HTTP requests, multiple workers, multiple containers, or persistent quota state. Status: **PARTIALLY REMEDIATED**.

### ST21A-012 - SQL Server integrity

Migration 006 adds `proof_archive_hash` and migration 007 adds proof column length changes. Migrations 005 and ORM add some bounds and uniqueness. There are no executed migrations, no SQL Server schema inspection, and no observed SQL Server constraint failures/successes. Status: **PARTIALLY REMEDIATED / SQL SERVER RUNTIME VALIDATION NOT PERFORMED**.

### ST21B-NEW-001 - Certificate secret

Both repository signing paths require `CERTIFICATE_SECRET_KEY`; tests verify JWT-secret rejection. Startup requirement exists in source and mocked startup tests. No real startup or persisted signature rotation test ran. Status: **PARTIALLY REMEDIATED**.

### ST21B-NEW-002 - BB timeout

Application Nargo/BB calls use the profile timeout and catch timeout exceptions. Tests mock timeout. Several scripts contain subprocess calls without a timeout; their production status is not consistently separated from audit/development paths. No actual timeout execution occurred. Status: **PARTIALLY REMEDIATED**.

### ST21B-NEW-003 - Archive evidence

The archive code creates a temporary job directory, proof files, profile copy, VK copies, manifest, zip, and SHA-256. The manifest contains roots, job ID, ownership, profile identity, versions, and proof/VK hashes, but does not include a profile SHA-256 or circuit hashes for each entry and uses a literal timestamp marker. The negative test does not inspect a real completed archive. Status: **PARTIALLY REMEDIATED**.

### ST21C-NEW-001 - JWT/certificate signing regression

Repository search and source inspection show certificate creation/update uses `CERTIFICATE_SECRET_KEY` and no default fallback. Direct mocked JWT decode tests passed in the runnable subset. Status: **REMEDIATED at source; runtime startup and persistence evidence pending**.

### ST21C-NEW-002 - Debug leak

No verifier print path was found in the searched application paths. Logger calls include subprocess stderr on BB failure, so the absence of `print` does not itself prove sensitive-output redaction. Status: **REMEDIATED at source for print removal; log redaction runtime not verified**.

### ST21C-NEW-003 - Proof bounds

The verifier rejects encoded proof strings longer than the configured 5000 value before base64 decoding. The database migration limits persisted columns to 5000 characters. The setting name says bytes, while the source check measures encoded characters, and no SQL Server migration was applied. Status: **PARTIALLY REMEDIATED**.

### ST21C-NEW-004 - Archive atomicity

The zip rename is separate from database status/hash persistence. A process crash or DB failure can leave a completed-looking archive without a corresponding durable DB state, or a DB state update can fail after an archive exists. No recovery or crash injection was run. Status: **PARTIALLY REMEDIATED**.

## 8. Test Quality Assessment

The focused runnable slice passed 21 tests, but its security boundaries are mixed:

- `test_resource_control_limits` manipulates module locks and counters directly; it does not prove HTTP-level or deployment-wide admission control.
- `test_archive_proofs_negative_incomplete` creates fake 255/256 records and exercises source branching; it does not inspect a real archive or prove archive contents.
- Profile tests mock `open`, `exists`, and SHA-256, so they do not prove the production artifacts. The separate runtime profile probe does prove actual file/hash validation.
- Verifier tests mock database query results, base64 decoding, file access, profile, hash, subprocess, and paths. They are unit tests for failure branches, not BB tests.
- The SQLite certificate listing test is a meaningful two-user integration test for SQLite ownership filters. It is not SQL Server validation.
- The service-level IDOR test mocks query chains and is not independent persistence evidence.
- Certificate tests verify JWT behavior with mocked sessions. They do not prove a real transaction or trust-chain input.
- Startup tests patch profile validation, so a passing test can coexist with invalid real artifacts.
- The empty/pass-only `test_startup_validation_uses_same_requirement` is vacuous and provides no security evidence.
- Full-suite collection was blocked by missing `packageurl`; therefore no 503/503 claim was independently reproduced.

## 9. Cryptographic Trust Chain

| Link | Independent result |
|---|---|
| Authoritative SBOM/vulnerability/policy records | Source paths exist; real end-to-end data not run |
| ProofJob and persisted proofs | Source/model paths exist; no complete persisted job observed |
| Proof hash comparison | Source verified; mocked unit tests only |
| Profile/VK selection | Actual profile/file hash validation succeeded; real verifier use not run |
| BB proof verification | NOT VERIFIED; `bb` unavailable |
| Complete 32 x 8 ProofSet | NOT VERIFIED; no complete artifact set |
| Archive | NOT VERIFIED; no completed archive |
| Certificate issuance | Mock verifier/unit tests only |
| Certificate signing | Mock-session JWT tests; source uses correct secret |
| Certificate retrieval | SQLite ownership test only |

## 10. Certificate Trust Boundary

Certificate signing is source-isolated to `CERTIFICATE_SECRET_KEY` in both create and update paths. The tests decode signatures with the certificate secret and reject the JWT secret, so the isolation implementation is **UNIT TEST VERIFIED**. Startup also checks the variable in source. No real application startup, persisted certificate transaction, secret-rotation execution, or certificate derived from a real verified ProofSet was observed. The trust boundary is therefore implemented but not runtime-proven.

## 11. ProofSet Integrity

Application verification enforces substantial topology checks: 32 chunks, indices 0..31, eight segments, indices 0..7, metadata equality, component boundaries, commitments, and hash linkage. Database constraints enforce only selected index bounds and uniqueness. The requested adversarial matrix was not independently executed, and there is no complete ProofSet to verify. ProofSet integrity is **PARTIALLY REMEDIATED**.

## 12. Archive/Evidence Integrity

Archive code has job-scoped temporary assembly and zip-file rename. The manifest records job/roots/ownership/profile identity/tool version/proof and VK hashes. It omits a cryptographic profile hash and circuit hashes, includes a literal `timestamp_marker`, and copies `profile.json` without separately recording its digest. `archive_status` is written as `complete` before independent archive inspection, and DB persistence is separate from filesystem finalization. No archive exists to inspect. Status: **PARTIALLY REMEDIATED; complete evidence NOT VERIFIED**.

## 13. Authentication/Authorization

The frontend proof route and backend route align. Certificate listing and detail source paths use current-user ownership. The SQLite two-user test verifies list isolation and cross-user detail denial in SQLite. Proof-job detail has a current-user check. No SQL Server execution, admin behavior test, or complete verification-request/proof-job ownership integration was run.

## 14. Resource Exhaustion

The application has a process-local global lock, process-local per-user count, proof encoded-length checks, database string bounds, and subprocess timeouts. None is deployment-wide. Multiple Uvicorn workers, containers, replicas, database growth, temporary disk, archive retention, and repeated serial submissions remain outside the demonstrated bound. The lock is not persistent admission control.

## 15. Database Integrity

The declared target is SQL Server 2022. Migrations 005-007 add selected topology uniqueness/checks, `proof_archive_hash`, and proof column length changes. ORM and migration contents are source-verified, but no migration was applied. SQL Server runtime validation was **NOT PERFORMED** because Docker daemon and port 1433 were unavailable. SQLite constraint tests must not be promoted to SQL Server evidence.

## 16. Real Runtime Evidence

Observed real runtime evidence:

- Actual profile JSON was loaded and actual circuit/VK files were hashed successfully.
- Frontend TypeScript compiler completed successfully.
- 21 focused tests completed successfully using the local Python environment.
- Full suite attempted and failed at collection due missing `packageurl`.
- Docker CLI version reported, but daemon connection failed.
- SQL Server TCP probe to `localhost:1433` failed.
- WSL Kali reported no `nargo` or `bb` commands.

Not observed:

- Nargo witness execution for this job architecture.
- BB prove or BB verify execution.
- 256 real proofs.
- Complete ProofSet verification.
- Complete archive production and independent inspection.
- SQL Server migration/schema/persistence execution.
- Certificate produced from a real cryptographically verified ProofSet.

## 17. New Findings

### ST21F-NEW-001 - Prover global lock can remain held on early failure

**Severity:** MEDIUM availability/security risk  
**Status:** SOURCE VERIFIED; runtime NOT VERIFIED

In `ProverService.process_job`, `user_id` is assigned only after `_repo.get_job(job_id)` returns a job. The `finally` block unconditionally reads `_user_active_jobs[user_id]`. If the job is missing or an exception occurs before assignment, the `finally` block can raise `UnboundLocalError` before `_global_prover_lock.release()` executes. This can leave the process-local prover lock held and deny subsequent proof jobs until process restart. No test covers this early path.

### ST21F-NEW-002 - Full-suite evidence is not reproducible in the audit environment

**Severity:** MEDIUM evidence/release risk  
**Status:** REAL RUNTIME VERIFIED

The repository’s active `.venv` lacks the declared/imported `packageurl` dependency. The full suite stops during collection with 14 import errors. This is not asserted as an application vulnerability, but it prevents independent confirmation of the claimed suite count and leaves identity/authorization tests unexecuted in the full run.

## 18. Evidence Gaps

1. Complete 32-chunk, 8-segment-per-chunk proof and witness archive.
2. Reproducible Nargo witness, BB prove, and BB verify commands and exit codes.
3. Independent public-input format validation against the actual proof format.
4. Complete ProofSet mutation/rejection matrix.
5. SQL Server 2022 migration, schema, constraint, ownership, and persistence execution.
6. Real startup with profile, circuit, VK, DB, JWT, and certificate-secret failures.
7. Real certificate trust-chain run from authoritative records through retrieval.
8. Archive manifest/profile/circuit hash inspection and crash/recovery tests.
9. Deployment-wide resource controls across workers/containers/replicas.
10. Full suite execution after restoring declared dependencies.
11. A non-vacuous startup certificate-secret test and real secret-isolation runtime test.
12. Verification that all subprocess scripts are correctly classified and bounded.

## 19. Regression Risks

- Profile validation can succeed while real BB execution remains unavailable or selects an unintended shared mid circuit.
- A database can accept a schema different from the ORM until migrations are actually applied.
- Archive filesystem success and DB completion are separate state transitions.
- Process-local controls do not survive worker/container multiplication.
- Mocked verifier success can still issue a certificate without proving the real cryptographic chain.
- The early `process_job` failure path can strand the process-local lock.
- The full suite’s dependency failure hides regressions in PURL, API, and vulnerability paths.

## 20. Final Security Disposition

1. **Is Stage 21E independently validated?** No.
2. **Are all previous findings remediated?** No.
3. **Are HIGH/CRITICAL findings still open?** Yes: complete proof evidence, cryptographic runtime binding, proof integrity, topology completeness, resource scope, and trust-chain evidence remain open or partial.
4. **Are any findings only source-verified?** Yes, including route alignment, secret usage, debug-print removal, migrations, and parts of startup/topology.
5. **Are any findings only mock-tested?** Yes, especially verifier/BB, profile tests, certificate issuance, timeout, archive negative paths, and service-level IDOR.
6. **Was SQL Server actually executed?** No.
7. **Was Nargo actually executed?** No.
8. **Was Barretenberg actually executed?** No.
9. **Were 256 real proofs generated?** No evidence; not performed.
10. **Were 256 real proofs independently verified?** No.
11. **Was a complete archive produced?** No.
12. **Was the archive independently inspected?** No.
13. **Was a real certificate trust-chain execution performed?** No.
14. **Is certificate signing isolated to `CERTIFICATE_SECRET_KEY`?** Source and unit tests indicate yes; real runtime not verified.
15. **Does startup require `CERTIFICATE_SECRET_KEY`?** Source indicates yes; complete startup runtime not verified.
16. **Does startup validate `CryptoProfile`?** Source indicates yes; tests patch parts and real DB startup was not run.
17. **Is ProofSet topology completely enforced?** Application source has substantial checks; complete enforcement and database consistency are not demonstrated.
18. **Is ownership isolation integration-tested?** Yes for SQLite certificate list/detail; no for SQL Server or the whole resource graph.
19. **Is proof generation deployment-wide bounded?** No.
20. **Is the SQL Server schema consistent with ORM?** Source appears partially aligned; runtime consistency is not verified.
21. **Is `proof_archive_hash` actually migrated?** Migration 006 exists; it was not applied or observed on SQL Server.
22. **Is the archive lifecycle durable and recoverable?** No evidence; DB and filesystem finalization are separate.
23. **Are there new security findings?** Yes, ST21F-NEW-001 lock-release risk; ST21F-NEW-002 is an evidence/release blocker.
24. **What evidence remains missing?** The gaps in Section 18, especially real BB, 256 proofs, SQL Server, archive, and certificate E2E.
25. **Can the project advance to Stage 22?** No. Return to the implementation team for remediation and evidence production.

## 21. Exact Commands Executed

Commands were executed read-only except for normal test/tool cache behavior; no repository file was intentionally modified.

```text
git status --short --branch
python --version
node --version
nargo --version
bb --version
docker --version
docker compose version
Get-ChildItem -Recurse -File -Include '*proof*','*.gz','*.zip','*.json','*.nr'
git ls-files ...
git check-ignore -v ...
.\.venv\Scripts\python.exe -m pytest backend/shared/tests/test_smt.py backend/shared/tests/test_crypto_profile.py backend/shared/tests/test_startup_validation.py backend/zkp_service/tests/test_prover_service.py -q
.\.venv\Scripts\python.exe -m pytest -q
Push-Location frontend; npm run typecheck; Pop-Location
$env:PYTHONPATH='backend'; $env:CRYPTO_PROFILE='prod'; $env:DEBUG='false'; .\.venv\Scripts\python.exe -c "from shared.crypto.config import get_crypto_profile; ..."
Get-FileHash ... -Algorithm SHA256
Test-NetConnection -ComputerName localhost -Port 1433 -InformationLevel Detailed
docker info --format '{{.ServerVersion}}'
wsl -d kali-linux -- bash -lc 'command -v nargo; command -v bb; nargo --version; bb --version'
Get-ChildItem -Recurse -File backend,scripts,frontend\src | Select-String -Pattern 'subprocess\.run|CERTIFICATE_SECRET_KEY|JWT_SECRET_KEY|print\(|stdout|stderr|proof_archive_hash|archive_status|make_archive|lifespan'
```

Observed test outcomes:

```text
Focused runnable security slice: 21 passed, 1 warning in 6.79s
Frontend typecheck: passed
Full suite: collection interrupted, 14 errors, 1 warning; missing packageurl
Production profile probe: prod, 1024, three real artifact path tuples printed
SQL Server TCP probe: TcpTestSucceeded False
Docker daemon: failed to connect to Docker API
WSL tools: nargo command not found; bb command not found
```

## 22. Files Inspected

- `docs/STAGE21D_INDEPENDENT_FORENSIC_REAUDIT.md`
- `docs/STAGE21E_REMEDIATION_PLAN.md`
- `docs/STAGE21E_REMEDIATION_REPORT.md`
- `backend/shared/app_factory.py`
- `backend/shared/config.py`
- `backend/shared/crypto/config.py`
- `backend/shared/crypto/smt.py`
- `backend/zkp_service/app/services/prover_service.py`
- `backend/zkp_service/app/models/zkp_models.py`
- `backend/zkp_service/app/api/routes/zkp_routes.py`
- `backend/verification_service/app/core/verifier.py`
- `backend/verification_service/app/services/verification_service.py`
- `backend/verification_service/app/repositories/verification_repository.py`
- `backend/verification_service/app/api/routes/verification_routes.py`
- `backend/shared/tests/test_smt.py`
- `backend/shared/tests/test_crypto_profile.py`
- `backend/shared/tests/test_startup_validation.py`
- `backend/zkp_service/tests/test_prover_service.py`
- `backend/verification_service/tests/test_verifier.py`
- `backend/verification_service/tests/test_verification_api.py`
- `backend/verification_service/tests/test_verification_service.py`
- `backend/verification_service/tests/test_certificate_signing.py`
- `backend/verification_service/tests/test_db_constraints.py`
- `backend/sbom_service/app/services/canonicalization.py`
- `backend/shared/utils/purl.py`
- `frontend/src/api/services/proofService.ts`
- `backend/alembic/versions/003_add_chunk_proof_models.py`
- `backend/alembic/versions/005_add_topology_constraints.py`
- `backend/alembic/versions/006_add_proof_archive_hash.py`
- `backend/alembic/versions/007_enforce_proof_size.py`
- `backend/alembic/env.py`
- `backend/shared/crypto/profile.json`
- `docker-compose.yml`
- `.env.example`
- `archives/proofs/`
- `segment_init_32/target/`, `segment_mid_32/target/`, `segment_final_32/target/`

## 23. Final Recommendation

Do not advance to Stage 22. Return the repository to the implementation team with the remaining findings open. The next acceptance gate must require actual SQL Server execution, real Nargo/Barretenberg execution, a reproducible complete 256-proof set, independent archive inspection, and a certificate generated from that real verified ProofSet. The implementation report must not be treated as proof until those boundaries are observed.

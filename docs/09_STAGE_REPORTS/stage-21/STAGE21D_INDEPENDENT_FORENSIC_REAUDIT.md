# STAGE 21D — FINAL INDEPENDENT FORENSIC RE-AUDIT

## 1. Executive Summary

This audit independently checked the Stage 21D plan and report against the
current source, tests, migrations, configuration, and filesystem. The Stage
21D implementation report was treated as a claim, not evidence.

Stage 21D made real code changes: persisted proof hashes are checked, proof
artifacts have a pre-decode length limit, production BB calls have timeouts,
certificate ownership filters were added, a per-process prover lock exists, the
frontend proof route was corrected, and archive assembly now uses a temporary
directory plus a manifest.

The acceptance criteria are not independently satisfied. There is still no
complete 256-proof archive, no real 256-proof Barretenberg execution evidence,
no SQL Server execution evidence, and no real certificate trust-chain run.

The most important new implementation defect is that `proof_archive_hash` is
used by the ORM, repository, and prover but is not added by migration 005. The
archive completion path is therefore not consistent with the declared SQL
Server schema.

## 2. Audit Scope

Audited:

- [Stage 21C independent audit](./STAGE21C_INDEPENDENT_FORENSIC_REAUDIT.md)
- [Stage 21D remediation plan](./STAGE21D_REMEDIATION_PLAN.md)
- [Stage 21D remediation report](./STAGE21D_REMEDIATION_REPORT.md)
- backend source, tests, configuration, migrations, and models
- frontend API client and executable backend routes
- proof, witness, VK, circuit, and archive artifacts
- targeted backend tests and frontend typecheck

No source, test, migration, configuration, frontend, or existing documentation
file was modified. This new report is the only requested repository addition.

## 3. Repository Baseline

- Host: Windows NT 10.0.26300.0
- Python: 3.12.10
- Node: 24.19.0
- Nargo: unavailable on PATH
- Barretenberg: unavailable on PATH
- Docker: unavailable
- Declared deployment database: SQL Server 2022
- Worktree: pre-existing dirty state
- Proof files: 11 extensionless `target/proof` artifacts
- Witness files: 11 `.gz` artifacts
- Archive files: none outside unrelated dependency files

Independent targeted backend execution:

```text
23 passed, 20 warnings
```

The executed tests were SMT, crypto-profile, certificate-signing, and startup
tests. They include mocks and do not establish real Barretenberg or SQL Server
behavior.

Frontend `npm run typecheck` passed from `frontend/`. Full frontend lint/build
and the full backend suite were not executed because they may create generated
or cache files during this audit.

## 4. Stage 21D Plan Versus Actual Implementation

| Plan Block | Acceptance Requirement | Actual Result |
|---|---|---|
| 1 | Certificate secret and profile validated at startup | DB/config errors rethrow, but startup does not invoke crypto-profile validation or require certificate secret |
| 2 | Runtime profile selection, proof size/hash checks, centralized timeout | Size/hash checks exist; profile paths remain partly hard-coded; timeout is duplicated/hard-coded |
| 3 | Exact 32x8 topology and cross-job checks | Exact top-level indices exist; child metadata and DB enforcement remain incomplete |
| 4 | Atomic complete archive with manifest | Temporary directory and manifest exist in code; no actual archive exists and manifest lacks several required bindings |
| 5 | Owner regression tests | Owner filters exist; test is a mocked query and does not exercise User A/User B isolation |
| 6 | Frontend route match | Route now matches backend |
| 7 | Bounded proof generation | One nonblocking process-local lock; no rate limit, quota, queue, or multi-worker bound |
| 8 | SQL Server topology constraints | Migration adds some uniqueness/check constraints, but no status checks and no SQL Server execution |
| 9 | Consistent component identity | PURL-bearing identity is aligned; missing-PURL fallback remains separate |
| 10 | Concurrent SMT test/protection | No concurrency test; cache invalidation remains single-threaded |
| 11 | No verifier prints | Verifier prints removed |
| 13/14 | Real 256-proof and certificate execution | Not executed; tooling unavailable and no complete artifacts exist |

## 5. Canonical Finding Register

| Finding | Severity | Stage 21C Status | Stage 21D Claim | Independent Status | Evidence | Remaining Risk |
|---------|----------|------------------|-----------------|-------------------|----------|----------------|
| ST21A-001 | HIGH | REMEDIATED | Remediated with concurrency tests | PARTIALLY REMEDIATED | Cache invalidation exists; no concurrency test | Race behavior unproven |
| ST21A-002 | CRITICAL | PARTIALLY REMEDIATED | Profile/runtime binding remediated | PARTIALLY REMEDIATED | Hashes match current decomposed artifacts | Runtime paths and startup validation remain incomplete |
| ST21A-003 | CRITICAL | PARTIALLY REMEDIATED | Proof hash and BB verification remediated | PARTIALLY REMEDIATED | Hash comparison and BB call exist | No real execution; public-input parsing remains ad hoc |
| ST21A-004 | HIGH | NOT REMEDIATED | Archive remediation claimed | NOT REMEDIATED | No archive or 256-proof evidence exists | 1024/256 claim remains unproven |
| ST21A-005 | HIGH | PARTIALLY REMEDIATED | Fallback semantics documented | PARTIALLY REMEDIATED | PURL identity aligned for present PURLs | Missing-PURL identity ambiguity remains |
| ST21A-006 | HIGH | REMEDIATED | Regression test added | PARTIALLY REMEDIATED | Owner filters exist; test is mocked | Real cross-user authorization not tested |
| ST21A-007 | HIGH | PARTIALLY REMEDIATED | Strict topology remediated | PARTIALLY REMEDIATED | Exact chunk/segment index lists checked | Child metadata and cross-job consistency incomplete |
| ST21A-008 | HIGH | PARTIALLY REMEDIATED | Startup fail-closed remediated | PARTIALLY REMEDIATED | Exceptions rethrow in app factory | Profile and certificate secret are not startup-validated |
| ST21A-009 | HIGH | PARTIALLY REMEDIATED | Certificate cryptographic gate remediated | PARTIALLY REMEDIATED | Certificate follows verifier result | Real end-to-end trust chain not demonstrated |
| ST21A-010 | MEDIUM | NOT REMEDIATED | Route confirmed correct | REMEDIATED | Frontend calls `/api/v1/zkp/jobs/{id}` | No executable integration test observed |
| ST21A-011 | HIGH | NOT REMEDIATED | Bounded control added | PARTIALLY REMEDIATED | Process-local nonblocking lock | Repeated jobs, multiple workers, and quotas remain uncontrolled |
| ST21A-012 | MEDIUM | NOT REMEDIATED | Migration constraints added | PARTIALLY REMEDIATED | Migration 005 adds some uniqueness/checks | No SQL Server execution; missing status/FK coverage |
| ST21B-NEW-001 | HIGH | PARTIALLY REMEDIATED | Certificate secret isolated | REMEDIATED | Both signing paths use `CERTIFICATE_SECRET_KEY`; no fallback found | Startup still does not require it |
| ST21B-NEW-002 | HIGH | PARTIALLY REMEDIATED | BB timeout and size controls added | PARTIALLY REMEDIATED | Runtime calls use 300 seconds; timeout failures reject | Audit scripts unbounded; no real timeout test |
| ST21B-NEW-003 | MEDIUM | NOT REMEDIATED | Archive integrity remediated | PARTIALLY REMEDIATED | Temp assembly, manifest, and rename exist | No archive, retention, disk protection, or completion marker |
| ST21C-NEW-001 | HIGH | PARTIALLY REMEDIATED | JWT/certificate secret split fixed | PARTIALLY REMEDIATED | Source now uses certificate secret in both paths | No direct update-path signing test |
| ST21C-NEW-002 | MEDIUM | PARTIALLY REMEDIATED | Debug prints removed | REMEDIATED | No verifier `print()` remains | No stdout regression test |
| ST21C-NEW-003 | HIGH | PARTIALLY REMEDIATED | Proof size limit added | PARTIALLY REMEDIATED | 5000-character check precedes decode | DB path and other tool paths are not comprehensively bounded |
| ST21C-NEW-004 | MEDIUM | NOT REMEDIATED | Atomic archive claimed | PARTIALLY REMEDIATED | Temp directory rename exists | Zip finalization and DB archive hash are not atomic/integrated |

## 6. Finding-by-Finding Analysis

### ST21A-001 — SMT cache invalidation

**Status: PARTIALLY REMEDIATED**

**Source/function:** [backend/shared/crypto/smt.py](../../../backend/shared/crypto/smt.py#L20-L28),
`SparseMerkleTree.insert` deletes `_cached_levels` after insertion or replacement.

**Tests:** [backend/shared/tests/test_smt.py](../../../backend/shared/tests/test_smt.py#L52-L82)
checks root mutation, replacement, path mutation, and instance isolation. These
tests passed in the narrow independent run.

**Gap:** The plan required a concurrency test. No such test was found. The cache
is unsynchronized, so concurrent reads and mutation remain unverified.

### ST21A-002 — Production profile and VK binding

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/shared/crypto/config.py](../../../backend/shared/crypto/config.py#L24-L108).
The production profile binds the three decomposed JSON/VK pairs. Current file
hashes match the profile values, including all six mid directories.

**Gaps:** `ProverService` and `NoirVerifier` derive paths directly from the
project root. Startup does not call `get_crypto_profile()`. The profile still
allows a DEBUG-only fallback to the manifest's active profile.

**Tests:** The successful profile test uses `mock_open`, mocked `exists`, and a
mocked hash function. It proves validation logic under mocks, not the actual
production artifacts.

### ST21A-003 — Persisted proof integrity and BB verification

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/verification_service/app/core/verifier.py](../../../backend/verification_service/app/core/verifier.py#L92-L113).
The verifier rejects proof text over 5000 characters before decoding and compares
SHA-256 of decoded bytes to `proof_artifact_hash`.

It then invokes BB with the selected VK and a 300-second timeout.

**Gaps:** No real BB execution was performed. Public inputs are interpreted from
fixed 32-byte offsets in the raw proof rather than an independently verified
Barretenberg proof format. The selected circuit is inferred from segment index,
and the profile does not supply an explicit artifact path.

**Tests:** [backend/verification_service/tests/test_verifier.py](../../../backend/verification_service/tests/test_verifier.py#L25-L185)
mock `subprocess.run`, `base64.b64decode`, file I/O, profile, and SHA-256. They
prove failure branching, not cryptographic verification.

### ST21A-004 — Complete 256-proof evidence

**Status: NOT REMEDIATED**

**Source:** [backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L150-L249).
The code assembles a temporary directory and requires 256 manifest entries.

**Filesystem evidence:** No archive directory or archive file exists. Only 11
sample proofs and 11 witnesses exist. No successful 32x8 job is independently
available, and no manifest maps all proofs to a job, circuit, VK, profile, and
roots.

### ST21A-005 — Component identity

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/sbom_service/app/services/canonicalization.py](../../../backend/sbom_service/app/services/canonicalization.py#L150-L164)
uses canonical PURL-derived name/version when a PURL exists. Vulnerability
ingestion uses the same PURL-derived fields.

**Tests:** [backend/shared/tests/test_component_identity.py](../../../backend/shared/tests/test_component_identity.py#L19-L56)
covers differing display name and vulnerable PURL cases.

**Gap:** Missing PURLs use SBOM name/version. The new documentation does not
eliminate the semantic possibility of two identity regimes; no security policy
proves missing-PURL components cannot collide or bypass lookup.

### ST21A-006 — Certificate ownership

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/verification_service/app/api/routes/verification_routes.py](../../../backend/verification_service/app/api/routes/verification_routes.py#L94-L125)
filters listing by request owner and requires authentication for detail. The
service checks `req.user_id` in `_validate_cert_job`.

**Tests:** `test_certificate_listing_idor` uses a fully mocked SQLAlchemy chain
and returns the mocked certificate regardless of actual owner data. It does not
test User A/User B access. Detail tests also mock the service.

**Conclusion:** Source control exists, but the plan's owner regression acceptance
is not independently demonstrated by a real persistence test.

### ST21A-007 — Exact ProofSet topology

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/verification_service/app/core/verifier.py](../../../backend/verification_service/app/core/verifier.py#L35-L86)
checks 32 chunks, chunk indices `0..31`, eight segments, segment indices `0..7`,
total chunks, component start/count, commitments, and hash continuity.

**Gaps:** It does not validate `SegmentProof.chunk_index` against its parent,
`SegmentProof.total_chunks`, or all cross-job/cross-chunk metadata. It relies on
the `chunk_id` query and application checks. No real malformed topology test was
found.

### ST21A-008 — Startup fail-closed

**Status: PARTIALLY REMEDIATED**

**Source:** [backend/shared/app_factory.py](../../../backend/shared/app_factory.py#L40-L56)
re-raises initialization errors in all modes.

**Gaps:** The lifespan never invokes `get_crypto_profile()` and never validates
`CERTIFICATE_SECRET_KEY`. Missing/invalid profile, missing VK, VK hash mismatch,
and missing certificate secret therefore do not fail startup through this path.

`get_crypto_profile()` itself rejects a missing `CRYPTO_PROFILE` only when
`DEBUG` is not true in [backend/shared/crypto/config.py](../../../backend/shared/crypto/config.py#L112-L127),
but the application startup does not call it.

The startup tests patch `get_crypto_profile` but the app factory does not call it;
that test is not reliable evidence of runtime crypto startup validation.

### ST21A-009 — Certificate cryptographic gating

**Status: PARTIALLY REMEDIATED**

Certificate records are only created when `VerificationService` receives
`verified` from the verifier in [backend/verification_service/app/services/verification_service.py](../../../backend/verification_service/app/services/verification_service.py#L35-L66).

The verifier now rejects failed BB results, timeouts, hash mismatches, oversized
proofs, incomplete topology, and public-input mismatches in source logic.

There is still no real 256-proof execution or real certificate-producing run.
The successful certificate tests use `MockVerifier`. The chain is therefore
implemented but not independently cryptographically established.

### ST21A-010 — Frontend proof route

**Status: REMEDIATED**

[frontend/src/api/services/proofService.ts](../../../frontend/src/api/services/proofService.ts#L17-L22)
calls `/api/v1/zkp/jobs/${id}`. The backend registers
`/api/v1/zkp/jobs/{job_id}` in [backend/zkp_service/app/api/routes/zkp_routes.py](../../../backend/zkp_service/app/api/routes/zkp_routes.py#L57-L75).

The frontend no-emit typecheck passed. No live API integration test was found.

### ST21A-011 — Proof-generation resource controls

**Status: PARTIALLY REMEDIATED**

`_global_prover_lock` in [backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L20-L31)
limits one proof job per Python process. A second job fails immediately.

This is not a deployment-wide worker bound. There is no rate limit, quota,
per-user admission policy, queue, cancellation, disk quota, archive retention,
or cleanup policy. The same authenticated user can repeatedly submit jobs,
serially consuming the worker.

### ST21A-012 — Database integrity

**Status: PARTIALLY REMEDIATED**

Migration 005 adds unique chunk-per-job and segment-per-chunk constraints,
chunk/segment index checks, and certificate-per-request uniqueness.

It does not add status checks, component bounds, or all required cross-table
constraints. SQL Server execution was not available.

Further, `proof_archive_hash` exists in the ORM and repository but is absent from
all migrations, including migration 005. A completed archive update can therefore
be inconsistent with the actual SQL Server schema.

### ST21B-NEW-001 — Certificate secret fallback/isolation

**Status: REMEDIATED for signing-path isolation; PARTIALLY REMEDIATED overall**

Both `create_verification_record` and `update_verification_record` now read
`CERTIFICATE_SECRET_KEY` in [backend/verification_service/app/repositories/verification_repository.py](../../../backend/verification_service/app/repositories/verification_repository.py#L31-L91).
Repository search found no certificate-signing use of `JWT_SECRET_KEY` and no
literal default certificate secret.

The startup requirement remains absent. Certificate tests cover create-path
missing/empty secret, but no direct update-path test verifies secret isolation.

### ST21B-NEW-002 — BB subprocess timeout

**Status: PARTIALLY REMEDIATED**

Application prover and verifier calls use `timeout=300`, and verifier catches
`TimeoutExpired` as invalid proof. Temporary verifier proof cleanup is in a
`finally` block.

The timeout is duplicated and hard-coded, not centrally configured. The audit
script `scripts/run_c32_negative_tests.py` still has BB subprocess calls without
timeouts. No real timeout was executed; the verifier timeout tests mock the
subprocess.

### ST21B-NEW-003 — Archive integrity

**Status: PARTIALLY REMEDIATED**

`_archive_proofs()` now uses a temporary directory, writes proof hashes, writes
a manifest, checks 256 entries, renames the directory, and creates a zip.

The current repository has no resulting archive. The manifest does not clearly
include a profile identity, Barretenberg version, archive completion marker,
ownership metadata, retention policy, or disk bound. It contains VK hashes and
proof hashes only when the runtime job actually supplies the artifacts.

### ST21C-NEW-001 — JWT secret used for certificate signing

**Status: REMEDIATED in current source**

Current repository search shows both repository signing paths use
`CERTIFICATE_SECRET_KEY`. The prior `JWT_SECRET_KEY` update-path defect is gone.

The direct update-path test requested by the plan is absent, so this is source
verified and only partially regression-test verified.

### ST21C-NEW-002 — Verifier debug prints

**Status: REMEDIATED**

The earlier verifier `print()` calls are absent from the current verifier.
Failures use `logger.error` or `logger.exception`. No dedicated stdout regression
test was found, but direct source search found no verifier print path.

### ST21C-NEW-003 — Unbounded persisted proof input

**Status: PARTIALLY REMEDIATED**

The verifier checks `len(seg.proof_artifact) > 5000` before base64 decode. This
addresses the direct application verification path.

No equivalent bound exists at persistence/schema level, and audit-only BB
scripts remain unbounded. No test exercises a real oversized persisted artifact
through the application database.

### ST21C-NEW-004 — Non-atomic archive creation

**Status: PARTIALLY REMEDIATED**

Temporary directory assembly and directory rename reduce partial-directory
exposure. However, zip creation happens after rename and is followed by deleting
the directory. There is no atomic zip replacement, completion marker, durable
manifest index, or recovery state. A failure during compression can leave no
usable archive or an ambiguous intermediate state.

## 7. Cryptographic Trust Chain

The implemented chain is:

`stored base64 -> size check -> decode -> SHA-256 compare -> fixed public-input offsets -> profile hash lookup -> temporary proof -> BB subprocess -> topology -> certificate`.

The following are not independently demonstrated:

- real BB verification of any current persisted proof;
- correctness of the fixed public-input offsets for the actual proof format;
- complete 256-proof verification;
- production profile validation at startup;
- certificate creation from authoritative SQL Server records and real proofs.

## 8. Certificate Trust Boundary

Signing is now source-isolated to `CERTIFICATE_SECRET_KEY`. JWT signing uses
`JWT_SECRET_KEY` elsewhere. However, the application startup path does not
require the certificate secret, so a service may start and only fail later when
issuing a certificate.

The certificate tests use mocked persistence and do not prove SQL Server
transactional certificate issuance.

## 9. ProofSet Integrity

The verifier rejects count/index mismatches and checks several parent/commitment
fields. Database uniqueness was added in migration 005, but SQL Server execution
was not validated. Child `chunk_index` and `total_chunks` are still accepted
without comparison to the parent chunk.

## 10. Archive and Evidence Integrity

Code-level archive assembly exists, but no archive was produced. The manifest
would contain job IDs, roots, chunk/segment metadata, commitment fields, proof
hashes, and VK hashes. It does not provide all required profile/version,
ownership, retention, disk, and durable completion guarantees.

The absence of a current archive means ST21A-004 remains unresolved regardless
of the archive code's existence.

## 11. Authentication and Authorization

Certificate list and detail routes are now authenticated and owner-scoped in
source. The regression test uses mocked query chains and does not distinguish a
real User A from User B row.

The frontend is not treated as an authorization control.

## 12. Resource Exhaustion

The process-local lock prevents simultaneous proving within one Python process.
It does not control multiple service workers, multiple containers, repeated
serial jobs, database growth, archive growth, or verification subprocess volume.

The 300-second timeout limits individual application subprocess duration but is
not a complete resource-control strategy.

## 13. Database Integrity

SQL Server remains the declared target. Migrations use SQL Server types and
functions, and Docker defines SQL Server 2022. SQL Server execution was not
independently validated.

Migration 005 does not add the ORM's `proof_archive_hash` column. This is a
direct implementation/schema mismatch affecting the new archive completion
path.

## 14. Test Integrity

The independent narrow run passed 23 tests with 20 warnings. The evidence is
limited:

- verifier BB tests mock `subprocess.run`, base64 decoding, file I/O, profile,
  and hashing;
- certificate tests use `MagicMock` sessions and `MockVerifier`;
- certificate-list IDOR test mocks the complete query chain;
- crypto-profile success test mocks files, existence, and hashes;
- startup profile test patches a function not invoked by the current app factory;
- `test_certificate_signing.py` still contains an unconditional `pass` in a
  startup-validation test;
- no complete 256-proof test exists;
- no SQL Server test exists;
- no archive artifact test creates and independently inspects a real archive.

## 15. Real Runtime Evidence

FULL 256-PROOF REAL CRYPTOGRAPHIC VALIDATION NOT EXECUTED.

Nargo, Barretenberg, and Docker were unavailable on this host. The repository
contains no command output, complete proof archive, or durable manifest proving
the claimed 256-proof run.

The frontend typecheck passed. Full frontend lint/build and the full backend
suite were not independently executed.

## 16. New Findings

### ST21D-NEW-001 — Crypto profile is not validated during application startup

**Severity: HIGH**

`create_app` validates database configuration but never calls
`get_crypto_profile()`. Invalid/missing production crypto artifacts therefore do
not fail startup unless a later prover/verifier path is instantiated.

Affected file: [backend/shared/app_factory.py](../../../backend/shared/app_factory.py#L40-L56).

### ST21D-NEW-002 — ORM/archive hash has no SQL Server migration

**Severity: HIGH**

`ProofJob.proof_archive_hash` and `ZKPRepository.update_job_status` support the
new field, and `ProverService.generate_all_chunk_proofs` passes it, but migration
005 does not add the column. A successful archive path can fail against the
declared database schema.

Affected files:

- [backend/zkp_service/app/models/zkp_models.py](../../../backend/zkp_service/app/models/zkp_models.py#L60-L76)
- [backend/zkp_service/app/repositories/zkp_repository.py](../../../backend/zkp_service/app/repositories/zkp_repository.py#L47-L91)
- [backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L125-L130)
- [backend/alembic/versions/005_add_topology_constraints.py](../../../backend/alembic/versions/005_add_topology_constraints.py#L15-L30)

### ST21D-NEW-003 — Archive manifest omits required profile/runtime identity

**Severity: MEDIUM**

The manifest records Nargo version but not an explicit profile identity or
Barretenberg version. It copies `profile.json`, but does not hash or bind that
file in the manifest. The archive therefore cannot independently prove which
runtime profile and BB version produced each proof.

Affected function: `_archive_proofs` in
[backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L150-L249).

### ST21D-NEW-004 — Process-local prover lock is not deployment-wide

**Severity: MEDIUM**

`threading.Lock()` limits one Python process only. Multiple Uvicorn workers,
containers, or service replicas can each run one expensive proof job. The plan's
bounded-control claim is therefore narrower than the deployment boundary.

Affected file: [backend/zkp_service/app/services/prover_service.py](../../../backend/zkp_service/app/services/prover_service.py#L20-L31).

## 17. Evidence Gaps

- No complete 256-proof archive.
- No real 256-proof Nargo/BB execution output.
- No real certificate trust-chain execution.
- No SQL Server execution.
- No profile startup validation execution.
- No certificate update-path secret test.
- No real owner-isolation test.
- No archive completeness/atomicity test over actual proof files.
- No deployment-wide concurrency test.
- No full backend/frontend validation run independently reproduced.

## 18. Regression Risks

- Archive completion may fail because `proof_archive_hash` is not migrated.
- Archive compression is outside the atomic directory rename and has no durable
  completion state.
- The fixed proof public-input offsets may not correspond to the actual BB proof
  format.
- The profile is validated lazily rather than at startup.
- Mocked tests can pass while real BB, SQL Server, ownership, and archive paths
  fail.

## 19. Final Security Disposition

1. **Is ST21D independently validated?** No. Code-level changes are verified, but the complete acceptance criteria are not.
2. **Are all 19 findings remediated?** No. Several remain partial or unresolved.
3. **Is certificate signing exclusively isolated to `CERTIFICATE_SECRET_KEY`?** Yes in the current repository signing paths.
4. **Can `JWT_SECRET_KEY` alone affect certificate signing?** Not in the current repository signing paths; this is not independently tested on the update path.
5. **Does production startup fail without `CERTIFICATE_SECRET_KEY`?** No.
6. **Does production startup validate the production CryptoProfile?** No.
7. **Can production silently fall back to another profile?** The profile helper can fall back when DEBUG is true; application startup does not invoke it.
8. **Is persisted `proof_artifact_hash` verified?** Yes in the verifier source before BB execution; real runtime verification is not demonstrated.
9. **Is proof size bounded before decoding?** Yes for the application verifier at 5000 base64 characters; not universally across all tools/paths.
10. **Are all production BB calls timeout bounded?** Application prover/verifier calls are; audit scripts are not.
11. **Are exactly 32 chunks required?** Yes in verifier source, with index checks.
12. **Are exactly 8 segments required per chunk?** Yes in verifier source, with index checks.
13. **Are cross-job/cross-chunk proofs rejected?** Partially. Parent queries and some checks exist, but child metadata consistency is incomplete.
14. **Does the DB enforce topology uniqueness?** Partially through migration 005; SQL Server execution is not independently validated and status/bounds coverage is incomplete.
15. **Does an actual 256-proof archive exist?** No.
16. **Does the archive contain a manifest?** The code would create one; no actual archive exists.
17. **Is archive finalization atomic?** Directory assembly/rename is atomic in concept; zip finalization and database hash persistence are not atomic.
18. **Can partial evidence be mistaken for complete evidence?** Yes; no durable completion marker or repository archive exists.
19. **Is certificate listing owner-scoped?** Yes in source; only mocked regression evidence exists.
20. **Is certificate detail owner-scoped where required?** Yes in source; only mocked regression evidence exists.
21. **Is the frontend proof route correct?** Yes: frontend and backend both use `/api/v1/zkp/jobs/{id}`.
22. **Is proof-generation concurrency bounded?** Per Python process only.
23. **Is repeated expensive proving controlled?** No rate, quota, queue, or per-user control exists.
24. **Is SQL Server integrity independently validated?** No. SQL SERVER EXECUTION NOT INDEPENDENTLY VALIDATED.
25. **Is PURL identity consistent?** For PURL-bearing components, mostly yes; missing-PURL fallback remains separate.
26. **Is SMT cache behavior still correct?** Mutation behavior is test-verified; concurrency behavior is not.
27. **Are verifier debug leaks removed?** The verifier `print()` calls are removed.
28. **Which tests are mocked?** BB timeout/nonzero/exception tests, verifier success paths, certificate persistence, profile validation, and certificate listing.
29. **Which cryptographic tests are real?** None independently executed in this audit; vector/unit tests are not real BB proof validation.
30. **Was a real 256-proof execution performed?** No.
31. **Was a real certificate trust-chain execution performed?** No.
32. **What evidence is reproducible from the repository?** Source checks, profile hash comparisons, unit tests, and frontend typecheck.
33. **What remains unproven?** Complete proof generation, complete proof verification, certificate trust-chain execution, archive completeness, and SQL Server behavior.
34. **What remains vulnerable?** Startup crypto validation, resource admission, archive durability/schema integration, topology child metadata, and missing-PURL identity ambiguity.
35. **Is the repository ready for the next project stage?** No. Release freeze and architectural progression should remain blocked.
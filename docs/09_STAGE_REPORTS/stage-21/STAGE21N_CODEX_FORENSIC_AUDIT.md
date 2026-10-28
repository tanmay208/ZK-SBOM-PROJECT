# Stage 21N — Independent Security / Forensic Audit

**Auditor:** Codex  
**Mode:** Strict read-only forensic audit  
**Project:** Zero-Knowledge SBOM Vulnerability Verification Platform  
**Audit date:** 2026-10-03  
**Audit result:** **BLOCKED**  
**Stage 22:** **NOT AUTHORIZED**

## 1. Executive Summary

This review independently inspected the current checkout’s source, Compose/deployment configuration, crypto profile, migrations, local artifact bundle, selected tests as source (not executed), and Git status. The separate Copilot Stage 21N report was explicitly excluded.

Two unresolved HIGH findings block Stage 22:

1. `docker-compose.yml` supplies known default JWT and certificate signing secrets. The app checks only for presence, so Compose defaults defeat the apparent fail-closed startup requirement and permit predictable authentication tokens and certificate signatures.
2. Verification idempotency uses a global fingerprint without owner scoping. A second authenticated account submitting the same proof job and roots gets the existing verification record; the endpoint can then return its signed certificate without checking ownership. This is a backend IDOR/cross-tenant disclosure.

The archive for authoritative Stage 21L job `340235b8-71d6-4d6b-84de-284e72a7fb18` exists. Its SHA-256 matches the supplied value and its ZIP has 256 proof files and a 256-segment manifest. This verifies file identity and stated topology only. The manifest reports cryptographic status `pending`; archive bytes are not checked against the DB `proof_archive_hash` during verification, and no DB connection was used. Stage 21L was not rerun.

The source provides meaningful binding of requested public inputs to per-segment public inputs and authoritative records. I did not independently establish the production runtime, database state, certificate issuance, or Stage 21L proof verification claim. No tests or mutating validation were run.

## 2. Scope

Audited the current working tree and local files for all 28 requested areas, with focused attention to certificate secret defaults, authentication/authorization/ownership, public-input and artifact binding, proof topology/archive, API-001, ZK-001/ZK-002, production crypto profile/VK enforcement, and SQL Server residue. The Copilot audit file was not opened, searched, or used. Stage 21L was not rerun. No database writes, migrations, proof generation, dependency operations, remediation, or source/configuration changes were performed.

## 3. Methodology

Read-only source/configuration inspection; `rg` searches; Git status and diff-name inspection; read-only filesystem metadata inspection; Python `zipfile` and SHA-256 inspection of the existing archive. Findings are based on directly inspected implementation or artifacts. Stage 21L/21M report documents were treated as claims, not proof of runtime behavior. The `.env` file was not read or disclosed; a name-only search confirmed secret variable names exist, with values redacted. No tests were run.

Classification terms: `[VERIFIED]` means directly supported by inspected source/artifact; `[PARTIALLY VERIFIED]` means limited evidence exists but an essential runtime or end-to-end property is unestablished; `[NOT VERIFIED]` means evidence is unavailable; `[CONTRADICTED]` means inspected evidence conflicts with the security claim.

## 4. Evidence Available

- Directly inspected backend authentication, verification, proving, repositories, schemas/models, crypto configuration/profile, PURL/canonicalization and SMT implementation; Compose, Docker/nginx, example configuration, and migrations.
- Existing archive `archives/proofs/340235b8-71d6-4d6b-84de-284e72a7fb18.zip`: read-only digest `362be7463b3af52fb499a9bf95d64a69d1dac44e64d48f52cb197a5b48bb7e3d`; 261 ZIP entries, including 256 `.proof` files; manifest contains 256 segments and expected job ID. Manifest status is `complete`, while `cryptographic_verification_status` is `pending`.
- Existing crypto target files are present for init/mid/final artifacts and VKs. Their presence alone does not establish trusted runtime use.
- Local `.env` exists (525 bytes); values were not inspected. Its presence does not prove deployed secret quality.
- A local `.venv`, test sources, and audit documents exist. Tests were not executed; prior reports were not accepted as evidence.
- No live PostgreSQL/Supabase connection or database rows were queried. Runtime evidence is **NOT INDEPENDENTLY VERIFIED**.

## 5. Repository Integrity

**[PARTIALLY VERIFIED]** Git reports a large working tree with many untracked project files and tracked-file line-ending warnings. The audit report did not exist before this review and is the only file intentionally created. Baseline repository integrity and provenance of the untracked artifacts cannot be established from this checkout. No Git write command was issued.

## 6. Authentication

**[PARTIALLY VERIFIED]** `backend/shared/auth.py` uses bcrypt password hashing, HS256 JWTs, requires `exp` and `sub`, then resolves the user from the database. The production Compose environment sets `JWT_SECRET_KEY=${JWT_SECRET_KEY:-default_insecure_jwt_secret}`. `backend/shared/app_factory.py` rejects only an absent variable; because Compose always provides a predictable value when unset, production startup can use a known signing key. See finding **ST21N-001**.

## 7. Authorization / RBAC

**[PARTIALLY VERIFIED]** Server-side `require_roles` exists. Proof generation requires vendor/admin. Registration assigns the base `auditor` role rather than accepting a caller-selected role. Endpoint-by-endpoint live RBAC behavior and deployed role data are **NOT INDEPENDENTLY VERIFIED**. Authentication secret default also undermines token authenticity (ST21N-001).

## 8. Ownership / IDOR

**[CONTRADICTED]** Proof-job creation validates SBOM owner in `ZKPRepository.create_job`; job lookup checks `job.user_id`; list endpoints filter by current user; certificate list/detail queries have owner checks. However, verification idempotency lookup in `VerificationRepository.get_request_by_fingerprint` filters only roots, policy and proof job, not `user_id`. `VerificationService.process_verification` returns any matching existing record. The verify route then fetches its certificate without passing/checking the current owner. A different authenticated user can obtain another tenant’s result and certificate token by replaying identical values. Finding **ST21N-002 (HIGH)** blocks Stage 22.

## 9. ZKP Public-Input Binding

**[PARTIALLY VERIFIED]** Verification service first checks authoritative SBOM root (committed/completed), vulnerability root (approved snapshot), and active policy hash. The verifier compares extracted per-segment public inputs against requested SBOM root, vulnerability DB root, policy hash, chunk commitment and intermediate commitments, then calls `bb verify`. The source’s parsing takes leading 32-byte words from serialized proof bytes; local artifact presence and previous runtime claims do not independently establish this parser’s relation to actual Barretenberg public-input serialization. DB ownership/association among the three authoritative records is not bound together by `validate_authoritative_records`. Requested roots are not sufficient proof of one coherent tenant-owned tuple. Overall public-input-to-certificate chain: **[PARTIALLY VERIFIED]**.

## 10. Crypto Profile / VK

**[PARTIALLY VERIFIED]** Production profile declares `segment_init_32`, `segment_mid_32`, and `segment_final_32`, expected circuit JSON hashes and VK hashes. `CryptoProfile` checks artifacts at load/startup and fails for missing/mismatched files; app startup calls it. File presence was observed. Hashes were not independently recomputed in this audit, nor was the full app runtime started. Additionally, verifier selects fixed `segment_mid_32` and `get_artifact_paths` enforces the configured canonical mid VK; multiple prover circuit directories are present, but a complete production proving/verifying runtime binding was not re-executed. Production fail-closed implementation is source-supported; runtime enforcement is **NOT INDEPENDENTLY VERIFIED**.

## 11. Cryptographic Semantics

- **SBOM canonicalization — [PARTIALLY VERIFIED]:** Source sorts deterministic canonical JSON and normalizes PURLs. PURL-less components receive synthesized generic PURLs. Cross-format adversarial and authoritative runtime semantics were not run.
- **PURL/component identity / ZK-002 — [PARTIALLY VERIFIED]:** SBOM and vulnerability ingestion both canonicalize PURL and create canonical component JSON, but vulnerability processing derives component name/version from PURL while SBOM processing can use the SBOM component name. The implementation itself documents hashes can diverge if names differ. Equality of effective identity for all supported sources is not established. This leaves ZK-002 partially remediated.
- **SMT non-vulnerable leaf / ZK-001 — [PARTIALLY VERIFIED]:** Prover source constructs leaf as `Poseidon([hash, score])` only when presence is 1 and otherwise uses zero. Existing SMT is a sparse tree with empty hashes; circuit semantics must agree exactly. The relevant end-to-end negative proof was not run, so non-vulnerable absence semantics are not independently established.
- **CVSS — [PARTIALLY VERIFIED]:** Vulnerability ingestion scales float score to integer with `round(score * 10)` and aggregates max. This is source evidence, not independent proof that circuit thresholds and ingestion encoding are identical.
- **Merkle/SMT semantics — [PARTIALLY VERIFIED]:** Source implementations exist, but no fresh vector or proof validation was executed.

## 12. ProofSet Integrity

**[PARTIALLY VERIFIED]** Verifier checks exactly 32 chunks with indices 0–31, 8 segments per chunk with indices 0–7, status, chunk span/count, component commitment consistency, proof byte SHA-256 against stored segment hash, proof structure, Barretenberg verification, and adjacent hash linkage. Migrations/model constraints add unique bounded chunk/segment indices. No DB data was queried, and these constraints do not guarantee exactly 32/8 children or all denormalized fields/FKs agree. The inspected local archive topology is consistent with 32×8. Cryptographic verification of this exact persisted ProofSet was not rerun.

## 13. Proof Archive Integrity

**[PARTIALLY VERIFIED]** Existing archive SHA-256 exactly matches the supplied Stage 21L hash. ZIP contains 256 proof entries and a manifest for the expected job. Generation writes a manifest and creates a zip through temp paths before rename, with a 50 MiB size/non-empty check. Limitations: the manifest leaves cryptographic status `pending`; archive validation checks only existence, size, non-emptiness; no archive hash comparison is performed by the verifier; the manifest is not independently verified against DB proof bytes/VK contents; final zip and DB hash update are separate operations; fixed temporary/final names and cleanup can affect concurrent/retry behavior. No extraction/path-traversal consumer was found in the audited runtime path. Current archive evidence confirms identity/topology, not complete archive trust or atomic DB linkage.

## 14. Certificate Security

**[CONTRADICTED]** Repository signing uses `CERTIFICATE_SECRET_KEY` and creates HS256 JWT certificates only for exact result `verified`; certificate has expiry and binds public roots/policy. Compose defaults the certificate key to `default_insecure_cert_secret`, making signatures predictable in deployments without explicit env overrides. App presence checks do not reject that known value. Finding **ST21N-001 (HIGH)**. Certificate verification/public validation endpoint behavior was not established from the inspected route set; possession/verification semantics and live signing are **NOT INDEPENDENTLY VERIFIED**. Finding ST21N-002 additionally exposes a previously issued certificate cross-tenant.

## 15. Database Integrity

**[PARTIALLY VERIFIED]** PostgreSQL-oriented SQLAlchemy models and Alembic revisions define schemas, foreign keys, uniqueness/check constraints and archive hash field. No live database schema, migration head, constraints, RLS, Supabase policies or Stage 21M rows were inspected. Proof topology enforces uniqueness and bounds, not completeness. Stage 21M persistence claims are **NOT INDEPENDENTLY VERIFIED**.

## 16. API Security

**[PARTIALLY VERIFIED]** Verification request schema forbids extra fields, bounds public input lengths, and endpoints require authenticated users. JSON body is parsed directly and multipart is parsed through `request.form`; a general request-size middleware is present. The idempotency IDOR is confirmed (ST21N-002). The `proof_artifact` request field is not used by the verifier (proofs are loaded from persisted proof job). No live API validation, rate-limiting, or error-response exercise was performed. API-001’s retry behavior is source-supported: `record_mismatch` and `unavailable` are re-evaluated, so these states are not intentionally permanent cache hits. Concurrent races and DB uniqueness are not established.

## 17. Resource / DoS

**[PARTIALLY VERIFIED]** Global request-size middleware limits request bodies to 10 MiB, proof size is structurally bounded, and subprocess calls have profile-driven timeout. Proving is synchronous in the API request; its concurrency lock/quota is process-local and allows one active job per user per process, with no verified global rate limit, worker queue, disk quota, or deployment-wide enforcement. Authenticated resource exhaustion remains plausible. Runtime load behavior is **NOT INDEPENDENTLY VERIFIED**.

## 18. Frontend Security

**[PARTIALLY VERIFIED]** Frontend files exist and backend source contains authenticated owner checks for job/certificate reads. Frontend-only guards are not relied upon. No frontend build, browser inspection, token-storage review, or live integration test was run. Cross-tenant verification flaw is backend-side and cannot be cured by frontend controls.

## 19. Docker / Deployment

**[CONTRADICTED]** Compose uses PostgreSQL as the runtime default, exposes nginx gateway port 8000, mounts proof artifacts read-only, and passes predictable defaults for JWT and certificate secrets to every service. This is a material deployment security defect (ST21N-001). Dockerfiles and the actual production deployment/secret injection path were not executed. Deployment-grade isolation and startup behavior are **NOT INDEPENDENTLY VERIFIED**.

## 20. Dependency / Supply Chain

**[NOT VERIFIED]** Requirements files and local virtual environment exist. No lockfile/SBOM/dependency audit, clean installation, image provenance or vulnerability scan was performed. No package installation or upgrade occurred.

## 21. Test Integrity

**[PARTIALLY VERIFIED]** Test source exists, including tests for certificate signing, verification and tenant isolation. No tests were executed under this strict read-only audit. Prior report test counts are not independent evidence. Current tests’ coverage of cross-user identical-fingerprint replay and production secret defaults is not established.

## 22. Historical Finding Regression

Statuses below reflect this audit’s source/artifact review and independent evidence limits, not prior report conclusions.

| Historical finding | Current status | Independent basis |
|---|---|---|
| ST21A-001 | PARTIALLY REMEDIATED | SMT lock/cache code exists; no concurrency runtime proof. |
| ST21A-002 | PARTIALLY REMEDIATED | Hash-checked profile source and files exist; production runtime not independently run. |
| ST21A-003 | PARTIALLY REMEDIATED | Persisted bytes are hashed/structurally checked and BB invoked; serialization binding/runtime not independently established. |
| ST21A-004 | REMEDIATED (topology evidence only) | Existing 256-file archive/hash verified; cryptographic archive status remains pending. |
| ST21A-005 | PARTIALLY REMEDIATED | PURL normalization exists; divergent SBOM name vs PURL-derived vulnerability identity remains possible. |
| ST21A-006 | REGRESSED | Identical verification fingerprint can return another user’s request/certificate (ST21N-002). |
| ST21A-007 | PARTIALLY REMEDIATED | Source and archive check expected topology; DB completeness not enforced or queried. |
| ST21A-008 | REGRESSED | Compose defaults defeat missing-secret fail-closed checks (ST21N-001). |
| ST21A-009 | PARTIALLY REMEDIATED | Certificate gated on verified result in source; runtime chain unavailable and secret default unsafe. |
| ST21A-010 | NOT VERIFIABLE | No independent frontend route/build/live review. |
| ST21A-011 | PARTIALLY REMEDIATED | Process-local control exists; no deployment-wide controls established. |
| ST21A-012 | PARTIALLY REMEDIATED | PostgreSQL migration source present; deployed DB/migration state unavailable. |
| ST21B-NEW-001 | REGRESSED | Signing code uses separated certificate key, but Compose supplies a known default. |
| ST21B-NEW-002 | PARTIALLY REMEDIATED | Runtime BB timeout exists; no execution or global resource control evidence. |
| ST21B-NEW-003 | PARTIALLY REMEDIATED | Archive exists and hashes correctly; semantic validation/atomic DB linkage incomplete. |
| ST21C-NEW-001 | PARTIALLY REMEDIATED | Both signing paths use certificate secret in source; deployment secret is predictable by default. |
| ST21C-NEW-002 | NOT VERIFIABLE | No production logs/runtime checked. |
| ST21C-NEW-003 | PARTIALLY REMEDIATED | Proof size/structure checks exist; strict decoding and runtime path not established. |
| ST21C-NEW-004 | PARTIALLY REMEDIATED | Temp/rename zip generation exists; DB/archive atomicity and crash recovery not established. |
| ST21D-NEW-001 | PARTIALLY REMEDIATED | App startup calls profile validation; actual startup/profile enforcement not executed. |
| ST21D-NEW-002 | PARTIALLY REMEDIATED | PostgreSQL migration adds archive hash; no SQL Server migration path required by runtime was established, but schema state not queried. |
| ST21D-NEW-003 | PARTIALLY REMEDIATED | Manifest records profile identity, tool versions and hashes by segment; cryptographic status remains pending and no independent manifest-to-artifact verification. |
| ST21D-NEW-004 | PARTIALLY REMEDIATED | Process-local lock/quota still does not establish deployment-wide exclusion. |
| ST21F-NEW-001 | PARTIALLY REMEDIATED | Guarded quota cleanup source exists; exception/concurrency tests not run. |
| ST21F-NEW-002 | NOT VERIFIABLE | Dependency declaration inspected only; no clean environment or full suite run. |
| ST21G-NEW-001 | PARTIALLY REMEDIATED | Proof size/hash/structure checks and archive size check exist; base64/archive semantic validation remain incomplete. |

## 23. Findings Register

### ST21N-001 — Predictable production JWT and certificate signing secrets

- **Severity:** HIGH
- **Path / function:** `docker-compose.yml`, environment entries in services `sbom-service`, `vulnerability-service`, `policy-service`, `zkp-service`, and `verification-service`; `backend/shared/app_factory.py:create_app` startup checks.
- **Evidence:** Compose defaults JWT to `default_insecure_jwt_secret` and certificate secret to `default_insecure_cert_secret`. Startup rejects missing env values only; Compose guarantees these values by default.
- **Impact:** An attacker who can reach the app may mint accepted JWTs if using the known default and can forge apparently valid HS256 certificates. This compromises authentication and certificate integrity.
- **Exploitability:** High when deployment omits explicit overrides; Compose is the repository’s deployment configuration and silently starts with known values subject to other dependencies.
- **Current status:** OPEN / CONTRADICTED.
- **Recommended remediation:** Remove secret defaults; require high-entropy externally managed secrets and reject known placeholder values at startup. Rotate any secrets used in an exposed deployment and invalidate affected tokens/certificates.
- **Blocks Stage 22:** YES.

### ST21N-002 — Cross-tenant verification idempotency and certificate disclosure

- **Severity:** HIGH
- **Path / function / endpoint:** `backend/verification_service/app/repositories/verification_repository.py:VerificationRepository.get_request_by_fingerprint`; `backend/verification_service/app/services/verification_service.py:process_verification`; `POST /api/v1/verification/verify` in `backend/verification_service/app/api/routes/verification_routes.py`.
- **Evidence:** Fingerprint lookup matches roots, policy hash and proof job ID but omits user ID. Service returns the matching record for all results except retryable states. Route obtains certificate by request ID without supplying/checking current user.
- **Impact:** Any authenticated account that learns/reuses another tenant’s proof job and public roots can receive the other account’s verification response and certificate data. This defeats backend tenant isolation and discloses a reusable signed credential.
- **Exploitability:** Moderate to high; requires an authenticated caller and knowledge of the proof UUID/public commitments, which can be exposed/shared by normal verification workflows.
- **Current status:** OPEN / CONTRADICTED.
- **Recommended remediation:** Scope fingerprint lookup and uniqueness by owner or make the operation intentionally public without returning owner-bound credentials; enforce ownership before returning records/certificates on every path. Add persisted cross-user replay regression coverage.
- **Blocks Stage 22:** YES.

### ST21N-003 — Archive validation does not establish archived proof integrity

- **Severity:** MEDIUM
- **Path / function:** `backend/shared/crypto/config.py:CryptoProfile.validate_proof_archive`; `backend/zkp_service/app/services/prover_service.py:ProverService._archive_proofs`; `backend/verification_service/app/core/verifier.py:NoirVerifier.verify`.
- **Evidence:** Archive validator checks path existence, nonzero size and 50 MiB bound only. The verifier does not load archive or compare `ProofJob.proof_archive_hash`. Existing manifest says cryptographic status `pending`. File SHA-256/topology match the expected archive, but no archive-to-persisted-proof comparison was performed.
- **Impact:** Archive can be corrupted or replaced without detection by the verification path; its claimed value as an independent forensic/reproducibility record is incomplete. Live verification still separately checks DB segment bytes and BB proofs.
- **Exploitability:** Requires archive storage modification or operational mishandling; not shown to permit bypass of the live verifier.
- **Current status:** OPEN / PARTIALLY VERIFIED.
- **Recommended remediation:** Validate archive digest against the persisted immutable expected hash and validate manifest, exact membership, proof hashes, circuit/VK/profile identities and linkage before treating the archive as authoritative; make archive and DB completion recoverable as one state transition.
- **Blocks Stage 22:** NO by itself; contributes to unresolved proof evidence.

### ST21N-004 — Synchronous proof generation permits resource exhaustion

- **Severity:** MEDIUM
- **Path / endpoint:** `backend/zkp_service/app/api/routes/zkp_routes.py:generate_proof`; `backend/zkp_service/app/services/prover_service.py:ProverService.process_job`.
- **Evidence:** Route synchronously runs proof generation; active-job tracking/quota is process-local and allows at most one active job per user per process. BB calls may each run up to configured timeout; no deployment-wide admission control/rate limit/disk quota was verified.
- **Impact:** Authenticated users can consume request workers, CPU, memory and disk for extended intervals, reducing service availability.
- **Exploitability:** Authenticated vendor/admin required; repeated or distributed requests can evade process-local quotas.
- **Current status:** OPEN / PARTIALLY VERIFIED.
- **Recommended remediation:** Move work to bounded workers, add global/user quotas and rate limits, bound storage and request execution, and monitor queue pressure.
- **Blocks Stage 22:** NO by itself.

## 24. Required Remediation

1. Remove Compose fallback JWT and certificate secrets and require validated externally managed high-entropy values before deployment.
2. Make verification idempotency and certificate retrieval owner-safe, including the replay path; test cross-user identical-fingerprint requests against a persistent database.
3. Establish independent verification of the exact persisted Stage 21L ProofSet and complete proof archive/DB linkage without regenerating the proof job.
4. Close or formally accept remaining PURL identity, SMT absent-leaf, and deployment-wide resource-control gaps before production authorization.

## 25. Final Security Gate

**BLOCKED.** Two unresolved HIGH issues affect authentication/secrets and ownership/certificate confidentiality. No downgrade is applied to obtain a pass.

## 26. Stage 22 Authorization

**NOT AUTHORIZED.** Stage 22 must wait until ST21N-001 and ST21N-002 are remediated and independently reviewed. Other partial/not-verified evidence should be closed according to the project’s Stage 22 acceptance criteria.

## 27. Evidence Limitations

- No live PostgreSQL/Supabase DB access; Stage 21M persistence rows, policies, constraints and certificate rows are **NOT INDEPENDENTLY VERIFIED**.
- No running service, production environment, secret manager, live API, browser, Nargo, Barretenberg or WSL execution was used. Stage 21L runtime validation is not repeated.
- Existing archive digest and topology were inspected read-only, but persisted DB artifact hashes, segment proof contents against the archive, and actual proof verification were not compared/re-executed.
- No tests were executed. Prior Stage 21L/21M reports and historical audit reports were not treated as authoritative evidence. Copilot Stage 21N report was not inspected.
- Dependency vulnerabilities, image provenance, deployment secrets actually in use, and production logs remain **NOT INDEPENDENTLY VERIFIED**.
- `CERTIFICATE_SECRET_KEY` and `JWT_SECRET_KEY` values in `.env` were not opened or reported.
- No database or repository state was changed by validation.

### Commands and read-only inspections executed

The audit used PowerShell read-only inspection commands including:

- `Get-Location`, `git status --short`, `git status --porcelain=v1 -uno`, `git diff --name-only`, `git ls-files --error-unmatch ...`
- `rg --files`, `rg -n` searches for authentication, ownership, crypto, archive, API, and SQL Server residue
- `Get-Content` on the implementation/configuration/migration files identified above and selected historical finding tables (excluding the Copilot report)
- `Get-ChildItem` for existing artifact metadata and archive inventory
- `python -c "...zipfile...hashlib..."` to read ZIP metadata/manifest and compute SHA-256
- `rg` for `.env` variable names only; values were redacted and not inspected

**Tests executed:** None.  
**Stage 21L rerun:** No.  
**Repository modifications:** Only this requested report was created. No other repository file, database, configuration, proof, VK, artifact or dependency was modified.

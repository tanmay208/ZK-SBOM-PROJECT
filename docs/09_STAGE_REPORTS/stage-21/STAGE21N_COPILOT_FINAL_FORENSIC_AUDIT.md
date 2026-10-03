# Stage 21N Final Independent Forensic Acceptance Audit

**Auditor:** Copilot independent security audit  
**Date:** 2026-10-03  
**Disposition:** Read-only audit. The Stage21L workload was not rerun, proofs were not regenerated, and no source, test, migration, configuration, Docker, crypto, or historical artifact was modified.

## 1. Executive summary

The final security gate is **BLOCKED**. The remediation claims are not supported by a clean, reproducible acceptance boundary:

- `validate_config()` accepts a 32-space production JWT secret and certificate secret. Debug mode accepts arbitrary non-empty secrets.
- The checked-in gateway exposes authenticated APIs through plaintext HTTP (`127.0.0.1:8000:80` and nginx `listen 80`) with no TLS listener, redirect, HSTS, or enforced external terminator.
- Verification has meaningful owner checks at the route/service level, but the complete cross-tenant/public-sharing contract is not established and the verifier loads jobs by ID without an owner predicate.
- PostgreSQL-backed idempotency was not independently executed. The model and migration contain a uniqueness constraint, but concurrent convergence and duplicate certificate behavior remain unvalidated.
- Archive checks now cover ZIP size, traversal, count, archive hash, and persisted member hashes when available, but do not bind manifest identity, roots, profile, topology entries, or all metadata to the current `ProofJob`. Validation is conditional on a stored archive hash.
- Revoked certificates remain retrievable with the signed token; consumers must interpret `is_revoked` correctly, and no current-validity retrieval path is enforced.
- The default test collection does not produce the claimed `472/472`: it discovers 522 tests and then fails during collection because `backend/test_db.py` requires ambient `DB_USER`.
- The authoritative archive exists and independently hashes to `362be7463b3af52fb499a9bf95d64a69d1dac44e64d48f52cb197a5b48bb7e3d`. Its manifest has 256 segments and `cryptographic_verification_status: "pending"`. This is consistent metadata, not independent proof that 256 Barretenberg verifications occurred.

## 2. Scope and evidence rules

Inspected the requested Stage21N reports, historical Stage21C-G and Stage21L-M reports, current backend source, tests, Alembic migrations, Compose/nginx, crypto profile/archive, and git state. Safe commands included pytest collection, source inspection, archive listing/hash calculation, and historical comparison. The requested `docs/STAGE21N_REMEDIATION_REPORT.md` is absent; the remediation report claim therefore could not be reconciled.

Evidence classifications:

- **CLOSED:** current source plus executable evidence supports the complete property.
- **PARTIALLY CLOSED:** meaningful controls exist, but a material boundary or regression target remains.
- **OPEN:** a vulnerability or required control remains.
- **NOT INDEPENDENTLY VALIDATED:** required runtime, database, historical, or cryptographic evidence was unavailable.

Mocks, SQLite tests, a remediation report, or a SHA-256 archive digest are not treated as PostgreSQL, production authorization, or cryptographic runtime evidence.

## 3. Evidence inventory

| Evidence | Observation |
|---|---|
| Current git | HEAD `733fd63`; worktree has broad add/rename state, so a clean remediation-only diff is unavailable |
| Python | Project venv, Python 3.12.10 |
| Tests | `pytest --collect-only -q`: 522 collected, then collection error in `backend/test_db.py` (`KeyError: DB_USER`) |
| Historical tests | Stage21G report claims 513 passed; current claimed 472 is not reproduced |
| Archive | `archives/proofs/340235b8-71d6-4d6b-84de-284e72a7fb18.zip` |
| Archive digest | Matches authoritative SHA-256 `362be7463b3af52fb499a9bf95d64a69d1dac44e64d48f52cb197a5b48bb7e3d` |
| Archive contents | 261 members, 256 `.proof` members, `manifest.json`, 256 manifest segments |
| Archive status | Manifest says `cryptographic_verification_status: pending` |
| Database runtime | No independent PostgreSQL migration/concurrency execution performed |
| Stage21L | Explicitly not rerun |
| Crypto tools | No new Nargo/Barretenberg execution performed |

## 4. A-N finding matrix

| Area | Classification | Independent basis |
|---|---|---|
| **A. Secret security** | **OPEN** | `backend/shared/config.py` checks length and placeholders but not trim/entropy. 32 spaces pass production validation; debug mode only requires presence. Secrets are separate and not logged, but fail-closed quality is insufficient. |
| **B. Cross-tenant ProofJob verification** | **PARTIALLY CLOSED** | Verification route passes `current_user.id`, fingerprint lookup is user-scoped, certificate validation checks request ownership, and proof-job routes return 404 for unauthorized jobs. The verifier and repository load by ID without ownership predicates; public-sharing policy is not persisted or documented. Two-user PostgreSQL integration evidence is absent. |
| **C. Idempotency race** | **PARTIALLY CLOSED** | Model and migration `008` define `uq_verification_request_idempotency`; certificate-per-request uniqueness exists. No target PostgreSQL execution proves migration application, concurrent convergence, rollback/retry behavior, or duplicate-certificate prevention. |
| **D. Archive integrity** | **PARTIALLY CLOSED** | Archive hash, size, ZIP validity, traversal rejection, count, manifest presence, and DB member hashes are checked. Manifest `job_id`, roots, policy, profile, segment records, and exact current job binding are not fully validated; checks are conditional on `proof_archive_hash`. |
| **E. Cryptographic status** | **PARTIALLY CLOSED** | Archive generation records `pending`, which is honest for the archived artifact. The verifier returns `verified` only after per-segment BB calls in source, but no new real BB execution was performed and the archive does not derive status from those results. |
| **F. Certificate lifecycle/revocation** | **OPEN** | Authorization and signed issuance exist; uniqueness and revocation columns/migration exist. Retrieval still returns `certificate_data` after revocation and no explicit current-validity verifier is enforced. |
| **G. Database schema** | **NOT INDEPENDENTLY VALIDATED** | `result` width migration and constraints are present in source. The actual PostgreSQL schema, applied revision, nullability, cascades, and new indexes were not independently queried. |
| **H. Resource exhaustion** | **PARTIALLY CLOSED** | Proof size/archive size and a subprocess timeout exist; Compose limits the prover container. Synchronous generation, process-local admission, no durable multi-worker/global quota, and no demonstrated disk/concurrency admission leave DoS risk. |
| **I. TLS/network boundary** | **OPEN** | Compose publishes `127.0.0.1:8000:80`; nginx only listens on port 80. No TLS, redirect, HSTS, or enforced external terminator is defined. |
| **J. Anti-enumeration** | **PARTIALLY CLOSED** | Unauthorized proof-job retrieval returns 404. Other lower-layer lookups and verification/public-sharing semantics are not uniformly proven indistinguishable. |
| **K. Strict hex validation** | **CLOSED (source/test boundary)** | Pydantic requires `^0x[a-fA-F0-9]{64}$` before verification. Whitespace, missing prefix, wrong length, and non-hex values are rejected; uppercase is accepted by policy. A production integration execution was not performed. |
| **L. Timestamp/metadata integrity** | **PARTIALLY CLOSED** | Event timestamps are generated in several persistence paths, but archive `creation_timestamp` is not validated against an event or authoritative record and uses naive UTC semantics. |
| **M. Authoritative re-evaluation** | **PARTIALLY CLOSED** | Existing `record_mismatch`/`unavailable` records can be re-evaluated and authoritative records are queried. No complete replay/stale-state integration test proves updated approved records cannot be poisoned or bypassed. |
| **N. Final acceptance/novel issues** | **OPEN** | High-severity secret and transport defects, archive gaps, revocation semantics, snapshot exposure, test-collection failure, and missing runtime evidence block acceptance. |

## 5. Test-suite forensic comparison

The claimed `472/472 passed` is not an independently reproducible result. Current collection found **522 tests before interruption**, then failed importing `backend/test_db.py` because it reads `DB_USER` at module import time. This is a collection failure, not a passing suite.

Historical Stage21G records **513 passed**. The current 522-vs-513 difference is unexplained by a clean manifest. The current checkout has a broad add/rename worktree and no reliable remediation-only baseline. No evidence in the available git state proves deliberate deletion, but the following acceptance risks remain:

- default collection depends on ambient database variables;
- the live PostgreSQL probe is not isolated from ordinary pytest collection;
- the 472 claim is lower than both the historical 513 execution and current 522 discovery;
- many verification/archive/certificate tests use mocks rather than real PostgreSQL, Nargo, Barretenberg, or a complete persisted ProofSet;
- no independent evidence demonstrates that security assertions were not weakened or tests replaced.

The test count therefore cannot be used as security-closure evidence.

## 6. New vulnerabilities and regression targets

1. **HIGH — whitespace-only signing secrets accepted:** `backend/shared/config.py`; directly executable source behavior, independently exercised by the security review.
2. **HIGH — plaintext authenticated API path:** `docker-compose.yml` and `docker/nginx.conf`; bearer tokens can traverse an unencrypted path.
3. **HIGH — cross-tenant snapshot metadata exposure:** `backend/vulnerability_service/app/api/routes/vulnerability_routes.py` lists snapshots without tenant/role scoping.
4. **HIGH — incomplete archive semantic binding:** `backend/shared/crypto/config.py` and `backend/verification_service/app/core/verifier.py`; manifest fields are not fully matched to the exact job and DB topology.
5. **MEDIUM — revoked certificate token remains retrievable:** revocation sets flags but retrieval does not reject or invalidate the returned token.
6. **MEDIUM — default test collection failure:** `backend/test_db.py` imports required environment variables at collection time.
7. **MEDIUM — synchronous proof generation and local admission:** `zkp_service/app/api/routes/zkp_routes.py` runs expensive generation in the request path; container limits do not establish distributed admission control.
8. **MEDIUM — proof-job existence leak:** unauthorized existing jobs and nonexistent jobs are not guaranteed to have identical behavior across all related endpoints and lower-layer callers.

## 7. PostgreSQL validation

Migration `008` adds the request idempotency uniqueness constraint and widens `verification_requests.result`; migration `009` adds revocation fields. SQLAlchemy models mirror these declarations. However, no independent connection was available to query `pg_constraint`, indexes, applied Alembic revision, or concurrent transactions. SQLite/mocked tests cannot establish PostgreSQL behavior. PostgreSQL closure is therefore **NOT INDEPENDENTLY VALIDATED**.

## 8. Docker and network validation

Only nginx is host-published, but it is published as host loopback port 8000 to container port 80. nginx contains only `listen 80` and proxy locations. No `listen 443 ssl`, certificate, redirect, HSTS, or trusted external ingress enforcement is present. Docker CPU/memory limits apply only to the prover service and do not bound request size, durable disk, duplicate requests, or multi-container admission. Deployment security is **OPEN**.

## 9. Crypto preservation

The archive digest and manifest were inspected without modification. The current profile contains the claimed 1024/32/8 topology, and the Stage21L report claims the production circuit/VK and Poseidon/Merkle/SMT construction. Nevertheless, the broad current git add/rename baseline does not permit a reliable historical diff proving that circuit semantics, parameters, C32 decomposition, segment structure, VKs, or Stage21L artifacts are unchanged. Crypto preservation is **NOT INDEPENDENTLY VALIDATED**. The Stage21L archive itself was not regenerated or altered.

## 10. Historical regression analysis

Stage21C-G repeatedly identified missing real runtime, archive, database, and certificate evidence. Stage21G reported 513 passing tests while still blocking Stage22. Stage21L/M reports claim the real workload and persistence/certificate completion, but this audit did not rerun or reproduce them. The current archive digest matches the authoritative hash, but the manifest explicitly remains `pending`; this prevents overclaiming cryptographic verification.

The absent `STAGE21N_REMEDIATION_REPORT.md`, unexplained test-count change, collection failure, and dirty broad baseline are material evidence gaps.

## 11. Evidence classification

| Claim | Classification |
|---|---|
| Secret checks exist | Source verified, but security property open |
| Owner checks exist on primary routes | Partially closed |
| PostgreSQL uniqueness is declared | Source verified |
| PostgreSQL uniqueness is applied and race-safe | Not independently validated |
| Archive SHA-256 matches historical value | Independently verified |
| Archive is semantically bound to current DB state | Partially closed |
| Archive cryptographic status is verified | Not supported; manifest says pending |
| 256 real BB verifications remain valid | Not independently validated in this audit |
| 472/472 regression suite passed | Contradicted by current collection result |
| Crypto artifacts are historically unchanged | Not independently validated |

## 12. Exact remaining blockers

- Reject trimmed-empty, whitespace-only, repeated, low-entropy, placeholder, and debug-relaxed production secrets.
- Enforce TLS or technically enforce a trusted external TLS boundary that cannot be bypassed.
- Establish and test a persisted public-sharing policy or enforce owner-only verification end-to-end.
- Bind every archive manifest field and member to the exact ProofJob, roots, policy, profile, chunk/segment topology, and persisted proof digest.
- Define current certificate validity and prevent revoked certificates from being accepted as current.
- Execute Alembic and concurrent idempotency tests against PostgreSQL.
- Isolate live database probes from default test collection and publish a reproducible inventory explaining 472, 513, and 522.
- Produce independent evidence for the existing Stage21L runtime claim without rerunning it during this audit.

## 13. Final gate

**BLOCKED**

Stage21N is not eligible for security-gate passage, Stage22 authorization, or a production-readiness declaration. The remediation report’s `VERIFIED` claims do not overcome the source-confirmed vulnerabilities, failed default test collection, incomplete archive binding, and unavailable PostgreSQL/cryptographic runtime evidence.

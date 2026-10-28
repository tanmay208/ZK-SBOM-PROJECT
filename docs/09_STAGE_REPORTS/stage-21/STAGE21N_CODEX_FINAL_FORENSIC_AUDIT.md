# Stage 21N Final Independent Forensic Acceptance Audit

**Auditor:** Codex independent security audit  
**Date:** 2026-10-03  
**Mode:** Read-only, except for this requested report  
**Final gate:** **BLOCKED**

## 1. Executive summary

The Stage21N remediation claims are not sufficient to pass the security gate. Source inspection confirms useful controls, including an owner check on the verification service path, a PostgreSQL idempotency constraint in the model and migration, strict-format root validation, persisted proof hashes, and explicit certificate revocation fields. However, material risks remain and multiple claims cannot be independently validated in this checkout.

The strongest current findings are:

- `validate_config()` accepts the required adversarial cases: 32 spaces for both production secrets, one-character secrets with `DEBUG=true`, and the same production value for JWT and certificate signing. The Compose file requires values to be supplied but does not cure the validator weaknesses.
- The gateway is published only on host loopback (`127.0.0.1:8000:80`); internal services have no host `ports`. This prevents direct remote access through the Compose-published port, but there is no TLS listener or enforced external TLS terminator. Plaintext is available to local callers and the deployment boundary is not fully established.
- A verification service owner check blocks a foreign ProofJob before NoirVerifier is called. Certificate/request retrieval also checks request ownership. The lower-level verifier remains owner-agnostic, there is no persisted public-share grant, and no executable two-user HTTP/PostgreSQL acceptance test was run.
- Idempotency is declared as a real database unique constraint and migration, with IntegrityError recovery in Python. PostgreSQL migration application, concurrency convergence, and rollback behavior were not tested against PostgreSQL.
- Archive validation has materially improved but does not bind all manifest fields to the exact authoritative ProofJob and DB state. The historical artifact manifest says `cryptographic_verification_status: pending`; its matching SHA-256 establishes file identity only.
- `pytest --collect-only -q` found 522 tests and then failed while importing root-level `test_db.py`, which attempted a PostgreSQL connection requiring SSL unsupported by the local server. This does not reproduce the claimed 472/472 result. Historical Stage21G reports 513 passed; the current broad untracked worktree prevents reliable deleted/renamed-test attribution.

The Stage21L workload was not rerun. No proofs, VKs, migrations, database rows, source files, tests, or configuration were changed. This requested report replaces the pre-existing report at the same output path.

## 2. Scope and method

Inspected the three requested Stage21N reports, relevant Stage21C–M documents, source configuration, Compose/nginx, verification routes/services/repositories, proof verifier and archive generation/validation, models, migrations, schemas, tests, crypto profile, existing archive, and Git state. Focused configuration probes and the required pytest collection were run. No database mutation or real cryptographic workload was run.

The requested `docs/STAGE21N_REMEDIATION_REPORT.md` does not exist. Therefore the claimed A–N “VERIFIED” remediation evidence and its changed-file/test manifest could not be reconciled. The two requested forensic source reports are present, but they contain prior findings and claims, not a substitute for the missing remediation record.

Classification meanings:

- **CLOSED** — source and executable evidence support the full property.
- **PARTIALLY CLOSED** — meaningful mitigation exists but a material risk or evidence gap remains.
- **OPEN** — the finding remains in current source/configuration.
- **NOT INDEPENDENTLY VALIDATED** — required runtime or historical evidence is unavailable.

Neither report assertions, test totals, archive hashes, nor mocked tests are treated as proof of live PostgreSQL, production deployment, or real proof verification.

## 3. Evidence inventory

| Evidence | Result |
|---|---|
| Checkout | `E:\Main Project`, HEAD `733fd63` (`day-01-architecture`); implementation/test files are broadly untracked in this checkout, limiting historical diff attribution |
| Requested remediation report | Missing: `docs/STAGE21N_REMEDIATION_REPORT.md` |
| Focused secret probes | Production 32-space values: ACCEPTED; DEBUG one-character values: ACCEPTED; identical JWT/certificate values: ACCEPTED |
| Compose exposure | Only gateway publishes a host port; mapping is `127.0.0.1:8000:80`; internal application services declare no published ports |
| Pytest collection | `522 tests collected`, then collection error in root `test_db.py` during PostgreSQL connection (`server does not support SSL, but SSL was required`) |
| Historical comparison | Stage21G report says `513 passed`; current claim `472/472` not reproduced; current discovered count is 522 before collection interruption |
| Archive | `archives/proofs/340235b8-71d6-4d6b-84de-284e72a7fb18.zip`; 261 ZIP members, 256 `.proof` entries, 256 manifest segment records |
| Archive digest | `362be7463b3af52fb499a9bf95d64a69d1dac44e64d48f52cb197a5b48bb7e3d`, matching the supplied authoritative digest |
| Archive verification status | Manifest value is `pending` |
| PostgreSQL | No independent schema query, migration application, or concurrent transaction test performed |
| Nargo/Barretenberg | Stage21L workload was not rerun and no new real proof verification was performed |

## 4. A–N finding matrix

| Finding | Classification | Independent basis |
|---|---|---|
| **A — Secret security** | **OPEN** | Executed `validate_config()` probes accepted 32-space production values, one-character values under DEBUG, and equal JWT/certificate secrets. Length checks do not establish entropy or independence. Missing values are rejected in production mode; secrets are not interpolated into validation logs. Compose uses required variable expressions with no insecure fallback. |
| **B — Cross-tenant ProofJob verification** | **PARTIALLY CLOSED** | `VerificationService.process_verification()` queries the ProofJob and returns `verification_unavailable` when absent or not owned by the caller before calling NoirVerifier. Fingerprint lookup is owner-scoped; certificate retrieval checks request owner. No persisted public-sharing grant exists, as expected for owner-only access. The verifier itself loads by ID without ownership, and no executable two-user HTTP/PostgreSQL matrix proved the complete boundary. |
| **C — Idempotency race** | **PARTIALLY CLOSED** | `VerificationRequest` declares `uq_verification_request_idempotency`; Alembic revision 008 creates it and widens result to 50 chars. Create handles IntegrityError by rollback and re-query. Certificate-per-request unique constraint exists in model and migration 005. PostgreSQL constraint application, concurrent convergence, transaction visibility, and duplicate certificate behavior were not exercised. |
| **D — Proof archive integrity** | **PARTIALLY CLOSED** | Validator checks file existence, nonzero size, 50 MiB compressed-file bound, optional whole-file SHA-256, ZIP validity, traversal-like member paths, proof count, and manifest presence. Verifier invokes it only when `proof_archive_hash` is truthy. ZIP expansion size/member count and complete archive-to-job identity checks are not bounded/validated. |
| **E — Cryptographic verification status** | **PARTIALLY CLOSED** | Archive generation marks status `pending`, not `verified`. Source returns `verified` only after all proof rows pass checks and all 256 BB calls return success. The historic archive remains pending; no Stage21L BB execution was repeated, so the historical assertion is not independently established here. Public-input byte-offset assumptions still carry a source comment that serialization runtime validation is pending. |
| **F — Manifest binding** | **PARTIALLY CLOSED** | Validation parses JSON and checks nonempty `job_id`, `total_chunks=32`, `total_segments=256`, expected member hashes (when supplied), and unexpected `.proof` names. It does not compare manifest job ID to the requested/current ProofJob; does not bind manifest roots, vulnerability root, policy hash, profile, tool/VK identities, or per-segment metadata to authoritative DB rows; duplicate ZIP names are not explicitly rejected; extra non-proof members are accepted. |
| **G — Certificate lifecycle/revocation** | **PARTIALLY CLOSED** | Revocation endpoint is authenticated and service checks certificate request ownership; model/migration store revoked flag/time/reason; one-certificate-per-request constraint exists; signature issuance uses HS256 and the certificate key. Retrieval still returns revoked certificate data, no current-validity verifier or public signature-verification path was established, and owner/admin policy and post-issuance snapshot/policy semantics are not fully specified. Revocation does not invalidate an already copied JWT. |
| **H — Database schema** | **NOT INDEPENDENTLY VALIDATED** | Model and Alembic revision 008 declare `result` length 50 and uniqueness; revisions declare certificate/topology constraints and FKs. No live PostgreSQL schema, applied revision, nullability, cascade, or index was inspected. The `user_id` column remains nullable with `ON DELETE SET NULL`; runtime DB semantics are unverified. |
| **I — Resource exhaustion** | **PARTIALLY CLOSED** | Source includes request-body bound, proof-size checks, archive compressed-size bound, subprocess timeouts, process-local prover exclusion/quota; Compose configures CPU/memory limits only for zkp-service. Proof generation is synchronous. No global/multi-worker admission, distributed per-user quota, durable bounded queue, disk quota, or repeated-request control is evidenced. Docker limits are deployment controls and do not solve application-level admission. |
| **J — TLS/network boundary** | **PARTIALLY CLOSED** | Compose binds gateway to host loopback, so remote hosts cannot reach that published port directly under this exact mapping; no other service publishes host ports. Nginx listens only on port 80; no TLS/redirect/HSTS or defined/enforced external terminator exists. Local plaintext callers and a changed/published deployment remain possible; TLS termination is an unverified deployment assumption. |
| **K — Anti-enumeration** | **PARTIALLY CLOSED** | Proof job detail returns the same 404 text for missing and foreign job IDs. Verification returns `verification_unavailable` for absent/foreign ProofJobs after authoritative roots pass. Certificate detail returns 404 for absent/unauthorized cert. The verifier/repository lower layers are not intrinsically owner-scoped; no full alternate-endpoint two-user execution checked response/body/timing equivalence. |
| **L — Strict hex validation** | **PARTIALLY CLOSED** | `VerifyProofRequest` requires `^0x[a-fA-F0-9]{64}$` for all three public roots before service/verifier execution. Prefix, exact length, whitespace, non-hex and extra characters are rejected by the expression; mixed/uppercase hex is intentionally accepted. Source supports the control, but no adversarial API execution was performed this audit. |
| **M — Timestamp/metadata integrity** | **PARTIALLY CLOSED** | Proof/archive creation and persistence timestamp generation exists; archive `creation_timestamp` is set at archive build, not obviously fabricated. It uses naive `datetime.utcnow().isoformat()` and validator does not check timestamp schema, timezone, chronology, or relation to authoritative event times. Event accuracy is not independently validated. |
| **N — Authoritative re-evaluation** | **PARTIALLY CLOSED** | `record_mismatch` and `unavailable` can be re-evaluated; authoritative SBOM, approved snapshot and active policy lookups occur before verifier. Other cached outcomes, including `verified`, return immediately and are not re-evaluated if authoritative state later changes. No replay/stale-state integration evidence exists; verifier has no owner parameter but the current service checks ownership first. |

No A–N item meets the strict “source + executable evidence” threshold for unconditional closure in this audit. A and the plaintext TLS boundary contain concrete weaknesses; the remaining PARTIALLY CLOSED and NOT INDEPENDENTLY VALIDATED statuses must not be interpreted as gate clearance.

## 5. Test-suite forensic comparison

The required command was run with the workspace virtual environment:

```text
..\.venv\Scripts\python.exe -m pytest --collect-only -q
```

Result: **522 tests collected, 1 collection error**. The error arises from root-level `backend/test_db.py`, which connects to localhost PostgreSQL during module import; the available server rejects the required SSL mode. System Python had no pytest module. A successful full-suite execution of 472 tests is therefore not reproduced.

Test inventory observations:

- The current checkout contains service test directories and security-related files such as `test_tenant_isolation.py`, `test_certificate_signing.py`, `test_db_constraints.py`, `test_verifier_topology.py`, and `test_prover_service.py`.
- Existing test logic includes mocks and SQLite/in-memory fixtures. The checked-in tests do not constitute a demonstrated PostgreSQL concurrency suite or real Nargo/BB proof verification suite.
- Historical Stage21G report records **513 passed**. The claimed 472 is 41 fewer; current collection finds 522 test cases before interruption. This difference remains unexplained.
- `git log` contains only architecture-document commits; most present implementation, test, migration, and generated artifact paths are untracked in the current worktree. `git ls-files '*test*.py'` returns only one tracked matching file. Thus Git cannot establish which tests were removed, renamed, replaced, disabled, or weakened between the historical run and this tree.
- The pytest configuration declares an `env` setting, but pytest reports it as an unknown option in the installed environment. Tests depending on those values may not receive the declared configuration unless another setup layer injects them.
- The collection error means default test discovery has an unsafe live DB side effect and is not a reproducible acceptance boundary. This audit did not run the suite to avoid any application/database effects beyond the required collection attempt.

No evidence proves deliberate test removal or assertion weakening, but no reliable baseline proves the opposite. The 472/472 claim is **NOT INDEPENDENTLY VALIDATED** and is contradicted as a result of the requested current collection.

## 6. New vulnerabilities and regression findings

1. **High — weak signing secrets accepted.** Whitespace-only and one-character DEBUG keys passed direct `validate_config()` execution; identical production JWT/certificate values also passed, so separation is not enforced.
2. **High — manifest/ProofJob semantic mismatch can survive archive validation.** Validation checks that a manifest job ID is nonempty but never matches it against the current job, and does not bind roots/policy/profile and full segment metadata to authoritative state.
3. **Medium — certificate revocation is advisory at retrieval.** The response continues to expose signed `certificate_data` and `is_revoked=true`; relying consumers must independently interpret revocation, but no consumer-side validation path was established.
4. **Medium — default pytest collection opens a database connection.** `test_db.py` fails at import when PostgreSQL SSL/configuration is unavailable, preventing clean collection and making suite totals environment-dependent.
5. **Medium — archive validation is conditional.** `NoirVerifier` skips archive validation entirely when `proof_archive_hash` is null; the DB proof-row checks and BB verification continue, but archive integrity is not then part of that verification.
6. **Medium — ZIP resource controls cover compressed size only.** No bounded total uncompressed bytes or per-member decompressed size is checked before manifest/member reads, leaving expansion/resource exposure in archive validation.
7. **Medium — process-local proof admission.** Synchronous work plus per-process controls can be multiplied by workers/containers; Compose CPU/memory settings do not bound request count or persisted disk.

No subprocess shell injection was established in the inspected verifier: user input does not form the BB arguments, although the WSL command includes generated local paths and uses `bash -c`. Full path quoting and deployment behavior were not dynamically tested. Dependency vulnerability scanning, frontend runtime authorization, and production log redaction were not performed.

## 7. PostgreSQL validation

Source evidence:

- Migration 008 alters `verification.verification_requests.result` from length 20 to 50 and creates unique constraint `uq_verification_request_idempotency` on `(user_id, sbom_root, vulnerability_db_root, policy_hash, proof_job_id)`.
- The ORM model declares the same request uniqueness and result length. It also declares certificate uniqueness per verification request; migration 005 creates that constraint.
- Migration 009 adds `is_revoked`, `revoked_at`, and `revoked_reason`. Topology migrations declare unique chunk/segment indices.
- Python catches a flush IntegrityError, rolls back, and re-queries the fingerprint. That is a credible conflict recovery pattern under PostgreSQL READ COMMITTED after the winning transaction commits, but it was not executed. Commit-time errors and update/re-evaluation paths are not shown to converge uniformly.

No live PostgreSQL catalog query or Alembic upgrade was run. Therefore the actual `result` width, constraints/indexes, migration head, existing duplicate-row upgrade behavior, and foreign-key/cascade behavior are **NOT INDEPENDENTLY VALIDATED**. SQLite/mock tests cannot establish them. The schema source improves the C/H findings but does not close the runtime validation requirement.

## 8. Docker and network validation

`docker-compose.yml` publishes only `api-gateway`, using `127.0.0.1:8000:80`. Application services have no host port mappings. The nginx configuration listens on port 80 and proxies internal service DNS names. Consequently this checked-in mapping is loopback-only; it does not itself expose the gateway to remote interfaces. There is no TLS listener, certificate mount, redirect, HSTS, external terminator declaration, or technical prevention of deployment overrides that publish the gateway directly.

No forwarded-header trust configuration was found in the inspected nginx config. An external TLS proxy can be placed in front of loopback, but the repository does not define or enforce it. Therefore TLS/network closure is **PARTIALLY CLOSED**, with no claim that Compose currently publishes a remote plaintext port.

The prover service alone declares `cpus: 2.0` and `memory: 4G`; no Compose disk limit or global job queue exists. This is not application-level denial-of-service protection.

## 9. Cryptographic preservation

The existing Stage21L ZIP was read only. Its SHA-256 matches the supplied value, with 256 proof entries and a 256-record manifest for job `340235b8-71d6-4d6b-84de-284e72a7fb18`. Its manifest explicitly records `cryptographic_verification_status: pending`.

The current profile/source declares the 1024-component, 32-chunk, 8-segment topology and checks circuit/VK hashes when loading production artifacts. This audit did not establish historical equality of circuit semantics, Poseidon parameters, Merkle or SMT construction, C32 decomposition, segment structure, VK bytes, or proof artifacts. Git history has no implementation baseline for those current untracked paths. No circuit/profile/VK/proof file was modified, and no artifact replacement was generated. Preservation is **NOT INDEPENDENTLY VALIDATED**; the supplied archive digest proves only the exact archive bytes match the supplied digest.

## 10. Historical regression analysis

Stage21C–G reports repeatedly describe missing runtime/database/archive evidence; Stage21G states 513 tests passed while the security gate remained blocked. Stage21L/M report real-workload and persistence/certificate claims are historical assertions for this audit. The existing artifact digest and topology are independently confirmed, but pending status and absent runtime re-execution prevent independent confirmation of cryptographic verification.

The present 472 claim cannot be reconciled to Stage21G’s 513 or this run’s 522 collected cases. Because most current files are untracked and history is architecture-only, no defensible test deletion/rename/weakening diff or cryptographic-content diff can be produced. The missing remediation report and broad untracked tree are material forensic chain-of-custody gaps.

## 11. Evidence classification summary

| Claim | Classification |
|---|---|
| Secret quality fails closed for supplied adversarial cases | **CONTRADICTED by execution** |
| Owner check exists in the current verification service path | **SOURCE VERIFIED; full API/DB behavior partially validated** |
| PostgreSQL uniqueness is declared in model/migration | **SOURCE VERIFIED** |
| PostgreSQL uniqueness is applied and concurrent requests converge | **NOT INDEPENDENTLY VALIDATED** |
| Archive digest equals supplied Stage21L digest | **INDEPENDENTLY VERIFIED** |
| Archive is semantically bound to current job and all authoritative DB state | **PARTIALLY CLOSED** |
| Existing archive reports cryptographic completion | **CONTRADICTED**; manifest says pending |
| 256 real Stage21L BB verifications remain independently evidenced here | **NOT INDEPENDENTLY VALIDATED** |
| 472/472 suite passed | **NOT REPRODUCED; current collection fails** |
| Crypto/VK/proof contents are unchanged from historical baseline | **NOT INDEPENDENTLY VALIDATED** |
| Docker directly publishes API externally | **NOT SUPPORTED** by current loopback mapping |
| TLS is technically enforced for all deployment paths | **NOT ESTABLISHED** |

## 12. Exact remaining blockers

- Reject trimmed-empty, low-entropy/repeated, placeholder, identical, and DEBUG-relaxed production signing keys; preserve secret redaction.
- Establish an enforced TLS boundary for non-local deployments while preserving the current loopback-only gateway binding or equivalent network isolation.
- Execute the complete two-user verification/request/certificate matrix and prove owner-only access throughout HTTP route, service, repository, verifier call, and persistence; document any explicit sharing policy if one is later intended.
- Validate PostgreSQL migration head and actual constraints, then exercise concurrent identical requests and certificate uniqueness against PostgreSQL.
- Bind archive manifest identity, roots, policy hash, profile and every exact unique member to the current ProofJob and persisted SegmentProof rows; require archive digest for archive-authoritative verification and bound decompression.
- Define how revocation, expiration, snapshot revocation, policy deactivation, and job state affect a previously issued certificate, and ensure current-validity consumers enforce that policy.
- Produce a clean, reproducible test inventory explaining 472 vs 513 vs 522; remove DB connection side effects from test collection and provide Git evidence for any test changes.
- Supply independent Stage21L execution evidence consistent with the archive's pending status without rerunning the prohibited workload during this audit.
- Restore an auditable historical baseline or immutable manifests for implementation, test, circuit, VK, and proof artifacts so changes can be compared.

## 13. Final gate

**BLOCKED**

Stage21N is not ready to pass the security gate. The directly executed weak-secret acceptance, incomplete TLS enforcement evidence, archive semantic-binding gaps, unresolved certificate validity semantics, failed default test collection, and unavailable PostgreSQL and historical cryptographic validation prevent a defensible acceptance. No production-readiness declaration is supported.

## Commands and actions

- Read-only `git status`, `git log`, `git ls-files`, `rg`, and file inspection.
- `pytest --collect-only -q` using the project virtual environment; 522 collected, collection failed in root `test_db.py` during PostgreSQL SSL connection.
- Focused isolated `validate_config()` probes for 32-space production secrets, one-character DEBUG secrets, and identical JWT/certificate secrets; each was accepted.
- Read-only ZIP inventory, manifest inspection, and SHA-256 calculation for the existing Stage21L archive.
- No proof generation, Nargo/Barretenberg workload, database write, migration, dependency operation, test/source/configuration modification, or replacement artifact generation.

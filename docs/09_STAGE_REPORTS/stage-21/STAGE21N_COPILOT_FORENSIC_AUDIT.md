# Stage 21N — Copilot Independent Forensic Security Audit

## 1. Executive Summary

This is an independent, strict read-only audit of the repository after the
reported Stage 21L and Stage 21M work. No implementation, test, migration,
Docker, frontend, cryptographic, proof, or environment file was changed.

**Final security gate: BLOCKED**  
**Stage 22 authorization: NOT AUTHORIZED**

The repository contains meaningful source-level authorization controls,
focused tenant/certificate tests, and a proof archive whose SHA-256 matches
the supplied Stage 21L hash. However, two release-blocking HIGH findings
remain:

1. `docker-compose.yml` supplies known default JWT and certificate-signing
   secrets when deployment variables are omitted.
2. The repository exposes authenticated traffic through plaintext HTTP without
   a configured TLS boundary.

In addition, the archive manifest records
`cryptographic_verification_status: pending`, contradicting the historical
claim that all 256 proofs completed real Barretenberg verification. Real
Nargo/Barretenberg execution and production database behavior were not
independently verifiable in this environment.

## 2. Scope

Inspected repository integrity, authentication, authorization/RBAC, tenant
ownership, ZKP public-input binding, crypto profile and VK validation,
cryptographic semantics, ProofSet topology, proof archive handling,
certificate issuance and validation, database models/migrations, API
validation, resource controls, error disclosure, frontend behavior, Docker
deployment, dependencies, tests, and historical finding regressions.

The 2.9-hour Stage 21L workload was not rerun. Proofs and verification keys
were not regenerated. No migration or database write was performed.

## 3. Methodology

Evidence was classified as:

- **[VERIFIED]** — direct evidence establishes the property.
- **[PARTIALLY VERIFIED]** — evidence covers only part of the property.
- **[NOT VERIFIED]** — insufficient evidence.
- **[CONTRADICTED]** — current evidence conflicts with the claim.

Historical reports were treated as context only. Passing tests and source
inspection were not treated as proof of live deployment or production
database properties.

## 4. Evidence Available

| Area | Classification | Evidence |
|---|---|---|
| Git/repository state | [VERIFIED] | Git state, branch, history, and diffs inspected; no implementation files modified |
| Backend authorization source | [VERIFIED] | Auth middleware, routes, services, and repositories inspected |
| Focused security/tenant/certificate tests | [VERIFIED] | 66 tests passed |
| Proof archive and supplied hash | [VERIFIED] | 261 entries, 256 proof entries; SHA-256 matches supplied value |
| Archive topology | [VERIFIED] | Manifest references 256 proofs and all references exist |
| Real Nargo/Barretenberg execution | [NOT VERIFIED] | `nargo` and `bb` unavailable |
| Historical all-proofs-verified claim | [CONTRADICTED] | Manifest says `cryptographic_verification_status: pending` |
| Production PostgreSQL/Supabase behavior | [NOT VERIFIED] | No live database session was available |
| Complete deployment posture | [PARTIALLY VERIFIED] | Static configuration inspected; container deployment not started |

## 5. Repository Integrity

The current branch is `chore/final-project-cleanup`. Git status, diffs,
history, tracked/untracked state, and relevant generated/configuration paths
were inspected. No unexpected audit-created changes were made. The requested
report is the only file created by this audit.

The supplied archive exists at
`archives/proofs/340235b8-71d6-4d6b-84de-284e72a7fb18.zip`.
Its SHA-256 is:

`362be7463b3af52fb499a9bf95d64a69d1dac44e64d48f52cb197a5b48bb7e3d`

## 6. Authentication

**Classification: [PARTIALLY VERIFIED].**

`backend/shared/auth.py` requires JWT `sub` and `exp`, validates bearer tokens,
and restricts the algorithm to HS256. Registration assigns the auditor role
server-side rather than accepting a caller-selected role. Focused
authentication-related tests passed.

Authentication is materially weakened by Finding ST21N-001: Docker Compose
can configure a publicly predictable JWT signing secret. No live deployment
startup or end-to-end token-forgery test was run.

## 7. Authorization / RBAC

**Classification: [PARTIALLY VERIFIED].**

Administrative vulnerability ingestion/approval/revocation and policy
creation enforce admin roles. Sensitive SBOM, ZKP, verification, and
certificate paths contain server-side role and ownership checks. Focused
tests passed.

The result depends on secret integrity. A forged admin JWT under the Compose
fallback would bypass these controls. Production multi-container and
database-backed authorization were not independently executed.

## 8. Ownership / IDOR

**Classification: [PARTIALLY VERIFIED].**

SBOM and ZKP retrieval/listing filter by the authenticated user. Certificate
retrieval validates the associated verification job and request ownership.
Focused tenant-isolation and certificate tests passed.

No live PostgreSQL/Supabase test was run, so database-level ownership,
foreign-key, row-policy, and deployment configuration behavior remain
unverified. Frontend route guards were not treated as backend authorization.

## 9. ZKP Binding

**Classification: [PARTIALLY VERIFIED].**

The inspected verification chain contains checks for proof-to-job association,
authoritative SBOM/vulnerability/policy records, and public values including
`sbom_root`, `vulnerability_db_root`, and `policy_hash`. Structural and
record-mismatch paths are present.

The current archive does not establish successful real proof verification, and
real Nargo/Barretenberg execution was unavailable. Therefore complete
cryptographic binding, stale-cache behavior, and alternate-path resistance are
not independently verified.

## 10. Crypto Profile / VK

**Classification: [PARTIALLY VERIFIED].**

Crypto profile configuration and checked-in artifact hash validation paths were
present, including segment artifacts and startup validation.

The production profile was not exercised in a live deployment, and real
Nargo/Barretenberg binaries were unavailable. Missing-artifact fail-closed
behavior and wrong-VK rejection are therefore not independently verified.

## 11. Cryptographic Semantics

**Classification: [PARTIALLY VERIFIED].**

Source and tests cover SBOM canonicalization, PURL/component identity,
vulnerability encoding, Merkle/SMT construction, policy hashing, chunk
commitments, and segment linkage. ZK-001 (SMT empty-leaf mismatch), ZK-002
(component identity), CVSS `0.0` versus absence, and malformed PURL handling
were revisited through source/tests.

The implementation is internally exercised by tests, but a complete
production-equivalent proof/verification run was not available. These
properties remain partially rather than fully independently verified.

## 12. ProofSet Integrity

**Classification: [PARTIALLY VERIFIED].**

The archive manifest declares 256 segment proofs, and all 256 referenced proof
files exist. Source checks enforce expected chunk/segment counts, indexes,
associations, duplicate prevention, and linkage-related structure.

The archive and source establish topology, not successful cryptographic
validity. The manifest explicitly says verification is pending, so the
historical assertion of 256 successful Barretenberg verifications is
**[CONTRADICTED]** by current evidence.

## 13. Proof Archive

**Classification: [PARTIALLY VERIFIED].**

The archive contains 261 entries: 256 proofs and the manifest-referenced
supporting entries. The supplied archive hash matches exactly, and every
manifest proof reference exists.

Archive lifecycle helpers, manifest generation, and path handling were
inspected. Crash consistency, full decompression/path-traversal adversarial
testing, and production size-limit behavior were not independently executed.

## 14. Certificate Security

**Classification: [PARTIALLY VERIFIED].**

Certificate issuance is gated on a `verified` result and uses
`CERTIFICATE_SECRET_KEY`. Certificate retrieval validates ownership and the
associated verification job. Focused certificate tests passed.

Finding ST21N-001 permits a known certificate-signing fallback secret in
Compose. Real issuance, external trust-chain validation, revocation behavior,
and production secret rotation were not independently executed.

## 15. Database Integrity

**Classification: [PARTIALLY VERIFIED].**

Supabase/PostgreSQL-oriented migrations and SQLAlchemy models contain UUID
identifiers, ownership fields, proof archive hash data, certificate
relationships, status/timestamp fields, constraints, and indexes.

No live PostgreSQL/Supabase connection was available. Migration-head state,
remote schema equivalence, foreign-key enforcement, and production indexes
were therefore **[NOT VERIFIED]**.

## 16. API Security

**Classification: [PARTIALLY VERIFIED].**

Routes and schemas provide UUID/input validation, role checks, proof/archive
size controls, subprocess timeout controls, and explicit error paths.
Subprocess invocation was inspected for argument construction and injection
risk.

Full adversarial request-size, malformed archive, subprocess-failure,
database-error, and production error-redaction testing was not performed.

## 17. Resource / DoS

**Classification: [PARTIALLY VERIFIED].**

Process-local locks, quotas, proof-size checks, and timeout controls exist.
These controls are not deployment-wide concurrency or memory limits. No
container-level or multi-replica load test was run.

## 18. Frontend Security

**Classification: [PARTIALLY VERIFIED].**

Frontend auth state, Authorization handling, route/role guards, and
certificate access paths were inspected. No source evidence indicated that
witnesses, SMT paths, private SBOM data, proof artifacts, or secrets are
intentionally rendered.

Runtime browser storage, production error rendering, and deployed API
configuration were not independently exercised.

## 19. Docker / Deployment

**Classification: [CONTRADICTED for fail-closed secret behavior; PARTIALLY VERIFIED overall].**

`docker-compose.yml` exposes the gateway as host `8000:80`, and
`docker/nginx.conf` listens only on port 80. No TLS listener, redirect, HSTS
configuration, or repository-defined external TLS boundary is present.

The Compose configuration also contains:

```yaml
JWT_SECRET_KEY=${JWT_SECRET_KEY:-default_insecure_jwt_secret}
CERTIFICATE_SECRET_KEY=${CERTIFICATE_SECRET_KEY:-default_insecure_cert_secret}
```

This directly contradicts a fail-closed production-secret requirement.

## 20. Dependency / Supply Chain

**Classification: [PARTIALLY VERIFIED].**

Python/frontend manifests, lockfiles, Dockerfiles, and relevant crypto tool
metadata were inspected. No package was upgraded or installed. Dependency
execution was validated only in the existing environment; a clean isolated
installation and complete supply-chain review were not performed.

Floating or environment-dependent deployment values and unavailable crypto
tool binaries limit independent reproducibility.

## 21. Test Integrity

**Classification: [PARTIALLY VERIFIED].**

Focused security, tenant-isolation, and certificate tests passed:

`66 passed, 33 warnings`

Tests use configured test keys and mocks in places; they do not prove
deployment fallback rejection, live PostgreSQL behavior, TLS, or real
Nargo/Barretenberg execution. Warnings included short HMAC test-key warnings.
No test was modified or skipped by this audit.

## 22. Historical Finding Regression

| Finding | Status | Assessment |
|---|---|---|
| ST21A-001 | PARTIALLY REMEDIATED | SMT locking/cache paths exist; adversarial concurrent runtime proof absent |
| ST21A-002 | PARTIALLY REMEDIATED | Profile/artifact hashes validate; real Nargo/BB execution absent |
| ST21A-003 | PARTIALLY REMEDIATED | Structural/hash paths exist; strict real proof verification absent |
| ST21A-004 | PARTIALLY REMEDIATED | Complete archive exists; manifest verification remains pending |
| ST21A-005 | PARTIALLY REMEDIATED | Identity/PURL tests pass; production-ingestion equivalence unproven |
| ST21A-006 | PARTIALLY REMEDIATED | Ownership filtering and SQLite tests pass; production DB boundary unvalidated |
| ST21A-007 | PARTIALLY REMEDIATED | Topology and manifest exist; real ProofSet verification absent |
| ST21A-008 | PARTIALLY REMEDIATED | Startup checks exist; Compose known-secret fallback remains |
| ST21A-009 | PARTIALLY REMEDIATED | Issuance requires `verified`; real trust chain absent |
| ST21A-010 | PARTIALLY REMEDIATED | Frontend/backend alignment source/build-supported; runtime deployment unverified |
| ST21A-011 | PARTIALLY REMEDIATED | Process-local controls exist; deployment-wide controls untested |
| ST21A-012 | PARTIALLY REMEDIATED | Migration/model source exists; live schema not checked |
| ST21B-NEW-001 | PARTIALLY REMEDIATED | Secret separation exists in source; Compose fallback is a regression risk |
| ST21B-NEW-002 | PARTIALLY REMEDIATED | Timeout controls exist; all subprocess paths not runtime-tested |
| ST21B-NEW-003 | PARTIALLY REMEDIATED | Archive helper/manifest exist; complete validation not established |
| ST21C-NEW-001 | PARTIALLY REMEDIATED | Certificate key is separated in source; production signing unexecuted |
| ST21C-NEW-002 | PARTIALLY REMEDIATED | Debug-print issue appears addressed; runtime redaction unverified |
| ST21C-NEW-003 | PARTIALLY REMEDIATED | Proof-size checks exist; strict Base64/runtime validation unresolved |
| ST21C-NEW-004 | PARTIALLY REMEDIATED | Archive lifecycle exists; crash consistency untested |
| ST21D-NEW-001 | PARTIALLY REMEDIATED | Crypto profile startup validation exists; deployment not exercised |
| ST21F-NEW-001 | VERIFIED (source/test scope) | Guarded lock/quota cleanup and focused regression tests pass |
| ST21F-NEW-002 | VERIFIED (tested environment) | Declared dependency chain and focused tests execute |
| ST21G-NEW-001 | PARTIALLY REMEDIATED | Archive/topology inspectable; cryptographic status remains pending |

No historical issue was proven fully regressed in source. Deployment-level
regression risk exists for ST21B-NEW-001 and ST21C-NEW-001 because Compose
reintroduces predictable authentication/signing defaults.

## 23. Findings Register

### ST21N-001 — Known default authentication and certificate secrets

- **Severity:** HIGH
- **Exact path:** `docker-compose.yml`, service environment blocks, lines 32–33
- **Function/class/endpoint:** `backend/shared/auth.py:get_current_user`,
  `create_access_token`; certificate signing consumers
- **Evidence:** Compose defaults to
  `default_insecure_jwt_secret` and `default_insecure_cert_secret` when
  variables are absent. Startup validation checks presence/non-empty values
  but does not reject these known placeholders.
- **Impact:** An attacker can forge HS256 bearer tokens, including admin
  roles, and can forge certificate JWTs where the fallback is trusted.
- **Exploitability:** High wherever deployment variables are omitted or
  inherited from the Compose defaults; no brute force is required.
- **Status:** OPEN; **[CONTRADICTED]** fail-closed deployment behavior.
- **Recommended remediation:** Remove fallbacks; require externally supplied,
  independently generated secrets; reject known placeholders and enforce
  production minimum entropy/length.
- **Stage 22 blocking:** YES — authentication, authorization, and certificate
  integrity.

### ST21N-002 — Authenticated API exposed over plaintext HTTP

- **Severity:** HIGH
- **Exact paths:** `docker/nginx.conf`, lines 3–6; `docker-compose.yml`,
  lines 7–9
- **Function/class/endpoint:** Gateway proxy for login, bearer-token APIs,
  SBOM, proof, verification, and certificate endpoints
- **Evidence:** Host binding is `8000:80`; Nginx listens only on port 80.
  No TLS listener, redirect, HSTS, or repository-defined trusted TLS boundary
  is configured.
- **Impact:** Network observers can capture credentials or bearer tokens and
  replay them against administrative and data endpoints.
- **Exploitability:** High on any untrusted network path; depends on
  deployment exposure.
- **Status:** OPEN; **[PARTIALLY VERIFIED]** due to no live deployment.
- **Recommended remediation:** Terminate TLS at the gateway or require a
  verified trusted ingress, reject/redirect plaintext, configure HSTS, and
  document the boundary.
- **Stage 22 blocking:** YES — authentication confidentiality and session
  integrity.

### ST21N-003 — Cryptographic completion claim is not independently evidenced

- **Severity:** HIGH (release evidence blocker)
- **Exact path:** `archives/proofs/340235b8-71d6-4d6b-84de-284e72a7fb18.zip`,
  manifest
- **Function/class/endpoint:** Proof archive manifest and ProofSet verification
  evidence
- **Evidence:** Archive hash and topology match the supplied values, but the
  manifest records `"cryptographic_verification_status": "pending"`.
  `nargo` and `bb` were unavailable for independent execution.
- **Impact:** The archive proves packaging and declared topology, not that all
  256 proofs are valid real Barretenberg proofs. Proceeding could authorize
  unverified cryptographic evidence.
- **Exploitability:** Not an exploit path by itself; it is a material
  integrity/release assurance gap.
- **Status:** OPEN; historical completion assertion **[CONTRADICTED]** by the
  current manifest.
- **Recommended remediation:** In a controlled environment, independently run
  the frozen workload or provide independently verifiable execution evidence;
  only mark the manifest complete after all proof verification succeeds.
- **Stage 22 blocking:** YES — proof integrity and ZKP assurance.

## 24. Required Remediation

Before Stage 22:

1. Remove Compose secret fallbacks and enforce fail-closed, strong,
   independently generated JWT and certificate secrets.
2. Deploy authenticated traffic behind verified TLS and prevent untrusted
   plaintext access.
3. Independently verify the 256-proof workload with the frozen Nargo and
   Barretenberg configuration, and reconcile the archive manifest status.
4. Execute controlled production-like PostgreSQL/Supabase ownership,
   authorization, migration, and certificate trust-chain tests.
5. Reassess all historical findings after the above evidence is available.

## 25. Final Security Gate

**BLOCKED**

The unresolved HIGH findings materially affect authentication,
authorization, certificate integrity, transport confidentiality, and proof
integrity/evidence. The gate must not be lowered based on passing focused
tests or historical claims.

## 26. Stage 22 Authorization

**NOT AUTHORIZED**

Stage 22 may not proceed until the blocking findings are remediated and the
missing cryptographic and production-database evidence is independently
verified.

## 27. Evidence Limitations

- The full 2.9-hour Stage 21L workload was not rerun.
- `nargo` and `bb` were unavailable in the audit environment.
- No production PostgreSQL/Supabase session was connected.
- No container deployment was started; Docker daemon availability was not
  established.
- No TLS ingress or external reverse proxy was available for validation.
- Historical Stage 21L/M claims were treated as assertions unless corroborated
  by current read-only artifacts.
- Archive hash/topology do not prove cryptographic validity.
- Focused tests do not prove production deployment behavior.

## Exact Commands and Tests Executed

Read-only Git inspection:

```text
git status --porcelain=v1
git branch --show-current
git diff --name-only main...HEAD
git log --oneline --all -20
git diff
git diff --cached
```

Focused tests:

```text
E:\Main Project\.venv\Scripts\python.exe -m pytest -q backend/shared/tests/test_security.py backend/verification_service/tests/test_certificate_signing.py backend/sbom_service/tests/test_sbom_tenant_isolation.py backend/zkp_service/tests/test_tenant_isolation.py
```

Result: `66 passed, 33 warnings`.

Read-only archive probes counted entries, calculated SHA-256, read the
manifest, and cross-checked all 256 manifest proof references. Availability
probes found no `nargo` or `bb`; Docker CLI was `29.8.1`, but Docker daemon
availability was not established.

No migrations, database writes, package installation, proof regeneration,
long-running Stage 21L workload, or source modifications were performed.

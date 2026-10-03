# Remediation Plan

Date: 2026-09-13
Phase: 2 - Planning only
Implementation status: Not started

## 1. Execution rules

Remediation proceeds in small auditable stages. Every stage requires code evidence, targeted regression tests, migration evidence where relevant, and a validation record. No stage may weaken a security check to preserve an existing test. Existing uncommitted work remains preserved.

The plan is blocked from implementation until `25_SECURITY_DECISIONS_REQUIRED.md` is approved and the proof-binding design is validated against the selected cryptographic toolchain.

## 2. Gates and evidence standard

Each stage must produce:

- changed-file list and threat/invariant mapping;
- migration and rollback plan;
- focused security regression tests using real application code;
- exact commands and outputs;
- negative tests proving unauthorized and mismatched inputs fail;
- residual-risk update;
- no claim of production readiness while `CRYPTO-ENV-BLOCKER-001` is open.

## 3. Ordered remediation stages

### Stage 0 - Decision and artifact gate

Priority: P0 / ENV

Scope:

- Approve identity/tenant/role model and legacy-record treatment.
- Approve vulnerability importer and snapshot lifecycle.
- Approve authoritative proof-reference model and supported public-input binding mechanism.
- Select one production profile capacity and approve Nargo, Barretenberg, circuit, compiled artifact, and VK versions/hashes.
- Decide job queue/quota model, secret/session lifecycle, and service database principals.

Exit evidence:

- Signed decision record for all architecture questions.
- Toolchain versions and hashes in a controlled Linux/WSL or Docker environment.
- A supported proof API/CLI demonstration showing how expected public inputs are supplied or extracted.

Rollback: No runtime change. If decisions are not approved, implementation remains blocked.

### Stage 1 - Identity, authentication, and authorization foundation

Priority: P0
Findings: `RBAC-001`, `API-001`, `AUTH-001`

Scope:

- Require authentication on all sensitive, mutating, object-retrieval, and expensive routes.
- Enforce strict JWT algorithm, expiration, required claims, production secret startup failure, and consistent multi-process secret distribution.
- Implement server-side role and tenant resolution.
- Add route and service-layer authorization predicates.
- Remove client authority fields and protect diagnostics.

Database/API work:

- Add user membership/tenant ownership relationships and indexes.
- Add owner/tenant references to SBOMs, policies, proof jobs, and certificates.
- Quarantine legacy records without reliable ownership.
- Publish stable 401/403/404 behavior that avoids unnecessary cross-user existence disclosure.

Required tests:

- Missing, malformed, invalid-signature, expired, wrong-algorithm, missing-claim, weak/missing production secret, multi-process consistency, long-password, generic login, and hash non-disclosure tests.
- Vendor/auditor/buyer/admin matrix, cross-user object IDs, forged role/user IDs, unauthorized mutation, and related-object ownership tests.
- Every route inventory test proving sensitive endpoints require authentication.

Exit evidence: no unauthenticated sensitive route; cross-tenant reads/mutations fail; production secret absence fails startup/readiness; migration report accounts for every legacy record.

Rollback: Disable affected routes and quarantine records; never roll back to globally readable records or ephemeral production JWT secrets.

### Stage 2 - Vulnerability intelligence authority

Priority: P0
Findings: `VI-001`, `SNAP-001`

Scope:

- Restrict ingestion to trusted importer/admin roles.
- Add provenance, source digest/signature, importer identity, validation, approval, freeze, revocation, and replacement references.
- Make approved roots immutable and version changes as new snapshots.
- Allow proof/certificate use only for approved, frozen, non-revoked snapshots.
- Remove or clearly classify provisional roots in public schemas.

Database/API work:

- Add snapshot lifecycle/state transition tables or equivalent immutable audit fields.
- Add root/version uniqueness and indexes.
- Add approval/freeze/revocation API contracts that do not accept client booleans as authority.

Required tests: unauthorized ingestion/approval, provenance persistence, deterministic conflict handling, frozen mutation rejection, revoked-root rejection, malicious low-CVSS snapshot rejection, and public response contract tests.

Exit evidence: a database-derived lifecycle and an end-to-end proof admission check that rejects every ineligible state.

Rollback: Freeze new ingestion and certificate issuance; retain immutable historical snapshots. Never make a provisional root eligible as a rollback shortcut.

### Stage 3 - Authoritative proof binding and certificate integrity

Priority: P0 / release-blocking
Findings: `ZK-002`

Scope:

- Resolve authoritative SBOM, snapshot, and policy records before verification.
- Build expected ordered public inputs from those records.
- Use only a supported Barretenberg/Noir mechanism to pass expected inputs to verification or extract them from the verified proof.
- Compare verified inputs to request values and authoritative records before certificate issuance.
- Store authoritative IDs, roots, policy, profile, VK hash, verifier version, and proof digest in the certificate.

Required evidence:

- A real proof with matching inputs accepted.
- A real proof for another SBOM, snapshot, policy, or profile rejected.
- Request metadata mismatch rejected.
- Tampered proof and witness-as-proof rejected.
- Revoked/stale records rejected.
- The exact supported API/CLI invocation and public-input ordering recorded.

Hard stop: If the selected verifier cannot bind or expose public inputs through a supported mechanism, do not implement a string comparison, custom parser, or proof-label check. Stop and return to the architecture decision gate.

Database/API work: authoritative reference foreign keys, certificate uniqueness/idempotency, approved-state transaction locks, exact canonical input schema.

Rollback: Disable certificate issuance and mark verification as unavailable; do not revert to caller-only roots.

### Stage 4 - Circuit/profile/VK integrity

Priority: P0 / ENV
Findings: `ZK-001`, `CRYPTO-ENV-BLOCKER-001`

Scope:

- Freeze one production profile manifest.
- Resolve the Python depth/capacity versus circuit depth/capacity decision.
- Compile the selected circuit with Nargo `0.32.0` and the approved compatible Barretenberg version.
- Record circuit, compiled artifact, VK, proof format, and toolchain hashes.
- Validate startup/readiness and reject missing/mismatched/development artifacts.

Required tests: manifest self-check, missing artifact, hash mismatch, wrong VK, wrong dimensions, dev/prod cross-profile proof, public-input ordering, and real positive/negative proof verification.

Rollback: Select only a previously validated immutable profile; otherwise fail closed and stop proof/certificate processing.

### Stage 5 - Bounded proof jobs and artifact isolation

Priority: P1
Findings: `API-001`, `ART-001`, `SUB-001`, `PARSER-001`

Scope:

- Implement bounded admission/queue, global concurrency, per-user/tenant quotas, component/payload/depth limits, timeout and output limits.
- Use direct argument arrays, process groups/job objects, descendant cleanup, cancellation, and retry states.
- Use private per-job temporary directories, restrictive permissions, stale scavenging, and no stale artifact reuse.
- Sanitize internal errors and protect diagnostics.

Required tests: concurrent isolation, active-job quota, excessive payload/components, timeout cleanup, child-process termination, cancellation/recovery, stale artifact rejection, symlink/permission checks, exception cleanup, and sanitized subprocess failures.

Rollback: Stop admission and return a bounded unavailable response; do not revert to synchronous unbounded or shared artifact execution.

### Stage 6 - Database integrity and service isolation

Priority: P1
Findings: `DB-001`, `DB-002`

Scope:

- Add unique idempotency constraints and explicit state transitions.
- Use service-specific SQL principals and schema grants.
- Add transaction locking/atomicity for approval, freeze, verification, and certificate issuance.
- Validate migrations against a real supported SQL Server deployment.

Required tests: concurrent duplicate verification, rollback, double approval/freeze, cross-service permission denial, and partial certificate failure.

Rollback: Apply migration rollback only where it preserves uniqueness and access restrictions; otherwise disable affected mutation paths.

### Stage 7 - Readiness, deployment, privacy, and supply chain

Priority: P1/P2
Findings: `CFG-001`, `CFG-002`, `CFG-003`, `CFG-004`, `PRIV-001`, `DEP-001`, `API-003`

Scope:

- Separate liveness/readiness and check DB, profile/VK, secret, and required tools.
- Make Compose/gateway artifacts complete and reproducible; remove production DB exposure.
- Define TLS, CORS, browser-token, and CSRF policy.
- Complete structured logging, retention, backup, and artifact privacy controls.
- Add available dependency/container/SBOM/secret scans and pin release artifacts.
- Enforce exact public-input encoding.

Required tests: clean Compose build/config, dependency readiness failures, external reachability, browser cross-origin behavior, log/privacy corpus, secret scanning, and canonical encoding negatives.

Rollback: Fail readiness or disable exposure; never report healthy when critical dependencies are unavailable.

## 4. Validation sequence after implementation

1. Focused unit/service security regressions for the changed slice.
2. Migration upgrade, downgrade, and legacy-record accounting.
3. Full backend collection and tests.
4. Frontend lint/build.
5. Real circuit compile, witness, proof, verification, negative proof, and profile tests.
6. Compose and readiness deployment validation.
7. Dependency, container, SBOM, secret, and static analysis tools that are actually available.
8. Adversarial re-audit of auth, ownership, snapshot trust, proof binding, profile isolation, certificates, jobs, and error privacy.

## 5. Completion criteria

The remediation is not complete if any P0 finding is only mocked, if a certificate can be issued without authoritative proof-input equality, if production artifacts are missing or mismatched, if legacy ownership is ambiguous, or if the approved cryptographic toolchain has not executed real positive and negative proofs.

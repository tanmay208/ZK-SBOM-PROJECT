# Master Finding Reconciliation

Date: 2026-09-13
Scope: Read-only Phase 1 forensic reconciliation

## Executive conclusion

The audit corpus was reconciled against the current source tree, tests, configuration, and supporting security documentation. Audit titles were deduplicated by root cause rather than counted as separate vulnerabilities. No application, test, circuit, dependency, or configuration remediation was implemented in this phase.

The accepted baseline is sufficient to begin remediation planning: project-wide pytest collection and the configured 480-test suite pass, and the frontend build passes. Production cryptographic validation remains unavailable and is tracked separately as `CRYPTO-ENV-BLOCKER-001`; it is not automatically classified as an application vulnerability.

## Reconciliation counts

Active deduplicated records:

| Classification | Count |
| --- | ---: |
| Confirmed vulnerability or security-control deficiency | 12 |
| Requires further evidence / probable | 4 |
| Hardening recommendation | 5 |
| Environmental blocker | 1 |
| False-positive claim clusters, excluded from active findings | 9 |

Confirmed findings by severity:

| Severity | Count | IDs |
| --- | ---: | --- |
| Critical | 0 | None supported by current evidence |
| High | 5 | RBAC-001, API-001, VI-001, ZK-001, ZK-002 |
| Medium | 6 | API-002, CFG-001, CFG-002, AUTH-001, ART-001, DB-002 |
| Low | 1 | SNAP-001 |

There are 4 unconfirmed/probable records: `DB-001`, `CAN-001`, `SUB-001`, and `CFG-003`. There is 1 environmental blocker: `CRYPTO-ENV-BLOCKER-001`. No Critical finding is assigned because the evidence does not establish remote code execution, key compromise, or platform-wide catastrophic impact.

## Classification rules

- **Confirmed vulnerability:** Current code demonstrates a reachable security invariant violation with a credible attack path.
- **Confirmed security-control deficiency:** Current code demonstrates a missing or ineffective control; runtime exploitability may still depend on deployment assumptions.
- **Confirmed availability/operational risk:** Current deployment or runtime behavior can fail or consume resources without an adequate control.
- **Hardening recommendation:** A security-relevant improvement is justified, but current evidence does not establish a distinct exploitable vulnerability.
- **Environmental blocker:** Validation or deployment evidence is unavailable because a required external tool or environment is missing. This is not automatically an application defect.
- **False positive/unconfirmed:** The proposed claim is contradicted by current code or lacks enough evidence for an active finding.
- **Requires further evidence:** A plausible issue remains, but live reproduction, deployment evidence, or an architectural decision is required before confirming it.

## Confirmed findings

### RBAC-001 - Missing authorization, ownership, and tenant isolation

- Severity: High
- CWE: CWE-862 (missing authorization), CWE-639 (authorization bypass through user-controlled key)
- Classification: Confirmed security-control deficiency
- Exact code: `backend/shared/auth.py:get_current_user`; `backend/sbom_service/app/api/routes/sbom_routes.py:list_sboms`; `backend/vulnerability_service/app/api/routes/vulnerability_routes.py:list_snapshots`; `backend/policy_service/app/api/routes/policy_routes.py:list_policies`; `backend/zkp_service/app/api/routes/zkp_routes.py:get_proof_job`; `backend/verification_service/app/api/routes/verification_routes.py:get_certificate`; related service and repository methods.
- Evidence: Authentication dependencies exist in selected routes, but the inspected list and object retrieval paths do not apply owner, tenant, or role predicates. Database models for SBOMs, policies, snapshots, proof jobs, and certificates do not establish a reliable requesting-user ownership relationship.
- Attack scenario: An authenticated vendor or buyer supplies another record UUID, or enumerates a global list, and retrieves another tenant's metadata or proof-job/certificate data. Unauthenticated routes compound the exposure.
- Preconditions: Network access to the service or gateway and a valid account for authenticated paths; UUID secrecy is not a control.
- Impact: Horizontal privilege escalation, private metadata disclosure, cross-tenant access, and possible vertical privilege escalation through mutation paths.
- Exploitability: Confirmed at the application layer. An external gateway or database row-level policy was not evidenced and cannot be treated as mitigation.
- Existing controls: UUID and Pydantic validation; `get_current_user` authentication on some routes; logical database schemas. None enforce object ownership.
- Required remediation: Define the role and tenant matrix, add ownership/tenant relationships, enforce authorization in route and service layers, and reject client-supplied identity or role claims.
- Required regression test: Two-user/vendor cross-access matrix for list, get, mutate, proof job, certificate, policy, and related-object IDs; forged user and role fields; unauthenticated access.
- Schema/database migration: Yes. Existing records require an explicit safe migration policy; arbitrary assignment to one user is unsafe.
- Cryptographic tool blocker: No.
- Dependencies: Must precede proof, certificate, and vulnerability trust remediation.

### API-001 - Unauthenticated mutating and expensive routes

- Severity: High
- CWE: CWE-306 (missing authentication for critical function), CWE-400 (uncontrolled resource consumption)
- Classification: Confirmed vulnerability
- Exact code: `backend/sbom_service/app/api/routes/sbom_routes.py:upload_sbom`; `backend/vulnerability_service/app/api/routes/vulnerability_routes.py:ingest_vulns`; `backend/zkp_service/app/api/routes/zkp_routes.py:generate_proof`; `backend/verification_service/app/api/routes/verification_routes.py:verify_proof,get_certificate`.
- Evidence: The route signatures inspected do not consistently declare an authentication dependency. The expensive proof and verification paths invoke database, filesystem, and subprocess work before any proven user authorization boundary.
- Attack scenario: An unauthenticated caller repeatedly uploads SBOMs, ingests intelligence, starts proof work, verifies arbitrary artifacts, or retrieves certificates.
- Preconditions: Reachability through the deployed service or gateway.
- Impact: Unauthorized state mutation, confidential data exposure, CPU/process exhaustion, filesystem growth, and certificate workflow abuse.
- Exploitability: Confirmed from route control flow; external network allowlists were not evidenced.
- Existing controls: Request-size and schema bounds, some route-level database validation, and subprocess timeouts. No uniform authentication, quota, or rate control.
- Required remediation: Require authentication before all sensitive/state-changing/expensive work; add role checks, ownership checks, quotas, rate limits, and bounded job admission.
- Required regression test: Missing, malformed, and valid-token tests for every route; repeated and concurrent expensive-request admission tests.
- Schema/database migration: Usually no schema migration, but job ownership fields are required for safe quotas.
- Cryptographic tool blocker: No for route authorization; yes for live proof-cost testing.
- Dependencies: RBAC-001 and resource controls.

### VI-001 - Vulnerability snapshot poisoning and absent trust lifecycle

- Severity: High
- CWE: CWE-345 (insufficient verification of data authenticity), CWE-863 (incorrect authorization)
- Classification: Confirmed vulnerability
- Exact code: `backend/vulnerability_service/app/api/routes/vulnerability_routes.py:ingest_vulns`; `backend/vulnerability_service/app/services/vulnerability_service.py:ingest_vulnerabilities`; `backend/vulnerability_service/app/models/vulnerability_models.py:VulnerabilitySnapshot`; `backend/zkp_service/app/services/prover_service.py:process_job`.
- Evidence: Ingestion accepts caller-provided PURLs and CVSS values and creates a completed snapshot with a provisional SMT root. No trusted-importer authorization, source signature, approval, freeze, or revocation lifecycle is enforced. Proving consumes `snapshot.provisional_smt_root`.
- Attack scenario: A vendor or unauthenticated caller submits a malicious low-CVSS database and selects its snapshot for proof generation, producing a false-safe result.
- Preconditions: Access to ingestion and proof submission paths; no trusted external feed is required.
- Impact: Authoritative vulnerability intelligence poisoning and false compliance certificates.
- Exploitability: Confirmed as a trust-model defect without requiring a live proof; exact end-to-end certificate abuse remains toolchain-blocked.
- Existing controls: CVSS/PURL syntax validation, transaction rollback, deterministic aggregation. These do not establish provenance or authority.
- Required remediation: Restrict ingestion to a trusted importer/admin, persist provenance/source/identity, implement ingested/validated/approved/frozen/revoked states, make approved roots immutable, and reject unapproved or revoked snapshots in proof and certificate flows.
- Required regression test: Unauthenticated/vendor ingestion rejection; approval/freeze authorization; unapproved, modified, and revoked snapshot rejection; provenance persistence and root immutability.
- Schema/database migration: Yes. Status, provenance, importer, approval, freeze, revocation, and immutable-version fields are required.
- Cryptographic tool blocker: No to confirm trust failure; yes for live proof/certificate exploit validation.
- Dependencies: RBAC-001, ZK-002, and database transaction design.

### ZK-001 - Circuit, witness profile, and verification-key mismatch

- Severity: High
- CWE: CWE-693 (protection mechanism failure), CWE-16 (configuration)
- Classification: Confirmed security-control/deployment integrity deficiency
- Exact code: `backend/shared/crypto/merkle.py` depth/capacity defaults; `backend/zkp_service/app/services/prover_service.py:process_job`; `circuits/src/main.nr`; `circuits/src/merkle.nr`; `circuits/Nargo.toml`; `circuits_dev/Nargo.toml`; checked-in `circuits/target` and `circuits_dev/target` artifacts.
- Evidence: Python Merkle logic uses depth 10/1024 capacity, while the checked-in circuit and prover path use eight entries/depth 3. Development artifacts include a VK while the production VK is absent. Profile selection is derived from `DEV_MODE`, not a validated immutable manifest.
- Attack scenario: A deployment runs a mismatched circuit, witness dimensions, or VK, causing failures or accepting an artifact under an unintended profile if external artifact selection is inconsistent.
- Preconditions: Deployment of the affected proving/verifying services and reliance on checked-in/generated artifacts.
- Impact: Proof unavailability, cross-profile confusion, or cryptographic integrity failure if mismatched artifacts are accepted.
- Exploitability: Confirmed as a deployment/control defect. Live proof behavior is unverified because the required toolchain is unavailable.
- Existing controls: Separate `circuits` and `circuits_dev` directories, compiler version declarations, and some target metadata. No startup digest/profile validation.
- Required remediation: Define one authoritative profile manifest with circuit dimensions, compiler/tool versions, circuit hash, VK hash, artifact hashes, and public-input ordering; fail startup on mismatch or missing production artifacts; do not permit API-controlled profile selection.
- Required regression test: Compile selected profile, verify artifact hashes, reject wrong VK/profile, test production and development dimension mismatch, and run real proofs for supported capacities.
- Schema/database migration: No application data migration, but deployment artifact/profile migration is required.
- Cryptographic tool blocker: Yes. Nargo and Barretenberg availability blocks live validation.
- Dependencies: CRYPTO-ENV-BLOCKER-001 and authoritative production-capacity decision.

### ZK-002 - Proof public inputs are not bound to authoritative records

- Severity: High
- CWE: CWE-345 (insufficient verification of data authenticity), CWE-863 (incorrect authorization)
- Classification: Confirmed vulnerability
- Exact code: `backend/verification_service/app/api/routes/verification_routes.py:verify_proof`; `backend/verification_service/app/services/verification_service.py`; `backend/verification_service/app/repositories/verification_repository.py`; `backend/verification_service/app/schemas/verification_schemas.py`; `backend/zkp_service/app/services/prover_service.py:process_job`.
- Evidence: Verification persists and verifies request-supplied `sbom_root`, `vulnerability_db_root`, and `policy_hash`. The inspected path does not resolve these values to an authoritative SBOM record, approved/frozen vulnerability snapshot, and approved policy before certificate issuance. Circuit validity therefore proves consistency with caller inputs, not platform authority.
- Attack scenario: A caller submits a genuine proof for a caller-selected low-risk root/policy/snapshot triple and receives a certificate that is misattributed to the platform's authority.
- Preconditions: A valid proof for any accepted public inputs and access to verification/certificate routes.
- Impact: False compliance certificate, metadata misattribution, and loss of trust in the verification authority.
- Exploitability: Confirmed trust-model violation; live proof execution and exact artifact binding remain blocked by CRYPTO-ENV-BLOCKER-001.
- Existing controls: Mathematical verifier exit status, request schema bounds, certificate creation gate requiring `verified`. These do not perform authoritative lookup.
- Required remediation: Resolve every requested identifier/root to server-side approved records; compare proof public inputs with API inputs and authoritative records; enforce freshness/revocation and idempotency over authoritative identifiers; record actual verified references.
- Required regression test: Matching proof accepted; mismatched request roots, another SBOM/snapshot/policy, stale/revoked records, tampered proof, witness-as-proof, wrong VK/profile, and metadata misattribution rejected.
- Schema/database migration: Yes, unless an existing authoritative registry can be proven sufficient; certificate references and approval state must be persisted.
- Cryptographic tool blocker: Yes for real proof/artifact binding tests; application lookup tests can run without it.
- Dependencies: RBAC-001, VI-001, ZK-001, and an explicit authority model decision.

### API-002 - Internal proof-job error leakage

- Severity: Medium
- CWE: CWE-209 (generation of error message containing sensitive information)
- Classification: Confirmed security-control deficiency
- Exact code: `backend/zkp_service/app/services/prover_service.py:process_job`; `backend/zkp_service/app/repositories/zkp_repository.py:update_job_status`; `backend/zkp_service/app/schemas/zkp_schemas.py:ProofJobResponse`; `backend/zkp_service/app/api/routes/zkp_routes.py:get_proof_job`.
- Evidence: Subprocess stderr and `str(e)` are persisted in `error_message`, and the response schema exposes it. The job retrieval route lacks proven ownership enforcement.
- Attack scenario: A caller retrieves another job and reads filesystem paths, commands, tool diagnostics, or private witness-related details from an error.
- Preconditions: A failed job and access to the job retrieval route.
- Impact: Information disclosure and cross-tenant troubleshooting leakage.
- Exploitability: Confirmed from response and persistence flow.
- Existing controls: Some shared sanitization utilities and UUID job names; no allowlisted public error contract.
- Required remediation: Store protected internal diagnostics separately, return opaque error codes/correlation IDs, cap/redact logs, and authorize job access.
- Required regression test: Inject path/command/stderr/private markers and assert none appear in public response or unauthorized cross-user result.
- Schema/database migration: Possibly, if internal diagnostics are separated or response contract changes.
- Cryptographic tool blocker: No.
- Dependencies: RBAC-001 and ART-001.

### CFG-001 - Non-reproducible Compose deployment references

- Severity: Medium
- CWE: CWE-16 (configuration)
- Classification: Confirmed availability/operational risk
- Exact code/config: `docker-compose.yml` references `./docker/nginx.conf` and builds `frontend` from a context without an evidenced `frontend/Dockerfile`.
- Evidence: The referenced deployment artifacts were absent from the repository inventory; only an independent frontend build succeeded.
- Attack scenario: A clean deployment fails to build or starts without the intended gateway, leaving services unavailable or exposed differently than designed.
- Preconditions: Attempted Docker Compose deployment.
- Impact: Availability failure and security-boundary drift.
- Exploitability: Confirmed as a deployment defect; exact build failure was not claimed without executing the unavailable/unfinished topology.
- Existing controls: Compose dependency declarations and frontend build success outside Compose.
- Required remediation: Provide or correct deployment artifacts, pin images, define production profiles, and add clean-checkout Compose build/health validation.
- Required regression test: Clean checkout `docker compose config/build` and gateway/service health test.
- Schema/database migration: No.
- Cryptographic tool blocker: No, except if the production service image includes proof execution.
- Dependencies: CFG-002, CFG-003, and deployment architecture decision.

### CFG-002 - Health endpoint reports healthy without readiness checks

- Severity: Medium
- CWE: CWE-754 (improper check for unusual or exceptional conditions), CWE-693 (protection mechanism failure)
- Classification: Confirmed availability/operational security-control deficiency
- Exact code: `backend/shared/app_factory.py:create_app` initialization and `/api/v1/health` handler; `backend/shared/database.py:init_engine/get_engine`.
- Evidence: Database initialization exceptions are caught and startup continues. The health handler returns `healthy` without checking database connectivity, required circuit/VK artifacts, or proving tools.
- Attack scenario: Gateway routes traffic to a process that cannot persist data or execute required proof operations because readiness is falsely reported.
- Preconditions: Dependency failure during startup or runtime.
- Impact: Failed requests, inconsistent job state, misleading orchestration, and possible security-boundary bypass through degraded behavior.
- Exploitability: Confirmed code/control defect; deployment behavior remains unexecuted.
- Existing controls: Basic health response schema and startup logging.
- Required remediation: Split liveness from readiness; make readiness check required DB, selected profile, VK, and tool availability without exposing environment details; fail production startup or readiness as configured.
- Required regression test: DB unavailable, missing secret/VK/circuit/tool, degraded dependency, and liveness-versus-readiness cases.
- Schema/database migration: No.
- Cryptographic tool blocker: Tool checks can be tested without proof; real readiness validation is environment-blocked.
- Dependencies: ZK-001 and CRYPTO-ENV-BLOCKER-001.

### AUTH-001 - JWT secret fallback and password-length ambiguity

- Severity: Medium
- CWE: CWE-321 (use of hard-coded cryptographic key, for the fallback design), CWE-521 (weak password requirements), CWE-613 (insufficient session expiration/revocation control)
- Classification: Confirmed security-control deficiency
- Exact code: `backend/shared/auth.py:_get_secret_key`, `get_password_hash`, `verify_password`, `create_access_token`, `get_current_user`; `backend/shared/api/auth_routes.py:login`.
- Evidence: Missing `JWT_SECRET_KEY` creates a process-local ephemeral secret, making tokens inconsistent across workers/restarts. Password input is truncated to bcrypt's 72-byte limit. Issuer, audience, token ID, revocation, and rotation policy are not enforced in the inspected implementation.
- Attack scenario: A multi-process deployment rejects valid tokens unpredictably; users with distinct passwords after byte 72 authenticate equivalently; token compromise cannot be centrally revoked under the current lifecycle.
- Preconditions: Missing secret configuration, multi-process deployment, or long password input.
- Impact: Authentication availability, credential ambiguity, and incomplete session security.
- Exploitability: Confirmed configuration/control weakness. HS256 restriction, required `exp`/`sub`, dummy bcrypt checks, and generic login errors are valid mitigations for narrower claims.
- Existing controls: Explicit HS256 decode, required expiration and subject, bcrypt, dummy hash timing path, and password-hash exclusion from inspected responses.
- Required remediation: Fail production startup/readiness without a strong configured secret; define shared multi-service secret distribution, rotation and revocation; reject or safely pre-hash overlong passwords without weakening bcrypt semantics; add issuer/audience as architecture requires.
- Required regression test: Missing/weak production secret, multi-worker consistency, malformed/expired/wrong-algorithm/missing-claim tokens, long-password behavior, generic login failures, and hash non-disclosure.
- Schema/database migration: Potentially for password migration and token/session revocation state.
- Cryptographic tool blocker: No.
- Dependencies: Deployment secret-management decision.

### ART-001 - Unprotected witness/artifact storage and incomplete cleanup

- Severity: Medium
- CWE: CWE-922 (insecure storage of sensitive information), CWE-459 (incomplete cleanup)
- Classification: Confirmed security-control deficiency; impact unverified
- Exact code: `backend/zkp_service/app/services/prover_service.py:process_job`; `backend/verification_service/app/core/verifier.py:NoirVerifier.verify`; `circuits/Prover.toml` and proof directories.
- Evidence: Private witness TOML, generated witness/proof artifacts, and temporary files are written to shared circuit paths. `finally` cleanup exists, but restrictive permissions, crash scavenging, symlink defenses, retention, and artifact ownership are not evidenced.
- Attack scenario: Another local process, later job, backup, or failed cleanup reads witness or proof data; stale artifacts are reused or confused across jobs.
- Preconditions: Local filesystem access, crash/kill, cleanup failure, or concurrent jobs.
- Impact: Privacy leakage, cross-job integrity failure, and storage exhaustion.
- Exploitability: Code gap confirmed; deployment permissions and actual impact require evidence.
- Existing controls: UUID-based names and `finally` cleanup.
- Required remediation: Use per-job private directories, restrictive creation modes, no-follow/safe file handling, stale-artifact scavenging, bounded retention, container user isolation, and explicit artifact ownership.
- Required regression test: Exception/timeout cleanup, stale artifact rejection, concurrent isolation, symlink replacement, permission checks, and cancellation.
- Schema/database migration: No database migration; operational artifact policy required.
- Cryptographic tool blocker: No to establish file-control gap; yes for real proof artifact lifecycle testing.
- Dependencies: API-001, SUB-001, and resource architecture.

### DB-002 - Shared service database credentials defeat logical isolation

- Severity: Medium
- CWE: CWE-284 (improper access control), CWE-732 (incorrect permission assignment)
- Classification: Confirmed security-control deficiency; deployment permission impact unverified
- Exact code/config: `docker-compose.yml` gives each service the same DB host/user/password settings; `docs/DATABASE_SCHEMA.md` defines logical schemas; `backend/shared/database.py` provides shared database access.
- Evidence: Logical schemas are documented, but per-service principals, grants, row-level controls, and live SQL Server permission tests are absent.
- Attack scenario: A compromised service uses shared credentials to read or mutate another service's private schema.
- Preconditions: Service compromise or malicious code execution in one service and reachable database credentials.
- Impact: Cross-boundary confidentiality and integrity loss.
- Exploitability: Confirmed architectural deficiency; actual SQL permissions are unverified.
- Existing controls: ORM filters, logical schema naming, and intended service ownership documentation.
- Required remediation: Use service-specific principals, least-privilege grants, schema ownership, and deployment verification; do not rely on application convention alone.
- Required regression test: Live or faithfully provisioned SQL permission matrix proving cross-service denial.
- Schema/database migration: Yes, database principals/grants and potentially schema ownership.
- Cryptographic tool blocker: No.
- Dependencies: RBAC-001 and production database access.

### SNAP-001 - Provisional vulnerability root exposed or inconsistently contracted

- Severity: Low
- CWE: CWE-200 (exposure of sensitive information)
- Classification: Confirmed security-control/contract deficiency
- Exact code: `backend/vulnerability_service/app/schemas/vulnerability_schemas.py:VulnerabilitySnapshotResponse`; `backend/vulnerability_service/app/api/routes/vulnerability_routes.py:list_snapshots`; `backend/vulnerability_service/tests/test_vulnerability_ingestion.py:test_response_does_not_expose_provisional_smt_root`.
- Evidence: The schema includes `provisional_smt_root`, while the existing test and service documentation state that provisional roots should not be exposed. The root is also not an approved authoritative root.
- Attack scenario: A caller observes internal unapproved commitments and treats them as authoritative, or uses them to correlate snapshot state.
- Preconditions: Access to snapshot retrieval and contract mismatch surviving deployment.
- Impact: Contract/privacy confusion and increased trust-model attack surface; no direct cryptographic bypass established.
- Exploitability: Confirmed contract inconsistency from current schema/test evidence.
- Existing controls: A regression test expects non-disclosure, and approved-root semantics are documented.
- Required remediation: Decide whether provisional roots are private; remove them from public responses or replace them with immutable approved-root fields and state metadata.
- Required regression test: Response schema/state tests for ingested, approved, frozen, and revoked snapshots.
- Schema/database migration: Possible API/client migration; no database migration if existing columns remain private.
- Cryptographic tool blocker: No.
- Dependencies: VI-001 and authority lifecycle decision.

## Probable findings requiring further evidence

### DB-001 - Raceable verification idempotency and unconstrained state

- Severity: Medium
- CWE: CWE-362 (race condition), CWE-915 (improperly controlled modification of dynamically-managed code resources; only as a broad state-integrity analogue)
- Classification: Requires further evidence / probable security-control deficiency
- Exact code: `backend/verification_service/app/repositories/verification_repository.py:create_or_get_verification` and certificate creation; `backend/alembic/versions/001_initial_schema.py` verification tables.
- Evidence: Fingerprint lookup and insert are separate from a demonstrated unique database constraint; state values are strings. No live concurrent reproduction was executed.
- Attack scenario: Two identical requests race and create duplicate verification/certificate records or inconsistent states.
- Preconditions: Concurrent requests and a database configuration permitting the race.
- Impact: Duplicate certificates, inconsistent idempotency, and audit ambiguity.
- Exploitability: Plausible but unconfirmed; requires concurrent integration test and schema inspection.
- Existing controls: Repository lookup, transaction/session usage, and rollback behavior.
- Required remediation: Add unique constraints, explicit state enum/transitions, and transactionally atomic idempotency.
- Required regression test: Concurrent duplicate submissions and competing state transitions against a real supported database.
- Schema/database migration: Yes.
- Cryptographic tool blocker: No.

### CAN-001 - Cross-source canonicalization/identity mismatch

- Severity: Medium
- CWE: CWE-20 (improper input validation)
- Classification: Requires further evidence / probable integrity risk
- Exact code: `backend/sbom_service/app/services/canonicalization.py`; `backend/sbom_service/app/services/identity.py`; `backend/vulnerability_service/app/services/vulnerability_service.py`; shared PURL utilities.
- Evidence: SBOM identity and vulnerability mapping both use canonicalization-related helpers, but the audit observed differing behavior when display names and PURLs disagree. Full ecosystem, alias, Unicode, and malformed-field equivalence was not proven.
- Attack scenario: The SBOM commitment and vulnerability lookup identify the same package differently, causing a vulnerable component to be scored as absent or a wrong record to be matched.
- Preconditions: Ecosystem-specific alias/name/PURL mismatch.
- Impact: False negative vulnerability assessment or inconsistent roots.
- Exploitability: Plausible; current vector tests cover many cases but not the complete cross-service corpus.
- Existing controls: Shared PURL normalization, deterministic JSON, duplicate preservation, and crypto vectors.
- Required remediation: Freeze one cross-service identity contract and vectors for all supported ecosystems before changing protocol behavior.
- Required regression test: Same input through SBOM and vulnerability paths, aliases, Unicode, namespace, qualifiers, versions, duplicates, and malformed values.
- Schema/database migration: Possible protocol/data migration if existing commitments change.
- Cryptographic tool blocker: No for Python cross-service tests; yes for final Noir interoperability.
- Manual decision: Canonical identity contract must be approved before implementation changes.

### SUB-001 - Subprocess shell, descendant cleanup, and output/resource controls

- Severity: Medium
- CWE: CWE-78 (OS command injection, not demonstrated for current UUID values), CWE-400 (uncontrolled resource consumption)
- Classification: Requires further evidence / hardening-level runtime risk
- Exact code: `backend/zkp_service/app/services/prover_service.py:process_job`; `backend/verification_service/app/core/verifier.py:NoirVerifier.verify`.
- Evidence: Barretenberg is invoked through `bash -c`; UUID-derived values are currently not request-controlled, so direct injection is not shown. Timeouts are set, but process-group/descendant termination and stdout/stderr caps are not demonstrated.
- Attack scenario: A future controllable identifier or malicious tool output causes command interpretation, orphaned processes, memory growth, or cross-job artifact interference.
- Preconditions: Tool invocation, timeout/failure, concurrent jobs, or future input-path change.
- Impact: Availability loss, diagnostics leakage, and potentially command execution if the interpolation boundary changes.
- Exploitability: Current direct injection claim is unconfirmed; hardening is justified.
- Existing controls: UUID names, argument arrays for the outer WSL command, timeouts, and cleanup.
- Required remediation: Eliminate shell interpolation, use direct argument arrays, process groups/job objects, bounded output capture, cancellation, and descendant cleanup.
- Required regression test: Timeout with child process, oversized stderr/stdout, concurrent jobs, cancellation, and hostile identifier regression.
- Schema/database migration: No.
- Cryptographic tool blocker: Useful for runtime tests, but not needed to confirm the code design gap.

### CFG-003 - Host port and service exposure may bypass intended boundary

- Severity: Medium
- CWE: CWE-16 (configuration), CWE-284 (improper access control)
- Classification: Requires further evidence / probable deployment exposure
- Exact code/config: `docker-compose.yml` exposes ports 80 and 1433; service processes bind `0.0.0.0`; referenced gateway configuration is absent.
- Evidence: The database exposure is commented development-only, but no production profile or network policy enforces that restriction. Firewall, gateway, and hosting controls were unavailable.
- Attack scenario: An externally reachable database or direct service endpoint bypasses the intended gateway authentication and privacy boundary.
- Preconditions: Production deployment using the current Compose exposure and permissive host/network policy.
- Impact: Direct database access, authentication bypass at the gateway layer, and expanded attack surface.
- Exploitability: Requires deployment/network evidence.
- Existing controls: Intended Nginx gateway and development-only comment; neither is an enforced production control.
- Required remediation: Define production network policy, remove DB host exposure, restrict service networks, and validate the gateway path.
- Required regression test: External reachability matrix and clean Compose deployment test.
- Schema/database migration: No.
- Cryptographic tool blocker: No.

## Hardening recommendations

### PARSER-001 - Explicit parser/component/depth budgets

- Severity: Low
- CWE: CWE-400 (uncontrolled resource consumption)
- Classification: Hardening recommendation
- Exact code: `backend/sbom_service/app/services/parser.py`, `validator.py`, and `SBOMUploadRequest`; request-size middleware.
- Evidence: A 10 MB body bound exists, but component count, nesting depth, scalar count, and parser-time budgets are not all enforced before `json.loads` and validation. Existing tests cover many malformed inputs but not a complete resource corpus.
- Attack scenario: Deep or structurally expensive JSON consumes disproportionate CPU/memory within the body limit.
- Preconditions: Reachable upload route and parser resource pressure.
- Impact: Availability degradation; exploit severity depends on deployment limits.
- Exploitability: Not confirmed as a distinct vulnerability.
- Existing controls: 10 MB request bound, schema bounds, later Merkle capacity checks.
- Required remediation/test: Add bounded parser/depth/component/scalar limits and adversarial resource corpus; no schema migration.
- Cryptographic tool blocker: No.

### PRIV-001 - Logging, retention, backup, and private-data minimization

- Severity: Medium
- CWE: CWE-532 (insertion of sensitive information into log file), CWE-922 (insecure storage)
- Classification: Hardening recommendation; impact unverified
- Exact code: `backend/shared/logging.py`, response schemas, raw SBOM/witness persistence paths, deployment/backup configuration.
- Evidence: A limited `SecurityAwareFilter` exists, but live logs, backups, crash dumps, retention, storage permissions, and every structured field were not available for verification.
- Attack scenario: Raw SBOM, PURLs, witness data, paths, or secrets enter logs/backups/diagnostics outside the intended boundary.
- Preconditions: Logging/error/backup path containing an unhandled field.
- Impact: Confidentiality and privacy loss.
- Exploitability: Unverified operational impact.
- Existing controls: Redaction patterns, response field exclusions, and privacy tests.
- Required remediation/test: Allowlist structured logs, protected diagnostics, retention/deletion, encryption, and backup controls; no application schema migration unless storage policy requires it.
- Cryptographic tool blocker: No.

### DEP-001 - Dependency and container supply-chain assurance

- Severity: Medium
- CWE: CWE-1104 (use of unmaintained third-party components), CWE-16 (configuration)
- Classification: Hardening recommendation / scan availability gap
- Exact code/config: backend requirements, `frontend/package.json`/lockfile, service Dockerfiles, `docker-compose.yml`, absent CI workflows.
- Evidence: Frontend audit passed and Gitleaks was clean in limited scopes. Python/container/circuit scanners were unavailable; Docker tags float and no digest/signature/SBOM attestation pipeline was found.
- Attack scenario: A mutable base image, dependency, or downloaded toolchain changes between builds or contains a vulnerability.
- Preconditions: Build or deployment from unpinned external source.
- Impact: Supply-chain compromise and untracked vulnerability exposure.
- Exploitability: No specific compromised dependency was established.
- Existing controls: Pinned Python package requirements and frontend lockfile; Nargo version in the Noir Dockerfile.
- Required remediation/test: Add reproducible scans, approved artifact provenance, image digests, SBOM/signature verification, and CI checks; no application migration.
- Cryptographic tool blocker: CRYPTO-ENV-BLOCKER-001 is a separate concrete tool availability blocker.

### API-003 - Canonical public-input encoding validation

- Severity: Low
- CWE: CWE-20 (improper input validation)
- Classification: Hardening recommendation
- Exact code: `backend/verification_service/app/schemas/verification_schemas.py:VerifyProofRequest`.
- Evidence: Roots/hashes have broad length bounds and prefix/character validation rather than exact field encodings. A cryptographic bypass was not demonstrated.
- Attack scenario: Alternate encodings create ambiguous records, failed verification, or metadata confusion.
- Preconditions: Caller submits noncanonical but schema-accepted root strings.
- Impact: Integrity ambiguity and interoperability failures.
- Exploitability: Not confirmed as a bypass.
- Existing controls: Pydantic validators, maximum lengths, verifier result gate.
- Required remediation/test: Enforce exact canonical field encoding and negative encoding corpus; possible API contract migration.
- Cryptographic tool blocker: Needed only for final interoperability validation.

### CFG-004 - CORS, TLS, browser token, and CSRF deployment policy

- Severity: Low
- CWE: CWE-352 (cross-site request forgery, conditional), CWE-16 (configuration)
- Classification: Hardening recommendation / requires deployment evidence
- Exact code: `backend/shared/app_factory.py:create_app` CORS configuration; frontend auth flow; reverse-proxy/TLS deployment configuration.
- Evidence: Explicit origins are configured, but credentials are allowed and request headers are broad. TLS termination, browser token storage, CSRF posture, and reverse-proxy behavior were not evidenced.
- Attack scenario: Misconfigured browser credential flow permits cross-origin state-changing requests or token exposure.
- Preconditions: Cookie/credential-based browser flow and permissive deployment configuration.
- Impact: Conditional account or state mutation exposure.
- Exploitability: Not established because the frontend token flow and production proxy are not present.
- Existing controls: Explicit origin list and no observed completed browser auth flow.
- Required remediation/test: Decide token/CSRF architecture, constrain headers, validate TLS/proxy behavior, and execute browser-authenticated cross-origin tests.
- Schema/database migration: Possible client/auth-flow migration.
- Cryptographic tool blocker: No.

## Environmental blocker

### CRYPTO-ENV-BLOCKER-001 - Production cryptographic validation/toolchain availability

- Type: Production cryptographic validation/toolchain availability blocker
- Status: Open
- Severity: Informational for application classification; operationally release-blocking
- Impact: Production proof generation and verification cannot currently be re-executed.
- Evidence: Repository documentation and circuit manifests identify Noir/Nargo `0.32.0`; application code expects Linux tooling through WSL `kali-linux` and `~/.bb/bb`; Nargo and Barretenberg are unavailable in Windows and WSL; Barretenberg version is not pinned or approved. The bundled Windows Nargo did not provide usable version/check output.
- Classification: Environmental blocker, not automatically an application vulnerability.
- Safe next action: Obtain an approved Nargo `0.32.0` artifact and an explicitly approved compatible Barretenberg release, install in controlled Linux/WSL or Docker, record versions and hashes, validate the selected circuit/profile/VK, then run real positive and negative proof tests. Do not install an arbitrary version or alter circuit semantics.
- Required regression/validation: Real circuit compile, witness generation, proof generation, proof verification, wrong-VK/profile rejection, tampered proof rejection, and public-input binding tests.

## False positives and narrowed claims

The following proposed claims were reviewed and excluded from the active finding count:

1. SQL injection in inspected ORM filters: no user SQL string reaches the inspected SQLAlchemy filters; raw SQL and database permissions remain separate unknowns.
2. JWT algorithm confusion: encoding fixes HS256 and decoding restricts algorithms to HS256; secret lifecycle remains `AUTH-001`.
3. Password-hash disclosure in inspected register/login/me handlers: hashes are not included; future generic ORM responses remain a review concern.
4. Direct shell injection through current job IDs: UUID-derived values are not currently request-controlled; shell use remains `SUB-001` hardening.
5. Unbounded pagination bypass: limits are constrained to 1-100; repeated-page abuse remains covered by resource controls.
6. Duplicate component omission: identity and commitment paths preserve ordered duplicates; cross-source identity remains `CAN-001`.
7. Certificate without a verification gate: certificate creation checks `verified`; authoritative root binding remains `ZK-002`.
8. Fake/mutated proof artifacts proving a forgery vulnerability: no live bypass was executed, so this remains unverified and toolchain-blocked.
9. Passing backend tests as proof of security, or clean Gitleaks/npm scans as complete clearance: both claims exceed their tested scope and are not findings themselves.

## Priority and remediation order

### P0 - Fix before further product development

1. `RBAC-001` - Define and enforce ownership, tenant isolation, and effective role permissions.
2. `API-001` - Authenticate all sensitive/mutating/expensive routes before work begins.
3. `VI-001` - Establish trusted vulnerability ingestion, approval, freeze, revocation, and immutable roots.
4. `ZK-002` - Bind proof public inputs to request values and authoritative approved records before certificates.
5. `ZK-001` - Freeze the production circuit/profile/VK contract, subject to the toolchain blocker.

### P1 - Fix before security re-audit

1. `AUTH-001` - Remove production JWT fallback and define multi-process secret/session lifecycle.
2. `API-002` - Sanitize public job errors and protect diagnostics.
3. `CFG-002` - Separate liveness/readiness and validate required dependencies.
4. `ART-001` and `SUB-001` - Bound jobs, isolate artifacts, terminate descendants, and remove shell interpolation.
5. `DB-001` - Prove and enforce verification idempotency under concurrency.
6. `DB-002` - Establish service-specific database principals and least-privilege grants.
7. `CAN-001` - Freeze cross-service canonical identity semantics before protocol changes.

### P2 - Harden before release

1. `PARSER-001` - Add parser/depth/component resource budgets.
2. `PRIV-001` - Complete logging, retention, backup, and artifact privacy controls.
3. `DEP-001` - Add dependency/container/circuit supply-chain scans and artifact provenance.
4. `CFG-001` and `CFG-003` - Make Compose/gateway/network exposure reproducible and enforceable.
5. `SNAP-001`, `API-003`, and `CFG-004` - Resolve public contract, canonical encoding, and browser/deployment policy gaps.

### ENV - External blocker

1. `CRYPTO-ENV-BLOCKER-001` - Approve and provision the compatible Nargo/Barretenberg Linux toolchain, then execute real cryptographic validation.

## Adversarial challenge summary

- Authentication is not authorization: the presence of `get_current_user` does not establish role, owner, or tenant checks.
- A gateway is not a demonstrated compensating control: the referenced Nginx configuration is absent and service routes are directly defined.
- Cryptographic validity is not platform authority: caller-selected roots can be mathematically valid without representing approved records.
- Provisional roots and completed snapshots are not trusted merely because ingestion committed a transaction.
- UUID secrecy, request schema validation, and Pydantic bounds do not replace ownership, approval, or rate controls.
- Mocked verifier tests establish repository gating only; they do not establish proof authenticity, VK correctness, or public-input extraction.
- Timeouts alone do not establish process-tree cleanup, bounded output, or safe cancellation.
- A healthy HTTP response and passing unit tests do not establish database, artifact, toolchain, or deployment readiness.

## Manual architectural decisions required

Remediation cannot safely choose these values implicitly:

1. The role/tenant ownership matrix and safe treatment of legacy records.
2. The trusted vulnerability importer, snapshot approval/freeze/revocation lifecycle, and provenance/signature model.
3. Whether certificates may reference arbitrary public commitments or only approved registry triples.
4. The single production circuit capacity/profile and approved Nargo/Barretenberg/VK artifact set.
5. Canonical identity semantics across SBOM and vulnerability ingestion.
6. Proof job queue/quota model and private witness retention policy.
7. Per-service SQL principals and production gateway/TLS/network boundaries.

## Phase 1 report

PHASE: Phase 1 - Forensic finding reconciliation
STATUS: COMPLETE
FILES INSPECTED: All 22 files under `docs/security/audit/`; `docs/THREAT_MODEL.md`; `docs/SECURITY_BOUNDARY.md`; `docs/ARCHITECTURE.md`; `docs/SERVICE_CONTRACTS.md`; `docs/DATABASE_SCHEMA.md`; `docs/ZKP_SPECIFICATION.md`; `docs/CRYPTO_INTEROPERABILITY.md`; current high-risk route, model, auth, prover, verifier, database, Docker, and circuit files
FILES MODIFIED: `docs/security/audit/22_MASTER_FINDING_RECONCILIATION.md`
SECURITY FINDINGS ADDRESSED: None; this phase reconciled and prioritized findings only
TESTS ADDED: None
COMMANDS EXECUTED: Audit/document reads, source searches for routes/models/auth/subprocess/health controls, and baseline fact review
ACTUAL RESULTS: 12 confirmed findings, 4 probable/requires-evidence findings, 5 hardening recommendations, 1 environmental blocker, and 9 false-positive/narrowed claim clusters were deduplicated and classified
UNRESOLVED ISSUES: All findings listed above remain open; production cryptographic validation is blocked; manual architectural decisions are required before P0 implementation
ASSUMPTIONS: Existing uncommitted work is preserved and the inspected source is the source intended for deployment; external gateway, database, CI, firewall, secret-store, and hosting controls are not assumed without evidence
RESIDUAL RISK: High; authorization, trusted intelligence, proof authority binding, and production profile integrity remain unresolved
NEXT PHASE: Remediation stages beginning with P0 decisions and controls; no implementation was performed in Phase 1

PHASE 1 STATUS: COMPLETE

Confirmed findings by severity: Critical 0, High 5, Medium 6, Low 1.
Number of unconfirmed findings: 4 probable/requires further evidence.
Number of environmental blockers: 1.
Highest-risk finding: ZK-002, because a valid proof can be accepted and certified without proving that its public roots identify authoritative approved records.
Whether remediation can begin: Yes, after the manual architectural decisions above; no remediation was implemented in this phase.
Manual architectural decision required: Yes, especially ownership/tenant authority, vulnerability snapshot trust lifecycle, authoritative proof-binding model, and production circuit/VK/toolchain profile.

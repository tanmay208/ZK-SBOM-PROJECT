# Decision Closure

Date: 2026-09-13
Phase: 3 - Release-blocking decision closure
Scope: Evidence and decision status only. No implementation performed.

## Executive result

The nine Phase 2 decisions were investigated against the current source, models, migrations, circuit manifests, artifacts, repository documentation, and locally available WSL tooling. No decision is resolved by explicit project approval in the current workspace. Three decisions are blocked by missing evidence or an unsafe legacy-data choice; the remaining six require manual approval of the proposed architecture.

The current WSL environment contains `/home/kali/.bb/bb`, which reports Barretenberg `0.46.1`. This is a newly verified binary-presence fact, not an approved production toolchain. Nargo remains unavailable, the production VK is absent, and the current verifier invocation accepts only a VK path and proof path. No supported expected-public-input interface or public-input extraction mechanism was demonstrated.

## Evidence boundary

Evidence used:

- [22_MASTER_FINDING_RECONCILIATION.md](./22_MASTER_FINDING_RECONCILIATION.md)
- [23_REMEDIATION_ARCHITECTURE.md](./23_REMEDIATION_ARCHITECTURE.md)
- [24_REMEDIATION_PLAN.md](./24_REMEDIATION_PLAN.md)
- [25_SECURITY_DECISIONS_REQUIRED.md](./25_SECURITY_DECISIONS_REQUIRED.md)
- `docs/security/audit/09_CRYPTOGRAPHIC_ZK_AUDIT.md` and `10_RUNTIME_SUBPROCESS_AUDIT.md`
- `docs/ZKP_SPECIFICATION.md`, `docs/CRYPTO_INTEROPERABILITY.md`, `docs/DATABASE_SCHEMA.md`, `docs/SERVICE_CONTRACTS.md`, and `docs/IMPLEMENTATION_PLAN.md`
- Current verifier/prover routes and services, current SQLAlchemy models and initial Alembic migration, `circuits/Nargo.toml`, `circuits_dev/Nargo.toml`, `docker/Dockerfile.noir`, and checked-in target artifacts.

Important distinctions:

- **Capability unknown:** the installed or selected tool may support a capability, but no supported documentation or executable evidence was available.
- **Capability disproven in current implementation:** the current application path does not perform the required control, regardless of what a future tool may support.
- **Environment unavailable:** a required binary, artifact, deployment, or external authority is absent, so the behavior cannot be validated.

## Decision dispositions

### D-001 - Tenant and role authority

Status: REQUIRES MANUAL APPROVAL

Proposed decision: Use server-side user, tenant-membership, and role records. Keep `admin`, `vendor`, `auditor`, `buyer/verifier`, and `trusted_importer` distinct. Resolve authorization from the authenticated `sub` and database state, never from request fields. Deny by default and enforce policy in both routes and services.

Alternatives considered:

- Trust roles in JWT claims: rejected because role revocation and multi-service consistency are not assured.
- Enforce only at the gateway: rejected because the gateway configuration is absent and direct service boundaries must remain safe.
- Use one broad service role: rejected because it cannot enforce tenant isolation or least privilege.

Security and operational consequences: Adds reliable vertical and horizontal authorization but requires membership lookup, cache invalidation, service-to-service identity, and careful 401/403/404 behavior. A bad policy can deny legitimate operations; fail-open behavior is unacceptable.

Migration impact: Add tenant/membership and resource-owner relationships. Existing records cannot be assigned automatically without evidence and must be mapped or quarantined.

Evidence needed: Approved permission matrix, owner/tenant source of truth, service identity design, and two-user cross-tenant authorization tests.

Disposition rationale: The current `User` model has only a single `role` and no tenant membership; resource models have no reliable owner relationship. This is an architecture choice, not something current evidence can resolve.

### D-002 - Legacy record ownership and migration

Status: BLOCKED

Proposed decision: Backfill only records with reliable owner evidence, explicitly review exceptional mappings, and quarantine records with no safe mapping. Quarantined records cannot be read, mutated, used for proofs, or used for certificates until mapped.

Alternatives considered:

- Assign all legacy records to an administrator: rejected as unsafe misattribution.
- Treat UUID ownership as sufficient: rejected because UUID secrecy is not authorization.
- Leave all legacy records globally readable: rejected because it preserves the confirmed IDOR/control defect.

Security and operational consequences: Quarantine may make historical records temporarily unavailable, but it prevents cross-user disclosure and false certificates. Mapping requires an auditable operator workflow.

Migration impact: The initial migration contains no owner or tenant columns for the affected domain resources. A new migration and a record-by-record accounting report are required; rollback must not make quarantined records public.

Evidence needed: Existing user/application ownership metadata, deployment data inventory, tenant assignment source, and an approved mapping/quarantine procedure. None is present in the repository evidence.

Disposition rationale: The code and schema demonstrate missing ownership fields, but no safe assignment evidence exists. Implementation is blocked until data owners approve the treatment.

### D-003 - Vulnerability importer and approval separation

Status: REQUIRES MANUAL APPROVAL

Proposed decision: Permit ingestion only for an authenticated trusted importer. Require server-side validation, source provenance/digest, explicit approval, immutable freeze, and revocation. Separate importer and approver roles unless an approved exception is documented. Only approved, frozen, non-revoked roots may enter proof or certificate workflows.

Alternatives considered:

- Treat every authenticated vendor as an importer: rejected because it permits snapshot poisoning.
- Treat ingestion completion as approval: rejected because syntax validity is not trust.
- Let the client submit an approved/frozen boolean: rejected because authority must come from the database and authorization workflow.

Security and operational consequences: Protects the authority statement but introduces source outage, approval latency, revocation, and replacement-version operations. A compromised importer or approver remains a residual supply-chain risk.

Migration impact: Add provenance, importer, lifecycle, approval, freeze, revocation, replacement, canonicalization-version, and immutable-root data. Existing provisional snapshots require classification and cannot automatically become authoritative.

Evidence needed: Named trusted sources, approver ownership, signature/digest policy, state-transition policy, and retention/revocation procedure.

Disposition rationale: Current code has only a free status string and provisional root; this confirms the defect but does not choose the organization’s trust authority or separation of duties.

### D-004 - Authoritative proof-input binding mechanism

Status: BLOCKED

Proposed decision: Certificate issuance must require a supported cryptographic mechanism that establishes:

```text
verified proof public inputs == API request public inputs == authoritative records
```

The ordered vector is `SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`. Acceptable evidence is a supported verifier interface that takes expected inputs, or a supported proof API that exposes public inputs for exact comparison before/with verification.

Alternatives considered:

- Compare request strings only: rejected; caller data is not authority.
- Hash the proof artifact or inspect labels: rejected; this does not bind semantic public inputs.
- Invent byte offsets or a custom proof parser: rejected; proof format is tool-version-specific and unsupported parsing could create a false security claim.
- Trust Barretenberg exit code with only `-k` and `-p`: rejected; it proves only what the verifier actually verifies, not equality to authoritative records.

Security and operational consequences: Correct binding prevents false certificate attribution but may require a supported verifier API, wrapper, or principled circuit/interface change. If no supported mechanism exists, certificate issuance must remain disabled.

Migration impact: Certificate records need authoritative SBOM/snapshot/policy IDs, profile ID, VK hash, verified-input digest/vector, and verifier version. Existing certificates cannot be reclassified as authority-bound without re-verification.

Evidence available: `NoirVerifier.verify` invokes `bb verify -k ./target/vk -p proofs/<id>.proof` and supplies no expected input vector. `VerificationService.process_verification` passes only the proof artifact to the verifier and `VerificationRepository.create_verification_record` stores caller-supplied roots. The current implementation therefore disproves that the required invariant is enforced today.

Evidence missing: An approved Barretenberg/Noir version, a valid production VK and proof, official interface documentation, and executable positive/negative tests showing expected-input enforcement or supported public-input extraction.

Tool result: WSL `/home/kali/.bb/bb` reports `0.46.1`; `verify --help`, `verify -h`, and `verify --verbose` did not display an interface and attempted to read a missing `./target/vk`. Nargo is absent. This is environment unavailability and does not disprove what the binary may support under valid artifacts.

Disposition rationale: Capability is unknown for the approved stack, current application enforcement is disproven, and the decision is release-blocked. No implementation may claim ZK-002 closure.

### D-005 - Production circuit/profile/VK contract

Status: BLOCKED

Proposed decision: Select one immutable production profile manifest containing circuit source/compiled hashes, `MAX_COMPONENTS`, Merkle/SMT depths, witness dimensions, public-input order, Nargo/Noir version, Barretenberg version, VK hash, proof artifact hash, and verifier interface version. Startup/readiness fails closed on any mismatch or missing production artifact.

Alternatives considered:

- Use `DEV_MODE` to select a profile at runtime: rejected as an unsafe production fallback.
- Treat checked-in target JSON as proof of a valid production VK: rejected because production `target/vk` is absent.
- Support implicit profile inference from a request: rejected because API callers must not select cryptographic profiles.

Security and operational consequences: Prevents cross-profile proof confusion but requires artifact release management and fail-closed deployment behavior. Missing artifacts cause service unavailability rather than silently degraded proof claims.

Migration impact: Proof jobs and certificates must record profile/VK identity. Existing artifacts require inventory and either validation under the selected profile or retirement/quarantine.

Evidence available: Both circuit manifests declare compiler version `0.32.0`; Docker pins Nargo `v0.32.0`; production target JSON exists without `target/vk`; development target contains a 1,719-byte `vk`; production proof is a 10-byte placeholder. Phase 1 also identified Python depth 10/1024 versus circuit/prover eight/depth 3.

Evidence missing: Approved capacity decision, Nargo executable, approved Barretenberg version, reproducible compilation, production VK, artifact hashes, and real cross-profile tests.

Disposition rationale: The profile mismatch and missing production VK are established, but the authoritative production profile cannot be selected from repository evidence. This decision is blocked.

### D-006 - Proof job queue, quotas, and process isolation

Status: REQUIRES MANUAL APPROVAL

Proposed decision: Initially use durable job states with bounded admission and a global concurrency limit, plus per-user/tenant queued and active quotas. Use private job directories, direct subprocess arguments, process-group cleanup, timeouts, cancellation, output caps, and stale-artifact scavenging. Adopt an external queue when deployment scale requires it.

Alternatives considered:

- Keep synchronous proof generation in the request: rejected because expensive work is directly exposed and current route is synchronous.
- Add only a timeout: rejected because it does not provide admission control, descendant cleanup, quota, or artifact isolation.
- Introduce a full external queue immediately: possible, but operationally larger than the first bounded-admission stage.

Security and operational consequences: Limits DoS and cross-job leakage but introduces queue backpressure, cancellation semantics, worker monitoring, and quota administration.

Migration impact: Add job owner/tenant, queue state, attempt, timeout, and artifact metadata fields; clients must consume asynchronous job states.

Evidence needed: Expected workload, deployment worker count, acceptable proof latency, quota owner, retention SLA, and operational queue capability.

Disposition rationale: The security direction is supported by code evidence, but the product’s operational capacity and queue ownership are not decided.

### D-007 - Database isolation model

Status: REQUIRES MANUAL APPROVAL

Proposed decision: Give each microservice a distinct SQL principal with least-privilege schema grants; retain application-level owner/tenant predicates and use database row-level controls if required by the deployment threat model.

Alternatives considered:

- Shared `sa`-style credentials for every service: rejected because logical schema names do not enforce isolation.
- Application predicates only: insufficient after service compromise.
- Separate database servers: inconsistent with the documented one SQL Server logical-schema architecture and not required if grants are correctly configured.

Security and operational consequences: Reduces lateral database access but adds credential rotation, migration ownership, deployment secrets, and permission testing.

Migration impact: Database users, schema grants, possibly row-level policies, and service connection configuration must be migrated atomically.

Evidence needed: SQL Server deployment permissions, service account ownership, required cross-schema reads, and operational credential rotation support.

Disposition rationale: Compose currently supplies shared database settings and no live grant evidence exists. The risk is confirmed, but the exact SQL Server control model requires deployment-owner approval.

### D-008 - JWT secret and session lifecycle

Status: REQUIRES MANUAL APPROVAL

Proposed decision: Production fails startup/readiness without a strong configured shared verification secret or an approved asymmetric service-verification design. Define issuer/audience, token lifetime, rotation overlap, revocation, logout/replay behavior, and multi-worker consistency. Define an approved policy for passwords exceeding bcrypt’s native input limit.

Alternatives considered:

- Process-local ephemeral secret: rejected for independently running services.
- Put roles/tenant authority only in JWT claims: rejected because revocation and authority become stale/client-carried.
- Silently truncate long passwords: rejected because distinct passwords become equivalent.

Security and operational consequences: Improves consistency and session control but requires secret distribution, rotation, recovery, and potentially session state.

Migration impact: Existing tokens may be invalidated during secret/lifecycle migration; long-password policy may require user reauthentication or password reset.

Evidence needed: Deployment secret store, service topology, rotation requirements, token consumers, logout requirements, and approved password policy.

Disposition rationale: Current code evidence confirms the fallback and bcrypt ambiguity; it cannot select the organization’s lifecycle policy.

### D-009 - Canonical identity and public-input API contract

Status: REQUIRES MANUAL APPROVAL

Proposed decision: Freeze a versioned canonical identity contract shared by SBOM, vulnerability, SMT, and proof witness paths, including PURL/name/version precedence, aliases, Unicode, duplicates, field encoding, and public-input order.

Alternatives considered:

- Let each service canonicalize independently: rejected because roots can diverge.
- Change canonicalization opportunistically while fixing ZK code: rejected because existing commitments may become unverifiable.
- Preserve current behavior without a versioned contract: insufficient for future migrations and cross-service evidence.

Security and operational consequences: Prevents mismatched vulnerability lookups and root derivation, but changes may invalidate existing data or require versioned commitments.

Migration impact: Existing records may require a canonicalization version, re-ingestion, or quarantine; proof/profile manifests must record the version.

Evidence needed: Approved ecosystem support list, cross-service vector corpus, existing data compatibility assessment, and protocol owner approval.

Disposition rationale: Current Python vectors provide partial evidence, but full cross-service and Noir compatibility is not proven. Manual approval remains required.

## Release-blocking question closure

### RQ-001 - Can proof inputs be bound to request and authority?

Status: BLOCKED.

Current implementation: Does not enforce it. The verifier receives only VK/proof paths; the service verifies only the artifact and persists request roots. This is capability disproven in the current application path.

Underlying stack: Capability unknown. The installed WSL Barretenberg binary is `0.46.1`, but no approved version, valid production VK, successful verification, or documented expected-input/public-input interface was available. Nargo is absent. `bb verify` attempts without a valid VK fail before exposing useful interface evidence.

Required owner/action: Cryptography/platform owner must approve tool versions and demonstrate a supported expected-input or public-input extraction mechanism with positive and negative proofs.

Implementation may proceed: No for certificate issuance or any claim of ZK-002 remediation. Authority lookup scaffolding may be designed but must not issue certificates.

Release impact: Blocking.

### RQ-002 - Is one production profile/VK/toolchain authoritative and executable?

Status: BLOCKED.

Evidence: Nargo manifests and Docker specify `0.32.0`; production target JSON exists but production `target/vk` is absent; development VK exists; Python and circuit dimensions conflict; WSL BB `0.46.1` is not approved; Nargo is unavailable.

Required owner/action: Cryptography/release owner must select capacity, approve compatible tool versions, create/validate production artifacts, and publish hashes.

Implementation may proceed: No production profile/startup validation implementation can be finalized before the profile manifest is approved.

Release impact: Blocking.

### RQ-003 - Can legacy records be mapped without misattribution?

Status: BLOCKED.

Evidence: Current `User` has role but no tenant membership; SBOM, policy, proof, snapshot, and certificate models lack complete owner/tenant relationships; initial migration has no safe mapping procedure. No deployment data or owner evidence was available.

Required owner/action: Data/architecture owner must inventory records, define evidence sources, approve mapping/quarantine, and sign the migration/rollback plan.

Implementation may proceed: No ownership migration or authorization rollout that exposes existing records may proceed.

Release impact: Blocking for multi-tenant/private-record release.

### RQ-004 - What makes a vulnerability root authoritative?

Status: BLOCKED.

Evidence: Current snapshot model has `status` and `provisional_smt_root` only; no importer, provenance, approval, freeze, revocation, or immutable transition fields. Ingestion is not restricted to a trusted importer, and the prover consumes the provisional root.

Required owner/action: Security/product owner must name trusted sources/importers/approvers and approve lifecycle, provenance, signature, revocation, replacement, and public-root policy.

Implementation may proceed: No authoritative snapshot or certificate eligibility implementation may proceed without the lifecycle decision; syntax validation may not be treated as approval.

Release impact: Blocking for trusted vulnerability verification.

## Final closure assessment

No decision is resolved by evidence or explicit project approval. Current code disproves required controls in the verifier, ownership, and snapshot paths; it does not resolve what the approved replacement architecture must be. Tool availability is partially improved by the discovery of WSL BB `0.46.1`, but the production cryptographic environment remains unavailable and unapproved.

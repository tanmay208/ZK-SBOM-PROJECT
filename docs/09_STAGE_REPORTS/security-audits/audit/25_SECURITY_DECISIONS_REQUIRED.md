# Security Decisions Required

Date: 2026-09-13
Phase: 2 - Decision gate
Decision status: Open

This document records decisions that must be approved before implementation. It intentionally does not choose a weaker fallback when evidence is unavailable.

## Decision register

### D-001 - Tenant and role authority

Question: What is the authoritative tenant model, and which server-side roles may perform each operation?

Required decision:

- Confirm whether every user belongs to one tenant or may have explicit memberships in several tenants.
- Approve `admin`, `vendor`, `auditor`, `buyer/verifier`, and `trusted_importer` semantics and whether approval is separate from import.
- Define whether auditors receive explicit assignment scope or tenant-wide read scope.
- Define service-to-service identity separately from end-user identity.

Recommended default: server-side tenant membership and role records; deny by default; separate trusted importer from snapshot approver where practical.

Release impact: P0. Without this, ownership and vertical authorization cannot be implemented safely.

### D-002 - Legacy record ownership and migration

Question: How can existing SBOMs, policies, proof jobs, snapshots, and certificates be assigned safely?

Options:

1. Backfill from reliable existing identity metadata.
2. Explicitly map records through reviewed admin evidence.
3. Quarantine records with no reliable mapping.

Recommended default: use 1 where evidence exists, 2 for reviewed exceptions, and 3 otherwise. Never assign all records to one user or tenant.

Release impact: P0. A migration that misattributes private records is unacceptable.

### D-003 - Vulnerability importer and approval separation

Question: Who may ingest, validate, approve, freeze, and revoke vulnerability snapshots?

Required decision:

- Name the trusted source/feed classes and provenance requirements.
- Decide whether the importer and approver must be different principals.
- Define signature/digest verification and source outage behavior.
- Define revocation and replacement semantics.

Recommended default: authenticated trusted importer plus separate admin/approver for authoritative status; only `APPROVED` + `FROZEN` + non-revoked roots are eligible.

Release impact: P0. Without this, vulnerability intelligence remains caller-poisonable.

### D-004 - Authoritative proof-input binding mechanism

Question: Which supported cryptographic mechanism proves and exposes the ordered public inputs so that proof inputs equal request inputs and authoritative records?

Required evidence, not assumption:

- Verify whether the approved Barretenberg CLI/API accepts expected public inputs or a verifier-input file.
- Otherwise verify whether the supported proof API extracts public inputs from the proof in a version-stable manner.
- Record exact public-input order: `SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`.
- Demonstrate a matching proof and negative proofs for each mismatch.

Prohibited choices: custom byte offsets, undocumented proof parsing, comparing only request strings, proof hashing as a substitute for input binding, caller labels, or trusting verifier exit code without expected-input comparison.

Recommended decision: do not issue certificates until one supported mechanism is demonstrated with the approved toolchain. If none exists, authorize a principled verifier-wrapper/circuit interface design review; do not ship a partial workaround.

Release impact: Release-blocking. This is the primary unresolved ZK-002 decision.

### D-005 - Production circuit/profile/VK contract

Question: What is the single production profile and which circuit capacity is authoritative?

Required decision:

- Resolve Python depth 10/1024 versus checked-in circuit/prover depth 3/eight dimensions.
- Approve profile ID, circuit source/compiled hashes, `MAX_COMPONENTS`, Merkle depth, SMT depth, public-input ordering, witness dimensions, proof format, Nargo version, Barretenberg version, VK hash, and artifact hashes.
- Define whether one or multiple profiles are supported and how profile identity is recorded.

Recommended default: one production profile with an immutable manifest and no API-controlled selection. Nargo `0.32.0` is the repository-stated expectation; Barretenberg must be explicitly approved and pinned.

Release impact: Release-blocking until real compile/proof/verification evidence exists.

### D-006 - Proof job queue, quotas, and process isolation

Question: Is a durable external queue required, or is a bounded in-process admission controller acceptable for the first remediation release?

Required decision:

- Global active-job limit and per-user/tenant queued/running quotas.
- Maximum proof wall time, output bytes, artifact bytes, and cancellation grace period.
- Worker isolation, process-group termination, retry policy, and recovery after crash.
- Private witness retention and cleanup SLA.

Recommended default: bounded durable job states and a global semaphore initially, with an external queue when service scaling requires it. No synchronous unbounded request execution.

Release impact: P0/P1 availability and privacy gate.

### D-007 - Database isolation model

Question: Will each service receive a distinct SQL principal with schema-level least privilege, and what database features are available for row-level enforcement?

Required decision:

- Service principal and schema grants for all five services.
- Whether SQL Server row-level security is required in addition to application predicates.
- Migration owner, credential rotation, and deployment verification method.

Recommended default: distinct service principals and least-privilege schema grants; application ownership predicates remain mandatory.

Release impact: P1 and required before claiming microservice boundary enforcement.

### D-008 - JWT secret and session lifecycle

Question: What secret-management, rotation, revocation, issuer, audience, and token lifetime policy applies to independently running services?

Required decision:

- Shared configured secret or asymmetric service-verification design.
- Production startup behavior when secret/configuration is missing or weak.
- Rotation overlap, token revocation, logout, replay, and multi-worker consistency.
- Password handling policy for inputs exceeding bcrypt's native limit.

Recommended default: fail closed in production without a strong centrally distributed secret; explicitly version and rotate tokens; reject or safely pre-hash overlong passwords under an approved policy.

Release impact: P1; required before production deployment.

### D-009 - Canonical identity and public-input API contract

Question: Which exact canonical component identity is shared by SBOM ingestion, vulnerability ingestion, SMT construction, and proof witness generation?

Required decision:

- Name/PURL/version precedence and alias behavior.
- Unicode, qualifier, namespace, duplicate, and malformed-input semantics.
- Exact hexadecimal/field encoding and public-input ordering.
- Compatibility policy for records already committed under an older rule.

Recommended default: freeze a versioned canonicalization contract and vectors before changing cryptographic or database semantics.

Release impact: P0 for proof integrity if existing commitments are affected; otherwise P1 protocol gate.

## Release-blocking questions

1. Can the approved proving/verifying stack cryptographically bind or expose ordered public inputs so `PROOF == REQUEST == AUTHORITY` can be tested with real artifacts?
2. Which production circuit capacity/profile and approved VK/toolchain are authoritative, and can they produce and verify real proofs?
3. How will legacy records be mapped or quarantined without misattributing private resources?
4. Which trusted importer/approver lifecycle makes a vulnerability root authoritative, immutable, and revocable?

No certificate or production-readiness claim is permitted while any of these questions is unanswered.

## Decision acceptance criteria

An approved decision must name the owner, chosen option, rejected alternatives, compatibility impact, migration/rollback plan, tests, and evidence required. A statement that a gateway, UUID, verifier exit code, or client field will provide authority is not an accepted decision without code and deployment evidence.

## Phase 2 gate result

The target architecture and implementation sequence are documented, but decisions remain open. The proof-binding decision is explicitly release-blocking because the current stack has not demonstrated a supported expected-input or public-input extraction mechanism. The environmental toolchain blocker remains open and is not classified as an application vulnerability.

ARCHITECTURAL DECISIONS REQUIRED: 9
RELEASE-BLOCKING QUESTIONS: 4
IMPLEMENTATION AUTHORIZED: NO

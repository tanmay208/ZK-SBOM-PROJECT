# Remediation Architecture

Date: 2026-09-13
Phase: 2 - Remediation architecture and decision gate
Status: Design only. No implementation is authorized by this document.

## 1. Design principles

The remediation must preserve the three public ZKP inputs and the existing service boundaries while moving authority decisions out of caller-controlled request data. The target architecture is fail-closed for missing identity, ownership, approved intelligence, profile artifacts, or proof-input binding.

The following invariants are mandatory:

1. Authentication precedes every sensitive read, mutation, and expensive operation.
2. Authorization is derived from server-side identity, role, tenant, and object relationships, never from request-body roles or owner IDs.
3. A vulnerability root is eligible for proving or certification only when its server-side snapshot is approved, frozen, immutable, and not revoked.
4. A certificate is issued only when the cryptographically verified proof public inputs equal the request inputs and the authoritative approved records.
5. The selected circuit, witness dimensions, verification key, and toolchain are one immutable profile. Missing or mismatched production artifacts fail closed.
6. Proof jobs are bounded, owned, isolated, cancellable, and auditable.
7. Public errors are stable and sanitized; detailed diagnostics remain protected internal data.

## 2. Target trust boundaries

The gateway is a transport boundary, not an authorization authority. Each service must enforce authentication and authorization itself. The verification service remains public-data-only and must never need raw SBOM components or private witness data.

Recommended logical boundaries:

- Identity boundary: a configured identity provider or the existing user store issues tokens. The `sub` claim maps to a server-side user record; roles and tenant membership are loaded from the database.
- Vendor boundary: SBOM upload, private component storage, witness construction, and proof generation. Vendor users can access only owned or tenant-authorized resources.
- Intelligence boundary: a trusted importer/admin pipeline ingests and approves vulnerability data. Ordinary vendors cannot create authoritative snapshots.
- Policy boundary: policies are owned by an organization or tenant and become eligible for proving only under an explicit approval policy.
- Verification boundary: receives a proof and public references, resolves authoritative records server-side, performs cryptographic verification, and stores a certificate containing actual verified references.
- Database boundary: one SQL Server may remain, but each service receives a distinct principal with least-privilege schema grants. Logical schema names alone are not isolation.
- Tool boundary: the prover and verifier run approved Linux toolchain artifacts in isolated job directories. API callers cannot select executables, profiles, working directories, or tool arguments.

## 3. Identity, ownership, and RBAC model

### 3.1 Identity

The authenticated principal is the database user identified by a validated token `sub`. The token identifies the principal; it does not carry authoritative role or tenant permissions. Role and tenant memberships are loaded server-side for every authorization decision or from a safely cached, versioned authorization record.

Required principal data:

- `user_id`: immutable server-generated identifier.
- `tenant_id`: owning organization boundary; a user may have more than one membership only if explicitly modeled.
- `roles`: server-side memberships such as `admin`, `vendor`, `auditor`, `buyer/verifier`, and `trusted_importer`.
- `status`: active, suspended, or disabled.
- `authorization_version`: optional revocation/version value for cache invalidation.

### 3.2 Resource ownership

SBOM uploads, proof jobs, certificates, policies, and any private diagnostic records must carry an owner or tenant relationship. Vulnerability snapshots carry importer/provenance and approval authority rather than ordinary vendor ownership. Certificates record the requesting principal and authoritative references but expose only permitted public metadata.

Authorization must be enforced twice:

1. Route layer: authenticate, authorize the operation, and reject before sensitive retrieval or expensive work.
2. Service/repository layer: apply owner/tenant predicates and reject direct internal calls that bypass a route.

The query must scope retrieval by authorization before returning a record. UUID lookup followed by a later check is not an acceptable default for sensitive records.

### 3.3 Minimum permission matrix

| Operation | Admin | Vendor | Auditor | Buyer/verifier | Trusted importer |
| --- | --- | --- | --- | --- | --- |
| Upload SBOM | Yes | Own tenant | No | No | No |
| View SBOM metadata | Yes | Own tenant | Assigned/audited scope | No private data | No |
| View another tenant SBOM | Explicit admin scope only | No | Explicit audited scope only | No | No |
| Create/update policy | Yes | Tenant policy scope if approved by policy | No | Read public approved policy | No |
| Ingest vulnerability data | Yes | No | No | No | Yes, assigned source |
| Approve/freeze/revoke snapshot | Yes | No | No | No | Separate approval role or admin |
| Generate proof | Yes | Own tenant and approved references | No | No | No |
| View proof job | Yes | Own tenant jobs | Assigned/audited scope | No private diagnostics | No |
| Verify proof | Yes | Authorized workflow | Authorized workflow | Yes, public inputs only | No |
| Issue certificate | Server workflow after verification | Server workflow for own authorized job | No direct issuance | Server workflow | No |
| View certificate | Yes | Own authorized certificate | Assigned/audited scope | Public certificate scope | No |
| View metrics/audit | Yes | Tenant-scoped operational metrics | Approved audit scope | Public metrics only | Import audit scope |
| Administer users | Yes | No | No | No | No |

The exact auditor and importer separation requires the decisions in `25_SECURITY_DECISIONS_REQUIRED.md`. No role supplied in a request body can grant any permission.

### 3.4 Legacy records

Existing records cannot be silently assigned to an arbitrary user or tenant. Before migration, records must be classified:

- Records with a reliable existing owner mapping are backfilled transactionally.
- Records with no reliable owner are quarantined from sensitive reads, mutations, proof generation, and certificate issuance until an administrator performs an explicit reviewed mapping.
- Public immutable artifacts may remain readable only if their public status and provenance are independently established.
- Every backfill decision is logged with actor, source evidence, timestamp, and migration version.
- Rollback restores the pre-migration state and does not make quarantined records available.

This is a release gate because ownership cannot be safely implemented without a legacy-record policy.

## 4. Vulnerability intelligence trust lifecycle

The authoritative lifecycle is:

`INGESTED -> VALIDATED -> APPROVED -> FROZEN`

Any non-frozen state can transition to `REVOKED`; a frozen state can be revoked but never edited. A correction creates a new snapshot/version and root. The old snapshot remains immutable and records the revocation reason and replacement reference.

Required snapshot fields:

- immutable snapshot/version ID;
- source name, source URI/feed identifier, source release timestamp, and source digest/signature;
- importer principal and import event ID;
- validation result and validation version;
- computed root and root algorithm/profile;
- lifecycle status and state-transition audit record;
- approval principal, approval time, freeze time, revocation time/reason, and replacement ID;
- deterministic canonicalization/version used to derive the root.

Only an authorized trusted importer may ingest. Approval must be performed by an authorized admin or separate approver according to the selected separation-of-duties policy. The database, not a client boolean, supplies status. Only `APPROVED` + `FROZEN` + non-revoked snapshots are eligible for proof generation and certificate issuance.

Approved roots are immutable. A root change is a new version. Snapshot retrieval must not expose provisional roots as if they were authoritative; public responses expose only approved public metadata and approved roots under the chosen contract.

## 5. Proof authority and public-input binding

### 5.1 Required equality

Certificate issuance must establish:

```text
verified proof public inputs
    == API request public inputs
    == authoritative database records
```

The three values are ordered and exact:

1. `SBOM_ROOT` from the authorized SBOM record.
2. `VULNERABILITY_DB_ROOT` from an approved, frozen, non-revoked snapshot.
3. `POLICY_HASH` from an approved policy record.

The proof job and certificate must also persist authoritative record IDs, profile ID, verification-key identity, and the exact verified public inputs.

### 5.2 Current capability and hard stop

The current verifier invocation is a Barretenberg command that receives a verification key and proof artifact. The inspected implementation does not pass expected public inputs to the verifier, does not extract public inputs through a validated supported API, and does not compare them to authoritative records before certificate creation. The current code therefore cannot claim the required invariant.

No proof parser or byte-offset interpretation may be invented. The following implementation paths are acceptable only after validation against the approved Barretenberg/Noir version:

1. A supported verifier API/CLI accepts an expected public-input vector or verifier-input file and cryptographically verifies the proof against those expected values.
2. A supported proof API exposes the public-input vector; the system extracts it using that supported interface, compares exact ordering and values to authoritative records, and then performs cryptographic verification under the same profile.
3. A supported verifier wrapper provides a cryptographic binding/commitment API that accepts the expected public inputs and returns a verified result.

If the approved stack supports none of these mechanisms, the platform cannot safely issue authoritative certificates without a principled proof-wrapper or circuit/interface change. That is a release-blocking architectural limitation. A check of caller-supplied strings, a proof hash, a label, or a custom unsupported parser is not sufficient.

### 5.3 Verification transaction

The target verification transaction is:

1. Authenticate and authorize the verifier request.
2. Resolve SBOM, snapshot, and policy references server-side.
3. Require the snapshot and policy states to be eligible and the SBOM to be accessible in the authorized scope.
4. Construct the expected ordered public-input vector from authoritative records.
5. Verify the proof using a supported expected-input/public-input mechanism and the profile's VK.
6. Compare the verified vector with both request values and authoritative values.
7. Recheck revocation/freshness under a transaction or version lock.
8. Atomically store the certificate with actual authoritative IDs, roots, policy identity, profile ID, VK hash, verifier version, and correlation ID.

If any step is unavailable or ambiguous, return a non-success result and do not issue a certificate.

## 6. Circuit/profile/VK integrity

A profile is an immutable manifest selected by trusted deployment configuration, never by an API request. It must contain:

- profile name and immutable profile ID;
- circuit source hash and compiled artifact hash;
- `MAX_COMPONENTS`, Merkle depth, SMT depth, public-input order, and witness dimensions;
- Noir/Nargo version and Barretenberg version;
- verification-key hash and proving artifact hash where applicable;
- supported proof format and verifier interface version.

Startup/readiness must fail closed when a production artifact is missing, a hash does not match, a dimension differs, a tool version differs, or a development artifact is selected for production. A production service must not fall back to `DEV_MODE`, development VKs, or checked-in placeholder proofs. Cross-profile proofs must be rejected by the verifier.

The capacity mismatch between the Python reference (depth 10/1024) and the checked-in circuit/prover path (eight/depth 3) is unresolved until an approved production capacity is selected and validated. No profile is declared production-ready in this phase.

## 7. Resource and job execution architecture

The immediate target is a bounded job-admission architecture; a durable queue may be introduced if the deployment requires it.

- Authentication and authorization occur before admission.
- Upload and proof requests enforce maximum bytes, components, depth, and public-input sizes.
- A durable `ProofJob` has explicit states: `QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCEL_REQUESTED`, `CANCELLED`, `TIMED_OUT`, and `REJECTED`.
- A global semaphore limits active proof processes; per-tenant and per-user quotas limit queued and running work.
- Jobs have admission, execution, wall-clock, output-byte, and artifact-size limits.
- Each job receives a private temporary directory with restrictive permissions and UUID-derived paths. No shared `Prover.toml`, target, or proof path is reused.
- Executables, profile, working directory, and arguments are server configuration. Use direct argument arrays; do not interpolate into `bash -c`.
- Subprocesses run in a process group/job object and are terminated with descendants on timeout or cancellation where the host supports it.
- Cleanup is attempted in `finally`, on cancellation, on timeout, and by a startup/periodic stale-artifact scavenger.
- Public job responses expose state, opaque error code, and correlation ID only. Detailed diagnostics are protected and size-limited.
- Retries are idempotent and cannot accept stale artifacts; artifact identity includes job ID, profile ID, VK hash, and expected public-input digest.

## 8. Database and API contract direction

The schema changes are additive and migration-controlled:

- Add owner/tenant relationships and indexes to private resources.
- Add snapshot provenance, lifecycle state, approval/freeze/revocation, root version, and immutable transition records.
- Add profile/VK identifiers and authoritative record references to proof jobs and certificates.
- Add unique idempotency/fingerprint constraints after duplicate handling is defined.
- Add explicit status enums/check constraints where supported.
- Add service principals and grants outside application row models.

API contracts must:

- require bearer authentication for sensitive routes;
- remove client-controlled owner, tenant, role, profile, authority, and approval fields;
- expose only authorized resources;
- replace internal error strings with stable public codes and correlation IDs;
- distinguish liveness from readiness;
- represent snapshot status and approved-root eligibility explicitly;
- require canonical public-input encodings and authoritative identifiers where applicable.

## 9. High-finding architecture summary

| Finding | Root cause | Required invariant | Main architecture change | DB/API impact | Validation gate | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| RBAC-001 | Authentication is not authorization; resources lack owner/tenant enforcement | A principal can access only permitted tenant/resource scope | Server-side policy engine plus route/service predicates | Owner/tenant migration; protected resource contracts | Multi-user matrix and legacy migration evidence | Misclassified legacy records or policy drift |
| API-001 | Sensitive routes lack uniform auth and admission control | No sensitive/expensive work occurs before auth and quota admission | Authenticated route policy plus bounded job admission | Job owner/quota fields; 401/403 contract | Route matrix, burst, and concurrency tests | External gateway/network assumptions |
| VI-001 | Ingestion completion is treated as trust | Only approved/frozen/non-revoked roots are authoritative | Trusted importer and snapshot state machine | Provenance/status/approval/freeze/revocation migration | Lifecycle, immutability, and unauthorized-action tests | Source authenticity and approver compromise |
| ZK-001 | Python/circuit dimensions and VK profile are not one manifest | Runtime uses exactly the validated profile/VK | Immutable profile manifest and fail-closed startup | Profile references in jobs/certs; artifact deployment | Hash, dimension, VK, and cross-profile tests | Toolchain/vendor behavior until real validation |
| ZK-002 | Verifier trusts caller metadata and lacks expected-input binding | Verified proof inputs equal request and authoritative records | Supported public-input extraction/expected-input verifier interface | Authority references and certificate transaction | Real positive/negative proof binding tests | No certificate issuance if stack cannot support binding |

## 10. Rollback and compatibility principles

No remediation should be deployed without a reversible migration and a feature-flagged rollout where the security invariant is not weakened. Rollback may restore availability only if it does not re-enable unsafe certificate issuance or cross-tenant access. In particular:

- Failed ownership migration leaves records quarantined, not globally accessible.
- Snapshot lifecycle rollback cannot make an unapproved root eligible.
- Profile rollback can select a previously validated profile only; it cannot select development artifacts in production.
- Proof-binding rollback must disable certificate issuance rather than revert to caller-only binding.
- Job-system rollback must reject new work if isolation or cleanup cannot be guaranteed.

## 11. Architecture gate result

This document defines a target architecture but does not resolve the approved role model, legacy migration, proof-binding interface, production profile, toolchain, or database-principal decisions. Implementation remains unauthorized until the decision document is approved and the release-blocking questions are answered.

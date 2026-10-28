# Data Lifecycle and Deletion

Date: 2026-10-01
Stage: 2 — Frontend Data Storage & Persistence Architecture

## Scope

Define the lifecycle state machine for each major resource, including create/process/complete/fail/approve/revoke/delete transitions, and the deletion/cascade model. Evidence sourced from executable service code, repository layers, and database migrations.

## Resource Lifecycle State Machines

### User

```
REGISTER → ACTIVE
```

- **CREATE:** Registration creates user with role `auditor`; admin role assignment is UNKNOWN.
- **UPDATE:** No profile update API exists.
- **DELETE:** No deletion path. No `disabled` or `deleted_at` field.
- **DB state:** Row persists indefinitely.
- **Frontend-visible state:** `id`, `username`, `role` via `/me`.

### Application

```
CREATE (get-or-create) → ACTIVE
```

- **CREATE:** Implicit via SBOM upload; `get_or_create_application` by `(name, vendor)`.
- **UPDATE:** `updated_at` auto-updates on modification (ORM `onupdate`); no explicit update API.
- **DELETE:** No deletion API. ORM cascade `all, delete-orphan` to SBOMUpload.
- **DB state:** Row persists indefinitely.
- **Frontend-visible state:** Not directly exposed; application_id visible in SBOM list.

### SBOMUpload

```
UPLOAD → pending → committed
              ↘ (failure) → pending with error
```

- **CREATE:** `POST /api/v1/sbom/upload` creates with status `pending`.
- **PROCESS:** Commitment pipeline runs synchronously: parse → validate → canonicalize → hash → Merkle → SBOM_ROOT.
- **COMPLETE:** Status transitions to `committed`; `sbom_root` and `component_count` populated.
- **FAIL:** Transaction rollback — entire upload fails atomically; no partial state.
- **DELETE:** No deletion API. DB CASCADE from Application parent.
- **Artifacts:** Raw content stored in DB column. Components created as children.
- **Frontend-visible state:** `upload_id`, `application_id`, `status`, `format`, `filename`, `sbom_root`, `component_count`, `created_at`.

### VulnerabilitySnapshot

```
INGEST → processing → pending → approved
                                  ↓
                                revoked
```

- **CREATE:** `POST /api/v1/vulnerability/ingest` creates with status `processing`, transitions to `pending`.
- **APPROVE:** `POST /api/v1/vulnerability/snapshots/{id}/approve` — admin only; status must be `pending`.
- **REVOKE:** `POST /api/v1/vulnerability/snapshots/{id}/revoke` — admin only; any status can be revoked.
- **RE-APPROVAL:** No guard preventing revoked → approved, but current code checks `status != "pending"` for approval. A revoked snapshot CANNOT be re-approved (status would be "revoked", not "pending").
- **DELETE:** No deletion API. Cascade to ComponentVulnerabilityMapping and ProofJob.
- **Immutable fields:** `snapshot_label`, `record_count`, `provisional_smt_root` — set at creation, never modified.
- **Mutable fields:** `status` only.
- **Frontend-visible state:** `id`, `snapshot_label`, `record_count`, `status`.

### SecurityPolicy

```
CREATE → active
           ↓ (new policy created)
        inactive
```

- **CREATE:** `POST /api/v1/policy` — admin only. Deactivates all existing policies, creates new active one.
- **UPDATE:** No update API. Policies are implicitly versioned by deactivation/creation.
- **DELETE:** No deletion API.
- **Invalidation:** Creating a new policy does NOT invalidate previous verification certificates. Certificates reference `policy_hash` by value, not by FK to the policy record.
- **Frontend-visible state:** `id`, `name`, `description`, `max_cvss_score`, `policy_hash`, `created_at`, `active`.

### ProofJob

```
CREATE → pending → assembling_witness → completed
                                           ↓
                   (any failure) → failed
                   (env block) → execution_blocked
```

- **CREATE:** `POST /api/v1/zkp/generate` — vendor/admin only; SBOM ownership verified; snapshot must be `approved`.
- **PROCESS:** Synchronous in current implementation; production would use task queue.
- **COMPLETE:** Status `completed`; `sbom_root`, `vulnerability_db_root`, `policy_hash`, `proof_artifact` populated; `completed_at` set.
- **FAIL:** Status `failed`; `error_message` set (sanitized to "Proof generation failed" in response); `completed_at` set.
- **EXECUTION_BLOCKED:** Status `execution_blocked`; `completed_at` set. This occurs when WSL/Noir environment is unavailable.
- **RETRY:** No retry mechanism. A new job must be created.
- **DELETE:** No deletion API.
- **Temporary artifacts:** Prover.toml, witness .gz, proof .proof — cleaned in `finally` block.
- **Frontend-visible state:** `id`, `sbom_upload_id`, `snapshot_id`, `policy_id`, `status`, `sbom_root`, `vulnerability_db_root`, `policy_hash`, `proof_artifact`, `error_message` (sanitized), `created_at`, `completed_at`.

### VerificationRequest

```
SUBMIT → verified / invalid / authoritative_record_mismatch / public_input_mismatch / unavailable
```

- **CREATE:** `POST /api/v1/verification/verify` — any authenticated user.
- **IDEMPOTENCY:** Exact fingerprint match returns existing record without re-verification.
- **RESULT STATES:**
  - `verified`: Cryptographic proof valid AND public inputs match AND authoritative records exist. Certificate issued atomically.
  - `invalid`: Cryptographic verification failed.
  - `authoritative_record_mismatch`: Roots/hash don't match active records.
  - `public_input_mismatch`: Proof public inputs don't match submitted roots.
  - `unavailable`: Verifier tool unavailable.
- **IMMUTABLE:** Result is set at creation; never modified.
- **DELETE:** No deletion API.
- **Frontend-visible state:** `id`, `sbom_root`, `vulnerability_db_root`, `policy_hash`, `result`, `verified_at`, `created_at`, `certificate` (if verified).

### VerificationCertificate

```
ISSUED (atomic with verified request)
```

- **CREATE:** Atomically with `VerificationRequest` when result is `verified`.
- **IMMUTABLE:** Never modified after creation. No revocation mechanism.
- **DELETE:** No deletion API. CASCADE from VerificationRequest.
- **ACCESS:** Public metadata by UUID; list requires authentication.
- **Frontend-visible state:** `id`, `verification_request_id`, `certificate_data`, `sbom_root`, `vulnerability_db_root`, `policy_hash`, `issued_at`.

## Deletion / Cascade Analysis

### Delete Application

```
Application (deleted)
  → SBOMUpload (CASCADE from DB FK + ORM cascade)
    → Component (CASCADE from DB FK + ORM cascade)
    → ScanResult (CASCADE from migration 002 FK)
    → ProofJob (CASCADE from migration 002 FK)
  ↛ VerificationRequest (NO FK relationship)
  ↛ VerificationCertificate (indirect only through request)
```

**RISK:** Deleting an application would cascade-delete proof jobs, which may contain verification evidence. No application delete API exists, but the cascade relationship is defined.

### Delete SBOMUpload

```
SBOMUpload (deleted)
  → Component (CASCADE)
  → ScanResult (CASCADE)
  → ProofJob (CASCADE)
```

**RISK:** Same as above — proof jobs cascaded.

### Delete VulnerabilitySnapshot

```
VulnerabilitySnapshot (deleted)
  → ComponentVulnerabilityMapping (CASCADE)
  → ProofJob (CASCADE)
```

**RISK:** Deleting a snapshot cascades to all proof jobs referencing it.

### Delete SecurityPolicy

```
SecurityPolicy (deleted)
  → ProofJob (CASCADE)
```

**RISK:** Deleting a policy cascades to all proof jobs referencing it.

### Delete VerificationRequest

```
VerificationRequest (deleted)
  → VerificationCertificate (CASCADE)
```

**RISK:** Deleting a verification request destroys its certificate.

### Summary of Cascade Risks

The CASCADE relationships in migration 002 create a situation where deleting any upstream resource (Application, SBOM, Snapshot, or Policy) would cascade-delete proof jobs. This is a **significant architectural concern** because:

1. Proof jobs contain verification evidence that may need to be retained.
2. Verification certificates reference roots by value (not FK), so they survive proof job deletion, but the provenance chain is broken.
3. No delete API exists currently, so the risk is dormant but structurally present.

> [!WARNING]
> The CASCADE delete relationships on proof_jobs from three parent tables (sbom_uploads, vulnerability_snapshots, security_policies) mean that deleting any of these parents would destroy proof evidence. Future deletion features must address this by implementing soft-delete, archive, or FK policy changes.

## Failed Proof Job Analysis

When a proof job fails:

| Aspect | Behavior | Status |
|---|---|---|
| DB record | Retained with status `failed`, `error_message` set, `completed_at` set | VERIFIED |
| Prover.toml | Deleted in `finally` block | VERIFIED |
| Witness .gz | Deleted in `finally` block | VERIFIED |
| Proof .proof | Deleted in `finally` block (if never created, no-op) | VERIFIED |
| Frontend display | Status `failed`, error "Proof generation failed" (sanitized) | VERIFIED |
| Retry | No retry mechanism; user must create new job | VERIFIED |
| Cleanup | No scheduled cleanup for old failed job DB records | UNDEFINED |

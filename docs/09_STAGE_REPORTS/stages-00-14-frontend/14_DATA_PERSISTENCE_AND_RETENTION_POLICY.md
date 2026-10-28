# Data Persistence and Retention Policy

Date: 2026-10-01
Stage: 2 — Frontend Data Storage & Persistence Architecture

## Scope

Document the retention, deletion, and lifecycle policy for every persistent data entity, derived exclusively from executable code evidence. Where no policy exists, mark it UNDEFINED.

## Retention Summary

| Entity | Retention | Deletion Owner | Deletion Trigger | Dependencies | Recovery Implication | Status |
|---|---|---|---|---|---|---|
| User | Indefinite | UNDEFINED | None implemented | Application, SBOMUpload (via user_id) | User deletion would orphan owned resources | UNDEFINED |
| Application | Indefinite | CASCADE from no parent | None implemented; cascade delete-orphan from ORM relationship only | SBOMUpload (cascade) | Application deletion cascades to all uploads | UNDEFINED |
| SBOMUpload | Indefinite | CASCADE from Application (DB FK) | None implemented | Components (cascade), ProofJob (FK but CASCADE in DB) | Upload deletion cascades to components and could cascade to proof jobs | UNDEFINED |
| Component | Cascaded with SBOMUpload | Parent cascade | SBOMUpload deletion | None | Derived from SBOM; can be regenerated from raw_content | VERIFIED |
| VulnerabilityRecord | Indefinite | UNDEFINED | None implemented | None (standalone) | Independent of other entities | UNDEFINED |
| VulnerabilitySnapshot | Indefinite | UNDEFINED | None implemented | ComponentVulnerabilityMapping (cascade), ProofJob (FK with CASCADE) | Snapshot deletion would cascade to its mappings and proof jobs | UNDEFINED |
| ComponentVulnerabilityMapping | Cascaded with Snapshot | Parent cascade | Snapshot deletion | None | Derived from ingestion; can be re-ingested | VERIFIED |
| ScanResult | Cascaded with SBOMUpload (FK in migration 002) | Parent cascade | SBOMUpload deletion | None | Minor flow result; not critical path | VERIFIED |
| SecurityPolicy | Indefinite (deactivated, not deleted) | UNDEFINED | Deactivation on new policy creation | ProofJob (FK with CASCADE), VerificationRequest (references policy_hash) | Policy deletion would cascade to proof jobs; verification references are by value | UNDEFINED |
| ProofJob | Indefinite | UNDEFINED | None implemented | None downstream | Contains proof artifact and status | UNDEFINED |
| VerificationRequest | Indefinite | UNDEFINED | None implemented | VerificationCertificate (cascade) | Request deletion cascades to certificate | UNDEFINED |
| VerificationCertificate | Indefinite | Cascaded with VerificationRequest | Request deletion | None | Public record of verification | UNDEFINED |

## Critical Retention Observations

### No Explicit Retention Policy Exists

The current codebase defines NO time-based retention, archival, or cleanup mechanisms for any entity. All data persists indefinitely until manual database intervention.

**RETENTION POLICY: UNDEFINED** for all entities.

### No Soft Delete

No entity has a `deleted_at`, `is_deleted`, or soft-delete column. Deletion where supported (via FK CASCADE) is hard deletion.

### No Archival

No archive tables, archive flags, or archive processes exist.

### No Expiration

No entity has an `expires_at` field or TTL mechanism.

## Deletion Capability Analysis

### Database-Level Cascades (from migrations)

| Parent | Child | Cascade | Source |
|---|---|---|---|
| `sbom.applications` | `sbom.sbom_uploads` | CASCADE | Migration 001 |
| `sbom.sbom_uploads` | `sbom.components` | CASCADE | Migration 001 |
| `vulnerability.vulnerability_snapshots` | `vulnerability.component_vulnerability_mappings` | CASCADE | Migration 001 |
| `sbom.sbom_uploads` | `zkp.proof_jobs` | CASCADE | Migration 002 FK |
| `vulnerability.vulnerability_snapshots` | `zkp.proof_jobs` | CASCADE | Migration 002 FK |
| `policy.security_policies` | `zkp.proof_jobs` | CASCADE | Migration 002 FK |
| `verification.verification_requests` | `verification.verification_certificates` | CASCADE | Migration 002 FK |
| `sbom.sbom_uploads` | `vulnerability.scan_results` | CASCADE | Migration 002 FK |

### ORM-Level Cascades

| Parent | Child | ORM Cascade |
|---|---|---|
| Application | SBOMUpload | `all, delete-orphan` |
| SBOMUpload | Component | `all, delete-orphan` |

### No Application-Level Delete API

No API endpoint exists for deleting any resource. No service or repository method performs deletion.

## Backup/Recovery Architecture

| Aspect | Status |
|---|---|
| SQL Server backup strategy | UNDEFINED |
| Artifact backup | UNDEFINED |
| Point-in-time recovery | UNDEFINED |
| Cross-region replication | UNDEFINED |
| Disaster recovery plan | UNDEFINED |
| Restore ordering | UNDEFINED |
| DB-artifact consistency | UNDEFINED |
| Docker volume backup | Docker Compose defines `sqlserver_data` named volume; no backup strategy |

**BACKUP/RECOVERY ARCHITECTURE: UNDEFINED**

No production backup, recovery, or disaster recovery infrastructure is defined in the current codebase or deployment configuration. This is an explicit deployment gate.

## Future Retention Considerations

1. **Raw SBOM content**: `sbom_uploads.raw_content` stores full SBOM text. This is the largest data element per record. Retention should be defined based on re-processing needs.
2. **Proof artifacts**: `proof_jobs.proof_artifact` stores base64-encoded proofs in the DB. No separate artifact storage exists.
3. **Verification certificates**: Immutable records that may have legal/compliance retention requirements.
4. **Vulnerability snapshots**: Approved snapshots are referenced by proof jobs; deletion could invalidate proof provenance.
5. **Deactivated policies**: Historical policies are retained as inactive; they provide audit trail for past proof jobs.

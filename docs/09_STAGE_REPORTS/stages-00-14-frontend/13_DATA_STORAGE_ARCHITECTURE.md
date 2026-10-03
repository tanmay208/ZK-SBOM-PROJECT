# Data Storage Architecture

Date: 2026-10-01
Stage: 2 — Frontend Data Storage & Persistence Architecture

## Scope

Evidence-based inventory of every persistent data entity in the platform, derived from executable ORM models, Alembic migrations, repository/service layers, and configuration files. No behavior is assumed from documentation alone.

## Database Architecture

**Engine:** SQL Server 2022 (single instance per DATABASE_SCHEMA.md)
**Database name:** `ZKP_SBOM` (default from `shared/config.py`)
**Logical schemas:** `sbom`, `vulnerability`, `policy`, `zkp`, `verification`
**ORM:** SQLAlchemy with declarative Base
**Migrations:** Alembic — two revisions: `001_initial` and `002_rbac`
**Session model:** `sessionmaker(autocommit=False, autoflush=False)` with per-request lifecycle via FastAPI dependency

### Users Table

The `users` table is defined in `shared/models/user.py` without a named SQL schema, meaning it lives in the default `dbo` schema. It is NOT in any of the five logical schemas.

| Property | Value | Status |
|---|---|---|
| Table | `users` (dbo) | VERIFIED |
| PK | `id` (UUID) | VERIFIED |
| Columns | `username` (String 255, unique, indexed), `hashed_password` (String 255), `role` (String 50, default `auditor`), `created_at` (DateTime) | VERIFIED |
| FK | None | VERIFIED |
| Owner | Self-owned identity | VERIFIED |
| Sensitive fields | `hashed_password` — NEVER exposed | VERIFIED |
| Public fields | `id`, `username`, `role` via `/me` | VERIFIED |
| Retention | No deletion behavior defined | UNDEFINED |
| Lifecycle | Created at registration; no update/disable/delete path exists | VERIFIED |
| Updated_at | NOT PRESENT | VERIFIED |

## Entity Inventory

### 1. Application (`sbom.applications`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `name` (255), `vendor` (255), `description` (Text), `user_id` (UUID, nullable), `created_at`, `updated_at` | VERIFIED |
| FK | None at DB level (migration adds `user_id` without FK constraint) | VERIFIED |
| Indexes | `ix_sbom_applications_vendor`, `ix_sbom_applications_user_id` | VERIFIED |
| Owner | `user_id` — set on creation via `get_or_create_application` | VERIFIED |
| ORM relationship | `sbom_uploads` with `cascade="all, delete-orphan"` | VERIFIED |
| Lifecycle | Get-or-create by `(name, vendor)` pair; no update/delete API | VERIFIED |
| Retention | UNDEFINED — no deletion path | UNDEFINED |

### 2. SBOMUpload (`sbom.sbom_uploads`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `application_id` (FK), `user_id` (UUID, nullable), `filename` (512), `format` (50), `spec_version` (20), `status` (20, default "pending"), `sbom_root` (128), `component_count` (Integer), `raw_content` (Text), `created_at` | VERIFIED |
| FK | `application_id` → `sbom.applications.id` (CASCADE) | VERIFIED |
| Indexes | `ix_sbom_uploads_application_id`, `ix_sbom_uploads_status` | VERIFIED |
| Owner | `user_id` — set at upload time | VERIFIED |
| Sensitive fields | `raw_content` — NEVER exposed in any API response | VERIFIED |
| Public fields | `id`, `application_id`, `status`, `format`, `filename`, `sbom_root`, `component_count`, `created_at` | VERIFIED |
| Lifecycle | pending → committed (after commitment pipeline) or failure | VERIFIED |
| Immutable after commit | `raw_content`, `sbom_root`, `component_count` after status=committed | INFERRED |
| Retention | UNDEFINED — no deletion API | UNDEFINED |

### 3. Component (`sbom.components`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `sbom_upload_id` (FK), `name` (512), `version` (128), `purl` (1024), `purl_canonical` (1024), `component_hash` (128), `position` (Integer), `created_at` | VERIFIED |
| FK | `sbom_upload_id` → `sbom.sbom_uploads.id` (CASCADE) | VERIFIED |
| Indexes | `ix_sbom_components_sbom_upload_id`, `ix_sbom_components_purl` | VERIFIED |
| Owner | Derived — owned transitively through SBOMUpload | VERIFIED |
| Sensitive fields | ALL fields — `name`, `version`, `purl`, `purl_canonical`, `component_hash` are Private Data per SECURITY_BOUNDARY.md | VERIFIED |
| Frontend access | NEVER — no component detail API exists; no component data in any response schema | VERIFIED |
| Retention | Cascaded with SBOMUpload | VERIFIED |

### 4. VulnerabilityRecord (`vulnerability.vulnerability_records`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `cve_id` (30, unique), `description` (Text), `cvss_base_score` (Float), `cvss_vector` (255), `severity` (20), `published_date`, `modified_date`, `source` (50, default "NVD"), `created_at` | VERIFIED |
| FK | None | VERIFIED |
| Owner | Globally shared public threat intelligence | VERIFIED |
| Frontend access | No direct API endpoint exposes these records | VERIFIED |
| Retention | UNDEFINED | UNDEFINED |

### 5. VulnerabilitySnapshot (`vulnerability.vulnerability_snapshots`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `snapshot_label` (255), `record_count` (Integer), `provisional_smt_root` (128, nullable), `status` (20, default "pending"), `created_by` (UUID, nullable), `created_at` | VERIFIED |
| FK | None at DB level | VERIFIED |
| Indexes | `ix_vuln_snapshots_status` | VERIFIED |
| Owner | Admin-controlled (`created_by` records the admin who ingested) | VERIFIED |
| Lifecycle | processing → pending → approved / revoked | VERIFIED |
| Sensitive fields | `provisional_smt_root` — NOT exposed in API response (removed in Stage 1.5) | VERIFIED |
| Public fields | `id`, `snapshot_label`, `record_count`, `status` | VERIFIED |
| Immutable when approved | Approval is a state flag; no fields are modified besides status | VERIFIED |
| Revocation behavior | Status set to "revoked"; no field cleanup | VERIFIED |

### 6. ComponentVulnerabilityMapping (`vulnerability.component_vulnerability_mappings`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `snapshot_id` (FK), `component_hash` (128), `max_cvss` (Integer), `cve_ids` (Text, nullable), `created_at` | VERIFIED |
| FK | `snapshot_id` → `vulnerability.vulnerability_snapshots.id` (CASCADE) | VERIFIED |
| Indexes | `ix_vuln_mappings_snapshot_id`, `ix_vuln_mappings_component_hash` | VERIFIED |
| Constraints | `uq_vuln_mapping_snapshot_comp` unique on (snapshot_id, component_hash) | VERIFIED |
| Owner | Derived from snapshot (admin-controlled) | VERIFIED |
| Frontend access | NEVER — internal ZKP pipeline data only | VERIFIED |

### 7. ScanResult (`vulnerability.scan_results`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `sbom_upload_id` (UNIQUEIDENTIFIER, no FK in ORM but FK added in migration 002), `cve_id`, `component_name`, `component_version`, `component_purl`, `cvss_score`, `severity`, `fix_available`, `created_at` | VERIFIED |
| FK | `fk_scan_results_sbom_upload_id` → `sbom.sbom_uploads.id` (CASCADE) — migration 002 | VERIFIED |
| Owner | Derived from SBOMUpload (vendor-private) | INFERRED |
| Frontend access | No API endpoint exposes scan results | VERIFIED |
| Sensitive fields | `component_name`, `component_version`, `component_purl` — Private Data | VERIFIED |

### 8. SecurityPolicy (`policy.security_policies`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `name` (255), `description` (Text), `max_allowed_cvss` (Float), `max_allowed_cvss_int` (Integer), `policy_hash` (128), `is_active` (Integer, default 1), `created_at`, `updated_at` | VERIFIED |
| FK | None | VERIFIED |
| Owner | Globally shared, admin-controlled | VERIFIED |
| Creation behavior | Deactivates all prior policies; creates new active one | VERIFIED |
| Lifecycle | Active / inactive; no deletion | VERIFIED |
| Immutable fields | `policy_hash`, `max_allowed_cvss`, `max_allowed_cvss_int` after creation | INFERRED |
| Public fields | `id`, `name`, `description`, `max_cvss_score`, `policy_hash`, `created_at`, `active` | VERIFIED |
| Versioning | Implicit — new policy deactivates old; no explicit version chain | VERIFIED |

### 9. ProofJob (`zkp.proof_jobs`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `sbom_upload_id`, `snapshot_id`, `policy_id`, `user_id` (UUID, nullable), `status` (20, default "pending"), `sbom_root` (128), `vulnerability_db_root` (128), `policy_hash` (128), `proof_artifact` (Text), `error_message` (1024), `created_at`, `completed_at` | VERIFIED |
| FK (migration 002) | `sbom_upload_id` → `sbom.sbom_uploads.id` (CASCADE), `snapshot_id` → `vulnerability.vulnerability_snapshots.id` (CASCADE), `policy_id` → `policy.security_policies.id` (CASCADE) | VERIFIED |
| FK (ORM) | No FK constraints in ORM model — only in migration | VERIFIED |
| Owner | `user_id` — set at creation time; list and detail are owner-scoped | VERIFIED |
| Sensitive fields | `error_message` — sanitized to "Proof generation failed" in response schema | VERIFIED |
| Lifecycle | pending → assembling_witness → completed / failed / execution_blocked | VERIFIED |
| Artifact storage | `proof_artifact` stored as base64-encoded text in DB column | VERIFIED |
| Temporary files | Prover.toml, target .gz, and proof files are cleaned up in `finally` block | VERIFIED |

### 10. VerificationRequest (`verification.verification_requests`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `sbom_root` (128), `vulnerability_db_root` (128), `policy_hash` (128), `user_id` (UUID, nullable), `proof_artifact` (Text), `result` (20), `verified_at`, `created_at` | VERIFIED |
| FK | None | VERIFIED |
| Owner | `user_id` — recorded at verification time | VERIFIED |
| Lifecycle | Created atomically with result; idempotent by fingerprint | VERIFIED |
| Results | `verified`, `invalid`, `authoritative_record_mismatch`, `public_input_mismatch`, `unavailable` | VERIFIED |

### 11. VerificationCertificate (`verification.verification_certificates`)

| Property | Value | Status |
|---|---|---|
| PK | `id` (UNIQUEIDENTIFIER) | VERIFIED |
| Columns | `verification_request_id` (UNIQUEIDENTIFIER), `certificate_data` (Text), `sbom_root` (128), `vulnerability_db_root` (128), `policy_hash` (128), `issued_at` | VERIFIED |
| FK (migration 002) | `verification_request_id` → `verification.verification_requests.id` (CASCADE) | VERIFIED |
| FK (ORM) | No FK constraint defined in ORM model | VERIFIED |
| Owner | Public metadata by UUID; list requires authentication | VERIFIED |
| Lifecycle | Created atomically with verified VerificationRequest; immutable | VERIFIED |
| Public fields | All fields are classified as public certificate metadata | VERIFIED |

## Entities NOT FOUND

| Entity | Status |
|---|---|
| Audit logs table | NOT FOUND — no ORM model, migration, or API endpoint |
| Settings/preferences table | NOT FOUND |
| Tenant/organization table | NOT FOUND |
| Token revocation table | NOT FOUND |
| File upload metadata table | NOT FOUND (raw_content stored inline in sbom_uploads) |

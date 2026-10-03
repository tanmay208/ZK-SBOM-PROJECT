# Stage 2 Completion Matrix

Date: 2026-10-01
Stage: 2 — Frontend Data Storage & Persistence Architecture

## Scope

Summary audit gate for Stage 2. Every finding is traceable to executable source code.

## Baseline

| Property | Value |
|---|---|
| Git branch | `main` |
| Git commit | `733fd63` (captured at Stage 2 entry) |
| Backend tests | 497 passed, 26 warnings (pre-Stage-2 baseline) |
| Backend tests | 497 passed (post-Stage-2 validation — no source code modified) |
| Frontend build | lint: 0 errors, 1 warning; tsc: pass; build: pass |

## Documents Produced

| Document | File | Phase | Status |
|---|---|---|---|
| Data Storage Architecture | `13_DATA_STORAGE_ARCHITECTURE.md` | Phase 1 (Inventory) | COMPLETE |
| Data Persistence and Retention | `14_DATA_PERSISTENCE_AND_RETENTION_POLICY.md` | Phase 2 (Retention) | COMPLETE |
| Frontend Storage Policy | `15_FRONTEND_STORAGE_POLICY.md` | Phase 3 (Frontend Storage) | COMPLETE |
| Artifact Storage Architecture | `16_ARTIFACT_STORAGE_ARCHITECTURE.md` | Phase 4 (Artifacts) | COMPLETE |
| Data Lifecycle and Deletion | `17_DATA_LIFECYCLE_AND_DELETION.md` | Phase 5 (Lifecycle) | COMPLETE |
| Data Flow Architecture | `18_DATA_FLOW_ARCHITECTURE.md` | Phase 6 (Flows) | COMPLETE |
| Completion Matrix | `19_STAGE_2_COMPLETION_MATRIX.md` | Phase 7 (Matrix) | THIS FILE |

## Source Files Inspected

| Category | Files |
|---|---|
| Alembic migrations | `001_initial_schema.py`, `002_add_rbac_ownership_columns.py` |
| ORM models | `user.py`, `sbom_models.py`, `vulnerability_models.py`, `policy_models.py`, `zkp_models.py`, `verification_models.py` |
| Repositories | `sbom_repository.py`, `zkp_repository.py`, `verification_repository.py` |
| Services | `sbom_intake_service.py`, `commitment_service.py`, `prover_service.py`, `vulnerability_service.py`, `verification_service.py`, `policy_service.py` |
| Schemas | `sbom_schemas.py`, `zkp_schemas.py`, `verification_schemas.py`, `vulnerability_schemas.py`, `policy_schemas.py` |
| Routes | `sbom_routes.py`, `zkp_routes.py`, `verification_routes.py`, `vulnerability_routes.py`, `policy_routes.py`, `auth_routes.py`, `metrics_routes.py` |
| Infrastructure | `database.py`, `config.py`, `exceptions.py`, `app_factory.py`, `auth.py`, `security.py` |
| Crypto config | `shared/crypto/config.py`, `shared/crypto/profile.json` |
| Deployment | `docker-compose.yml` |
| Docs | All existing frontend docs (00–12), SECURITY_BOUNDARY.md, DATABASE_SCHEMA.md |

## Critical Findings

### 1. Raw SBOM Content Is Stored in the Database Column (Not Filesystem/Blob Storage)

`sbom_uploads.raw_content` is a `Text` column. For large SBOMs this will consume significant DB storage. No external object storage is used.

**RISK:** Performance and storage growth. Not a security risk but an operational constraint.

### 2. Proof Artifacts Are Stored in the Database Column

`proof_jobs.proof_artifact` stores base64-encoded binary proofs as `Text`. No artifact storage service exists.

**RISK:** Same as #1.

### 3. No Retention Policy Exists for Any Entity

No time-based retention, soft delete, archival, expiration, or cleanup mechanism exists anywhere.

**STATUS: UNDEFINED.** This is acceptable for development but is a production deployment gate.

### 4. CASCADE Delete Relationships Create Provenance Risk

Deleting any of `sbom_uploads`, `vulnerability_snapshots`, or `security_policies` would CASCADE-delete associated `proof_jobs`. This could destroy verification evidence.

**STATUS: RISK.** No delete API exists, so the risk is dormant.

### 5. Production Crypto Profile Is Incomplete

`profile.json` has `vk_hash: null` for the `prod` profile. The `CryptoProfile._validate_artifacts()` method will raise `CryptoProfileConfigError` if the prod profile is loaded.

**STATUS: KNOWN.** Production cryptographic artifact readiness remains a separate deployment gate.

### 6. User Table Is Not in a Named Schema

`dbo.users` is outside the five logical schemas. This is architecturally intentional (shared identity across services) but creates a schema ownership gap.

### 7. Audit Logging Table Does Not Exist

No `audit_logs` table, ORM model, or API exists. The frontend audit feature has no backend support.

### 8. No Tenant Isolation

No tenant entity, multi-tenant boundary, or row-level security exists. User-scoped queries provide basic isolation but not true multi-tenancy.

## UNKNOWN Items Carried Forward from Stage 2

| Item | Classification | Impact |
|---|---|---|
| Data retention policy | UNDEFINED | Production gate |
| Backup/recovery strategy | UNDEFINED | Production gate |
| Audit logging infrastructure | NOT FOUND | Frontend feature blocked |
| Tenant isolation model | UNDEFINED | Multi-user production gate |
| User administration | UNDEFINED | Admin feature blocked |
| Database encryption at rest | UNDEFINED | Compliance gate |
| Proof artifact external storage migration | UNDEFINED | Scale gate |
| Browser cache headers from reverse proxy | UNKNOWN | Security posture gap |
| Polling interval for proof jobs | UNKNOWN | Frontend UX decision |
| Rate limiting infrastructure | NOT FOUND | Production gate |

## Stage 2 Gate Assessment

| Criterion | Status |
|---|---|
| All entities inventoried | ✅ PASS |
| All FK/cascade relationships mapped | ✅ PASS |
| Frontend storage policy defined | ✅ PASS |
| Artifact lifecycle documented | ✅ PASS |
| Data flow for every frontend feature documented | ✅ PASS |
| Sensitive data boundaries confirmed | ✅ PASS |
| Cache strategy defined | ✅ PASS |
| Backend regression unchanged | ✅ PASS (497/497) |
| Frontend regression unchanged | ✅ PASS (build clean) |
| No source code modified | ✅ PASS (documentation-only stage) |

**STAGE 2 STATUS: COMPLETE.**

No unknowns were converted to assumptions. All findings are traceable to executable source. The architecture is ready for Stage 3 frontend implementation.

# Comprehensive Repository Cleanup Audit & Zero-Loss Master Archive Manifest

**Project:** Zero-Knowledge Verification for Software Supply Chain Security  
**Workspace Root:** [E:\Main Project](file:///E:/Main%20Project)  
**Audit Date:** 23 October 2026  
**Auditor:** AI Agent Pair-Programmer (Antigravity)  
**Safety Stance:** **PRESERVE FUNCTIONALITY AND EVIDENCE FIRST; REDUCE CLUTTER SECOND**  
**Core Policy:** Zero loss of cryptographic evidence, baseline user accounts, database state, release packages, or reproducibility assets.

---

## 1. Executive Summary & Audit Baseline (Phase 1)

A forensic whole-repository cleanup and archive audit was executed to transform the workspace into an organized, clean, and reproducible state while preserving every asset needed for live operations, automated regression testing, cryptographic verification, and viva defense demonstration.

### 1.1 Repository Baseline Coordinates
- **Repository Root:** `E:\Main Project`
- **Current Git Branch:** `chore/final-project-cleanup`
- **HEAD Commit:** `0881f9ecee25618ae7d9420313f17cf1f3d68672`
- **Active Operational Database:** PostgreSQL 16.15 on `127.0.0.1:5433` (`ZKP_SBOM_LOCAL_DEV`) at Alembic revision `016_add_snapshot_ttl_expires_at`.
- **Protected Database Instances:** PostgreSQL 17 on `127.0.0.1:5432` (`ZKP_SBOM`) and isolated container on port `5434` (100% untouched).
- **Baseline Users:** Exactly 8 accounts verified intact and active with valid role separation (Admin, Vendor, Trusted Importer, 5 Auditors).
- **Whole-Repository Inventory:** 43,216 files examined across all source trees and dependencies; 1,454 individual files cataloged in [`MASTER_PROJECT_CONTEXT/REPOSITORY_INVENTORY.json`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/REPOSITORY_INVENTORY.json) with 0 unclassified assets.
- **Total Audited Archive Assets:** 417 items cataloged in [`MASTER_PROJECT_CONTEXT/ARCHIVE_CONTENTS_MANIFEST.json`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/ARCHIVE_CONTENTS_MANIFEST.json).
- **Current Git Working Tree:** 8 staged changes, 105 unstaged/modified tracked files, 99 untracked files/directories.

---

## 2. Whole-Repository Taxonomy & Inventory Coverage (Phase 1)

Every file and meaningful directory across the entire repository was classified under the 12-category taxonomy:

| Taxonomy Category | File Count | Scope & Description |
|:---|:---:|:---|
| **GENERATED / REBUILDABLE** | 40,886 | Node modules (`frontend/node_modules`), Python virtual environment (`.venv`), Next.js build cache (`.next`), Pytest cache, and ephemeral scratch scripts. Rebuildable from manifest specifications. |
| **SECURITY / CRYPTOGRAPHIC RUNTIME** | 917 | Compiled native Barretenberg runtime (705 files in `crypto_runtime/`), decomposed chunk circuit artifacts (`segment_init_32`, `segment_mid_32`, `segment_final_32`), native launcher binary (`.bin/bb.exe`), and protected root `.env`. |
| **ACTIVE REQUIRED** | 698 | Production backend microservices, Next.js frontend application routes, Alembic migrations (`001`–`016`), active scripts, test suites, Docker definitions, and configuration files. |
| **HISTORICAL EVIDENCE** | 372 | Cold storage assets in `master_archive/` (135 files) and legacy documentation tree in `docs/` (237 files). Excluded from release packages. |
| **REPRODUCIBILITY EVIDENCE** | 264 | Active operational archive in `archive/proofs/` containing 3 historical proof bundles, 256 chunk segment proofs, and 3 verification keys required for independent verification. |
| **COMPATIBILITY MIRROR** | 41 | Mirrored rules (`.agents/rules/`), working context (`.context/`), project specifications (`project_context/`), and root compatibility entry points (`AGENTS.md`, `README.md`, `PROJECT_CONTEXT.md`, `PROJECT_ROADMAP.md`, `bootstrap.ps1`). |
| **AUTHORITATIVE DOCUMENTATION** | 32 | Canonical documentation root in `MASTER_PROJECT_CONTEXT/` (ADRs, roadmap, project state, security rules, cryptography rules, runbook, viva prep). |
| **RECOVERY / BACKUP** | 6 | Live demonstration rollback manifests (`.cache/demo_manifests/`) and recovery tools (`recover_d9_state.py`, `d9_cleanup_manifest.py`). |
| **UNKNOWN / INVESTIGATE** | **0** | **100% of all files across the repository have been inspected and classified.** |
| **Total Files Examined** | **43,216** | Comprehensive whole-repository coverage. |

---

## 3. Deep Audit of `archive/` vs `master_archive/` (Phase 2)

| Metric / Attribute | `archive/` (Active Operational Archive) | `master_archive/` (Historical Cold Storage) |
|:---|:---|:---|
| **Primary Location** | `E:\Main Project\archive\` | `E:\Main Project\master_archive\` |
| **File Count** | 264 files (2.67 MB) | 135 files (339.2 MB) |
| **Source ZIP Status** | **MANDATORY INCLUSION** (Verified by packaging test) | **STRICTLY EXCLUDED** (Verified by packaging test) |
| **Local Disk Requirement** | Required for local verification & packaging | Required on local disk for reproducibility audit |
| **Contents** | 3 completed ProofJob zip bundles + 256 chunk segment proofs + 3 VKs (`segment_init_32.vk`, `segment_mid_32.vk`, `segment_final_32.vk`) + manifest + profile | Historical docs, obsolete monolithic circuits, Stage 21 evaluation copies, historical logs, relocated historical experiment scripts and release backups |
| **Classification** | **ACTIVE REQUIRED / REPRODUCIBILITY EVIDENCE** | **HISTORICAL EVIDENCE / SUPERSEDED** |
| **Action** | **RETAINED IN FULL IN `archive/`** | **RETAINED IN FULL IN `master_archive/`** |

---

## 4. Working-Tree Clutter Remediation & Relocations (Phase 3)

To resolve repository clutter while preserving 100% of historical reproducibility evidence, 18 historical and non-essential assets were safely relocated into structured subdirectories of `master_archive/`:

| Original Path | New Path in `master_archive/` | Size | SHA-256 | Rationale |
|:---|:---|:---:|:---:|:---|
| `scripts/execute_stage21.py` | `master_archive/historical_scripts/stage21/execute_stage21.py` | 9.2 KB | `292048255e3d` | Historical Stage 21 evaluation script. |
| `scripts/generate_stage21_vectors.py` | `master_archive/historical_scripts/stage21/generate_stage21_vectors.py` | 5.2 KB | `a85257739914` | Historical Stage 21 test vector generator. |
| `scripts/stage21_payload.json` | `master_archive/historical_scripts/stage21/stage21_payload.json` | 129 KB | `877885ab5b2b` | Historical Stage 21 test payload. |
| `scripts/generate_stage18_witnesses.py` | `master_archive/historical_scripts/stage18/generate_stage18_witnesses.py` | 4.9 KB | `58e026849aff` | Historical Stage 18 witness generator. |
| `scripts/measure_stage18.py` | `master_archive/historical_scripts/stage18/measure_stage18.py` | 3.1 KB | `685969f82061` | Historical Stage 18 benchmark script. |
| `scripts/generate_stage19_c32_witness.py` | `master_archive/historical_scripts/stage19/generate_stage19_c32_witness.py` | 7.5 KB | `eaa459526cdd` | Historical Stage 19 witness generator. |
| `scripts/measure_stage19.py` | `master_archive/historical_scripts/stage19/measure_stage19.py` | 4.4 KB | `0fe5366f649d` | Historical Stage 19 benchmark script. |
| `scripts/generate_c32_circuits.py` | `master_archive/historical_scripts/circuit_tools/generate_c32_circuits.py` | 5.1 KB | `3c21a7093649` | Historical circuit generation script. |
| `scripts/generate_inventory.py` | `master_archive/historical_scripts/inventory/generate_inventory.py` | 1.4 KB | `6de066f0ea36` | Historical one-off inventory script. |
| `scripts/refactor_canonical_json.py` | `master_archive/historical_scripts/refactoring/refactor_canonical_json.py` | 744 B | `3eedc94886a8` | Historical refactoring utility. |
| `scripts/negative_tests_evidence.json` | `master_archive/historical_evidence/negative_tests_evidence.json` | 1.9 KB | `4db5ed1e8f71` | Historical negative test evidence payload. |
| `scripts/isolated_policy_app.py` | `master_archive/historical_scripts/isolated_policy_app.py` | 1.4 KB | `6d2326b2e2a3` | Historical isolated policy test helper. |
| `backend/scripts/inspect_staging_readonly.py` | `master_archive/historical_scripts/backend_scripts/inspect_staging_readonly.py` | 57.6 KB | `9d8b458b644d` | Historical Phase 3A read-only staging inspection utility. |
| `backend/scripts/normalize_policy_hashes.py` | `master_archive/historical_scripts/backend_scripts/normalize_policy_hashes.py` | 2.2 KB | `59a3b542119e` | Historical hash normalization script. |
| `backend/scripts/extract_exceptions.py` | `master_archive/historical_scripts/backend_scripts/extract_exceptions.py` | 568 B | `2a70e8118b6d` | Historical log exception extraction script. |
| `backend/scripts/inspect_db_logs.py` | `master_archive/historical_scripts/backend_scripts/inspect_db_logs.py` | 1.1 KB | `ee104332b795` | Historical DB log inspection script. |
| `dist/zkp-sbom-source.zip.bak_rev015` | `master_archive/historical_releases/zkp-sbom-source.zip.bak_rev015` | 19.8 MB | `d222f3c86914` | Pre-016 release package backup. |
| `dist/zkp-sbom-source.zip.prior_20261012.bak` | `master_archive/historical_releases/zkp-sbom-source.zip.prior_20261012.bak` | 18.7 MB | `72563e82f31b` | Early release package backup. |

**Zero Deletions Policy:** No files were permanently deleted during this remediation pass. Every non-essential or superseded file was verified to have zero active dependencies and safely relocated to `master_archive/` with exact cryptographic SHA-256 integrity checks.

---

## 5. Protected Assets Retained in Active Paths (Phase 4)

The following untracked and modified assets remain in their active paths because they are strictly required for runtime execution, testing, or recovery:

1. **Active Core Source Code:**
   - `backend/sbom_service/app/api/routes/application_routes.py` (and schemas, service)
   - `backend/shared/api/admin_user_routes.py`
   - `backend/verification_service/app/core/legacy_acir.py`
   - `backend/vulnerability_service/app/core/snapshot_expiry.py`
   - `backend/zkp_service/app/core/job_lock.py`
   - `frontend/src/api/services/adminService.ts` & `applicationService.ts`
   - `frontend/src/app/admin/`, `applications/`, `profile/` routes and UI components
2. **Database Migrations & Infrastructure:**
   - `backend/alembic/versions/012` through `016`: Complete ordered migration chain through rev `016`.
   - `backend/alembic/baseline_users.py`: Seed definition for 8 baseline accounts.
   - `backend/alembic/staging_guard.py`: Guard enforcing local database port isolation.
   - `docker-compose.local.yml`: Local Docker compose configuration.
3. **Automated Test Suites (1,345 backend tests + 96 frontend tests):**
   - Untracked test suites in `policy_service/tests/`, `sbom_service/tests/`, `shared/tests/`, `verification_service/tests/`, `vulnerability_service/tests/`, `zkp_service/tests/`, and `alembic/tests/`.
4. **Active Operations & Packaging Scripts:**
   - [`scripts/package_source_zip.py`](file:///E:/Main%20Project/scripts/package_source_zip.py): Authoritative source package builder.
   - [`scripts/prepare_d9_demo.py`](file:///E:/Main%20Project/scripts/prepare_d9_demo.py): D9 live demo preparation runner.
   - [`scripts/start_d9_gateway.py`](file:///E:/Main%20Project/scripts/start_d9_gateway.py): Gateway launcher on port 8080.
   - [`scripts/project_context.py`](file:///E:/Main%20Project/scripts/project_context.py): Context validator called by bootstrap.
   - [`scripts/recover_d9_state.py`](file:///E:/Main%20Project/scripts/recover_d9_state.py): Rollback tool for D9 manifests.
   - [`scripts/run_d9_4_live_acceptance.py`](file:///E:/Main%20Project/scripts/run_d9_4_live_acceptance.py): Live D9 non-proving acceptance runner.
   - [`scripts/verify_archive.py`](file:///E:/Main%20Project/scripts/verify_archive.py): Proof archive verification script.
   - [`bootstrap.ps1`](file:///E:/Main%20Project/bootstrap.ps1): Developer onboarding and bootstrap script.

---

## 6. Status Reconciliation & Empirical Validation (Phases 5 & 7)

### 6.1 Status Reconciliation
- **D7 Snapshot TTL:** `FORMALLY ACCEPTED BY OWNER WITH LIMITATIONS` (rev 016 applied to port 5433; 42/42 tests pass; isolated live migration re-test was not rerun in closure task).
- **D9 Category A Live Non-Proving Acceptance:** `REPORTED PASS` (gateway port 8080 healthy; RBAC 403 verified; demo policy CVSS 7.0; frozen snapshot with SMT root & TTL; compliant and vulnerable SBOMs ingested; fail-closed unproven job returned `verification_unavailable` with `certificate: null`; 0 fake certificates minted).
- **D5 Full 256-Segment Proving:** `DEFERRED / UNVERIFIED` (bounded 1-segment proof verified live in 83.25s; full 256-segment proof deferred due to host RAM safety threshold).
- **D9 Category B Cryptographic Acceptance:** `DEFERRED / UNVERIFIED` (multi-segment UltraPlonk proof, independent verification, and legitimate certificate issuance remain deferred).
- **External Feeds:** `FUTURE WORK` (demonstration dataset used; no live synchronization to external NVD/OSV APIs claimed).

### 6.2 Validation Results
1. **Source Packaging Validation (`scripts/package_source_zip.py`):**
   - Validated: Excludes `master_archive/`, `.cache/`, `.venv/`, `.env`, and credentials; includes `archive/` (264 files) and all active sources and migrations.
   - Generated package: `dist/zkp-sbom-source.zip` (SHA-256 `3CF91E822F...`).
2. **Session Bootstrap Script:**
   - `.\bootstrap.ps1` executed cleanly (Exit code: 0) and rendered updated canonical context and handoff.
3. **Application Gateway Health:**
   - `GET http://127.0.0.1:8080/api/v1/health` returned `HTTP 200 OK` (`"service": "verification_service", "status": "healthy"`).
4. **Database State Preserved:**
   - Docker container `zkp_sbom_local_dev` on `127.0.0.1:5433` verified at revision 016 with 8 baseline accounts and seeded demo fixtures.
   - Local PostgreSQL 17 on port 5432 and isolated DB on port 5434 are 100% untouched.

---

## 7. Deliverables & Next Steps (Phase 8)

### 7.1 Deliverables Generated
1. [`MASTER_PROJECT_CONTEXT/README.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/README.md): Canonical navigation index and governance guide.
2. [`MASTER_PROJECT_CONTEXT/REPOSITORY_INVENTORY.json`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/REPOSITORY_INVENTORY.json): Exhaustive whole-repository inventory (43,216 files examined, 1,454 cataloged, 0 unclassified).
3. [`MASTER_PROJECT_CONTEXT/ARCHIVE_CONTENTS_MANIFEST.json`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/ARCHIVE_CONTENTS_MANIFEST.json): 417-item archive audit manifest.
4. [`REPOSITORY_CLEANUP_AUDIT.md`](file:///E:/Main%20Project/REPOSITORY_CLEANUP_AUDIT.md): This authoritative cleanup audit report.

### 7.2 Immediate Next Step: Live UI Walkthrough
The repository is clean, organized, and primed for the immediate live role-by-role UI walkthrough:
- **API Gateway:** Active on port 8080.
- **Frontend UI:** Launch with `cd frontend; npm run dev`. Navigate to `http://localhost:3000`.
- **Role Sequence:** Admin $\to$ Trusted Importer $\to$ Vendor $\to$ Buyer/Auditor.

# Context Consolidation & Documentation Changelog

**Workspace Root:** `E:\Main Project`  
**Authoritative Location:** `MASTER_PROJECT_CONTEXT/project_context/CHANGELOG.md`  

## [2.6.0] — 2026-10-23 (D9 Live Non-Proving Acceptance, Forensic Repository Cleanup & Canonical Context Synchronization)

### Summary of Changes
- **Stage D9 — Live Non-Proving Acceptance Workflow (`scripts/prepare_d9_demo.py --execute`)**:
  - Executed authorized live non-proving demonstration against PostgreSQL 16 development container `zkp_sbom_local_dev` on host port `5433` (`ZKP_SBOM_LOCAL_DEV`, Alembic revision `016_add_snapshot_ttl_expires_at`).
  - Verified active API gateway health at `http://127.0.0.1:8080/api/v1/health` (`{"service":"verification_service","status":"healthy","version":"0.1.0"}`).
  - Validated strict Separation of Duties: Vendor attempt to call `POST /api/v1/vulnerability/ingest` was rejected with `HTTP 403 Forbidden`.
  - Executed vulnerability feed ingestion under `trusted_importer` role, followed by administrative review, approval, and snapshot freezing with authoritative SMT root and TTL expiry (`expires_at` populated).
  - Registered two distinct demonstration applications and uploaded CycloneDX SBOMs:
    1. Compliant Payment Gateway (`certifi@2021.5.30`, component score 3.7 / scaled 37 $\le$ policy threshold 70).
    2. Vulnerable Payment Gateway (`urllib3@1.26.5`, component score 7.5 / scaled 75 > policy threshold 70).
  - Resolved foreign-key resilience gap in `verification_service.py` & `verification_repository.py`: unproven or missing `proof_job_id` now safely maps to `proof_job_id = None` on audit records instead of raising SQL `ForeignKeyViolation` (HTTP 500).
  - Verified fail-closed verification: Verification attempt for an unproven job cleanly returned `verification_unavailable` with `certificate: null` (HTTP 200).
  - Exactly **0 certificates minted** during this non-proving acceptance run.
  - Durable rollback manifest generated: `.cache/demo_manifests/manifest_d9_run_20261023_034148_34d279f0.json`.
  - Stage D9 Category A is marked **REPORTED PASS (LIVE NON-PROVING ACCEPTANCE)**. Category B (Full Cryptographic Acceptance) remains UNVERIFIED.
- **Stage D5 Limitation Explicitly Preserved**:
  - Full 256-segment proving remains **DEFERRED / UNVERIFIED** due to host workstation memory floor constraints (bounded 1-segment pass in 83.25s verified; watchdog safety containment verified at 1.54 GiB RAM; 254 segments unattempted).
- **Forensic Repository Cleanup & Archive Manifest (`REPOSITORY_CLEANUP_AUDIT.md`, `ARCHIVE_CONTENTS_MANIFEST.json`)**:
  - Relocated historical root scripts (`container_repo.py`, `continue_golden_path.py`, `execute_golden_path.py`) to `master_archive/historical_scripts/`.
  - Relocated diagnostic log dumps (`compose_logs.txt`, `verification_logs.txt`) to `master_archive/logs/`.
  - Archived earlier cleanup audit to `master_archive/cleanup_audits/REPOSITORY_CLEANUP_AUDIT.20261014.md`.
  - Retained `archive/proofs/` in full (264 files) as an active operational requirement for `scripts/verify_archive.py` and `scripts/package_source_zip.py`.
  - Retained historical evaluation circuit duplicates (`segment_mid_32_1` through `_6`) in `master_archive/obsolete_circuits/` as documented Stage 21 evaluation evidence.
  - Cataloged 399 archive assets across `archive/`, `master_archive/`, `.cache/`, and `dist/` in `ARCHIVE_CONTENTS_MANIFEST.json`.
  - Working tree state recorded: Organized but not Git-clean (historical baseline: 8 staged, 115 modified, 119 untracked; verified current: 8 staged, 121 modified, 115 untracked).
- **Canonical Context Structure (`MASTER_PROJECT_CONTEXT/`)**:
  - Created canonical 3-tier hierarchy (`.agents/rules/`, `.context/`, `project_context/`) rooted in `MASTER_PROJECT_CONTEXT/`.
  - Preserved root-level compatibility mirrors (`.agents/`, `.context/`, `project_context/`, `AGENTS.md`, `README.md`, `PROJECT_CONTEXT.md`) for IDE rules discovery and `bootstrap.ps1`.
- **Packaging Integrity & Test Regressions**:
  - `scripts/package_source_zip.py`: Executed cleanly, all 5 assertions passed (991 files included, 0 secrets, `archive/` included, `master_archive/` excluded).
  - Backend regression: 181/181 unit/integration tests passed across 10 targeted test suites (0 failures, 0 skips).
  - Cleanup regression: 24/24 tests passed in `test_d9_cleanup_and_recovery.py`.
  - Frontend test suite: 96/96 tests passed (`npx tsx --test src/**/*.test.ts`).
  - Session bootstrap: `.\bootstrap.ps1` executed cleanly without error.

---

## [2.5.1] — 2026-10-23 (Stage D7 Packaging Synchronization & COND-01 Closure)

### Summary of Changes
- **Source ZIP Packaging Synchronization (`scripts/package_source_zip.py`)**:
  - Preserved historical pre-sync archive as `dist/zkp-sbom-source.zip.bak_rev015` (19,753,988 bytes, SHA-256: `D222F3C86914116E7163C84F30BAC36895C992EA26EA85D4BD68B7000B43FB6D`).
  - Updated packaging validator in `scripts/package_source_zip.py` to assert inclusion of migration `backend/alembic/versions/016_add_snapshot_ttl_expires_at.py` and verify migrations 001–016.
  - Rebuilt `dist/zkp-sbom-source.zip` (19,810,356 bytes, SHA-256: `3CF91E822F1A9308B8C37814649AB232FE70CCD9C53E757BC186AA9DEE80FE58`).
  - Confirmed archive integrity via `testzip()` (0 CRC errors, 959 files included, 4 excluded), strictly 0 active `.env` or private keys, and presence of all 16 Alembic migrations in correct numerical sequence.
  - Resolves conditional packaging gap `COND-01` without mutating any database or active runtime configuration. Note: Stage D7 overall owner acceptance remains pending.

---

## [2.5.0] — 2026-10-19 (Stage D4 Application & SBOM API Integration — Full Pass and Operational Closure)

### Summary of Changes
- **Unit D4.1 — Application ORM Synchronization & Standalone API (Backend)**:
  - Synchronized `Application` ORM model (`is_active: bool = True`, `archived_at: datetime | None = None`) in `sbom_models.py`.
  - Implemented standalone application endpoints in `application_routes.py`: `POST /api/v1/applications`, `GET /api/v1/applications`, `GET /api/v1/applications/{app_id}`, `PATCH /api/v1/applications/{app_id}`, `POST /api/v1/applications/{app_id}/archive`, `POST /api/v1/applications/{app_id}/reactivate`.
  - Enforced tenant isolation with non-disclosing 404 for cross-tenant access. Updated intake repository to reject SBOM uploads targeting archived applications.
- **Unit D4.2 — Policy Lifecycle & Proof Pre-Validation (Backend)**:
  - Implemented explicit policy activation endpoint: `POST /api/v1/policy/{policy_id}/activate` (admin-only) enforcing the single-active-policy invariant.
  - Hardened proof job creation in `zkp_repository.py` to validate that referenced security policies exist and are active (`active == True`).
- **Unit D4.3 — Frontend Application Management & SBOM Metadata Enhancement**:
  - Implemented typed `applicationService.ts` (`list`, `create`, `get`, `update`, `archive`, `reactivate`).
  - Created `/applications` management workspace with status filtering (`active`/`archived`), inline registration modal, and reversible soft-archival/reactivation dialogs.
  - Implemented **Select Existing or Create New** application selector in `/sboms/upload` with retry form preservation.
  - Enriched SBOM listing in `/sboms` with human-readable `application_name` and `vendor`, with graceful fallback (`Application details unavailable` / `—`) for historical unlinked records.
  - Implemented policy activation UI in `/admin/policies` with single-active-policy transition feedback and duplicate submission prevention.
  - Enriched backend `SBOMUploadResponse` schema with optional `application_name` and `vendor` fields via bounded `joinedload` query optimization.
  - Added admin-only `all_tenants: bool = False` query parameter to `GET /api/v1/sbom`, strictly rejecting non-admin access with `HTTP 403 Forbidden`.
- **Unit D4.4 — Consolidated Stage D4 Acceptance & Regression Gate**:
  - Corrected Finding D4.3-F1 test fixture mock property in `admin.test.ts` (`is_active` → `active`) matching schema contract.
  - Executed full backend offline test suites: **569 passed, 0 failed, 0 skipped** across `sbom_service` (247), `policy_service` (22), `zkp_service` (38), and `shared` (262).
  - Executed full frontend quality gates: TypeScript typecheck (0 errors), ESLint (0 errors/warnings), unit tests (**96 passed, 0 failed, 0 skipped**), and Next.js production build (**19 application routes** generated successfully).
  - Officially marked Stage D4 as **OPERATIONALLY CLOSED / FULL PASS**. Identified Stage D5 as the next active module.
- **Preservation & Safety Verified**:
  - Zero database connections (PG16/PG17 untouched). Migrations 001–015 frozen. Docker and infrastructure untouched. Circuits, UltraPlonk proofs, and Poseidon commitments frozen.

---

## [2.4.0] — 2026-10-17 (Stage D1 Phase 3A Inspection Acceptance, Baseline Synchronization & Work Units D1.1/D1.2 Authorization)

### Summary of Changes
- **Stage D1 Phase 3A Verified Findings Accepted**:
  - Confirmed empirical state of development database `ZKP_SBOM_LOCAL_DEV` on `127.0.0.1:5433` (PostgreSQL 16.15 in Docker container `zkp_sbom_local_dev`).
  - `public.users` verified present (5 users) and 100% compliant with canonical schema contract with 0 discrepancies.
  - Active Alembic migration revision confirmed at `014` (`014_application_tenant_isolation`).
  - Migration 011 confirmed applied (all 8 constraints, 1 index, 1 comment active).
  - Inspected ownership relationships confirmed **0 orphan rows** across all schemas.
  - Local PostgreSQL 17 on `127.0.0.1:5432` (`ZKP_SBOM`) verified strictly isolated and untouched.
- **Provisional Architectural Directions Adopted by Owner (Planning Only)**:
  1. Detached buyer verification adopted (subject to separate cryptographic design review).
  2. Certificate revocation authority: Admins may revoke any eligible certificate; vendors may revoke within their application ownership scope.
  3. Planned 5-role model adopted (`vendor`, `buyer`, `auditor`, `admin`, `trusted_importer`).
  4. Durable database audit table adopted for Stage D7 (`audit.audit_logs`).
  5. Policy deactivation (`is_active: bool`) and tenant-scoped application updates with deletion safeguards adopted.
- **Authorization Boundary (Work Units D1.1 & D1.2 Only)**:
  - Authorized Work Unit D1.1 (documentation synchronization across canonical state, handoff, and changelog records).
  - Authorized Work Unit D1.2 (offline mocked guard and inspection safety tests).
  - Explicitly prohibited: live database writes, migrations, DDL, Docker container/volume changes, migration 015 implementation, and access to PostgreSQL 17.

---

## [2.3.0] — 2026-10-16 (Stage C0 Final Roadmap Lock, Governance Alignment & Database Policy Revision)

### Summary of Changes
- **Locked Modular Roadmap**: Established agreed planning baseline across authoritative documentation and agent rules:
  - **Stage C (Product Experience, C0–C9)**: C0 (Scope/Architecture/Workflow Contract), C1 (Design System), C2 (Public Homepage), C3 (Authentication/Onboarding), C4 (Workspace/Dashboard), C5 (App & SBOM Management), C6 (Proof Generation Workflow), C7 (Buyer Verification & Certificates), C8 (Admin/Profiles/Role Workspaces), C9 (Frontend Acceptance).
  - **Stage D (Backend, Database & System Integration, D0–D9)**: D0 (API/Schema/Dependency Audit), D1 (Database/Migration Design), D2 (Auth/Onboarding/Profiles), D3 (RBAC & User Management), D4 (App & SBOM API Integration), D5 (Proof Generation & Job Lifecycle), D6 (Independent Verification & Certificate Lifecycle), D7 (Vulnerability Intelligence & Observability), D8 (Backend Security & Regression Validation), D9 (Full E2E Acceptance).
  - **Interleaved Execution Sequence**: `C0 → D0 → C1 → C2–C3/D1–D3 → C4–C6/D4–D5 → C7–C8/D3,D6,D7 → C9 → D8–D9`. Module acceptance gates cannot be skipped.
- **Database Environment Policy & Target Selection**:
  - Main database: PostgreSQL 17 on `127.0.0.1:5432` (`ZKP_SBOM`). Removed earlier blanket permanent prohibition. Target selection requires a verified environment assessment and explicit owner confirmation before schema-changing operations.
  - Development database: Docker PostgreSQL 16 on `127.0.0.1:5433` (`ZKP_SBOM_LOCAL_DEV` at rev `014`).
  - Zero database mutations, write queries, migrations, seeds, table drops, or container resets permitted during C0.
- **Product Architecture & Governance Alignment**:
  - **Planned 5-Role Model**: `vendor`, `buyer`, `auditor`, `admin`, `trusted_importer`. Documented distinction between planned product roles and existing code baseline (`vendor`, `admin`, `trusted_importer`, and `default="auditor"`).
  - **Frontend UX Direction**: Light-first design (white/cool-grey surfaces, navy/slate typography, restrained blue/teal accents) with authentic backend data, zero invented metrics, and optional dark mode.
  - **Cryptographic Freeze**: Noir 0.32.0 / Barretenberg 0.46.1 / UltraPlonk / BN254 / Poseidon Merkle & SMT trees strictly frozen. No circuit or proof format redesigns.
  - **Privacy & In-Memory Auth**: Session tokens maintained in memory; avoided insecure localStorage/sessionStorage persistence for bearer tokens.
  - **Auditability**: In scope; existing structured logging preserved; minimal persistent audit trail assessment deferred to D7.
  - **Excluded Scope**: Bounded out payments, subscriptions, third-party IDPs, email infrastructure, complex org hierarchies, custom vulnerability scanners, and new circuits.
- **Rules & Context Alignment**: Updated `AGENTS.md`, `project_context/PROJECT_ROADMAP.md`, `PROJECT_ROADMAP.md`, `project_context/PROJECT_STATE.md`, `project_context/PROJECT_CONTEXT.md`, `PROJECT_CONTEXT.md`, `project_context/REPOSITORY_SAFETY.md`, `project_context/EXECUTION_MAP.md`, `project_context/HANDOFF.md`, `project_context/README.md`, `.agents/rules/project-state.md`, `.agents/rules/repository-safety.md`, and `.agents/rules/security.md`.

---

## [2.2.0] — 2026-10-16 (Operational Policy Alignment — Network Assumption Correction)

### Summary of Changes
- Removed obsolete assumption that local development mode is restricted specifically due to SRMIST Wi-Fi.
- Standardized Operating Mode header across all authoritative records:
  `Operating Mode: LOCAL-ONLY. No remote operations, deployments, or external environment access without explicit authorization.`
- Preserved all independent safety boundaries: protected database isolation (`127.0.0.1:5432/ZKP_SBOM` strictly untouched), disposable development database usage (`127.0.0.1:5433/ZKP_SBOM_LOCAL_DEV`), Docker volume preservation, Gate 5R staging deployment prohibition, zero secret disclosure, and cryptographic/tenant invariants.

---

## [2.1.0] — 2026-10-14 (Zero-Loss Repository Cleanup & Preservation Audit)

### Summary of Audit
Performed a comprehensive, preservation-first repository cleanup audit in accordance with strict zero-loss governance:
- Created [`REPOSITORY_CLEANUP_AUDIT.md`](../REPOSITORY_CLEANUP_AUDIT.md) with complete inventory and classification of all project artifacts.
- Verified 100% SHA-256 parity between legacy `.context/` files and `project_context/archive/`.
- Verified archive integrity of `archive/proofs/` (263 files, 2 completed ZIPs, 256 segment proofs, manifest.json) and `master_archive/` (109 files, 286 MB).
- Validated all 22 markdown documentation files with 0 broken links.
- Confirmed zero destructive commands, zero file deletions, zero file moves, and zero secret disclosures.
- Established candidate list for eventual cache purging awaiting explicit user approval (`.pytest_cache/`, `__pycache__/`).

---

## [2.0.0] — 2026-10-14 (Authoritative Context Consolidation)

### Summary of Consolidation
Consolidated fragmented, duplicated, and conflicting project context documents from root `AGENTS.md`, root `PROJECT_CONTEXT.md`, root `PROJECT_ROADMAP.md`, `.agents/rules/`, and `.context/` into one centralized, authoritative directory: `E:\Main Project\project_context/`.

### Source-to-Destination Consolidation Mapping

| Destination Document (`project_context/`) | Primary Sources Merged | Core Content & Purpose |
| :--- | :--- | :--- |
| **`README.md`** | *New Consolidated Hub* | Onboarding guide, document index, relative links, and roadmap summary. |
| **`PROJECT_ROADMAP.md`** | Root `PROJECT_ROADMAP.md` & Master Prompt Specifications | Locked six-stage roadmap (`Stage A` through `Stage F`) with stable subtask IDs, deliverables, tests, and acceptance criteria. |
| **`PROJECT_CONTEXT.md`** | Root `PROJECT_CONTEXT.md` + `.context/canonical_context.md` | Core mission, ZK problem statement, system roles, technology stack, and operational constraints. |
| **`PROJECT_STATE.md`** | `.context/project_state.md` + Live Verified Runtime Evidence (13–14 Oct) | Empirical test accounting, database revision `014`, findings registers (`AUD-A-*`, `INT-DEF-*`, `F2-*`), and active work status. |
| **`ARCHITECTURE.md`** | `.context/architecture_reference.md` + Verified Source Tree | Microservices topology, data flows, 32-component chunking, public input binding order, and database schema models. |
| **`SECURITY_RULES.md`** | `.agents/rules/security.md` + `SECURITY_BOUNDARY.md` | Threat model, RBAC roles (`vendor`, `auditor`, `admin`, `trusted_importer`), multi-tenant scoping, input limits, and negative testing rules. |
| **`CRYPTOGRAPHY_RULES.md`** | `.agents/rules/cryptography.md` + Invariants from `canonical_context.md` | Pinned Noir 0.32.0 / Barretenberg 0.46.1 versions, BN254 field, Poseidon sponge ($t=2, t=3$), SMT depth 256, legacy ACIR 2144-byte body, and fail-closed Boolean verification. |
| **`REPOSITORY_SAFETY.md`** | `.agents/rules/repository-safety.md` + Core 18 from `AGENTS.md` | Git working tree preservation, protected DB isolation, root `.env` protection, zero persistent secret storage, and two-folder archive policy. |
| **`EXECUTION_MAP.md`** | `.context/execution_map.md` + Verified Local Commands | Step-by-step test commands, mandatory directory contexts (e.g. Cwd=`backend/` with `--import-mode=importlib`), and blocked operational commands. |
| **`DECISIONS.md`** | `.context/adrs.md` (ADRs 1–10) + ADRs 11 & 12 | Architecture Decision Records 1 through 12, documenting rationale for crypto, circuit segmentation, memory limits, roadmap lock, and DB isolation. |
| **`HANDOFF.md`** | `.context/handoff.md` + Current Local Verification State | Active milestone, next steps for Stage C, onboarding checklist for fresh AI sessions, and recent verified facts. |
| **`CHANGELOG.md`** | *New Consolidated Hub* | Documentation history and consolidation tracking. |
| **`archive/`** | Historical snapshots from `.context/` | Exact immutable copies of superseded `.context/*.md` files preserved for auditability and zero data loss. |

### Key Ambiguities & Conflicts Resolved
1. **Roadmap Status Dispute**: Formally resolved the prior conflict between on-disk governance (Stage F closed, Stage C active) and conversational reports (Stages D/E2/F2 closed with gaps). The project is now unified under the locked six-stage roadmap (`Stage A` through `Stage F`), with Stage A passed with gaps, Stage B substantially complete, and Stage C as the active next milestone.
2. **Database Target Clarity**: Reconciled local database configuration. Clarified that PostgreSQL on port 5432 (`ZKP_SBOM`) is strictly protected, while Docker PostgreSQL on port 5433 (`ZKP_SBOM_LOCAL_DEV`) is the authorized disposable target.
3. **IDE Rules Discovery Compatibility**: Preserved root `AGENTS.md`, root `PROJECT_CONTEXT.md`, and `.agents/rules/*.md` as concise compatibility entry points pointing directly to `project_context/`, maintaining automated IDE discovery without duplicating full policy texts.

---

## [1.1.0] — 2026-10-13 (Pre-Consolidation Baseline)
- Created `.context/` directory with `canonical_context.md`, `project_state.md`, `handoff.md`, `execution_map.md`, `architecture_reference.md`, and `adrs.md`.
- Documented findings `AUD-A-001` through `AUD-A-011` and `INT-DEF-001` through `INT-DEF-004`.
- Recorded SRMIST Wi-Fi constraint and Gate 5R boundary.

---

## [1.0.0] — 2026-10-10 (Initial Governance Baseline)
- Established root `AGENTS.md` and initial `.agents/rules/` policy files.

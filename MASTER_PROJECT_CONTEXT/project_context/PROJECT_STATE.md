# Authoritative Project State & Findings Register

**Document Version:** 3.2.0-final-publication-ready  
**Freshness Date:** 2026-10-27  
**Workspace:** `E:\Main Project`  
**Current Branch:** `chore/final-project-cleanup`  
**Head Commit:** `f92699da85825ef93680c17e6a212e4a8b475a4d`  
**Active Milestone:** Official Locked Roadmap V3 — Final Publication Clearance, Full Git History Eradication & Remote Synchronization Complete (Stage G G0–G6 Closed with `G6 PASS` on 25 Oct 2026; Follow-On Stage D Reassessment Closed with `STAGE D PASS` on 26 Oct 2026; Priority 3 Security Remediation & Priority 4 E2E Integration Closed on 27 Oct 2026; Git history eradication verified with 0 Gitleaks history leaks; all 7 legacy scripts preserved and verified in HEAD; frontend passing 116 tests with 0 skips; API gateway healthy on port 8000 exposing `/api/v1/*`).  
**Operating Mode:** LOCAL-ONLY. No remote operations, deployments, or external environment access without explicit authorization.

---

## 1. Verified Repository & Runtime Baseline

### 1.1 Service & Database Runtime Status
| Component | Runtime Identity | Verified Port | Status / Evidence |
| :--- | :--- | :--- | :--- |
| **Authoritative Presentation DB** | Supabase PostgreSQL 17.11 (`aws-0-ap-southeast-2.pooler.supabase.com`) | `127.0.0.1:5432` | **AUTHORITATIVE PRESENTATION TARGET / EMPIRICALLY VERIFIED**. Database `postgres` confirmed at Alembic revision **`016`** (`016_add_snapshot_ttl_expires_at`); baseline accounts active. Workflows 1–6 verified live. Protected / read-only during non-presentation tasks. |
| **Isolated Regression DB** | Docker PostgreSQL 17 (`zkp_sbom_g2_integration`) | `127.0.0.1:5435` | **AUTOMATED TEST TARGET / EMPIRICALLY VERIFIED**. Database `zkp_sbom_g2_integration` confirmed at Alembic revision **`016`**. Dedicated target for automated regression and security tests (155/155 passed). Preserves Supabase 5432 from mutation. |
| **API Gateway** | Unified Service Runner (`start_d9_gateway.py`) | `http://127.0.0.1:8080` | **HEALTHY / EMPIRICALLY VERIFIED**. `GET /api/v1/health` returns `HTTP 200 OK` (`"service":"verification_service","status":"healthy","version":"0.1.0"`). Connected to presentation DB on port 5432. Routes requests to backend microservices. |
| **Frontend UI** | Next.js 16.3.5 (Turbopack) | `http://127.0.0.1:3000` | **READY FOR LAUNCH**. Interactive UI serving dashboard, auth, applications, SBOM upload, proof wizards, certificates, and all 17 application routes. Configured API base: `http://127.0.0.1:8080`. Start via `cd frontend; npm run dev`. |
| **PostgreSQL 16 (Excluded)** | Docker PostgreSQL 16.15 (`zkp_sbom_local_dev`) | `127.0.0.1:5433` | **EXCLUDED FROM STAGE G / PRESERVED**. Historical dev database; not to be used for Stage G presentation or testing. |


### 1.2 Git Working Tree Inventory
- **Working Tree Modifications (61 tracked files across repository)**:
  - Repository root & orchestration (4 files): `.gitignore`, `README.md`, `docker-compose.yml`, `docker/nginx.conf`.
  - Backend services & infrastructure (38 files): `backend/alembic/env.py`, `backend/conftest.py`, `backend/pytest.ini`, `backend/test_concurrency_db.py`, `backend/shared/...` (auth, config, crypto SMT, test suites), `backend/sbom_service/...` (detail routes, repo tenant scoping, models, tests), `backend/policy_service/...` (detail routes, service, models), `backend/vulnerability_service/...` (routes, models, schemas, services, tests), `backend/verification_service/...` (Dockerfile, routes, verifier, main, repo, service, tests), `backend/zkp_service/...` (Dockerfile, routes, main, repo, prover service, tests).
  - Frontend services & routes (18 files): `frontend/next.config.ts`, `frontend/src/api/...` (client, services, types, tests), `frontend/src/app/...` (admin, dashboard, login, proofs, register, layout, tests), `frontend/src/auth/...` (RouteGuard, tests), `frontend/src/config/navigation.ts`.
  - Scripts (1 file): `scripts/verify_archive.py`.
- **Tracked Circuit & Script Evolution (19 changes)**:
  - 3 circuit deletions: `circuits/Nargo.toml`, `circuits/src/main.nr`, `circuits/src/smt.nr`.
  - 1 circuit rename: `circuits/src/merkle.nr` -> `scripts/noir_compatibility/src/main.nr`.
  - 15 added script files in `scripts/` (`bn254.nr`, `consts.nr`, etc.).
- **Governance & Launcher Assets (Approved for selective staging)**:
  - Native launcher source: [`scripts/bb_launcher.c`](file:///E:/Main%20Project/scripts/bb_launcher.c).
  - Runtime setup script: [`scripts/setup_crypto_runtime.ps1`](file:///E:/Main%20Project/scripts/setup_crypto_runtime.ps1).
  - Harmonized governance records: [`AGENTS.md`](file:///E:/Main%20Project/AGENTS.md), [`project_context/HANDOFF.md`](file:///E:/Main%20Project/project_context/HANDOFF.md), [`project_context/EXECUTION_MAP.md`](file:///E:/Main%20Project/project_context/EXECUTION_MAP.md), [`project_context/PROJECT_STATE.md`](file:///E:/Main%20Project/project_context/PROJECT_STATE.md), [`project_context/PROJECT_ROADMAP.md`](file:///E:/Main%20Project/project_context/PROJECT_ROADMAP.md), [`PROJECT_ROADMAP.md`](file:///E:/Main%20Project/PROJECT_ROADMAP.md).
- **Untracked Assets Preserved**:
  - Alembic migrations: `backend/alembic/versions/012_vulnerability_ingestion_provenance.py`, `013_add_vuln_lifecycle.py`, `014_application_tenant_isolation.py`, and `backend/alembic/baseline_users.py`, `staging_guard.py`, `backend/alembic/tests/`.
  - Untracked regression tests: `backend/policy_service/tests/test_policy_api.py`, `test_policy_creation.py`, `backend/sbom_service/tests/test_tenant_isolation.py`, `backend/verification_service/tests/test_b1_live_crypto.py`, `test_certificate_rotation.py`, `test_legacy_acir_adapter.py`, `test_public_input_binding.py`, `backend/zkp_service/tests/test_job_recovery.py`.
  - Untracked modules & runtimes: `backend/verification_service/app/core/legacy_acir.py`, `backend/verification_service/crypto_runtime/`, `backend/zkp_service/app/core/job_lock.py`.
  - Governance, context & bootstrap: `.agents/`, `.context/`, `AGENTS.md`, `PROJECT_CONTEXT.md`, `PROJECT_ROADMAP.md`, `REPOSITORY_CLEANUP_AUDIT.md`, `bootstrap.ps1`, `project_context/`.
  - Evidence & root archives: `archive/` (263 files), `master_archive/` (109 files), `verification_logs.txt`, `compose_logs.txt`.
  - Local gitignored tooling: `.bin/bb.exe`, `.bin/bb.cmd`, `.bin/bb`.

---

## 2. Empirical Test Execution Accounting

All test results below were executed and verified against the local environment on 13–16 October 2026:

| Test Suite / Inspection | Execution Scope | Passed | Skipped | Failed | Notes & Evidence |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `verification_service/tests/` | Pinned verifier, legacy ACIR adapter, live crypto, certificates | **146** | **0** | 0 | 100% passed. All 24 tests in `test_b1_live_crypto.py` passed via native launcher `bb.exe` (`F2-C-001` resolved); fail-closed verification validated. |
| `shared/tests/` | BN254 Poseidon sponge, Merkle trees, SMT, security, admin users, auth | **296** | 0 | 0 | 296 passed. Target allowlist, admin management, and dynamic SMT depth 256 verified. |
| `sbom_service/tests/` | Intake, CycloneDX validation, tenant isolation, application lifecycle, metadata enrichment | **247** | 0 | 0 | 247 passed. Standalone app lifecycle (D4.1), metadata enrichment, and admin all_tenants (D4.3) verified. |
| `policy_service/tests/` | Policy creation, CVSS validation, activation lifecycle, proof pre-validation | **26** | 0 | 0 | 26 passed. Policy activation endpoint, single active policy invariant, and proof pre-validation (D4.2) verified. |
| `vulnerability_service/tests/` | Ingestion schema, Separation of Duties, lifecycle, TTL matrix | **121** | 0 | 0 | 121 passed. Importer vs admin role boundaries and 37/37 deterministic TTL matrix tests verified. |
| `zkp_service/tests/` | Proof job recovery, advisory locks, API routes, active-policy validation, TTL checks | **85** | 0 | 0 | 85 passed. Active-policy validation, job recovery, and synchronous snapshot expiry checks verified. |
| `alembic/tests/` | Revision chain integrity (001-016), staging guard v2, baseline | **424** | 0 | 0 | 424 passed. Linear migration tree strictly validated (001 through 016). |
| **Backend Total** | **All 7 Microservices + Migrations** | **1,345** | **0** | **0** | **100% executable tests passed cleanly. Zero skipped.** |
| **Concurrency Probe** | `backend/test_concurrency_db.py` | **PASS** | 0 | 0 | 10 concurrent requests converged to 1 VerificationRequest and 1 Certificate on port 5433 with 0 deadlocks (16 Oct). |
| **Historical Frontend Baseline** | `npm test` (`tsx --test src/**/*.test.ts`) | **39** | 0 | 0 | Historical baseline (15 Oct): 39 passed in 488ms across initial route, auth, and store specs. |
| **Frontend Unit Tests (Priority 4 Gate)** | `npm test` (`tsx --test src/**/*.test.ts`) | **116** | **0** | **0** | **Empirically Verified (27 Oct)**: 116 passed in 1.15s with 0 skips across all application management, SBOM upload, dateTime/ETA calculations, policy activation, certificates, and auth specs. |
| **Frontend TypeScript (Stage D4.4 Gate)** | `npm run typecheck` (`tsc --noEmit`) | **PASS** | 0 | 0 | **Empirically Verified (19 Oct)**: 0 compilation errors. |
| **Frontend ESLint (Stage D4.4 Gate)** | `npm run lint` (`eslint`) | **PASS** | 0 | 0 | **Empirically Verified (19 Oct)**: 0 errors, 0 warnings. |
| **Frontend Production Build (Stage D4.4 Gate)** | `npm run build` (`next build`) | **PASS** | 0 | 0 | **Empirically Verified (19 Oct)**: 19 application routes generated (17 static prerendered, 2 dynamic server-rendered) with Turbopack (including `/applications`). |

---

## 3. Findings Register: Historical & Resolved Issues

### 3.1 Stage B Remediation Register (`AUD-A-001` through `AUD-A-011`)
| ID | Finding Title | Implementation Resolution | Current Verified Status |
| :--- | :--- | :--- | :--- |
| **AUD-A-001** | Cross-tenant Application Collision | Added `user_id` scoping to `(name, vendor, user_id)` in `sbom_repository.py`; added database unique constraint via migration `014`. | **CLOSED / VERIFIED** (`test_tenant_isolation.py` passing). |
| **AUD-A-002** | Noir/Barretenberg Compatibility | Fixed WSL distribution detection and host CLI fallback in `prover_service.py`. | **CLOSED / VERIFIED** (`test_prover_service.py` passing). |
| **AUD-A-003** | Concurrency & Advisory Locking | Implemented session advisory locks and orphan job recovery. Tested live against PostgreSQL 16 on port 5433 via `test_concurrency_db.py`. | **CLOSED / VERIFIED** (10-worker probe passed on port 5433 with zero deadlocks). |
| **AUD-A-004** | Migration Tracking Integrity | Validated linear chain `001` $\rightarrow$ `014`. Migrations `012..014` preserved on disk and applied to `ZKP_SBOM_LOCAL_DEV`. | **CLOSED / DEPLOYMENT DEFERRED**: Verified on local disposable DB; staging deployment deferred under Gate 5R. |
| **AUD-A-005** | Verification Event-Loop Blocking | Wrapped 256-subprocess execution in Starlette `run_in_threadpool` in `verification_routes.py`. | **CLOSED / VERIFIED** (`test_verification_api.py` passing). |
| **AUD-A-006** | Certificate Signing Trust Model | Standardized on symmetric HS256 tokens coupled with mandatory real-time online database revocation checks (`revoked_at`). | **CLOSED / ACCEPTED DESIGN**: Real-time revocation check operational. |
| **AUD-A-007** | Pending Snapshot Discoverability | `/snapshots` endpoint excluded pending records by default. Handled via explicit query parameters in UI. | **CLOSED / ACCEPTED**: Query parameters supported. |
| **AUD-A-008** | Password Schema Validation | Enforced min 8 chars, max 72 UTF-8 bytes (bcrypt ceiling), and username whitespace normalization in `auth_routes.py`. | **CLOSED / VERIFIED** (`test_stage3_security.py` passing). |
| **AUD-A-009** | Vulnerability Ingestion Role Boundary | Strict role check (`trusted_importer`) confirmed as intentional Separation of Duties control vs `admin`. | **CLOSED / VERIFIED** (`test_vulnerability_ingestion.py` passing). |
| **AUD-A-010** | Sparse Merkle Tree Depth Bounds | Added dynamic construction-time depth validation and empty hash precomputation in `SparseMerkleTree.__init__`. | **CLOSED / VERIFIED** (`test_smt.py` passing). |
| **AUD-A-011** | Granular REST Detail Endpoints | Missing GET-by-ID routes for SBOM and policy details. | **CLOSED / VERIFIED**: Implemented `GET /api/v1/sbom/{upload_id}` and `GET /api/v1/policy/{policy_id}` with strict tenant ownership, non-disclosure (404 on cross-tenant access), safe response schemas excluding `raw_content`, and 11 focused regression tests. |

### 3.2 Stage E Defect Register (`INT-DEF-001` through `INT-DEF-004`)
| ID | Title & Summary | Remediation Status |
| :--- | :--- | :--- |
| **INT-DEF-001** | Dashboard Metrics Schema Key Mismatch (`total_sboms` vs `sbom_count`) | **RESOLVED**: Aligned in `metricsService.ts`. Verified live `GET /api/v1/metrics` reflects real DB counts. |
| **INT-DEF-002** | Vulnerability Ingestion Schema & Role Mismatch | **RESOLVED**: Aligned frontend service to include provenance under `trusted_importer` role. |
| **INT-DEF-003** | Missing Snapshot "Freeze" Step in Proving UI | **RESOLVED**: Proving wizard filtered strictly for `frozen` snapshots with `authoritative_smt_root`. |
| **INT-DEF-004** | Nginx Gateway Trailing-Slash Routing Mismatch | **RESOLVED**: Trailing slashes harmonized in API client (`/api/v1/sbom/`, etc.). |

### 3.3 Active Audit Findings & Evidence Gaps
- **`F2-C-001` (Host Binary Gap)**: **RESOLVED / CLOSED**. Lightweight native launcher source code preserved in tracked [`scripts/bb_launcher.c`](file:///E:/Main%20Project/scripts/bb_launcher.c) and build automation integrated into [`scripts/setup_crypto_runtime.ps1`](file:///E:/Main%20Project/scripts/setup_crypto_runtime.ps1). Built binary `.bin/bb.exe` on PATH. All 24 tests in `test_b1_live_crypto.py` executed and passed without mocks or assertion changes.
- **`F2-B-001` (Low — Worker Revalidation)**: Prover background worker does not re-check `snapshot.status == "frozen"` at queue pickup time. *Mitigation*: The verification service re-checks snapshot status at verification time and rejects revoked snapshots.
- **`F2-B-002` (Low — Concurrency Row Lock)**: SMT root calculation during snapshot freeze does not acquire an exclusive row lock (`SELECT FOR UPDATE`). Freeze operation is idempotent.

---

## 4. Status Conflict Resolution & Roadmap Synchronization

Prior project transcripts recorded an unadjudicated conflict between on-disk governance (Stage F closed, Stage C active) and conversational reports (Stages D/E2/F2 closed with gaps).

**Resolution & Current Status (Effective 17 October 2026)**:
The project follows the authoritative **Locked Six-Stage Roadmap** (`Stage A` through `Stage F`) structured into dependency-aware modules:
- **Stage A (Re-entry Audit and Project Baseline)**: **FULL PASS (CLOSED)** (Baseline documented, test accounting verified, `F2-C-001` resolved with 24/24 crypto tests passing, 0 skipped).
- **Stage B (Backend, Database, and Security Fixes)**: **FULL PASS (CLOSED)** (Secret protection, RBAC, multi-tenant isolation, DB uniqueness constraints, REST detail routes, 10-worker concurrency probe passed on port 5433, 861/861 backend tests passing).
- **Stage C (Product Experience, Modules C0–C9)**: **REPORTED COMPLETE (PENDING OVERALL OWNER ACCEPTANCE)** (Modules C0 through C9 completed, with C6.1 correcting `running` proof-job state consistency and C9 completing frontend integration and acceptance. Quality gates reported by Antigravity: 80 unit tests passed, 0 failed, 0 skipped; TypeScript typecheck 0 errors; ESLint 0 errors, 0 warnings; Next.js production build 17 routes compiled).
- **Stage D (Backend, Database and System Integration, Modules D0–D9)**: **OPERATIONALLY CLOSED / FORMALLY ACCEPTED BY OWNER WITH DISCLOSED LIMITATIONS** (D0–D4, D6, D8 Full Pass; D7 snapshot TTL formally accepted by owner with migration 016; D9 Category A live non-proving workflow pass verified on dev port 5433; D5 bounded pass at 1 segment in 83.25s / full 256-segment run deferred as UNVERIFIED due to host RAM safety floor; 1,345 backend tests pass with 0 skips; 0 fake certificates minted).
  - `D0` Read-only discovery and audit: Operationally Closed / Full Pass.
  - `D1` Database and migration design: Operationally Closed / Full Pass (Alembic migrations 001–016 applied and verified on PG16 port 5433; 424 Alembic tests pass).
  - `D2` Authentication, onboarding and profiles: Operationally Closed / Full Pass (Bcrypt max 72-byte hashing, `/auth/me` role assertion verified live and offline).
  - `D3` RBAC and administrative user management: Operationally Closed / Full Pass (5-role enforcement active; 19 admin management tests pass).
  - `D4` Application and SBOM API Integration: Operationally Closed / Full Pass (569 offline backend tests + 96 frontend tests passing; tenant-scoped creation & upload verified).
  - `D5` Proof Generation and Job Lifecycle: **BOUNDED PASS AT 1 SEGMENT / FULL 256-SEGMENT WORKLOAD DEFERRED / UNVERIFIED** (Segment 0 verified live in 83.25s via in-flight proof generation and verification; raw proof body 2,144 bytes / serialized with public inputs 2,304 bytes; Segment 1 aborted by watchdog at 1.54 GiB host RAM falling below 2.0 GiB safety floor; guest PID 757 cleanly terminated via SIGTERM within 1.0s; 254 segments unattempted; full 256-segment workload remains explicitly deferred and unverified; 85 tests pass).
  - `D6` Independent Verification and Certificate Lifecycle: Operationally Closed / Full Pass (146 offline tests pass; fail-closed cert issuance verified live).
  - `D7` Vulnerability Intelligence, Observability and Snapshot TTL: **FORMALLY ACCEPTED BY OWNER WITH LIMITATIONS** (7 locked decisions D7-POL-01..07 implemented in source; default 30-day TTL [2,592,000s], 1h–365d bounds via `VULNERABILITY_SNAPSHOT_TTL_SECONDS`; synchronous fail-closed evaluation across 3 checkpoints; legacy grandfathering; historical certificates preserved; 42/42 targeted unit and matrix tests pass; migration 016 packaged in deliverable ZIP `3CF91E822F1A9308B8C37814649AB232FE70CCD9C53E757BC186AA9DEE80FE58`; formally accepted by owner on 23 October 2026 subject to documented limitations: isolated live migration test was not rerun in closure task, and not all live deployment scenarios have been tested).
  - `D8` Backend Security and Regression Validation: Operationally Closed / Full Pass (1,345 automated tests pass across security, IDOR, SQLi, payload size, adversarial crypto).
  - `D9` Full End-to-End Acceptance: **CATEGORY A: REPORTED PASS FOR LIVE NON-PROVING WORKFLOW / CATEGORY B: DEFERRED / UNVERIFIED**
    - **Category A (Live Non-Proving Acceptance Workflow)**: `REPORTED PASS`. Executed live against PostgreSQL 16 on port 5433 (`ZKP_SBOM_LOCAL_DEV`, rev 016). Gateway on port 8080 healthy. Vendor vulnerability-ingestion denied with HTTP 403 Forbidden. Vulnerability feed ingested under `trusted_importer`, approved and frozen by `admin` with authoritative SMT root and TTL expiry. Compliant application (`certifi@2021.5.30`, score 3.7 / scaled 37 $\le$ 70) and Vulnerable application (`urllib3@1.26.5`, score 7.5 / scaled 75 > 70) ingested. Unproven job verification cleanly returns `verification_unavailable` with `certificate: null`. Exactly 0 certificates minted. Durable rollback manifest: `.cache/demo_manifests/manifest_d9_run_20261023_034148_34d279f0.json`.
    - **Category B (Cryptographic Acceptance)**: `DEFERRED / UNVERIFIED`. Full witness generation, live UltraPlonk proof generation across all segments, independent cryptographic proof verification, and legitimate certificate issuance remain unexecuted in this non-proving demonstration.
- **Stage E (Security and Cryptographic Validation)**: **OPERATIONALLY CLOSED / FULL PASS** (270 dedicated security and cryptographic tests passed with 0 skips, 0 failures; E1–E7 verified; formal validation report and 20-threat security matrix published in `project_context/SECURITY_VALIDATION_REPORT.md`).
- **Stage F (Final Testing, Documentation, and Submission)**: **ACTIVE / IN PROGRESS** (Comprehensive regression, clean build, architecture documentation, student runbook, viva prep, submission packaging, forensic cleanup audit).

### 4.1 Stage D1 Phase 3A Verified Findings & Baseline Observations
On 17 October 2026, bounded read-only inspection of the development container `zkp_sbom_local_dev` (`127.0.0.1:5433`, `ZKP_SBOM_LOCAL_DEV`) verified:
1. **Server Identity**: PostgreSQL 16.15 on x86_64-pc-linux-musl running in container `zkp_sbom_local_dev`. Host-side authentication restored via `postgres` superuser.
2. **`public.users` Baseline Parity**: Table exists, contains 5 users (`idem_43068bbb`, `idem_2ec0a7bd`, `idem_c60ea9b9`, `local_auditor_alpha`, `Tanmay`), and matches the canonical baseline contract (`id` UUID PK, `username` VARCHAR(255) UNIQUE, `hashed_password` VARCHAR(255), `role` VARCHAR(50), `created_at` TIMESTAMP) with **0 discrepancies**.
3. **Alembic Head Revision**: Active revision is **`014`** (`014_application_tenant_isolation`).
4. **Migration 011 Status**: Confirmed **ALREADY APPLIED**. All 8 constraints, 1 index, and 1 column comment added by migration 011 are active in the database.
5. **Zero Orphan Rows**: Inspected ownership relationships across all schemas reported **0 orphan rows** (`sbom.applications`: 0/0, `vulnerability_snapshots`: 0/0, `zkp.proof_jobs`: 0/0, `verification_requests`: 5 valid rows pointing to `public.users` / 0 orphans, `chunk_proof_sets`: 0/0).
6. **PostgreSQL 17 Isolation**: Local PostgreSQL 17 at `127.0.0.1:5432` (`ZKP_SBOM`) was not targeted and remains strictly frozen and isolated.

*Discipline Notice*: These are reported inspection findings confirming database schema and current row counts; they do not constitute proof that every application workflow is correct, nor does the absence of orphan rows eliminate all data-loss risks for future migrations.

### 4.2 Provisional Architectural Directions Adopted by Owner (Planning Only)
The project owner has provisionally adopted the following architectural directions for Stage D planning:
1. **Detached Buyer Verification**: Adopted in principle, subject to separate cryptographic design review.
2. **Certificate Revocation Authority**: Administrators may revoke any eligible certificate; vendors may revoke eligible certificates within their application ownership scope.
3. **Consolidated 3-Role Model**: Finalized 3 active roles across services: `vendor`, `buyer`, `admin` (legacy roles `auditor` and `trusted_importer` retired from active use; historical migrations 001–016 preserved).
4. **Durable Database Audit Table**: Adopted for planning in Stage D7 (`audit.audit_logs`).
5. **Policy Lifecycle & Application Updates**: Policy deactivation (`is_active: bool`) and tenant-scoped application updates with deletion safeguards adopted.

### 4.3 Authorization Boundary & Active Constraints
- **Authorized Work**: Work Unit D1.1 (documentation synchronization) and Work Unit D1.2 (offline mocked guard and inspection tests) only.
- **Strictly Prohibited**:
  - No database writes, DDL, migrations, or live SQL execution.
  - No Docker container/volume modifications.
  - No edits to historical migrations `001`–`014`.
  - Migration `015` design implementation and live database verification remain unauthorized.
  - PostgreSQL 17 on port `5432` remains strictly protected.

### 4.5 Stage G3 Live Presentation Acceptance & G4 Authorization
On 24 October 2026, Stage G3 completed all live staging presentation workflows, verified the canonical $10\times$ CVSS policy contract, and satisfied all 15 mandatory acceptance criteria:
1. **Authoritative Presentation Database**: Supabase PostgreSQL 17.11 on remote port 5432 (`aws-0-ap-southeast-2.pooler.supabase.com:5432`), database `postgres`, Alembic revision `016`.
2. **Automated Test Database**: Isolated Docker PostgreSQL 17 on `127.0.0.1:5435`, database `zkp_sbom_g2_integration`.
3. **Canonical CVSS Scale Resolution**: Canonical $10\times$ integer scaling ($6.9 \rightarrow 69, 7.0 \rightarrow 70, 7.1 \rightarrow 71, 10.0 \rightarrow 100$) verified across policy serialization, vulnerability ingestion, SMT leaves, public inputs, and circuit constraints.
4. **Approach B (Versioned Policy Binding)**: Implemented in `VerificationRepository.validate_authoritative_records`. Historical proofs/certificates remain bound to their registered policy hash (`Stage 21L Policy`, `0x0628b30d...`), while new jobs bind strictly to `viva_presentation_policy` (`a1c325e7-...`, threshold 70).
5. **Genuine Live Circuit Rejection (Workflow 3 PASS)**: Ingested Log4j 2.14.1 (CVSS 10.0 $\rightarrow$ 100). Witness generation in `segment_init_32` failed constraint `assert(scores[i] <= policy_max_cvss)` in Nargo 0.32.0 ($100 > 70$). Job status transitioned to `failed`; negative verification returned `structural_rejection`; exactly 0 certificates issued.
6. **All 6 Presentation Workflows Passed**: Workflows 1–6 executed through supported application REST routes against Supabase PostgreSQL 17 (6/6 PASS). Evidence captured in `scratch/stage-g/g3/20261024_183500/G3_LIVE_WORKFLOW_RESULTS.json`.
7. **Zero Regression Gate Failures**: 148 automated tests passed across 8 test suites on isolated Docker PostgreSQL 17 port 5435 with 0 failures and 0 skips.
8. **Disclosed Limitations**: Full 256-segment UltraPlonk proof generation accurately disclosed as UNVERIFIED / DEFERRED under Stage D5.
9. **Gate Status**: **STAGE G3 ACCEPTED — STAGE G4 AUTHORIZED**.

### 4.6 Stage G4 Final Presentation Readiness, Packaging & Submission Sign-Off
On 25 October 2026, Stage G4 completed final presentation readiness, packaging, repository cleanliness audit, and submission sign-off:
1. **Repository Cleanliness & Secret Exposure Audit (G4.1 PASS)**: Tracked files audited with zero secret or key leakage. Root `.env`, `master_archive/`, and ephemeral scratch spaces strictly excluded from packaging.
2. **Documentation Synchronization (G4.2 PASS)**: Verified active project state, examiner runbooks, and test evidence reconciliation. Retained Stage D5 256-segment proving as `UNVERIFIED / DEFERRED`.
3. **Submission Package Integrity (G4.3 PASS)**: Candidate archive `dist/zkp-sbom-source.zip` verified (949 files, 19,898,493 bytes) with dual-tool SHA-256 match `13d46d23421c8228ea04fdbb2b865cb21014cdae0b36d62d92a89903c0f307eb`. Verified zero `.env`, keys, or caches. Extraction tested to isolated temporary directory.
4. **Shutdown & Socket Isolation (G4.4 PASS)**: Verified demo process lifecycle and port listener release without lingering sockets.
5. **Phase 1 Acceptance (G4.5 PASS)**: All mandatory G4 criteria verified with zero gaps.

### 4.7 Official Locked Roadmap V3 Stage G (G0–G6) Independent Closure
On 25 October 2026 (03:48 IST), Stage G completed full-stack security hardening, role consolidation, and cross-role regression under Roadmap V3:
1. **Role Consolidation**: Active user roles consolidated to `vendor`, `buyer`, and `admin`. Self-registration defaults to `buyer`; caller role injection rejected. Retired roles (`auditor`, `trusted_importer`) return HTTP 422.
2. **Backend Hardening**: Thread-safe sliding-window rate limiting on auth and proving endpoints with `Retry-After` headers; CSP `default-src 'none'`; CORS `PATCH` method; mandatory two-person snapshot approval rule.
3. **Frontend Simplification**: Application shell and route guards structured strictly around 3 primary roles with truthful metrics and unproven job handling.
4. **Cross-Role Regression**: 348 automated tests passed (250 backend + 98 frontend) with 0 failures and 0 skips; clean Next.js production build across 19 routes.
5. **Gate Status**: **`G6 PASS — STAGE G CLOSED`** (`scratch/stage-g/v3_g6/20261025_034800/G6_INDEPENDENT_CLOSURE_REPORT.md`).

### 4.8 Follow-On Stage D Reassessment & 256-Proof Acceptance Closure
On 25–26 October 2026, the follow-on Stage D Reassessment resolved all remaining integration and proving gates:
1. **D9 Category A Live Re-Validation**: 9-step non-proving workflow verified against Docker PostgreSQL 17 port 5435 (`zkp_sbom_g2_integration`) under the 3-role model with 0 fake certificates minted (`scratch/stage-d/20261025_043000/`).
2. **Historical Full Proof Generation & Runner Crash**: On 2026-10-25 (`scratch/stage-d/20261025_failed_run_256_evidence/`), all 256 segment proofs were authentically generated and persisted across 32 chunks over 3h 29m (7,722.73s CPU proving). The runner subsequently crashed during negative rejection testing due to an ORM attribute access (`ProofJob.sbom_upload` instead of `sbom_upload_id` / authoritative commitments).
3. **Recovery Independent Verification (0 Proof Regeneration)**: On 2026-10-25/26 (`scratch/stage-d/recovery_acceptance_linux_20261025/`), the runner was repaired, the precomputed proof archive `68c06b8e-c7b8-4402-b98e-f6c1f2236cd9.zip` (SHA-256 `60a41c69448e6a59fd9c697d9c7d0d0500198d61c6b38b3100190134906d7bce`) was loaded with zero proof regeneration (`proof_generation_invoked: false`), and all 256 segment proofs were cryptographically verified in 531.826s using Barretenberg 0.46.1. All 6 negative rejection tests passed.
4. **Authoritative Certificate Minted**: Active compliance Certificate `81d1a4f0-1ae4-4baf-9716-9081c6ae9f7b` issued and bound to canonical commitments ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$).
5. **Demonstration & Scope Invariants**: Re-running full 256-segment proving during live presentations remains explicitly deferred to avoid host memory exhaustion and 3.5-hour delays. Academic viva readiness is verified; production readiness is NOT claimed, and Gate 5R remains strictly blocked in LOCAL-ONLY mode.
6. **Independent Evidence Audit**: Formally audited on 26 October 2026 02:45 IST (`scratch/stage-d/final_evidence_audit_20261026_0236/final_audit_report.md`).
7. **Gate Status**: **`STAGE D FINAL STATUS: PASS`**.

### 4.9 Phase 4.4 Source Package Hardening, Crash-Recovery Audit & Local Commit
On 26 October 2026 (19:22 IST), Phase 4.4 completed final source package hardening, recovery testing, and local commit (`15726e7919df2f4211d293dfb0fccc765e29ff03`):
1. **Durable Packaging Publication Protocol**: Implemented crash-safe journaled publication protocol with `.journal.json` and `.prev` rollback in `scripts/package_source_zip.py`; verified all 8 failure-injection recovery scenarios with 100% pass (`--test-recovery`).
2. **Deterministic Source ZIP**: Published `dist/zkp-sbom-source.zip` (4,988,222 bytes, 949 entries) with SHA-256 `34d2922e3debe173ec5715c3a2478f30bdd6b72f000fb3d27711c35eb1906337`; two-build reproducibility verified bit-for-bit identical.
3. **Fresh-Extraction Verification**: Extracted to isolated directory; verified runtime setup via `setup_crypto_runtime.ps1`, native `bb.exe` compilation, and live UltraPlonk proof verification (exit code 0; tampered proof rejected with exit code 1).
4. **Documentation & Version Reconciliation**: Reconciled `@noir-lang/backend_barretenberg@0.32.0` and `@aztec/bb.js@0.46.1` in `README.md` and setup instructions.
5. **Commit Scope**: Staged and committed strictly `README.md` and `scripts/package_source_zip.py` with 0 unstaged or untracked changes.

### 4.10 Priority 3 & 4 Closure, Git History Credential Eradication & Publication Clearance
On 27 October 2026, Priority 3 (Security & Credential Remediation) and Priority 4 (E2E Integration & Expo Readiness) completed authoritative verification, credential eradication, and publication clearance:
1. **Legacy Historical Script Remediation**: All seven historical scripts in `master_archive/scripts/` (`update_db.py`, `check_chunks.py`, `mark_failed.py`, `host_db_check.py`, `update_job.py`, `check_progress.py`, `audit.py`) verified fully remediated with fail-closed environment-driven database connectivity (`get_db_connection()`), resource cleanup, and zero hardcoded credentials. All 7 scripts preserved and tracked in HEAD.
2. **Git History Credential Eradication**: Full Git history rewritten in isolated workspace using `git-filter-repo` to excise historical database connection strings and sequential 64-hex placeholder keys in `EXECUTION_MAP.md`. Gitleaks full history scan over all reachable commits returned **0 findings** (0 leaks across all commits).
3. **End-to-End API Gateway & Microservices Health**: API gateway on port 8000 verified healthy (`GET /api/v1/health` returning HTTP 200). Upstream routing for SBOM, policy, vulnerability, verification, and ZKP microservices validated.
4. **Frontend Integration & Test Suites**: Next.js frontend verified serving all 17 routes on port 3000; 116 frontend unit and integration tests passing cleanly with 0 skips; TypeScript compilation 0 errors; ESLint 0 errors and 0 warnings.
5. **Publication Clearance**: Local workspace and clean publication history verified 100% leak-free without broad allowlisting or suppression. Repository ready for publication and synchronization.

# Authoritative Project State

**Freshness Date:** 2026-10-13  
**Documentation Cutoff:** October 13, 2026  
**Current Branch:** `chore/final-project-cleanup`  
**Operating Mode:** LOCAL-ONLY (SRMIST Wi-Fi Constraint; Gate 5R Strictly Blocked)  
**Gate 5R Status:** **STRICTLY BLOCKED** (No live DB migrations, no staging access, no container restarts, no production exports)

---

## 1. Locked Roadmap Progress & Stage-Status Ledger

The project strictly follows the single locked roadmap:  
$$\mathbf{A0 \longrightarrow A \longrightarrow B \longrightarrow E \longrightarrow F \longrightarrow C \longrightarrow D \longrightarrow E2 \longrightarrow F2 \longrightarrow Stage\ 23}$$

| Stage | Name | Recorded Status | Supporting Evidence Base | Outstanding Gaps & Operational Restrictions | Status Confidence | Next Permitted Action |
|---|---|---|---|---|---|---|
| **A0** | Reproducibility Audit | **PASS / CLOSED** | Baseline Git tree, lockfiles, environment verified | Host lacks native `bb` binary | Verified in repo | Complete |
| **A** | Backend In-Depth Audit | **PASS / CLOSED** | Audited all backend services; `AUD-A-001..011` cataloged | None (Audit phase) | Verified in repo | Complete |
| **B** | Backend Remediation | **ACCEPTED / CLOSED** | Remediated `AUD-A-001..010`; 161 Alembic tests pass; 20 isolation tests pass | PostgreSQL advisory locks verified on SQLite mock; migrations `012..014` untracked | Verified (Gap-Qualified) | Complete |
| **E** | Full-Stack Integration Audit | **PASS WITH GAPS** | Cataloged `INT-DEF-001..004`, risks `INT-RISK-001..002`, gaps `INT-GAP-001..002` | Defects carried forward to Stages C/D | Verified in repo | Complete |
| **F** | Crypto Regression Audit | **PASS WITH GAPS / CLOSED** | Confirmed zero regressions; 102 core crypto tests pass; 5 invariants intact | Native host `bb` execution skipped (`F2-C-001`) | Verified (Gap-Qualified) | Complete |
| **C** | Frontend Architecture | **DISPUTED** (Pending vs Closed) | On-disk: designated active next step. Conversational: reported closed in Step 10664 | Formal architectural specification uncommitted in `.context/` | **CONFLICTED** | **Flag for Owner Adjudication** |
| **D** | Frontend Implementation | **DISPUTED** (On Hold vs Closed) | Code exists in `frontend/`; 39 tests pass; `npx tsc --noEmit` 0 errors | Browser E2E relies on mocks; live integration unverified under Gate 5R | **CONFLICTED** | **Flag for Owner Adjudication** |
| **E2** | Full-Stack Re-Audit | **DISPUTED** (On Hold vs Pass w/ Gaps) | Contract mapping between frontend, gateway, and backend services inspected | Live multi-container gateway stack unverified under Gate 5R | **CONFLICTED** | **Flag for Owner Adjudication** |
| **F2** | Final Security Audit | **DISPUTED** (On Hold vs Pass w/ Gaps) | Units F2-A..D synthesized in conversational report Step 10664 | Native `bb` tests skipped; PostgreSQL concurrency unverified | **CONFLICTED** | **Flag for Owner Adjudication** |
| **Stage 23** | Deployment & Ingress | **STRICTLY BLOCKED / NOT AUTHORIZED** | Operational documentation prepared (`STAGING_READINESS_ENVIRONMENT_GUIDE.md`) | Gate 5R strictly blocked; all 6 prerequisites unfulfilled; no deployment authorization | Verified (Blocked) | None (Halt) |

---

## 2. Stage B Remediation Register (`AUD-A-001` through `AUD-A-011`)

| Finding ID | Title & Summary | Remediation Implementation | Current Evidence & Status |
|---|---|---|---|
| **AUD-A-001** | Unscoped Application Lookup (Cross-tenant collision) | Added `user_id` scoping to `(name, vendor, user_id)` in `sbom_repository.py`; added database model `UniqueConstraint`; migration `014`. | **CLOSED / ACCEPTED** (`test_tenant_isolation.py` passing; 20 tests). |
| **AUD-A-002** | Noir/Barretenberg Runtime Compatibility | Fixed WSL distribution detection and host CLI fallback in `prover_service.py`. | **CLOSED / ACCEPTED** (`test_prover_service.py` passing). |
| **AUD-A-003** | Proof-Job Concurrency & Advisory Locking | Implemented PostgreSQL session advisory locks and orphan job recovery in `zkp_service/app/core/job_lock.py`. | **CLOSED / ACCEPTED (Gap-Qualified)**: Tested on in-memory SQLite mock harness (`_mock_held_locks`). Live multi-connection PostgreSQL advisory-lock release unverified under Gate 5R. |
| **AUD-A-004** | Migration Chain & Tracking Integrity | Validated linear chain `001` $\rightarrow$ `014`. 161 Alembic tests pass. Migrations `012..014` intentionally preserved untracked for deployment. | **INFORMATIONAL / DEFERRED DELIVERY**: Files `012`, `013`, `014` are untracked on disk; a clean Git clone ends at migration `011`. Live staging database schema has not been updated past `011`. |
| **AUD-A-005** | Verification Event-Loop Blocking | Wrapped 256-subprocess execution in `run_in_threadpool` in `verification_routes.py`. | **CLOSED / ACCEPTED** (`test_verification_api.py` passing). |
| **AUD-A-006** | Certificate JWT Signing Trust Model | Standardized on symmetric HS256 tokens coupled with mandatory real-time database revocation checks (`revoked_at` query). | **CLOSED / INTENTIONAL DESIGN DECISION**: Offline asymmetric key verification deferred. |
| **AUD-A-007** | Pending Snapshot Discoverability | `/snapshots` endpoint excluded pending records by default. | **DEFERRED / LOW RISK**: Handled via explicit query parameters in UI. |
| **AUD-A-008** | Registration Password Schema Validation | Enforced min 8 chars, max 72 UTF-8 bytes (bcrypt ceiling), and username whitespace normalization in `auth_routes.py`. | **CLOSED / ACCEPTED** (`test_stage3_security.py` passing). |
| **AUD-A-009** | Vulnerability Ingestion Role Boundary | Strict role check (`trusted_importer`) confirmed as intentional Separation of Duties security control vs `admin`. | **CLOSED / INTENTIONAL CONTROL** (`test_vulnerability_ingestion.py` passing; 37 tests). |
| **AUD-A-010** | Sparse Merkle Tree Depth Safety | Added dynamic construction-time depth validation and empty hash precomputation in `SparseMerkleTree.__init__`. | **CLOSED / ACCEPTED** (`test_smt.py` passing). |
| **AUD-A-011** | Missing Granular REST Endpoints | Missing GET-by-ID routes for SBOM and policy details. | **DEFERRED / NON-BLOCKING**: API enhancement. |

---

## 3. Stage E Findings Carry-Forward Register (Inputs to Stage C/D)

### A. Confirmed Functional Integration Defects
1. **`INT-DEF-001` (Dashboard Metrics Schema Key Mismatch)**:
   - Backend `GET /api/v1/metrics/` returns `{ total_sboms, total_jobs, total_certificates, total_verifications }`.
   - Frontend `types/index.ts` originally expected `{ sbom_count, proof_count, ... }`.
   - Result: Dashboard cards rendered `—`. Resolved in frontend service mapping.
2. **`INT-DEF-002` (Vulnerability Ingestion Schema & Role Mismatch)**:
   - Backend `POST /api/v1/vulnerability/ingest` requires `source_identity` (string) and `provenance` (dict), and mandates role `trusted_importer`.
   - Frontend service aligned to pass provenance under `trusted_importer` role.
3. **`INT-DEF-003` (Missing Snapshot "Freeze" Step in Frontend Workflow)**:
   - Backend verification strictly requires `snapshot.status == "frozen"` and matches on `authoritative_smt_root`.
   - Frontend proof generation UI aligned to filter strictly for `frozen` snapshots.
4. **`INT-DEF-004` (Nginx Gateway Trailing-Slash Routing Mismatches)**:
   - `docker/nginx.conf` proxies upstream services with trailing slashes (`/api/v1/sbom/`, `/api/v1/zkp/`).
   - Frontend API client harmonized to append trailing slashes.

### B. Operational Risks
- **`INT-RISK-001` (In-Memory JWT Loss on Refresh)**: Token is kept in memory to mitigate XSS; hard refresh prompts re-login. Intentional security posture vs UX trade-off.
- **`INT-RISK-002` (Proof-Job Concurrency / Capacity)**: Heavy concurrent proof jobs require up to 6–8GB per Node process. Container memory limit raised to 8GB (`ADR 4`).

### C. Test Coverage Gaps
- **`INT-GAP-001` (Missing Frontend/Backend Contract Tests)**: Absence of automated schema drift checks between FastAPI OpenAPI and TypeScript interfaces.
- **`INT-GAP-002` (Missing Automated Browser E2E Tests)**: Frontend tests rely on `npx tsx --test` mocks; no live Playwright/Cypress browser suite configured.

---

## 4. Stage F / F2 Cryptographic Invariants & Unresolved Findings

### A. Cryptographic Invariants Verified Intact
1. **Canonical Field Encoding**: BN254 scalar field elements strictly constrained ($0 \le x < p$); 32-byte big-endian representation.
2. **Poseidon Sponge Constraints**: Pinned to $t=3$ (binary Merkle nodes) and $t=2$ (leaf commitments).
3. **Tree Topologies**: Depth-10 SBOM Merkle Tree (1024 components); Depth-256 Vulnerability SMT with dynamic construction bounds.
4. **Legacy ACIR Proof Layout**: Pinned to `@noir-lang/backend_barretenberg@0.32.0`. Proof body is exactly 2144 bytes. Public inputs prepended canonically (`init`: 5 inputs / 2304 bytes; `mid`: 4 inputs / 2272 bytes; `final`: 3 inputs / 2240 bytes).
5. **Fail-Closed Verification Strictness**: Only explicit Boolean `true` from `BarretenbergVerifier.verifyProof()` triggers certificate issuance. `STRUCTURAL_REJECTION`, `RUNTIME_FAILURE`, and `ENVIRONMENT_FAILURE` remain distinct from `CRYPTOGRAPHIC_FALSE`.

### B. Unresolved Security & Cryptographic Findings Register
- **`F2-B-001` (Medium — Evidence Gap)**: Background prover worker in `prover_service.py` does not re-check `snapshot.status == "frozen"` when picking up a queued job from the database. *Mitigation*: Verification service validates the snapshot status at verification time and rejects revoked snapshots with `record_mismatch`. *Residual Risk*: Prover compute could be wasted on un-verifiable proofs.
- **`F2-B-002` (Low — Evidence Gap)**: SMT root calculation during snapshot freeze in `vulnerability_routes.py` does not acquire an exclusive row lock (`SELECT ... FOR UPDATE`). *Mitigation*: Freeze operation is idempotent. *Residual Risk*: Concurrent freeze race behavior unverified on live PostgreSQL.
- **`F2-C-001` (Medium — Evidence Gap)**: 24 live Barretenberg integration tests in `test_b1_live_crypto.py` were skipped because native Linux `bb` binary is unavailable on the Windows host.
- **`F2-C-002` (Low / Informational)**: Design observation confirming proof bytes combine canonical 32-byte BE public inputs with 2144-byte body for `bb verify -k vk -p proof`, avoiding prohibited `-i`.
- **`AUD-A-003` (Medium — Evidence Gap)**: PostgreSQL advisory locks tested only via SQLite mock harness (`_mock_held_locks`).
- **`AUD-A-004` (Low / Operational)**: Migrations `012`, `013`, `014` are untracked in Git and have never been applied to staging.

---

## 5. Golden Path Historical Evidence References

- **Upload ID**: `542e6e26-8a44-4573-b209-e1f0fe580605`
- **Frozen Snapshot ID**: `ae12c17f-9667-43ca-855d-92fc23e06ab3`
- **Authoritative Snapshot Root**: `0x1cfc169b50f494414cd8fd079178c0310fb404ba99bf84f430114bbf25845446`
- **Authoritative SBOM Root**: `0x19885c209f550e127998ed816fca0d54a91810ad699ddad8cb73f634e3e3ff5bc`
- **Policy ID**: `639428d4-1a6c-4350-9302-b391beff1d30`
- **Canonical Policy Hash**: `0x0628b30da1be08030f8d6d03a88cc029595ca9c43cf6d5bf1122d3491fa35c0a`
- **Verification Request ID**: `ae93d187-8fba-49b3-9d7a-ffa219b92c6f`
- **Proof Job ID**: `0859e5a5-b449-4ac9-93ad-1f0bb66ed882`

### Certificate ID Historical Discrepancy
- In `.context/project_state.md:101`, `backend/scripts/check_schema.py`, and `backend/scripts/check_records.py`, the recorded Certificate ID is:
  $$\mathbf{444d6620-8e13-4511-8b11-ff78c6294cf0}$$
- In earlier conversational logs and mock test scripts, synthetic UUIDs (e.g. `11111111-1111-1111-1111-111111111111` or dynamic `uuid4()`) were referenced.
- *Status*: The exact live record cannot be queried under Gate 5R / SRMIST Wi-Fi. The discrepancy is documented without normalization.

---

## 6. Archive, Packaging, and Preservation State

- **Root `archive/`**: **263 files** (2 proof bundle ZIPs, 256 chunk segment proofs in `archive/proofs/temp/`, 5 VK/manifest files). Reusable assets and fixtures.
- **Root `master_archive/`**: **109 files**. Retained historical reports, obsolete monolithic circuits. Excluded from source ZIP.
- **Obsolete `archives/` and `backend/archives/`**: Confirmed absent (`Test-Path: False`).
- **Source ZIP (`dist/zkp-sbom-source.zip`)**: Exists (874 entries, ~18.7 MB).
  - Excludes `master_archive/` (0 entries).
  - Retains `archive/` (263 files).
  - Retains untracked migrations `012`, `013`, `014`.
  - **External-Distribution Safety Warning**: `scripts/package_source_zip.py` relies solely on filename and extension patterns (`.env`, `.pem`, `.key`). It does **not** inspect file contents or catch arbitrary names like `credentials.json` or plaintext connection strings in `.txt`/`.log` files. **The ZIP is NOT certified safe for external distribution without an authorized content-level secret audit.**

---

## 7. Test Evidence Accounting (Strict Provenance)

1. **Verified Observed (Recent Turn — 2026-10-12)**:
   - Suite A (Core Crypto & Security): **102 passed**, 71 warnings in 14.63s.
   - Suite B (Tenant Isolation & Job Recovery): **20 passed**, 9 warnings in 1.00s (`--import-mode=importlib`).
   - Suite C (Vulnerability Ingestion & Separation of Duties): **37 passed**, 2 warnings in 2.18s.
   - Suite D (Alembic Migrations 001–014): **161 passed**, 1 warning in 1.20s.
   - Suite E (Frontend Unit Tests): **39 passed** in 405ms (`npx tsx --test`).
   - Suite F (Frontend TypeScript Compilation): **0 errors** (`npx tsc --noEmit`).
   - *Test Accounting Note*: Historical execution reports record suite results of 102 + 20 + 37 + 161 + 39 passes, plus a separate TypeScript check with zero errors. These figures total 359 reported passes across the listed suites, but the number of unique test cases has not been independently established. Suite overlap and test-case identity have not been deduplicated.
2. **Historical Reported Tests**:
   - Stage B full backend suite: reported ~822 passed, 24 skipped (requires `--import-mode=importlib` to avoid `test_tenant_isolation.py` collision).
   - Stage F2 audit units: reported 314 focused tests (175 in F2-A, 58 in F2-B, 81 in F2-C).
3. **Skipped Tests**:
   - 24 live Barretenberg integration tests (`test_b1_live_crypto.py`) skipped due to missing host `bb` binary.
4. **Tests Run During Current Turn**: **0 tests** (safe documentation synchronization task).
5. **Unverified Live Behavior**: Live PostgreSQL multi-connection concurrency and staging ingress routing remain unverified under Gate 5R and SRMIST Wi-Fi.

---

## 8. Gate 5R & Operational Prerequisites

**Status:** **STRICTLY BLOCKED.**

Operational activities remain prohibited until all six prerequisites are satisfied:
1. Explicit, bounded read-only inspection authorization from the project owner.
2. Verified backup/recovery arrangements (reports found no confirmed PITR on Supabase; backup architecture unverified).
3. Secure `.env.staging` configuration file (template is insufficient).
4. Trusted root CA and verified TLS boundary.
5. Dedicated least-privilege PostgreSQL inspection role provisioned and verified.
6. Administrator confirmation of target identity, endpoint pooling mode, server version, and scope.

---

## 9. Decision & Change Log

### Entry: October 13, 2026
- **Documentation Synchronized**: `PROJECT_CONTEXT.md`, `AGENTS.md`, `.context/canonical_context.md`, `.context/project_state.md`, `.context/handoff.md`, `.context/execution_map.md`, `.agents/rules/`.
- **Sources Used**: Local repository inspection, `.context/` files, session transcripts, test logs, `git status`.
- **Contradictions Recorded**: Explicitly documented the Stage C (active next on disk) vs Stage D/E2/F2 (closed with gaps in conversational reports) status conflict; documented Certificate ID discrepancy (`444d6620...` vs synthetic mocks).
- **Environmental Constraints Added**: Recorded the SRMIST Wi-Fi / Local-Only work constraint alongside Gate 5R.
- **Facts Verified vs Historical**: Verified 263 files in `archive/`, 109 in `master_archive/`, 874 in `dist/zkp-sbom-source.zip`. Historical execution reports record suite results of 102 + 20 + 37 + 161 + 39 passes, plus a separate TypeScript check with zero errors. These figures total 359 reported passes across the listed suites, but the number of unique test cases has not been independently established. Suite overlap and test-case identity have not been deduplicated. Historical Golden Path execution and live PostgreSQL concurrency labeled historical/unverified.
- **Deliberately Preserved**: No application code, circuits, VKs, migrations, configuration, or test fixtures were modified.
- **Next Permitted Action**: Stand by for project-owner adjudication on the Stage C vs F2 status conflict.

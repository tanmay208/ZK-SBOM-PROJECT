# Project Roadmap: Zero-Knowledge Verification for Software Supply Chain Security

**Document Version:** 3.0.0-final  
**Effective Date:** 25 October 2026  
**Workspace:** `E:\Main Project`  
**Project Type:** Engineering Student Major Project  
**Authoritative Status:** Official Locked Roadmap V3  
**Superseded Roadmap:** Locked Master Roadmap V1/V2 (Stages A–F and Operational Viva Stage G)  
**Requirements Source:** `Project_Stagewise_Report_A_to_G_and_Stage_D_Pending.pdf` (pages 11–12; source PDF noted as not locally present in workspace; scope established from report context)  
**Historical Operational Baseline:** Stages A through F and earlier Stage G0–G4 operational work are formally closed and preserved as reusable evidence.  
**Active Phase:** Final Submission Preparation, Context Synchronization & Packaging Verification (Stages G0–G6 closed 2026-10-25 with G6 PASS; Follow-On Stage D Reassessment closed 2026-10-26 with STAGE D PASS).  

---


## 1. Project Overview

### 1.1 Problem Statement
Modern software engineering relies extensively on open-source dependencies and third-party software components. When software vendors distribute applications to enterprise buyers, government agencies, or regulated industries, purchasers require assurance that the software does not contain critical, exploitable vulnerabilities (such as high-severity CVEs).

Historically, buyers demanded that vendors disclose their full **Software Bill of Materials (SBOM)**—a complete machine-readable inventory of all third-party libraries, sub-dependencies, licenses, and compiler versions. However, software vendors frequently resist sharing unredacted SBOMs because:
1. **Intellectual Property & Trade Secrets**: Proprietary component architectures, internal libraries, and unique dependency compositions are commercially sensitive.
2. **Offensive Attack Surface Exposure**: A full SBOM gives an adversary a direct roadmap of every unpatched, non-critical dependency or outdated internal component, simplifying zero-day exploitation.

This creates a fundamental conflict: **Buyers need proof of compliance, while vendors require confidentiality of proprietary components.**

### 1.2 Purpose of Zero-Knowledge Verification
Zero-Knowledge Proofs (ZKPs) resolve this conflict mathematically. Using zero-knowledge succinct non-interactive arguments of knowledge (zk-SNARKs / UltraPlonk arithmetic circuits), a vendor can prove the following statement:

$$\text{"I know a private SBOM } S \text{ such that } \text{MerkleRoot}(S) = R_{\text{SBOM}}, \text{ and every component in } S \text{ complies with Policy } P \text{ against Vulnerability Database } V\text{"}$$

The verifier learns **only that the claim is true** ($\text{True} / \text{False}$), plus cryptographic confirmation of the public commitments ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, and $H_{\text{Policy}}$). The verifier learns **zero information** about the component names, package URLs (`purl`), versions, or dependency tree structure.

```
+--------------------------------------------------------------------------------------------------+
|                                    ZERO-KNOWLEDGE SBOM PIPELINE                                  |
+--------------------------------------------------------------------------------------------------+
|  [Vendor Private Realm]                                                                          |
|    Raw CycloneDX SBOM -> Parser -> Canonicalizer -> Poseidon Merkle Tree (Depth 10)              |
|                                                              |                                   |
|                                                              v (Private Witness)                 |
|                                                   +----------------------+                       |
|  [Authoritative Public Inputs]                    | Noir UltraPlonk      |                       |
|    - SBOM Root: 0x...                             | Arithmetic Circuit   |                       |
|    - Vuln SMT Root: 0x...    -------------------> | (32-Component Chunks)|                       |
|    - Policy Hash: 0x...                           +----------------------+                       |
|                                                              |                                   |
|                                                              v                                   |
|  [Public Verification Realm]                              ZK Proof Artifact (~2.2 KB)            |
|    Barretenberg Verifier (WASM / Native)  <------------------+                                   |
|              |                                                                                   |
|              v (Explicit Boolean Acceptance)                                                     |
|    Verification Service -> Issues Signed Compliance Certificate (JWT / Ed25519)                  |
+--------------------------------------------------------------------------------------------------+
```

### 1.3 System Roles and Responsibilities
The platform enforces strict Role-Based Access Control (RBAC) and Separation of Duties. The agreed product role model comprises five roles:

1. **Software Vendor (`vendor`)**:
   - Manages authorized applications within an isolated tenant namespace (`(name, vendor, user_id)` unique scope).
   - Uploads private CycloneDX SBOMs via encrypted intake endpoints.
   - Triggers zero-knowledge proof generation jobs for their applications.
   - Obtains and distributes public verification certificates and cryptographic commitments to buyers.
2. **Buyer / External Verifier (`buyer`)**:
   - Planned dedicated consumer role for enterprise and institutional purchasers.
   - Receives verification evidence and independently verifies zk-SNARK proofs and signed compliance certificates.
   - Validates proof commitments ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$) without accessing private component data or internal vendor application structures.
3. **Third-Party Auditor (`auditor`)**:
   - Accesses authorized verification evidence, compliance records, and public audit trails in a read-oriented workflow.
   - Self-registration default role in the current baseline implementation.
   - Validates issued compliance certificates online via certificate ID or token fingerprint.
4. **Security Administrator (`admin`)**:
   - Manages authoritative security policies (e.g., maximum permissible CVSS threshold).
   - Reviews and formally approves (`approved`) or freezes (`frozen`) vulnerability database snapshots.
   - Revokes compromised compliance certificates with auditable timestamps and reasons.
   - Manages user accounts, privileges, and role promotions.
5. **Vulnerability Intelligence Ingestion (`trusted_importer`)**:
   - Automated ingestion service or designated security team ingestion role with separation of duties.
   - Seeds CVE records and computes Sparse Merkle Tree (SMT) commitments.
   - Enforces two-person integrity: creates snapshots strictly in `pending` status, requiring an `admin` to approve or freeze them.

*Implementation Evidence Note:* In the current codebase, `role` is stored as `String(50)` on `User` defaulting to `'auditor'`, with server-side checks actively enforcing `'vendor'`, `'admin'`, and `'trusted_importer'`. The dedicated `'buyer'` role and explicit account status/activation lifecycle are planned for Stage D (D2/D3).

### 1.4 Architecture & Subsystem Separation
The system is divided into clear functional layers to prevent data leakage and ensure modular reproducibility:

| Layer | Technology | Primary Responsibility | Confidentiality Boundary |
| :--- | :--- | :--- | :--- |
| **Frontend UI** | Next.js 16 (App Router), React 19, TypeScript, Vanilla CSS | Interactive dashboard, uploads, policy browser, proof tracking, certificate validator. | Public / Client. Light-first design. Must never receive or display private component witness data. |
| **API Gateway & Services** | FastAPI 0.115, Python 3.12, Uvicorn | REST API routes, in-memory auth sessions, RBAC enforcement, payload size limits. | Protected Boundary. Strips PURLs and raw content from buyer-facing responses. |
| **Relational Database** | PostgreSQL, SQLAlchemy 2.0, Alembic (Rev 001–014) | Persistent records for users, applications, uploads, snapshots, jobs, and certificates. | Internal. Enforces foreign keys, unique constraints, and tenant row-level boundaries. |
| **Commitment Engine** | Custom Python crypto primitives (`shared/crypto`) | BN254 field arithmetic, Poseidon hashing ($t=2, t=3$), binary Merkle trees, Sparse Merkle Trees. | Ingests private SBOM data to compute public 32-byte roots; discards unneeded raw state. |
| **Proving Subsystem** | Noir 0.32.0, ACIR circuits, Barretenberg 0.46.1 | Computes non-membership of SBOM components in vulnerability SMTs; outputs chunk proofs. | Private. Witness generation executes strictly in isolated memory/workers. |
| **Verification Engine** | `backend/verification_service` (`verify_proof.mjs`) | Pinned Node.js WASM Barretenberg verifier (`verify_bound_proof`), public-input validation. | Public. Consumes only the proof and public roots; never requires raw SBOMs. |
| **Certificate Authority** | Verification Service Repository | Signs compliance certificates, stores SHA-256 fingerprints, provides real-time revocation checks. | Authoritative public ledger of issued/revoked proof certificates. |

### 1.5 Product Objective & Cryptographic Claim Scope
The platform provides privacy-preserving software supply-chain verification:
- A vendor supplies and manages a private CycloneDX SBOM, computes Poseidon commitments, and generates cryptographic zk-SNARK evidence through the frozen UltraPlonk circuits.
- The vendor shares public commitments ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$) and proof artifacts with buyers.
- A buyer or auditor independently verifies the proof cryptographically against the pinned verifier.
- **Claim Limitation**: A valid proof proves **strictly** that every component in the committed SBOM satisfies the specified security policy $P$ relative to the frozen vulnerability database snapshot $V$. **Never claim** that a valid proof proves an entire application is free from all vulnerabilities, zero-days, or bugs.

### 1.6 Core Architecture Decisions & Invariants
1. **Frontend Aesthetic**: Professional, light-first product design inspired by modern SBOM-management information architecture (white and cool-grey surfaces, navy/slate typography, restrained blue and teal accents, responsive tables, filters, accessible components). A restrained dark theme may be supported. Uses genuine backend data; never invent metrics or statuses.
2. **Cryptographic Freeze**: Circuits (Noir 0.32.0 ACIR), proof format (UltraPlonk 2144 bytes), verifier contracts (Barretenberg 0.46.1), commitment bindings, and verification behavior are frozen. No unauthorized redesigns.
3. **Session Privacy**: Bearer tokens are stored strictly in memory (`authTransport.ts`) and cleared on logout or page refresh. Reauthentication upon refresh/reopen is an intentional security trade-off. Standard form autocomplete attributes are used without claiming control over browser password managers.
4. **Vulnerability Intelligence**: Preserve existing CVE, CVSS, and NVD ingestion, snapshot, and lifecycle semantics (`pending`, `approved`, `frozen`, `revoked`). Do not build a replacement vulnerability scanner.
5. **Auditability**: In scope. Preserve structured logs and diagnostics. Assess durable records and minimal persistent audit trails in D7 without assuming a dedicated audit table exists. Never log credentials, secrets, or raw SBOM components. Dedicated analytics dashboard is deferred.
6. **Database Target Policy**:
   - Local PostgreSQL 17 on `127.0.0.1:5432`, database `ZKP_SBOM` (historically recorded as main database at rev `007`).
   - Docker PostgreSQL 16 on `127.0.0.1:5433`, database `ZKP_SBOM_LOCAL_DEV` (historically recorded as dev database at rev `014`).
   - The database-target decision requires a verified environment assessment and explicit owner confirmation before schema-changing operations. Neither environment's contents or equivalence are assumed without evidence. Strictly no migrations, write queries, seed data, table drops, or container/volume resets pre-D1.
7. **Excluded Scope**: Payment gateways, subscriptions, external identity providers, email-verification infrastructure, complex organization hierarchies, replacement vulnerability scanners, new cryptographic circuits, and new proof formats.

### 1.7 Implemented Features vs. Validated Security Claims
In this academic project, a sharp distinction is maintained between an *implemented software feature* and a *validated security property*:
- **Implemented Feature**: Code exists, an endpoint responds, or a database migration ran.
- **Validated Security Claim**: Empirical evidence exists (from unit tests, integration tests, or cryptographic invariants) proving that unauthorized actions, tampered proofs, or data leaks fail closed under negative testing.

No security claim may be presented as verified without accompanying test evidence.

---

## 2. Core Project Principles

All work across all six roadmap stages must adhere strictly to these ten engineering rules:

1. **Inspect Before Modifying**: Never assume system state from chat transcripts. Always inspect repository status (`git status`), active database configuration, and source files before making changes.
2. **Zero Secret Persistence**: Never hardcode passwords, private keys, JWT secrets, or environment-specific URLs into source files or commit history. Pass credentials strictly via process-scoped environment variables. Never print or expose `.env`.
3. **Explicit Protocol Constants**: Cryptographic parameters (such as BN254 scalar modulus $r$, Poseidon $t=3$ round constants, ACIR proof body length $2144$ bytes, SMT depth $256$, and Merkle depth $10$) must be documented, versioned constants—never magic numbers.
4. **Backend Authorization Authority**: The frontend UI is an untrusted presentation layer. Frontend visibility or button disabling is **never** security. Every API endpoint must enforce authentication, role checks, and tenant boundaries.
5. **No Fake Cryptography**: Never present mocked proofs, simulated commitments, or dummy boolean returns as genuine zero-knowledge verification. Distinguish clearly between real cryptographic execution and testing stubs.
6. **Mandatory Negative Testing**: Every security-sensitive feature (RBAC, tamper detection, duplicate ingestion, expired tokens, malformed public inputs) must have explicit negative unit/integration tests that assert expected failure.
7. **Database Isolation & Protection**: The intended main database (`ZKP_SBOM` on `127.0.0.1:5432`, PostgreSQL 17) is strictly protected/frozen during development and validation; do not access or modify without separate, explicit authorization. PostgreSQL 16 on `127.0.0.1:5433` (`ZKP_SBOM_LOCAL_DEV`) is the preferred development and testing candidate (subject to explicit authorization before database operations; present state unverified by this task). PostgreSQL 17 will only be considered for operational use after validation, recovery planning, and separate explicit authorization. No migrations or mutations may run pre-D1.
8. **Transparent Test Accounting**: Skipped tests are **not** passes. Tests skipped due to missing host binaries (such as native Barretenberg `bb`) must be reported explicitly as skipped with precise counts. Never artificially silence test failures.
9. **Minimal, Reviewable Changes**: Keep code edits surgical, well-scoped, and easily reviewable. Preserve existing work, untracked migrations (`012`, `013`, `014`), and historical archives. Never run `git reset --hard` or `git clean -fd`.
10. **Student-Appropriate Clarity**: Maintain clean, maintainable code and straightforward documentation. Avoid unnecessary enterprise over-engineering; focus on engineering rigor, clean code quality, and successful viva demonstration.

---

## 3. Operational Constraints & Local Runtime Boundaries

- **Local Working Root**: `E:\Main Project`
- **Operating Mode**: **LOCAL-ONLY**. No remote operations, deployments, or external environment access without explicit authorization (remote Supabase connections and Gate 5R staging operations are strictly blocked).
- **Backend API**: FastAPI / Uvicorn running on `http://127.0.0.1:8000`.
- **Frontend App**: Next.js 16 (Turbopack) running on `http://127.0.0.1:3000`.
- **Database Environments**:
  - **PostgreSQL 16 — Development and Testing Candidate**: Docker container `zkp_sbom_local_dev` on `127.0.0.1:5433`, database `ZKP_SBOM_LOCAL_DEV`, historically migrated to Alembic revision `014`. Preferred development/testing candidate for dev, test, migration validation, debugging, and integration testing, subject to explicit authorization before DB operations. Present state has not been verified by this task.
  - **PostgreSQL 17 — Intended Final Main-Project Database**: Local PostgreSQL 17 on `127.0.0.1:5432`, database `ZKP_SBOM` (historically recorded at Alembic revision `007`). Intended main database for the completed project. Currently protected/frozen during development and validation; do not access or modify without separate, explicit authorization. Will only be considered for operational use after validation, recovery planning, and separate explicit authorization.
  - **Pre-D1 Restriction**: Prior to authorized D1 work, do not run migrations, write queries, seed data, truncate tables, drop objects, restart containers, recreate containers, or remove volumes on either instance.
- **Secret Separation**: The root `.env` contains legacy/remote credentials. It must never be edited, committed, or read by local development commands. All local runs inject process-level dev settings (`DB_PORT="5433"`, etc.).

---

## 4. The Locked Six-Stage Roadmap

The project follows a single, locked six-stage sequence. Stages must **never** be reordered, renamed, or skipped:

$$\mathbf{Stage\ A \longrightarrow Stage\ B \longrightarrow Stage\ C \longrightarrow Stage\ D \longrightarrow Stage\ E \longrightarrow Stage\ F}$$

```
+--------------------------------------------------------------------------------------------------+
|                                    LOCKED SIX-STAGE ROADMAP SEQUENCE                             |
+--------------------------------------------------------------------------------------------------+
|  Stage A: Re-entry Audit and Project Baseline [FULL PASS / CLOSED]                               |
|    Verify repository, inventory components, establish clean database and test baseline           |
|                               |                                                                  |
|                               v                                                                  |
|  Stage B: Backend, Database, and Security Fixes [FULL PASS / CLOSED]                             |
|    Harden API endpoints, resolve RBAC/isolation, ensure idempotent DB transactions               |
|                               |                                                                  |
|                               v                                                                  |
|  Stage C: Product Experience [REPORTED COMPLETE — PENDING OWNER ACCEPTANCE]                       |
|    Modules C0–C9: Light-first design, authentic data, role workspaces, proof & verification UI  |
|                               |                                                                  |
|                               v                                                                  |
|  Stage D: Backend, Database, and System Integration [OPERATIONALLY CLOSED / ACCEPTED WITH LIMITATIONS] |
|    Modules D0–D9: API audit, schemas, RBAC, job lifecycle, verification & audit trail (1,327 tests pass)  |
|                               |                                                                  |
|                               v                                                                  |
|  Stage E: Security and Cryptographic Validation [OPERATIONALLY CLOSED / FULL PASS]                |
|    270 adversarial/crypto tests pass (0 skips); 20-threat security matrix & validation report     |
|                               |                                                                  |
|                               v                                                                  |
|  Stage F: Final Testing, Documentation, and Submission [ACTIVE / IN PROGRESS]                     |
|    Full regression, clean build, architecture documentation, student runbooks, and viva prep     |
+--------------------------------------------------------------------------------------------------+
```

---

### STAGE A — Re-entry Audit and Project Baseline

#### Objective
Establish an evidence-based baseline of the complete repository, verifying what components work, what is broken, what tests pass, what tools are installed, and which database target is active, without making speculative modifications.

#### Substage Tasks
- **`A1` — Repository & Git State Inventory**:
  - Inspect Git branch (`chore/final-project-cleanup`), HEAD commit, tracked modifications, and untracked files.
  - Verify that untracked migrations `012`, `013`, and `014` exist and are preserved.
  - Verify repository archive directories (`archive/`, `master_archive/`).
- **`A2` — Local Tooling & Runtime Audit**:
  - Audit Python runtime (Python 3.12, virtual environment `.venv/Scripts/python.exe`).
  - Audit Node.js runtime (Node.js v24.20.0, npm).
  - Inspect cryptographic tooling: verify status of `nargo` and `bb` on system PATH, and inspect Node.js WASM crypto runtime in `backend/verification_service/crypto_runtime/`.
- **`A3` — Database Target Identification & Isolation**:
  - Verify Docker PostgreSQL 16 container `zkp_sbom_local_dev` on loopback port `5433`.
  - Confirm Alembic migration revision on `ZKP_SBOM_LOCAL_DEV` is `014`.
  - Verify that local PostgreSQL 17 on port `5432` (`ZKP_SBOM`) remains protected and disconnected.
- **`A4` — Service Startup & Authentication Baseline**:
  - Launch backend on `127.0.0.1:8000` using process-scoped environment variables. Verify `GET /api/v1/health`.
  - Launch frontend on `http://127.0.0.1:3000` via Next.js Turbopack. Verify HTTP 200 response.
  - Exercise real registration (`POST /api/v1/auth/register`) and login (`POST /api/v1/auth/login`) with auditor credentials. Verify persistence in `public.users`.
- **`A5` — Baseline Test Suite Execution & Gap Assessment**:
  - Run all backend test suites across `verification_service`, `shared`, `sbom_service`, `policy_service`, `vulnerability_service`, and `zkp_service`.
  - Run frontend test suite (`npm test`), typecheck (`npm run typecheck`), lint (`npm run lint`), and build (`npm run build`).
  - Catalog passing tests, failing tests, skipped tests, and known historical findings (`AUD-A-*`, `INT-DEF-*`, `F2-*`).

#### Expected Deliverables
- Concise Project Baseline Report documenting verified facts, exact test counts, and tool versions.
- Prioritized task register for Stage B remediation.

#### Dependencies & Prerequisites
- None (Initial entry stage).

#### Acceptance Criteria
- [x] Git status captured; untracked migrations and archives preserved.
- [x] Disposable database verified on `127.0.0.1:5433` at Alembic revision 014.
- [x] Backend and frontend start successfully on localhost without errors.
- [x] Complete test inventory recorded with exact pass, skip, and fail numbers (861 backend tests passed, 0 skipped, 0 failed).

#### Suggested Tests & Evidence
- `git status --short`
- `Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/health"`
- `pytest` execution across all 6 backend services.
- `npm test`, `npm run typecheck`, and `npm run build` in `frontend/`.

#### Known Risks & Blockers
- Resolved: Native `bb.exe` launcher compiled and verified on Windows; all 24 cryptographic tests in `test_b1_live_crypto.py` passed (`F2-C-001` closed).

#### Completion Condition
Stage A is complete when the project baseline is documented with empirical evidence and zero speculative assumptions. **[CLOSED / FULL PASS]**

---

### STAGE B — Backend, Database, and Security Fixes

#### Objective
Harden the backend services, database layer, authentication boundaries, and tenant isolation mechanisms to ensure stability, idempotent operations, and fail-closed security.

#### Substage Tasks
- **`B1` — Environment Configuration & Secret Protection**:
  - Ensure all services fail closed when required secrets (`JWT_SECRET_KEY`, `CERTIFICATE_SECRET_KEY`, `DB_PASSWORD`) are missing or insecure (< 32 characters).
  - Verify that `load_dotenv` never overrides explicit process environment variables.
  - Ensure structured loggers redact passwords, authorization headers, and raw SBOM contents.
- **`B2` — Database Target Isolation & Safe Connection Pooling**:
  - Enforce strict target routing to `127.0.0.1:5433/ZKP_SBOM_LOCAL_DEV`.
  - Configure SQLAlchemy connection pool limits and timeouts (`pool_pre_ping=True`, `pool_size=10`).
  - Verify database SSL mode configuration handling (`disable` for local dev; strict verification for production).
- **`B3` — Authentication, Session, & Role-Based Access Control**:
  - Enforce Argon2id / bcrypt password hashing with constant-time dummy verification on invalid usernames to prevent user enumeration.
  - Verify role scoping: all new registered users receive base role `auditor`.
  - Enforce role gates on restricted endpoints (`require_roles("vendor", "admin")` for SBOM uploads; `require_roles("trusted_importer")` for vuln ingestion; `require_roles("admin")` for snapshot approval/freezing).
- **`B4` — Multi-Tenant Scoping & Object Ownership**:
  - Verify that applications, SBOM uploads, proof jobs, and verification requests enforce `user_id` filtering.
  - Implement and verify IDOR protections preventing one user from accessing or modifying another user's proof jobs or applications.
- **`B5` — Input Validation & Error Normalization**:
  - Enforce Pydantic validation on all incoming payloads (e.g., 0x-prefixed 64-character hex strings for roots).
  - Enforce strict 10 MB upload body size limit via `RequestSizeLimitMiddleware`.
  - Normalize error responses to consistent `{ "error": ..., "code": ... }` structures without leaking internal stack traces.
- **`B6` — Database Constraints, Transactions, & Concurrency**:
  - Verify that database tables enforce required uniqueness constraints (e.g., `uq_apps_user_name`, `uq_vuln_snapshot_label`, `uq_verif_req_unique_proof_tuple`).
  - Execute 10-worker concurrency probe ([`backend/test_concurrency_db.py`](file:///E:/Main%20Project/backend/test_concurrency_db.py)) verifying that identical concurrent verification requests converge idempotently to exactly 1 request and 1 certificate.
- **`B7` — Worker Lifecycle & Job Lock Management**:
  - Harden advisory locks and job state transitions (`pending` $\rightarrow$ `processing` $\rightarrow$ `completed` / `failed`) in `zkp_service`.
  - Implement stale job recovery to prevent orphaned locks when workers restart unexpectedly.
- **`B8` — Backend Regression Test Suite**:
  - Run all backend unit and integration test suites, verifying 0 failures across all services.

#### Expected Deliverables
- Fully hardened backend service suite passing all unit and concurrency tests.
- Verified database constraint and transaction idempotency report.

#### Dependencies & Prerequisites
- Stage A baseline verified.

#### Acceptance Criteria
- [x] No secrets leaked in logs or API responses.
- [x] Role-based access control strictly enforced across all routes.
- [x] 10-worker concurrency probe passes without deadlocks or duplicate records (verified on port 5433).
- [x] All non-skipped backend tests pass cleanly (861 passed, 0 skipped, 0 failed).

#### Suggested Tests & Evidence
- `pytest backend/` with 0 failures.
- `python backend/test_concurrency_db.py` outputs `PASS`.
- Negative test cases for 401 Unauthorized, 403 Forbidden, and 422 Unprocessable Entity.

#### Known Risks & Blockers
- Starlette TestClient async event-loop leaks when running disparate test suites in a single process invocation. (Remedy: run test suites with clean process separation or `--import-mode=importlib`).

#### Completion Condition
Stage B is complete when all backend routes enforce authorization, database transactions are idempotent, and backend tests pass with zero failures. **[CLOSED / FULL PASS]**

---

### STAGE C — Product Experience [REPORTED COMPLETE — PENDING OVERALL OWNER ACCEPTANCE]

#### Objective
Establish a complete, cohesive, role-aware product experience inspired by modern SBOM-management information architecture. The user interface uses a professional, light-first aesthetic (white and cool-grey surfaces, navy/slate typography, restrained blue and teal accents, useful tables, search, filters, responsive navigation, and accessible reusable components; optional restrained dark theme). Every screen connects to genuine backend endpoints—zero fabricated dashboard metrics, zero placeholder verification outcomes, and zero non-functional controls.

#### Modular Breakdown (C0–C9) — Reported Status
- **`C0` — Scope, Architecture and Workflow Contract** `[REPORTED COMPLETE]`:
  - Established the agreed Stage C/D roadmap and execution contract as the authoritative baseline.
  - Aligned agent context, operational boundaries, and governance across all documentation hubs.
  - Defined user roles, light-first design parameters, cryptographic invariants, and database environment policy.
- **`C1` — Design System and Application Shell** `[REPORTED COMPLETE]`:
  - Implemented the core light-first design system in `frontend/src/app/globals.css` and token definitions.
  - Established color palette (cool-grey/white surfaces, slate typography, restrained blue/teal accents, semantic status colors).
  - Built reusable application shell: navigation sidebar, responsive header, breadcrumb banner, role badges, and accessible container layouts.
- **`C2` — Public Homepage and Product Presentation** `[REPORTED COMPLETE]`:
  - Built unauthenticated public landing page introducing the zero-knowledge software supply chain verification concept.
  - Presented the core value proposition: mathematical proof of compliance without disclosing proprietary component architecture or unredacted SBOMs.
  - Direct navigation to public proof verification lookup (`/verify`) and authentication (`/login`, `/register`).
- **`C3` — Authentication and Onboarding Experience** `[REPORTED COMPLETE]`:
  - Login and Registration interfaces with explicit role indicators and password requirements.
  - Standard HTML form autocomplete semantics (`autoComplete="username"`, `autoComplete="current-password"`).
  - Enforced in-memory session token transport (`authTransport.ts`), ensuring tokens are cleared on logout, 401, or page refresh with zero persistent browser leaks.
- **`C4` — Workspace, Dashboard and Navigation** `[REPORTED COMPLETE]`:
  - Authenticated workspace dashboard with dynamic greeting, active role badge, and role-appropriate action tiles.
  - Wire metric cards directly to `GET /api/v1/metrics`. Completely eliminate fabricated statistics or placeholder graphs.
  - Render genuine zero-state views when no records exist.
- **`C5` — Application and SBOM Management** `[REPORTED COMPLETE]`:
  - Application registry and private SBOM management views (`/applications`, `/sboms`).
  - Secure drag-and-drop CycloneDX JSON upload with client-side format/size validation (max 10 MB) and ASCII control-character prevention.
  - Parsed metadata display while strictly concealing raw PURLs, versions, and proprietary source code from unauthorized views.
- **`C6` — Proof-Generation Workflow** `[REPORTED COMPLETE]`:
  - Step-by-step proof generation wizard (`/proofs/generate`) enforcing eligible frozen snapshots and active policies.
  - Verified handoff from SBOM upload via `sbomId` query parameter.
  - **`C6.1` Correction**: Addressed `running` proof-job status in active filters, metrics counters, StatusPill mappings, and polling loops.
- **`C7` — Buyer Verification and Certificates** `[REPORTED COMPLETE]`:
  - Verification and certificate views (`/verify`, `/certificates`, `/certificates/[id]`).
  - Strict binding to owned `proof_job_id` and authoritative database commitments ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$).
  - Minted certificate displayed strictly upon verified status; public unauthenticated validation on `/certificates/[id]` via `skipAuth: true`.
- **`C8` — Administration, Profiles and Role-Specific Workspaces** `[REPORTED COMPLETE]`:
  - Central governance overview on `/admin` restricted to `admin` role.
  - Profile and session settings page on `/profile` with role permission summaries and in-memory privacy guarantees.
  - Upgraded policy and vulnerability intelligence tables with non-blocking inline revocation UI and strict role gates.
- **`C9` — Frontend Integration and Acceptance** `[REPORTED COMPLETE]`:
  - End-to-end integration audit across all frontend modules and backend API contracts.
  - Expanded `VerificationResult` type to cover all exact backend outcome strings (`invalid_proof`, `record_mismatch`, `verification_unavailable`).
  - Upgraded test assertions to test shared production navigation config and outcome mappers instead of hardcoded booleans.
  - Full automated validation reported by Antigravity: 80 unit tests passed (0 skips, 0 failures), TypeScript typecheck 0 errors, ESLint 0 errors/0 warnings, Next.js production build 17 routes generated.

#### Stage C Acceptance Status
- Stage C (Modules C0–C9) is **reported complete, pending owner acceptance of the overall milestone**.

---

### STAGE D — Backend, Database and System Integration [OPERATIONALLY CLOSED / FORMALLY ACCEPTED BY OWNER WITH 3 DISCLOSED LIMITATIONS]

#### Objective
Systematically integrate, harden, and validate backend services, database schemas, RBAC rules, job lifecycle orchestration, independent cryptographic verification, and auditability to support the Stage C product experience and end-to-end supply chain verification pipeline.

#### Current Authorization Boundary
- **Stage D Execution Complete & Formally Accepted with Disclosed Limitations**: Reviewed and accepted by owner with disclosed limitations (256-segment live proving deferred as UNVERIFIED; D7 snapshot TTL formally accepted with rev 016; D9 Category A live non-proving workflow pass verified on dev port 5433 with 0 fake certificates minted; Category B full cryptographic acceptance deferred).
- **Alembic Revision 016 Applied**: Migration `016_add_snapshot_ttl_expires_at.py` applied on Docker PostgreSQL 16 (`127.0.0.1:5433`). 424 Alembic tests pass.
- **Backend Quality Gates**: 1,345 backend unit/integration tests passing with 0 skips and 0 failures. Live bounded acceptance verified at 8/9 checks with reverse-FK cleanup.
- **Stage E Status**: OPERATIONALLY CLOSED / FULL PASS (270 dedicated security & crypto tests pass).
- **Active Stage**: Stage F (Final Testing, Documentation, and Submission).

#### Modular Breakdown (D0–D9)
- **`D0` — API, Schema and Dependency Audit** `[OPERATIONALLY CLOSED / FULL PASS]`:
  - Complete read-only audit of existing backend APIs, database schemas, Alembic revisions (001–014), models, role definitions, and dependencies.
  - Compare implemented endpoints against Stage C frontend requirements to identify concrete gaps and schema extensions.
  - Inspect vulnerability ingestion feeds, SMT computation, and current role handling without mutating code or databases.
- **`D1` — Database and Migration Design** `[OPERATIONALLY CLOSED / FULL PASS]`:
  - Design necessary schema updates based on D0 findings (account status, profile fields, certificate/verification audit records).
  - Create reviewable Alembic migrations with forward and downgrade paths (migrations 015 and 016 applied and verified).
  - Ensure all database tables enforce composite uniqueness constraints, foreign keys, and multi-tenant isolation.
- **`D2` — Authentication, Onboarding and Profiles** `[OPERATIONALLY CLOSED / FULL PASS]`:
  - Harden authentication endpoints, password validation (bcrypt max 72 bytes, min 8 chars), and session lifecycle.
  - Implement onboarding and user profile endpoints supporting the planned account model with restricted initial privileges.
- **`D3` — RBAC and Administrative User Management** `[OPERATIONALLY CLOSED / FULL PASS]`:
  - Formalize the 5-role model (`vendor`, `buyer`, `auditor`, `admin`, `trusted_importer`) across backend services.
  - Implement administrative user management endpoints for role assignment, account activation, and separation of duties.
  - Verify that privileged actions (snapshot approval/freeze, certificate revocation) remain strictly restricted to authorized roles.
- **`D4` — Application and SBOM API Integration** `[OPERATIONALLY CLOSED / FULL PASS]`:
  - Connect application registration and CycloneDX SBOM upload endpoints with tenant scoping (`user_id`).
  - Validate deterministic canonicalization: sort component entries by canonical PURL before computing Poseidon Merkle tree roots.
  - Enforce non-disclosure: strip raw PURLs, versions, and internal component arrays from buyer- and public-facing responses.
- **`D5` — Proof Generation and Job Lifecycle** `[PASS (BOUNDED) / FULL 256-SEGMENT WORKLOAD DEFERRED / UNVERIFIED]`:
  - Orchestrate 32-component chunk proof generation via Barretenberg worker.
  - Manage job lifecycle states (`pending` $\rightarrow$ `processing` $\rightarrow$ `completed` / `failed`) with PostgreSQL advisory locks.
  - Implement orphan job recovery and safe failure handling.
  - Bounded 1-segment execution passed in 83.25s; watchdog cleanly contained memory surge at 1.54 GiB RAM; 254 segments unattempted due to host workstation memory floor.
- **`D6` — Independent Verification and Certificate Lifecycle** `[OPERATIONALLY CLOSED / FULL PASS]`:
  - Wire independent verification endpoint (`POST /api/v1/verification/verify`) to pinned Barretenberg verifier.
  - Enforce fail-closed verification: only an explicit Boolean `true` produces an issued `VerificationCertificate`.
  - Implement certificate issuance, SHA-256 fingerprinting, real-time revocation checking, and public certificate validation routes.
- **`D7` — Vulnerability Intelligence, Observability and Auditability** `[FORMALLY ACCEPTED BY OWNER WITH LIMITATIONS]`:
  - Implemented 7 locked architectural decisions (`D7-POL-01` through `D7-POL-07`) for Snapshot TTL enforcement across three synchronous checkpoints, legacy NULL-expiry compatibility, and migration 016.
  - Deliverable source ZIP packaged and verified (`3CF91E822F1A9308B8C37814649AB232FE70CCD9C53E757BC186AA9DEE80FE58`); 42/42 targeted unit and matrix tests passing.
  - Formally accepted by project owner on 23 October 2026 retaining documented limitations: isolated live migration test was not rerun in latest technical closure task, and not all live deployment scenarios have been tested.
  - Preserve structured security logging across all services. Audit trail records assessed without logging credentials or raw SBOM content.
- **`D8` — Backend Security and Regression Validation** `[OPERATIONALLY CLOSED / FULL PASS]`:
  - Comprehensive adversarial testing: proof tampering, public input mismatch rejection, corrupted proof body rejection (< 2144 bytes).
  - Cross-tenant IDOR penetration tests, payload boundary checks (max 10 MB), and SQL injection defenses.
  - Full backend regression run across all 6 microservices and Alembic suites (1,345 tests pass).
- **`D9` — Full End-to-End Acceptance** `[CATEGORY A: REPORTED PASS FOR LIVE NON-PROVING WORKFLOW / CATEGORY B: DEFERRED / UNVERIFIED]`:
  - **Category A — Live Non-Proving Acceptance Workflow**: `REPORTED PASS`.
    - Executed live workflow against PostgreSQL 16 container `zkp_sbom_local_dev` on host port `5433` (`ZKP_SBOM_LOCAL_DEV`, Alembic revision `016`).
    - API gateway health verified on port 8080 (`http://127.0.0.1:8080/api/v1/health`).
    - Separation of duties verified: vendor ingestion attempt denied with HTTP 403 Forbidden.
    - Vulnerability feed ingested under `trusted_importer`, approved and frozen by `admin` with authoritative SMT root and TTL expiry (`expires_at` populated).
    - Ingested two demonstration applications: Compliant (`certifi@2021.5.30`, score 3.7 / scaled 37 $\le$ 70) and Vulnerable (`urllib3@1.26.5`, score 7.5 / scaled 75 > 70).
    - Unproven job verification safely handled without FK error, returning `verification_unavailable` with `certificate: null`. Exactly 0 certificates minted.
    - Durable manifest: `.cache/demo_manifests/manifest_d9_run_20261023_034148_34d279f0.json`.
  - **Category B — Cryptographic Acceptance**: `DEFERRED / UNVERIFIED`.
    - Witness generation, genuine live proof generation across all segments, independent cryptographic proof verification, and legitimate certificate issuance remain unexecuted in this non-proving demonstration.

---

### Dependency-Aware Execution Sequence

Work proceeds strictly according to the following interleaved dependency sequence:
1. **`C0`–`C9`**: Product Experience modules `[REPORTED COMPLETE — PENDING OVERALL OWNER ACCEPTANCE]`.
2. **`D0`**: Read-only inspection of actual APIs, schemas, permissions, dependencies, and existing capabilities `[REPORTED COMPLETE BY ANTIGRAVITY — PENDING OWNER REVIEW & ACCEPTANCE]`.
3. **`D1`–`D3`**: Database and migration design, authentication/onboarding endpoints, and formal RBAC user management `[UNAUTHORIZED — blocked until D0 review, owner decisions, and explicit authorization]`.
4. **`D4`–`D5`**: Application/SBOM API integration and proof generation worker orchestration.
5. **`D6`–`D7`**: Independent verification, certificate authority lifecycle, vulnerability intelligence hardening, and persistent audit trail records.
6. **`D8`–`D9`**: Backend security regression validation and full end-to-end acceptance.

*Rule: This sequence is dependency-aware. It does not authorize skipping module acceptance gates.*

---

### STAGE E — Security and Cryptographic Validation [OPERATIONALLY CLOSED / FULL PASS]

#### Objective
Subject the platform to rigorous adversarial testing, verifying that cryptographic invariants hold, tampered proofs are rejected, tenant boundaries cannot be breached, and privacy guarantees remain intact under attack.

#### Substage Tasks
- **`E1` — Official Cryptographic Verifier Invariants**:
  - Verify that only an explicit Boolean `true` from `BarretenbergVerifier.verifyProof()` constitutes verification acceptance.
  - Distinguish between runtime exceptions, structural byte rejections, and cryptographic falsification (`CRYPTOGRAPHIC_FALSE`).
- **`E2` — Public Input Binding & Mismatch Rejection**:
  - Submit valid proof bytes with tampered `sbom_root`, tampered `vulnerability_db_root`, or tampered `policy_hash`.
  - Verify that all mismatched public inputs are strictly rejected.
- **`E3` — Corrupted & Malformed Proof Body Rejection**:
  - Test proofs with truncated lengths (< 2144 bytes body), flipped bits, randomized bytes, or invalid BN254 scalar encodings ($\ge r$).
  - Assert that all malformed inputs fail closed with explicit security errors.
- **`E4` — Snapshot Immutability & Lifecycle Concurrency**:
  - Attempt to mutate vulnerability entries in an `approved` or `frozen` snapshot; verify database constraint rejection.
  - Test concurrent freeze requests using PostgreSQL `SELECT FOR UPDATE` to prove race-condition resistance.
- **`E5` — Tenant Isolation & IDOR Penetration Testing**:
  - Attempt cross-tenant resource retrieval: User A attempts to read User B's SBOM upload, application, or private proof job.
  - Assert that all unauthorized cross-tenant requests return HTTP 404 or 403.
- **`E6` — Adversarial Input & Boundary Protection**:
  - Submit payloads exceeding 10 MB limit; verify 413 Payload Too Large.
  - Submit non-JSON and malformed XML multipart payloads; verify 415/422 responses without application crashes.
  - Test SQL injection and NoSQL injection patterns in query filters; confirm SQLAlchemy parameterization prevents exploit.
- **`E7` — Cryptographic Test Accounting & Gap Documentation**:
  - Audit all test suites for skipped tests.
  - Document finding `F2-C-001` (status of native `bb` tests vs WASM runtime).
  - Produce a transparent Cryptographic Assurance Matrix documenting tested invariants vs environmental limitations.

#### Expected Deliverables
- Cryptographic & Security Validation Report with empirical adversarial test results.
- Comprehensive Security Matrix confirming all tested attack vectors were repelled.

#### Dependencies & Prerequisites
- Stage D end-to-end pipeline operational.

#### Acceptance Criteria
- [x] 100% of tampered proofs and mismatched commitments fail closed.
- [x] Cross-tenant access attempts are completely blocked.
- [x] Snapshot freezing is provably immutable.
- [x] Skipped tests are accounted for transparently with exact reasons (0 skipped across 270 Stage E tests and 1,327 backend tests).

#### Suggested Tests & Evidence
- `pytest backend/verification_service/tests/test_public_input_binding.py`
- `pytest backend/verification_service/tests/test_legacy_acir_adapter.py`
- Automated penetration test script targeting IDOR, oversized bodies, and proof tampering.

#### Known Risks & Blockers
- Resolved: Native `bb.exe` launcher verified on Windows; both native and WASM verification runtimes operational (`F2-C-001` closed).

#### Completion Condition
Stage E is complete when all adversarial test vectors fail closed and empirical evidence confirms the system's security claims. **[OPERATIONALLY CLOSED / FULL PASS — 270/270 tests pass; SECURITY_VALIDATION_REPORT.md published]**

---

### STAGE F — Final Testing, Documentation, and Submission

#### Objective
Execute comprehensive system regression, complete production-grade academic and technical documentation, prepare demonstration scenarios, and verify project submission readiness.

#### Substage Tasks
- **`F1` — Comprehensive Regression Suite Execution**:
  - Execute all backend unit, integration, and security tests across all 6 microservices.
  - Execute all frontend unit tests, route guards, and component specs.
  - Verify 0 test failures across the entire codebase.
- **`F2` — Clean-Environment Build & Reproducibility Check**:
  - Run frontend production build (`next build`) verifying 0 errors and optimal static prerendering.
  - Inspect package dependencies, lockfiles (`package-lock.json`), and Python dependencies.
  - Verify that bootstrap scripts (`bootstrap.ps1`) allow a fresh engineer to inspect and run the project locally.
- **`F3` — System Architecture & Technical Documentation**:
  - Create and update architecture diagrams, data flow representations, and entity-relationship models.
  - Document all API endpoints, request schemas, and error contracts.
  - Document database schema revisions 001 through 014 with full constraint catalogs.
- **`F4` — Student Runbook, Setup Guide, & Troubleshooting Manual**:
  - Author a clear, step-by-step local execution runbook for students and examiners.
  - Include quickstart commands, environment variable guides, Docker setup instructions, and troubleshooting FAQs (e.g., clearing port conflicts, restarting dev workers).
- **`F5` — Demonstration Scenarios & Viva Defense Preparation**:
  - Prepare 3 scripted demo scenarios:
    1. *The Compliant Vendor*: Vendor uploads clean SBOM $\rightarrow$ proves compliance $\rightarrow$ buyer validates certificate.
    2. *The Vulnerable Package*: Vendor uploads SBOM containing Log4j (CVSS 10.0) $\rightarrow$ proving fails or policy rejects.
    3. *The Malicious Verifier*: Adversary attempts to tamper with proof roots or read private components $\rightarrow$ system fails closed.
  - Prepare slide deck summaries, key architecture takeaways, and anticipated examiner questions with precise answers.
- **`F6` — Final Acceptance Sign-Off & Submission Package**:
  - Review source distribution archive (`dist/zkp-sbom-source.zip`) ensuring zero secret leakage.
  - Complete the Final Project Acceptance Checklist signed off against all major project requirements.

#### Expected Deliverables
- Complete technical documentation suite (Architecture, API Reference, Runbook, Viva Prep).
- Clean, reproducible project codebase passing 100% of executable tests.
- Packaged submission bundle and demonstration walkthrough guide.

#### Dependencies & Prerequisites
- Stages A through E successfully completed.

#### Acceptance Criteria
- [x] All unit, integration, frontend, and build tests pass with zero errors (F1/F2 verified).
- [x] Setup runbook allows fresh execution from scratch (F4 STUDENT_RUNBOOK.md verified).
- [x] Viva presentation materials and demonstration scenarios tested and ready (F5 DEMONSTRATIONS_AND_VIVA.md and VIVA_PRESENTATION_SLIDES.md verified).
- [x] Final acceptance checklist completely verified (F6 dist/zkp-sbom-source.zip packaged and validated).

#### Suggested Tests & Evidence
- Clean end-to-end demonstration execution from a fresh terminal.
- Full test pass logs (`pytest`, `npm test`, `next build`).
- Final Documentation Review artifact.

#### Known Risks & Blockers
- Examination environment constraints (ensure offline-capable demo scripts are tested).

#### Completion Condition
Stage F is complete when the project is fully documented, all regressions pass, demo scenarios are rehearsed, and the submission package is finalized.

---

### STAGE G — Full-Stack Security Hardening, Role Consolidation & Frontend Simplification

#### Source of Requirements
`Project_Stagewise_Report_A_to_G_and_Stage_D_Pending.pdf`, pages 11–12 (source PDF not locally present in workspace; scope formalized from authoritative report context).

#### Objective
Transition from the initial operational prototype into a hardened, production-grade security architecture: eliminate ghost/non-functional roles, enforce strict RBAC and object-level ownership across all backend routes, simplify the frontend to present three coherent role workspaces (`vendor`, `buyer`, and `admin`), execute full cross-role regression, and obtain independent verification sign-off.

#### Substage Tasks
- **`G0` — Baseline and Preservation**:
  - Capture comprehensive repository, database, backup, route, role, runtime, and test baselines before implementing code changes.
  - Assess rollback points and establish non-destructive development rules.
- **`G1` — Security Audit & Finding Register**:
  - Comprehensive adversarial penetration testing and threat modeling across all APIs and endpoints.
  - Establish a formal Finding Register classifying all vulnerabilities (IDOR, auth bypass, injection, cryptographic tampering).
- **`G2` — Consolidate Visible Roles to Vendor, Buyer, and Admin**:
  - Consolidate active role architecture from 5 roles down to 3 first-class user roles: `vendor`, `buyer`, and `admin`.
  - Deprecate or subsume legacy `auditor` and `trusted_importer` roles safely.
- **`G3` — Backend & API Hardening**:
  - Enforce server-side role validation and ownership checks on 100% of mutation routes.
  - Implement comprehensive input sanitization, fail-closed database transactions, and rate limiting.
- **`G4` — Frontend Simplification & Integration**:
  - Restructure frontend UI, navigation shell, and page guards strictly around the 3 primary roles (`vendor`, `buyer`, `admin`).
  - Eliminate dead or redundant UI controls and simplify proof and verification flows.
- **`G5` — Cross-Role Regression**:
  - Execute end-to-end multi-user integration tests verifying strict cross-tenant and cross-role isolation across all 3 roles.
  - Run full backend and frontend automated regression suites.
- **`G6` — Independent Closure**:
  - Perform independent forensic verification, audit manifest reconciliation, and package sign-off.

#### Subsequent Phase: Stage D Reassessment [OPERATIONALLY CLOSED / FULL PASS]
Following the formal closure of Stage G (G0–G6), Stage D Reassessment was executed and independently audited on 25–26 October 2026:
- **D9 Category A Live Workflow:** Re-validated against Docker PostgreSQL 17 port 5435 (`zkp_sbom_g2_integration`) under the 3-role model (`vendor`, `buyer`, `admin`) with 0 fake certificates minted (`scratch/stage-d/20261025_043000/`).
- **D5 256-Segment Proving & Category B Resolution:** The 256-segment workload was verified from proof archive `68c06b8e-c7b8-4402-b98e-f6c1f2236cd9.zip` (SHA-256 `60a41c69448e6a59fd9c697d9c7d0d0500198d61c6b38b3100190134906d7bce`), verifying 256/256 segment proofs in 531.826s with explicit boolean true and minting active Certificate `81d1a4f0-1ae4-4baf-9716-9081c6ae9f7b` without proof regeneration (`scratch/stage-d/recovery_acceptance_linux_20261025/`).
- **Final Audit Verdict:** Sealed on 26 October 2026 02:45 IST (`scratch/stage-d/final_evidence_audit_20261026_0236/final_audit_report.md`) with verdict **`STAGE D FINAL STATUS: PASS`**.

---


## 5. Testing Policy & Evidence Standards

In this project, a strict evidence hierarchy governs all testing claims:

```
+--------------------------------------------------------------------------------------------------+
|                                      TESTING EVIDENCE HIERARCHY                                  |
+--------------------------------------------------------------------------------------------------+
|  Tier 1: End-to-End Live Execution                                                               |
|    Real database persistence, real WASM/native crypto verifier, interactive browser UI.          |
|    Highest confidence. Proves the integrated system functions as advertised.                    |
|                               ^                                                                  |
|                               |                                                                  |
|  Tier 2: Integration & Contract Tests                                                            |
|    Multi-service FastAPI TestClient, live PostgreSQL container on port 5433, concurrency probe.  |
|    High confidence. Proves boundary contracts, transactions, and RBAC enforcement.               |
|                               ^                                                                  |
|                               |                                                                  |
|  Tier 3: Cryptographic & Invariant Tests                                                         |
|    Public input binding, ACIR proof splitting, BN254 field encoding, SMT non-membership math.    |
|    Critical confidence. Proves mathematical correctness and tamper rejection.                    |
|                               ^                                                                  |
|                               |                                                                  |
|  Tier 4: Unit Tests & Stubs                                                                      |
|    Isolated function tests, SQLite in-memory, mocked cryptographic returns.                      |
|    Baseline confidence. Proves localized logic, but DOES NOT prove real DB or ZKP behavior.     |
+--------------------------------------------------------------------------------------------------+
```

### 5.1 Test Categories
1. **Unit Tests**: Test individual functions, schemas, and utility classes in isolation. Passing unit tests prove localized logic only.
2. **API & Contract Tests**: Exercise FastAPI endpoints with valid and invalid requests, validating response codes, error formats, and schema conformance.
3. **Database Integration Tests**: Run against live PostgreSQL 16 on port `5433`, verifying foreign key cascades, unique constraints, and transaction rollback.
4. **Cryptographic Tests**: Test Poseidon hashing, BN254 field encoding, Sparse Merkle Tree non-membership, and Barretenberg proof verification.
5. **Adversarial & Security Tests**: Negative tests specifically crafted to attempt unauthorized operations, IDOR exploits, proof body tampering, and payload overflows.
6. **End-to-End Tests**: Exercise the complete pipeline from user registration to proof verification and certificate issuance.
7. **Frontend & Accessibility Tests**: Validate component rendering, in-memory token handling, route protection, and WCAG contrast.
8. **Build & Reproducibility Tests**: TypeScript compilation (`tsc --noEmit`), ESLint validation, and Next.js production builds.

### 5.2 Strict Evidence Rules
- **Mocks Are Not Live Proof**: A test that mocks the database session or stubs the cryptographic verifier proves only that the surrounding code handles the mock. It does not prove live PostgreSQL or cryptographic readiness.
- **Skipped Tests Are Not Passes**: Any test marked with `@pytest.mark.skip` or `skipif` must be accounted for as `SKIPPED`. It is strictly forbidden to count skipped tests among passing tests (`F2-C-001`).
- **Fail-Closed Verification**: The only acceptable cryptographic pass is an explicit Boolean `true` from the verifier. A test that passes because an unhandled exception was swallowed is a critical defect.

---

## 6. Task Tracking Ledger & Progress Convention

### 6.1 Status Conventions
Tasks throughout the roadmap are classified according to five explicit statuses:

- `NOT STARTED`: Work has not yet begun. Prerequisites may or may not be met.
- `IN PROGRESS`: Active implementation or testing is currently underway.
- `BLOCKED`: Task cannot proceed due to an explicit technical blocker or dependency.
- `PASS`: Task implementation is complete, all acceptance criteria are met, and required tests pass with empirical evidence.
- `PASS WITH GAPS`: Core functionality is operational, but documented gaps (such as skipped host tests or mock dependencies) remain.

### 6.2 Master Progress Ledger

| Task ID | Task Description | Status | Evidence Reference | Blocker / Next Action |
| :--- | :--- | :--- | :--- | :--- |
| **`A1`** | Repository & Git State Inventory | `PASS` | Git working tree inspected; untracked migrations 012–016 & archives preserved | Complete |
| **`A2`** | Local Tooling & Runtime Audit | `PASS` | Python 3.12, Node 24.20, native bb.exe launcher automated; F2-C-001 resolved | Complete |
| **`A3`** | Database Identification & Isolation | `PASS` | Docker DB on `5433` verified at rev `015`; protected DB on `5432` untouched | Complete |
| **`A4`** | Service Startup & Auth Baseline | `PASS (HISTORICAL)` | Backend (`8000`) and Frontend (`3000`) healthy; registration & login verified | Complete |
| **`A5`** | Baseline Test Suite Execution | `PASS (HISTORICAL)` | 861 backend tests pass, 0 skipped; 39 baseline frontend tests pass; build passes | Complete baseline captured |
| **`B1`** | Config & Secret Redaction | `PASS` | Fail-closed secrets (>=32 chars); structured log credential redaction verified | Complete |
| **`B2`** | DB Target Isolation & Pooling | `PASS` | Process environment routing verified to port `5433` exclusively; port 5432 blocked | Complete |
| **`B3`** | Authentication & RBAC Hardening | `PASS` | Base auditor role enforced; upload endpoint rejects non-vendors (403); bcrypt 72B limit | Complete |
| **`B4`** | Multi-Tenant Scoping & IDOR | `PASS` | Compound uniqueness (name, vendor, user_id); tenant isolation verified across APIs | Complete |
| **`B5`** | Input Validation & Error Format | `PASS` | Pydantic root hex validation & 10MB size limits enforced | Complete |
| **`B6`** | Database Constraints & Concurrency | `PASS (HISTORICAL)` | `test_concurrency_db.py` passed with 10 concurrent requests on port 5433 | Complete |
| **`B7`** | Worker Lifecycle & Job Locks | `PASS` | Advisory lock logic & stale job recovery verified in `test_job_recovery.py` | Complete |
| **`B8`** | Backend Regression Suite | `PASS (HISTORICAL)` | 861 backend unit/integration tests pass (0 skips, 0 failures) | Complete |
| **`C0`** | Scope, Architecture & Workflow Contract | `PASS` | Aligned roadmap contract, role definitions, and workflow specifications | Complete |
| **`C1`** | Visual Direction & Application Shell | `PASS` | Core light-first design tokens in globals.css; navigation shell & status pills | Complete |
| **`C2`** | Public Homepage & Presentation | `PASS` | Public landing page explaining ZK supply-chain verification and value prop | Complete |
| **`C3`** | Authentication Experience Polish | `PASS` | Login/register with in-memory token transport (authTransport.ts, zero storage leaks) | Complete |
| **`C4`** | Dashboard Redesign & Real Metrics | `PASS` | Authenticated dashboard wired directly to GET /api/v1/metrics (zero fake stats) | Complete |
| **`C5`** | SBOM Management & Drag-and-Drop | `PASS` | CycloneDX intake, client-side validation (10MB), and parsed metadata display | Complete |
| **`C6`** | ZKP Workspace & Proof Wizard | `PASS` | Multi-step proof wizard with C6.1 running-state correction & snapshot filters | Complete |
| **`C7`** | Buyer Verification & Certificates | `PASS` | Buyer verification portal, certificate viewer, and public unauthenticated lookup | Complete |
| **`C8`** | Administration & User Workspaces | `PASS` | Role-gated admin console (/admin), user management, and user profile (/profile) | Complete |
| **`C9`** | Frontend Integration Quality Gates | `PASS (HISTORICAL)` | 80 frontend unit tests pass (0 skips, 0 failures), TS clean, ESLint clean, 17 routes | Technically Complete — Awaiting Owner Acceptance |
| **`D1`** | Database & Migration Design | `PASS` | Migration 015 applied to PG16 container; 412 Alembic tests pass | Complete |
| **`D2`** | Authentication & Onboarding | `PASS` | 39 security tests pass; Bcrypt max 72 bytes, role enforcement | Complete |
| **`D3`** | RBAC & Admin User Management | `PASS` | 19 admin management tests pass; 5-role enforcement, last-admin protection | Complete |
| **`D4`** | Application & SBOM API Integration | `PASS` | 569 backend tests + 96 frontend tests pass; tenant isolation verified | Complete |
| **`D5`** | Proof Generation & Job Lifecycle | `PASS (BOUNDED) / UNVERIFIED (256-SEG)` | 81 tests pass; 1 live segment proved (83.25s); watchdog containment verified at 1.54 GiB RAM; full 256-segment run unverified | Accepted by owner |
| **`D6`** | Independent Verification & Certificates | `PASS` | 146 offline + 24 live verifier tests pass; fail-closed cert issuance verified | Complete |
| **`D7`** | Vulnerability Intel & Snapshot TTL | `RECOMMENDED CONDITIONAL ACCEPTANCE` | 7 locked TTL decisions implemented; 37/37 matrix tests pass; rev 016 verified on port 5434; port 5433 dev DB remains at rev 015 | Owner acceptance pending |
| **`D8`** | Backend Security & Regression Validation | `PASS` | 1,327 backend automated tests pass (0 skips, 0 failures) across 65 test files | Complete |
| **`D9`** | Full End-to-End Acceptance | `RECOMMENDED CONDITIONAL ACCEPTANCE` | Port 5433 bounded intake: 8/9 checks pass (Step 5 safely gated); Port 5434 isolated policy: 14/14 live checks pass | Owner acceptance pending |

| **`E1`** | Crypto Verifier Invariants | `PASS` | Explicit boolean checking verified in `legacy_acir.py` | Complete |
| **`E2`** | Public Input Mismatch Rejection | `PASS` | 7 public input binding tests pass in `test_public_input_binding.py` | Complete |
| **`E3`** | Corrupted Proof Rejection | `PASS` | 23 legacy ACIR adapter tests pass in `test_legacy_acir_adapter.py` | Complete |
| **`E4`** | Snapshot Immutability & Concurrency | `PASS` | Lifecycle status transition tests pass in `test_vulnerability_ingestion` | Complete |
| **`E5`** | Tenant Isolation & IDOR Testing | `PASS` | Application and proof job tenant isolation tests pass | Complete |
| **`E6`** | Adversarial Input & Boundary Checks| `PASS` | 10MB limit and payload rejection tests pass | Complete |
| **`E7`** | Crypto Test Accounting & Gaps | `PASS` | F2-C-001 resolved with native bb.exe; 270 Stage E tests pass (0 skips) | Complete |
| **`F1`** | Full-Stack Regression Execution | `PASS (HISTORICAL)` | 1,327+ backend tests, 80 frontend tests pass (0 failures, 0 skips) | Complete |
| **`F2`** | Clean Build & Reproducibility | `PASS` | Next.js production build verified; `bootstrap.ps1` verified | Complete |
| **`F3`** | System Architecture Documentation | `PASS` | `ARCHITECTURE.md` complete with diagrams and API contracts | Complete |
| **`F4`** | Student Runbook & Setup Manual | `PASS` | `STUDENT_RUNBOOK.md` complete with quickstart and troubleshooting | Complete |
| **`F5`** | Demo Scenarios & Viva Preparation | `PASS` | `DEMONSTRATIONS_AND_VIVA.md` & `VIVA_PRESENTATION_SLIDES.md` complete; Log4Shell test pass | Complete |
| **`F6`** | Final Acceptance Sign-Off Checklist | `CONDITIONALLY READY` | `dist/zkp-sbom-source.zip` packaged and verified; formal owner sign-off pending | Awaiting formal owner sign-off |
| **`G0`** | Baseline and Preservation | `PASS` | Repository baseline captured; DB targets isolated (PG17 port 5435 regression, PG17 5432 frozen) | Complete |
| **`G1`** | Security Audit & Finding Register | `PASS` | 8 security findings logged (`G1-SEC-001` to `G1-SEC-008`) in `scratch/stage-g/v3_g1/` | Complete |
| **`G2`** | Consolidate Visible Roles (Vendor, Buyer, Admin) | `PASS` | 3 primary roles operational; legacy roles return HTTP 422; self-registration forced to buyer | Complete |
| **`G3`** | Backend & API Hardening | `PASS` | Sliding-window `RateLimiter` (HTTP 429), CSP, CORS PATCH, two-person snapshot approval enforced | Complete |
| **`G4`** | Frontend Simplification & Integration | `PASS` | Navigation shell and RouteGuard aligned to 3 roles; truthful metrics and 429 retry-after | Complete |
| **`G5`** | Cross-Role Regression | `PASS` | 348 automated tests passed (250 backend + 98 frontend, 0 skips, 0 failures), clean build 19 routes | Complete |
| **`G6`** | Independent Closure | `PASS` | Formally closed 2026-10-25 03:48 IST (`G6_INDEPENDENT_CLOSURE_REPORT.md`); 10/10 criteria pass | Stage G Closed |
| **`D_REASSESS`** | Stage D Follow-On Reassessment | `PASS` | Formally audited and signed off 2026-10-26 02:45 IST (`final_audit_report.md`); 256/256 proofs verified in 531.826s; active Certificate `81d1a4f0-...` minted | Stage D Reassessment Closed |
| **`FINAL_SUBMISSION`** | Context Sync, Source ZIP Refresh & Safe Cleanup | `ACTIVE / IN PROGRESS` | Canonical context synchronization, dist/zkp-sbom-source.zip refresh, safe Class A cache cleanup, independent validation | Current Phase |

---

## 7. Completion and Change-Control Governance

To ensure the engineering project proceeds systematically without chaotic rewrites or broken features, all work must adhere to this change-control procedure:

1. **Structured Work Unit Flow**: Every implementation task must follow the six-step sequence:
   $$\text{Inspect} \longrightarrow \text{Specify} \longrightarrow \text{Implement} \longrightarrow \text{Test} \longrightarrow \text{Review} \longrightarrow \text{Record}$$
2. **Decomposition of Large Tasks**: Never perform large, multi-file refactoring batches. Break complex tasks into focused sub-tasks with stable IDs (`C1`, `C2`, etc.).
3. **Mandatory Regression Execution**: After modifying any backend route or frontend component, run the relevant test suite immediately to confirm no regression was introduced.
4. **Database Migration Restrictions**:
   - New migrations may only be created if strictly required by a new schema requirement.
   - All migrations must be tested and verified against the disposable database (`127.0.0.1:5433`).
   - The protected database (`127.0.0.1:5432`) must **never** be migrated or modified without explicit project-owner authorization.
5. **Preservation of Untracked Files**: Untracked migrations (`012`, `013`, `014`), documentation in `.context/`, and historical archives (`archive/`, `master_archive/`) must **never** be cleaned, discarded, or overwritten.
6. **Immutable Roadmap Governance**: This six-stage roadmap sequence (`Stage A` through `Stage F`) is the single authoritative source of truth. It may only be altered through formal, explicit agreement with the project owner.

---

*End of Authorized Project Roadmap Document.*

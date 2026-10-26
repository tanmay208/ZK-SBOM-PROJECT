# Project Context: Zero-Knowledge SBOM Vulnerability Verification

**Project Name:** Zero-Knowledge Verification for Software Supply Chain Security  
**Workspace Root:** `E:\Main Project`  
**Authoritative Location:** `project_context/PROJECT_CONTEXT.md`  
**Effective Date:** 14 October 2026  
**Operating Mode:** LOCAL-ONLY. No remote operations, deployments, or external environment access without explicit authorization.  
**Target Deadline:** 20 October 2026 (Planning constraint)  

---

## 1. Project Mission & Problem Statement

### 1.1 The Software Supply Chain Dilemma
Modern software development depends heavily on open-source packages and nested third-party dependencies. Enterprise purchasers, critical infrastructure operators, and regulated defense buyers routinely require assurances that software products comply with organizational vulnerability standards (e.g., zero unpatched vulnerabilities with CVSS scores $\ge 7.0$).

To satisfy this requirement, buyers historically demanded unredacted **Software Bills of Materials (SBOMs)**. However, software vendors frequently resist sharing complete SBOMs because:
1. **Intellectual Property Exposure**: Proprietary architectures, unique internal module structures, and commercially sensitive third-party integrations are revealed.
2. **Attack Surface Disclosure**: Providing a complete inventory of non-critical or legacy dependencies offers potential adversaries a roadmap for targeted zero-day exploitation.

### 1.2 Zero-Knowledge Resolution
This project resolves the supply chain conflict mathematically through Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge (zk-SNARKs / UltraPlonk circuits). The system allows a software vendor to prove:

$$\text{"The private software inventory } S \text{ committing to Merkle root } R_{\text{SBOM}} \text{ contains zero dependencies violating Policy } P \text{ against Authoritative Vulnerability Database } V\text{"}$$

The verifier receives mathematical certainty of compliance while learning **zero proprietary information** regarding package names, package URLs (`purl`), versions, or dependency topologies.

---

## 2. Technical Architecture & Technology Stack

The platform is designed with clear layer separation across the complete software stack:

```
+--------------------------------------------------------------------------------------------------+
|                                    SYSTEM TOPOLOGY & DATA FLOW                                   |
+--------------------------------------------------------------------------------------------------+
|  [Presentation Layer]                                                                            |
|    Next.js 16.3.5 (Turbopack) @ http://127.0.0.1:3000                                            |
|    - App Router, React 19.2.8, TypeScript 5, TanStack Query 5                                     |
|    - In-Memory JWT Transport (XSS Mitigation; zero token storage in localStorage/cookies)         |
|                               |                                                                  |
|                               v (REST APIs via JSON & multipart/form-data)                       |
|  [API Gateway & Service Layer]                                                                   |
|    FastAPI 0.115.6 / Uvicorn 0.34.0 @ http://127.0.0.1:8000                                      |
|    - Verification Service: Proof-to-DB binding, Barretenberg verifier runtime, certificate issuing |
|    - ZKP Prover Service: Proving orchestration, 32-component chunk witnesses, advisory job locks |
|    - SBOM Intake Service: CycloneDX parsing, canonical purl sorting, Poseidon Merkle commit       |
|    - Vulnerability Intel Service: CVE ingestion, Sparse Merkle Tree (SMT) management, lifecycle  |
|    - Policy Service: Max-CVSS rule definitions, canonical policy hash commitment computation     |
|    - Shared Cryptography: BN254 scalar field, Poseidon sponge permutation, Merkle & SMT engines  |
|                               |                                                                  |
|                               v (SQLAlchemy 2.0 / psycopg2)                                      |
|  [Persistence Layer]                                                                             |
|    Docker PostgreSQL 16.15 (Container: zkp_sbom_local_dev) @ 127.0.0.1:5433                       |
|    - Database: ZKP_SBOM_LOCAL_DEV (Alembic Revision 014)                                         |
|    - Multi-Tenant Scoping: (name, vendor, user_id) unique constraints on applications & uploads   |
|                                                                                                  |
|  [Zero-Knowledge Cryptographic Layer]                                                            |
|    Noir 0.32.0 (ACIR representation) & Barretenberg 0.46.1 (UltraPlonk)                          |
|    - Curve: BN254 (alt_bn128, scalar modulus r = 218882428718392752222464057452572750885483...) |
|    - Hashes: Poseidon Sponge (t=3 for 2-to-1 Merkle nodes, t=2 for leaf commitments)            |
|    - SBOM Capacity: Binary Merkle Tree Depth 10 (2^10 = 1024 components)                         |
|    - Vuln Database: Sparse Merkle Tree Depth 256 with dynamic depth empty hash precomputation    |
|    - Circuit Chunking: 32 components per segment (segment_init_32 -> mid_32 -> final_32)         |
|    - Verifier Runtime: Pinned Node.js WASM Barretenberg verifier (verify_proof.mjs)               |
+--------------------------------------------------------------------------------------------------+
```

---

## 3. System Roles & Separation of Duties

The application enforces strict Role-Based Access Control (RBAC) and Separation of Duties. The agreed product model comprises five roles:

1. **`vendor` (Software Supplier)**:
   - Registers applications within their isolated tenant namespace (`(name, vendor, user_id)` unique scope).
   - Submits raw CycloneDX SBOMs via encrypted upload routes.
   - Initiates zero-knowledge proof generation jobs for their applications.
   - Downloads issued compliance certificates to present to buyers.
2. **`buyer` (Enterprise / Regulated Buyer)**:
   - Planned dedicated consumer role for purchasing organizations.
   - Receives verification evidence and independently verifies zk-SNARK proofs and certificates.
   - Validates proof commitments without accessing private component data or proprietary vendor architectures.
3. **`auditor` (Third-Party Verifier)**:
   - Default base role assigned to newly registered users via `/api/v1/auth/register`.
   - Submits public roots (`sbom_root`, `vulnerability_db_root`, `policy_hash`) and proof artifacts for verification.
   - Performs real-time certificate validation via public routes in a read-oriented workflow.
   - Strictly forbidden from viewing private SBOM components or unapproved vulnerability feeds.
4. **`admin` (Security Administrator)**:
   - Defines authoritative security policies (e.g., maximum permissible CVSS score).
   - Reviews and formally transitions vulnerability database snapshots (`approved` $\rightarrow$ `frozen`).
   - Revokes compromised compliance certificates with auditable timestamps and reasons.
   - Manages user accounts and privileged role assignments.
5. **`trusted_importer` (Data Ingestor)**:
   - Ingests vulnerability CVE definitions and generates Sparse Merkle Trees.
   - Enforces two-person integrity: creates snapshots in `pending` status, requiring an `admin` to approve or freeze them.

*Implementation Evidence Note:* In the current codebase, `role` is stored as `String(50)` on `User` defaulting to `'auditor'`, with server-side checks actively enforcing `'vendor'`, `'admin'`, and `'trusted_importer'`. The dedicated `'buyer'` role and explicit account status/activation lifecycle are planned for Stage D (D2/D3).

---

## 4. Mandatory Environment & Security Constraints

All work in this repository must observe the following hard boundaries:

1. **Local-Only Operating Mode**:
   - Operating mode is strictly **LOCAL-ONLY**. No remote operations, deployments, or external environment access without explicit authorization.
   - Do not attempt live database provisioning, remote migrations, or remote staging queries.
2. **Gate 5R — Strictly Blocked**:
   - No live database mutations on remote/staging environments, no production exports, and no secret rotations.
3. **Database Strategy & Environment Policy**:
   - **PostgreSQL 16 — Development and Testing Candidate**: Docker container `zkp_sbom_local_dev` on `127.0.0.1:5433`, database `ZKP_SBOM_LOCAL_DEV` (historically migrated to rev `014`). Preferred development/testing candidate for dev, test, migration validation, debugging, and integration testing, subject to explicit authorization before DB operations. Present state has not been verified by this task.
   - **PostgreSQL 17 — Intended Final Main-Project Target**: Local PostgreSQL 17 on `127.0.0.1:5432`, database `ZKP_SBOM` (historically recorded at Alembic rev `007`). Intended main database for the completed project. Currently protected/frozen during development and validation; do not access or modify without separate, explicit authorization. Will only be considered for operational use after validation, recovery planning, and separate explicit authorization.
   - **Pre-D1 Database Restriction**: Prior to authorized D1 work, do not run migrations, write queries, seed data, truncate tables, drop objects, restart containers, recreate containers, or remove volumes on either instance. Read-only inspection must never disclose passwords or print `.env`. Stage D1 remains unauthorized.
4. **Credential & Secret Protection**:
   - The root `.env` file contains remote credentials. It must **NEVER** be printed, edited, committed, or read by local processes.
   - Secrets (`JWT_SECRET_KEY`, `CERTIFICATE_SECRET_KEY`, `DB_PASSWORD`) must be passed strictly via ephemeral process-scoped environment variables. Never persist secrets machine-wide.
5. **Git Working Tree Preservation**:
   - Inspect `git status` before and after changes.
   - Never run `git reset --hard` or `git clean -fd`.
   - Untracked Alembic migrations `012`, `013`, and `014`, plus `archive/` and `master_archive/`, must be preserved at all times.

---

## 5. Development Approach & Evidence Standards

Development follows a structured, student-appropriate engineering discipline:

$$\text{Inspect} \longrightarrow \text{Plan} \longrightarrow \text{Implement Small Unit} \longrightarrow \text{Test} \longrightarrow \text{Review} \longrightarrow \text{Record Evidence}$$

### Evidence Standards:
- **Implemented Feature vs Validated Claim**: An endpoint that returns 200 OK does not prove cryptographic zero-knowledge security. A security property must be validated through empirical negative tests.
- **Mocks Are Not Live Proof**: A test running on SQLite mocks does not prove PostgreSQL transaction safety (`AUD-A-003`).
- **Skipped Tests Are Not Passes**: Skipped native cryptographic tests (`test_b1_live_crypto.py`) due to missing host binaries must be explicitly accounted for as skipped (`F2-C-001`).
- **Fail-Closed Verification**: The only acceptable cryptographic verification outcome is an explicit Boolean `true` from the verifier. Swallowed exceptions or malformed inputs must result in rejection.

---

## 6. The Authoritative Six-Stage Roadmap

The repository follows the locked six-stage sequence (effective 14 October 2026):

1. **Stage A — Re-entry Audit and Project Baseline** `[FULL PASS / CLOSED]`: Repository inventory, local runtime check, database isolation, service startup, and baseline test suite accounting (861 passes, 0 skips).
2. **Stage B — Backend, Database, and Security Fixes** `[FULL PASS / CLOSED]`: Hardening API routes, DB connection pooling, RBAC enforcement, multi-tenant IDOR protection, 10-worker concurrency probe.
3. **Stage C — Product Experience (Modules C0–C9)** `[REPORTED COMPLETE — PENDING OVERALL OWNER ACCEPTANCE]`:
   - `C0`: Scope, architecture and workflow contract `[REPORTED COMPLETE]`
   - `C1`: Design system and application shell (light-first design, tokens, responsive shell)
   - `C2`: Public homepage and product presentation
   - `C3`: Authentication and onboarding experience (in-memory token transport, autocomplete)
   - `C4`: Workspace, dashboard and navigation (genuine `GET /api/v1/metrics`, zero fake data)
   - `C5`: Application and SBOM management (secure upload, metadata display, non-disclosure)
   - `C6`: Proof-generation workflow (chunk proving wizard, polling progress, C6.1 running state fix)
   - `C7`: Buyer verification and certificates (independent verification, live revocation)
   - `C8`: Administration, profiles and role-specific workspaces (lifecycle management)
   - `C9`: Frontend integration and acceptance (`npm test`, `tsc`, `next build`, 80 tests passing)
4. **Stage D — Backend, Database and System Integration (Modules D0–D9)** `[NOT STARTED — D0 AUDIT REPORTED COMPLETE, D1 UNAUTHORIZED]`:
   - `D0`: API, schema and dependency audit `[REPORTED COMPLETE BY ANTIGRAVITY — PENDING OWNER REVIEW & ACCEPTANCE]`
   - `D1`: Database and migration design `[UNAUTHORIZED — BLOCKED UNTIL D0 REVIEW, OWNER DECISIONS & EXPLICIT AUTHORIZATION]`
   - `D2`: Authentication, onboarding and profiles
   - `D3`: RBAC and administrative user management (formalizing 5 roles)
   - `D4`: Application and SBOM API integration
   - `D5`: Proof generation and job lifecycle
   - `D6`: Independent verification and certificate lifecycle
   - `D7`: Vulnerability intelligence, observability and auditability
   - `D8`: Backend security and regression validation
   - `D9`: Full end-to-end acceptance
5. **Stage E — Security and Cryptographic Validation**: Adversarial testing, proof tampering, public input mismatch rejection, snapshot immutability, IDOR penetration.
6. **Stage F — Final Testing, Documentation, and Submission**: Comprehensive regression across all 6 services, clean build verification, student setup runbook, viva defense preparation.

**Interleaved Execution Sequence**:
`C0–C9 (Reported Complete) → D0 (Read-Only Audit Reported Complete, Pending Owner Review) → D1–D3 (Unauthorized) → D4–D5 → D6–D7 → D8–D9`

Refer to [`project_context/PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md) for full task-by-task specifications.

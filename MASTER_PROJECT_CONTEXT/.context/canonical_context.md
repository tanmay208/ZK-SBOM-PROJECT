# Canonical Project Context

**Freshness Date:** 2026-10-24  
**Workspace:** `E:\Main Project`  
**Authoritative Documentation Root:** [`MASTER_PROJECT_CONTEXT/`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT)  
**Operating Mode:** LOCAL-ONLY (Gate 5R Strictly Blocked; No Remote Operations)  
**Purpose:** Primary entry point for fresh AI sessions, IDE agents, and engineers to understand system architecture, security invariants, verified state, and immediate next actions.

---

## 1. Project Objective & Core Workflow

**Zero-Knowledge Verification for Software Supply Chain Security**  
This platform implements a production-grade research and engineering system for privacy-preserving verification of Software Bill of Materials (SBOM) vulnerability policy compliance:
1. **Supplier Privacy**: Software vendors prove their SBOM satisfies a customer vulnerability policy ($C_{\text{CVSS}} \le \text{Threshold}$) against an authoritative vulnerability database without disclosing proprietary component names (`purl`), versions, or dependency graphs.
2. **Authoritative Cryptographic Commitments**:
   - $R_{\text{SBOM}}$: Poseidon Merkle tree root (depth 10, up to 1024 components, evaluated in 256-component chunks) over canonical component hashes.
   - $R_{\text{VulnDB}}$: Authoritative Sparse Merkle Tree (SMT, depth 256) root over all known CVE component hashes and maximum CVSS scores.
   - $H_{\text{Policy}}$: Poseidon hash over policy rules (maximum allowable CVSS score scaled $[0, 100]$ via canonical 10x multiplier).
3. **Cryptographic Circuits**: Noir 0.32.0 ACIR circuits with Barretenberg 0.46.1 UltraPlonk backend evaluating 32-component chunks linked cryptographically via Poseidon hash chains (`segment_init_32`, `segment_mid_32`, `segment_final_32`).
4. **Verifiable Certificates**: Verification service confirms cryptographic validity and database-backed authorization, issuing signed certificates with online database revocation checks.

---

## 2. Authoritative Locked Roadmap & Status Ledger

The project follows strictly the locked modular roadmap:

$$\mathbf{Stage\ A \longrightarrow Stage\ B \longrightarrow Stage\ C \longrightarrow Stage\ D \longrightarrow Stage\ E \longrightarrow Stage\ F \longrightarrow Stage\ G}$$

- **Stage A — Baseline Audit**: `OPERATIONALLY CLOSED / FULL PASS` (Baseline verified; native `bb.exe` launcher automated; 24/24 cryptographic tests passing).
- **Stage B — Backend & Security Fixes**: `OPERATIONALLY CLOSED / FULL PASS` (RBAC, multi-tenant isolation, DB uniqueness constraints, 10-worker concurrency probe passed on port 5433, 861/861 backend tests passing).
- **Stage C — Product Experience (C0–C9)**: `REPORTED COMPLETE (PENDING OVERALL OWNER ACCEPTANCE)` (80 unit tests pass, TypeScript clean, ESLint clean, 17 Next.js routes compiled).
- **Stage D — Backend & System Integration (D0–D9)**: `OPERATIONALLY CLOSED / FORMALLY ACCEPTED WITH DISCLOSED LIMITATIONS` (D0–D4, D6, D8 full pass; D7 formally accepted by owner with rev 016; D9 Category A live non-proving workflow pass verified on port 5433; D5 full 256-segment proving deferred as UNVERIFIED due to host RAM safety floor; 1,345 backend tests pass with 0 skips).
- **Stage E — Security & Cryptographic Validation**: `OPERATIONALLY CLOSED / FULL PASS` (270 dedicated security and cryptographic tests pass with 0 skips; 20-threat comprehensive security matrix published).
- **Stage F — Final Testing, Documentation, and Submission**: `OPERATIONALLY CLOSED / FULL PASS` (Comprehensive regression suites passing; clean environment build verified; forensic cleanup audit completed; viva demo environment seeded).
- **Stage G — Final Presentation Readiness & Viva Acceptance**: `G3 ACCEPTED / G4 AUTHORIZED` (Authoritative Supabase PostgreSQL 17 on port 5432 live workflows 1-6 verified; Log4Shell authentic circuit constraint rejection demonstrated; historical certificate validation separated from new compliance; 155/155 tests passing on port 5435; full 256-segment proving explicitly deferred as UNVERIFIED; Stage G paused temporarily for repository cleanup).

---

## 3. Fresh AI Session Onboarding Sequence

Any new AI session or engineer resuming this project must follow this sequence:
1. **Bootstrap Context**: Run `.\bootstrap.ps1` from the repository root to validate environment paths and display current working handoff from `MASTER_PROJECT_CONTEXT/.context/`.
2. **Read Canonical Context**: Inspect [`MASTER_PROJECT_CONTEXT/README.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/README.md) and [`MASTER_PROJECT_CONTEXT/project_context/HANDOFF.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/HANDOFF.md).
3. **Inspect Working Tree**: Run `git status --short`. Maintain all existing modifications and untracked files (`archive/`, `master_archive/`). **Never discard, clean, or reset them.**
4. **Observe Safety Invariants**:
   - Operating mode is strictly **LOCAL-ONLY**. Gate 5R is **STRICTLY BLOCKED**.
   - **Authoritative Presentation DB**: Supabase PostgreSQL 17 on `127.0.0.1:5432` (`aws-0-ap-southeast-2.pooler.supabase.com`, Alembic rev `016`). Strictly protected and read-only during non-presentation tasks.
   - **Automated Regression DB**: Docker PostgreSQL 17 on `127.0.0.1:5435` (`zkp_sbom_g2_integration`, Alembic rev `016`). Target for automated and destructive testing.
   - **PostgreSQL 16**: Excluded from Stage G and presentation workflows.
   - Never print or copy secrets, `.env` values, tokens, or private keys.
5. **Execute Next Action**: Resuming Stage G4 presentation execution once repository cleanup is finalized.

---

## 4. Current Runtime & Live Demonstration Coordinates

- **Authoritative Database**: Supabase PostgreSQL 17 on `127.0.0.1:5432` (Alembic rev `016`). 8 baseline accounts verified active.
- **Isolated Test Database**: Docker PostgreSQL 17 on `127.0.0.1:5435` (`zkp_sbom_g2_integration`).
- **Gateway**: Background process running on port `8080` (verified healthy at `http://127.0.0.1:8080/api/v1/health`).
- **Frontend UI**: `cd frontend; npm run dev` serving at `http://localhost:3000`.
- **Pre-Seeded Demonstration Fixtures (Supabase 5432)**:
  - Policy: Active presentation policy `viva_strict_policy` (Max CVSS: 7.0 / integer 70).
  - Snapshot: Frozen snapshot `viva_log4shell_snapshot` (SMT root `0x20d6d6e0...`) with unexpired TTL.
  - Compliant Application: `viva_demo_app` with clean CycloneDX SBOM (`0x099ff014...`, score 0 $\le$ 70).
  - Negative Circuit Rejection: Vulnerable Log4j SBOM rejected by circuit constraint (`100 > 70`). Zero certificates issued.
  - Active Presentation Certificate: `444d6620-8e13-4511-8b11-ff78c6294cf0` cryptographically verified and active.


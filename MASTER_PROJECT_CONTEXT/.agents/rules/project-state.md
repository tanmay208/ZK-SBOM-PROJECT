---
trigger: model_decision
description: Apply when planning work, proposing stages, interpreting project status, or updating project documentation.
---

# Project State & Roadmap Discipline

**Authoritative Documentation Root**: [`MASTER_PROJECT_CONTEXT/`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT)  
**Authoritative Roadmap**: [`MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md)  
**Authoritative State**: [`MASTER_PROJECT_CONTEXT/project_context/PROJECT_STATE.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/PROJECT_STATE.md)  

1. **Single Locked Six-Stage Roadmap**: Follow strictly the modular sequence:
   $$\mathbf{Stage\ A \longrightarrow Stage\ B \longrightarrow Stage\ C \longrightarrow Stage\ D \longrightarrow Stage\ E \longrightarrow Stage\ F}$$
   - **Stage A (Baseline Audit)**: `FULL PASS` (Closed).
   - **Stage B (Backend Fixes & Remediation)**: `FULL PASS` (Closed).
   - **Stage C (Product Experience, C0–C9)**: `REPORTED COMPLETE` (Pending overall owner acceptance).
   - **Stage D (Backend, Database & System Integration)**: `OPERATIONALLY CLOSED / FORMALLY ACCEPTED WITH DISCLOSED LIMITATIONS` (D0–D4, D6, D8 full pass; D7 formally accepted by owner with rev 016; D9 Category A live non-proving workflow pass verified; D5 full 256-segment proving DEFERRED / UNVERIFIED due to host RAM floor constraints; 0 fake certificates minted).
   - **Stage E (Security & Cryptographic Validation)**: `OPERATIONALLY CLOSED / FULL PASS` (270 dedicated tests pass, 20-threat security matrix published).
   - **Stage F (Final Testing, Documentation, and Submission)**: `ACTIVE / IN PROGRESS`.
   Never skip, reorder, or alter module acceptance gates.

2. **Mandatory Evidence & Status Conventions**:
   Every status statement must use one of these explicit labels:
   - **`VERIFIED`**: Direct evidence exists in the current task or in an inspectable test, log, or artifact.
   - **`REPORTED`**: Stated in a prior report but not independently re-verified in the current session.
   - **`OWNER ACCEPTED`**: Explicit owner acceptance exists and is documented in an acceptance record.
   - **`DEFERRED`**: Deliberately postponed to a future stage or activity.
   - **`UNVERIFIED`**: Required evidence is absent or incomplete.
   - **`NOT TESTED`**: The relevant operation has not been exercised.
   Prohibit false completion claims. Changing a status from UNVERIFIED/DEFERRED to VERIFIED requires citing concrete evidence (test output, log path, or manifest SHA-256).

3. **Operating Mode & Environmental Isolation**:
   - Mode: Strictly **LOCAL-ONLY**. Remote operations, external APIs, and unauthorized deployments are prohibited. Gate 5R is **STRICTLY BLOCKED**.
   - **PostgreSQL 16** on `127.0.0.1:5433` (`ZKP_SBOM_LOCAL_DEV`): Preferred development and live demo database, active at Alembic revision `016`. Exactly 8 baseline user accounts must be preserved intact.
   - **PostgreSQL 17** on `127.0.0.1:5432` (`ZKP_SBOM`): Protected main project target. Strictly frozen; do not connect, query, or migrate.
   - **Ephemeral Port 5434**: Isolated testing database.

4. **Cryptographic & Verification Boundaries**:
   - Mocks are not live proofs (`AUD-A-003`).
   - Skipped tests are not passes (`F2-C-001`).
   - HTTP 200 responses do not prove zero-knowledge cryptographic validity.
   - Verification without an authentic UltraPlonk proof must strictly fail closed with `verification_unavailable` and zero certificates minted.
   - Bounded 1-segment execution does NOT prove full 256-segment proving; D5 remains DEFERRED / UNVERIFIED.

5. **Stateless Account Recovery & Canonical Source of Truth**:
   - `MASTER_PROJECT_CONTEXT/` is the single authoritative source of truth.
   - Root compatibility mirrors (`.agents/`, `.context/`, `project_context/`, `AGENTS.md`, `README.md`, `PROJECT_CONTEXT.md`) exist for IDE discovery and tools like `bootstrap.ps1`.
   - When resuming sessions, always inspect `MASTER_PROJECT_CONTEXT/README.md` and run `.\bootstrap.ps1`. Reconstruct context without relying on conversational memory.


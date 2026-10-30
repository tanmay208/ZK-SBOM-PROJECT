# Master Project Context: Zero-Knowledge SBOM Verification

**Workspace:** [E:\Main Project](file:///E:/Main%20Project)
**Authoritative Documentation Root:** [MASTER_PROJECT_CONTEXT/](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT)
**Project:** Zero-Knowledge Verification for Software Supply Chain Security
**Operating Mode:** LOCAL-ONLY (No remote operations or deployments without explicit authorization; Gate 5R strictly blocked)
**Effective Date:** 30 October 2026

---

## 1. Single Authoritative Context Root

This directory (`MASTER_PROJECT_CONTEXT/`) is the **single canonical navigation point and authoritative source of truth** for the entire project. It eliminates conflicting, fragmented, or stale documentation by centralizing:
- The locked project roadmap ($A \to B \to C \to D \to E \to F \to G$ and Master Prompts 1–6).
- Verified environment metrics, runtime coordinates, and live demonstration fixtures.
- Formal architectural decision records (ADRs) and owner acceptance milestones.
- Operational safety, RBAC, and cryptographic invariant rules for AI coding agents.
- The repository cleanup audit, archive catalog, and viva defense handoff.

$$\mathbf{E:\backslash Main\ Project\backslash MASTER\_PROJECT\_CONTEXT\backslash}$$

Before proposing or executing any implementation or inspection, all fresh AI sessions or engineers must consult this directory first.

---

## 2. Canonical Structure & Three Conceptual Tiers

The canonical context is organized into three distinct functional tiers, supported by top-level audit manifests:

```text
MASTER_PROJECT_CONTEXT/
├── README.md                          <-- Canonical navigation index & orientation guide
├── ARCHIVE_CONTENTS_MANIFEST.json     <-- 399-item classified manifest of archives & historical assets
├── REPOSITORY_CLEANUP_AUDIT.md        <-- Zero-loss repository cleanup audit report
├── .agents/
│   └── rules/                         <-- TIER 1: Operational & Behavioral Rules
│       ├── cryptography.md            <-- Cryptographic invariants and verifier constraints
│       ├── project-state.md           <-- State interpretation, evidence labels & anti-hallucination rules
│       ├── repository-safety.md       <-- Non-destructive Git and database safeguards
│       └── security.md                <-- Authentication, RBAC, and boundary rules
├── .context/                          <-- TIER 2: Current Working Context & Immediate Handoffs
│   ├── adrs.md                        <-- Architectural Decision Records
│   ├── architecture_reference.md      <-- Architectural design reference
│   ├── canonical_context.md           <-- Working memory snapshot & verified runtime coordinates
│   ├── execution_map.md               <-- Milestone dependency mapping
│   ├── handoff.md                     <-- Active session continuity handoff (read by bootstrap.ps1)
│   ├── project_state.md               <-- Working ledger & live demonstration entity coordinates
│   └── README.md                      <-- Context directory notice and pointer
└── project_context/                   <-- TIER 3: Authoritative Technical Governance & Specifications
    ├── ARCHITECTURE.md                <-- End-to-end multi-tier architecture & dataflow
    ├── CHANGELOG.md                   <-- Complete versioned findings & modification log
    ├── CRYPTOGRAPHY_RULES.md          <-- Mathematical & cryptographic specifications
    ├── D7_OWNER_ACCEPTANCE_RECORD.md  <-- Formal Owner Acceptance for Stage D7 (TTL)
    ├── DECISIONS.md                   <-- Durable architectural & cryptographic decision register (ADRs 1–15)
    ├── DEMONSTRATIONS_AND_VIVA.md     <-- Scripted viva walkthroughs & demo flows
    ├── EXECUTION_MAP.md               <-- Detailed module execution status
    ├── HANDOFF.md                     <-- Master session handoff & limitations register
    ├── OWNER_ACCEPTANCE_REVIEW_A_B_C_E_F_20261022.md <-- Consolidated owner review
    ├── PROJECT_CONTEXT.md             <-- Core technical context and boundaries
    ├── PROJECT_ROADMAP.md             <-- The locked master six-stage roadmap (A through F)
    ├── PROJECT_STATE.md               <-- Authoritative long-term state, row counts, & findings register
    ├── README.md                      <-- Project context guide and table of contents
    ├── REPOSITORY_SAFETY.md           <-- Zero-loss repository and DB safety invariants
    ├── SECURITY_RULES.md              <-- Multi-tenant isolation & RBAC security model
    ├── SECURITY_VALIDATION_REPORT.md  <-- 20-threat comprehensive security matrix
    ├── STUDENT_RUNBOOK.md             <-- Step-by-step developer and viva operations guide
    └── VIVA_PRESENTATION_SLIDES.md    <-- Slide outline and defense speaking points
```

---

## 3. Authority Hierarchy & Conflict Resolution

To maintain consistency across diverse tools and development sessions:

1. **Tier 3 (`project_context/`) is Authoritative for Long-Term Specifications:**
   - [`PROJECT_ROADMAP.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md) defines the locked six-stage sequence ($A \to B \to C \to D \to E \to F$). Stages cannot be reordered or skipped.
   - [`PROJECT_STATE.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/PROJECT_STATE.md) maintains the authoritative long-term state, empirical test registers, and findings.
   - [`SECURITY_RULES.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/SECURITY_RULES.md) and [`CRYPTOGRAPHY_RULES.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/CRYPTOGRAPHY_RULES.md) define the cryptographic and security invariants.
   - [`DECISIONS.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/DECISIONS.md) records formal architectural decisions (ADRs 1–15).
   - [`D7_OWNER_ACCEPTANCE_RECORD.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/project_context/D7_OWNER_ACCEPTANCE_RECORD.md) records formal owner acceptance of Stage D7.
2. **Tier 2 (`.context/`) is Authoritative for Daily Working State:**
   - [`handoff.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/.context/handoff.md) records the immediate active session tasks, current coordinates, and exact next steps.
   - [`project_state.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/.context/project_state.md) captures the working ledger and live demonstration entity coordinates.
3. **Tier 1 (`.agents/rules/`) is Authoritative for AI Agent Operating Behavior:**
   - Governs tool invocation standards, non-destructive safety gates, and anti-hallucination evidence conventions.
4. **Resolution Policy:** If a lower-tier document conflicts with a higher-tier specification, the higher tier governs. When resolving discrepancies, inspect supporting test evidence, logs, or owner records before synchronizing.

---

## 4. Consolidated Canonical Context Architecture

Per the owner's explicit consolidation directive (24 October 2026), `MASTER_PROJECT_CONTEXT/` is the single, non-duplicated authoritative context root for the entire repository:
- **Canonical Context Root**: `MASTER_PROJECT_CONTEXT/` contains the authoritative rule tiers: `.agents/rules/`, `.context/`, and `project_context/`.
- **Root Entry Points Retained**:
  - `AGENTS.md`: Retained at repository root as the primary tool-discovered operational instruction file, pointing directly to `MASTER_PROJECT_CONTEXT/`.
  - `README.md`: Retained at repository root as the clean public orientation guide, linking directly to `MASTER_PROJECT_CONTEXT/README.md`.
  - `bootstrap.ps1`: Retained and updated to source context and handoff directly from `MASTER_PROJECT_CONTEXT/.context/`.
  - `pyproject.toml`, dependency manifests, `.gitignore`, `.dockerignore`, and Compose configurations: Retained at root as required by tooling and builds.
- **Redundant Root Folders Eliminated**: The standalone root-level `.agents/`, `.context/`, and `project_context/` directories have been consolidated and permanently removed to eliminate drift and duplication.

---

## 5. Strict Evidence & Status Conventions

All agents and developers must strictly apply these standardized evidence labels:

| Label | Meaning | Required Evidence |
|---|---|---|
| **`VERIFIED`** | Direct, empirical evidence exists in the current session or inspectable test/log/artifact. | Exact command line, exit code, test count, or inspectable database row. |
| **`REPORTED`** | Stated in an existing report but not independently re-validated in the current turn. | Reference to report document, date, and historical context. |
| **`OWNER ACCEPTED`** | Formally accepted by the project owner in writing. | Reference to explicit owner sign-off record (e.g., `D7_OWNER_ACCEPTANCE_RECORD.md`). |
| **`DEFERRED`** | Deliberately postponed by engineering or safety decision. | Recorded rationale and entry in limitations register. |
| **`UNVERIFIED`** | Implementation exists or is claimed, but required empirical proof is absent. | Clear qualification in all status tables and summaries. |
| **`NOT TESTED`** | The operation or scenario has not been exercised. | Explicit statement of omission. |

*Anti-Hallucination Invariant:* A test with mocks is not a live proof. An HTTP 200 response does not prove zero-knowledge cryptographic validity. Zero certificates minted in a non-proving run is fail-closed evidence, not a verification pass.

---

## 6. Repository Organization & Cleanup State

Following the forensic cleanup audit documented in [`REPOSITORY_CLEANUP_AUDIT.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/REPOSITORY_CLEANUP_AUDIT.md):
- **Current Git Status**: The repository is **organized but not fully Git-clean**. The current working tree contains 8 staged changes, 121 modified tracked files, and 115 untracked files/directories.
- **Archive Catalog (399 items in [`ARCHIVE_CONTENTS_MANIFEST.json`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/ARCHIVE_CONTENTS_MANIFEST.json))**:
  - `archive/proofs/` (264 files, 2.67 MB): **Retained in full** as active operational archives required by `scripts/verify_archive.py` and `scripts/package_source_zip.py`.
  - `master_archive/` (114 files, 300.7 MB): **Historical cold storage** strictly excluded from release packages (`dist/zkp-sbom-source.zip`). Contains relocated root scripts (`container_repo.py`, etc.), historical logs, and evaluation circuit duplicates.
- **Source Packaging Validation**: `scripts/package_source_zip.py` executes cleanly and packages source code and active archives into `dist/zkp-sbom-source.zip` (SHA-256 `3CF91E822F...`).
- **Retained Unknowns & Deferred Work**: Full git-clean working tree is deferred to preserve untracked Alembic migrations (`012..016`), runtime setups, and diagnostic fixtures needed for offline defense.

---

## 7. Current Project State & Known Limitations

- **Milestone:** **Stage F: Final Testing, Documentation, and Submission (ACTIVE / IN PROGRESS)**.
- **Stage D Outcome:** **OPERATIONALLY CLOSED / ACCEPTED BY OWNER WITH 3 DISCLOSED LIMITATIONS**:
  1. **D5 Full 256-Segment Proving**: **DEFERRED / UNVERIFIED**. (Bounded 1-segment proof verified in 83.25s; full 256-segment proof deferred due to host RAM safety threshold).
  2. **D7 Snapshot Freshness TTL**: **ACCEPTED BY OWNER WITH LIMITATIONS**. (Implemented in rev 016; 42/42 tests pass; live test was isolated; not all external scenarios exercised).
  3. **D9 Category A vs Category B**:
     - **Category A (Live Non-Proving Acceptance Workflow)**: `REPORTED PASS`. (Port 5433 dev DB, port 8080 gateway healthy, RBAC 403 verified, demo policy CVSS 7.0, frozen snapshot with SMT root & TTL, 2 SBOMs ingested, fail-closed unproven job returned `verification_unavailable` with `certificate: null`, 0 certificates minted).
     - **Category B (Cryptographic Proving Acceptance)**: `DEFERRED / UNVERIFIED`. (Live full witness generation, multi-segment UltraPlonk proof, independent cryptographic verification, and legitimate certificate issuance deferred).
- **External Feeds**: Local demonstration feed uses fixture datasets. Live NVD/OSV/GitHub advisory API integration is future work.

---

## 8. Quick Guide for Future Agents

When starting a session in this repository:
1. **Bootstrap Context:** Run `.\bootstrap.ps1` to verify the local environment and display the active handoff.
2. **Consult Canonical Navigation:** Review [`MASTER_PROJECT_CONTEXT/README.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/README.md) and [`MASTER_PROJECT_CONTEXT/.context/handoff.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/.context/handoff.md).
3. **Respect Operational Boundaries:**
   - Operating Mode is **LOCAL-ONLY**. Gate 5R is **STRICTLY BLOCKED**.
   - **Authoritative Presentation Database**: Supabase PostgreSQL 17 on `127.0.0.1:5432` (`aws-0-ap-southeast-2.pooler.supabase.com`, Alembic rev `016`). Dedicated target for live presentation and demonstration workflows. Protected / read-only during non-presentation tasks.
   - **Isolated Regression Test Database**: Docker PostgreSQL 17 on `127.0.0.1:5435` (`zkp_sbom_g2_integration`, Alembic rev `016`). Dedicated target for automated test suites and regression runs.
   - **PostgreSQL 16**: Excluded from Stage G and presentation workflows.
   - Never print or commit secrets, `.env` values, or bearer tokens.
4. **Immediate Priority:** The immediate priority is the **Live UI Walkthrough** across the 3 consolidated roles (`admin`, `vendor`, `buyer`), NOT further cleanup or code refactoring.

# Canonical Project Context

**Freshness Date:** 2026-10-13  
**Documentation Cutoff:** October 13, 2026  
**Target Project Deadline:** October 20, 2026 (Planning constraint, not a schedule compression license)  
**Operating Mode:** LOCAL-ONLY (SRMIST Wi-Fi Constraint; Gate 5R Strictly Blocked)  
**Purpose:** Primary entry point for a fresh AI session, IDE agent, or engineer to understand, audit, and safely continue the project without relying on prior conversational memory.

---

## 1. Project Objective & Core Workflow

**Zero-Knowledge Verification for Software Supply Chain Security**  
This repository implements a production-grade research and engineering platform for privacy-preserving verification of Software Bill of Materials (SBOM) vulnerability policy compliance:
1. **Supplier Privacy**: A software supplier proves that their software complies with a specified vulnerability policy without revealing raw, proprietary component identities or dependency graphs.
2. **Authoritative Context**: The verifier checks zero-knowledge proofs against authoritative, frozen vulnerability databases and official policy definitions.
3. **Cryptographic Proofs**: Noir circuits (UltraPlonk backend via Barretenberg 0.32.0 / bb.js 0.46.1) evaluate 32-component chunks linked cryptographically via Poseidon hash chains.
4. **Verifiable Certificates**: The verification service confirms cryptographic validity and database-backed authorization, issuing signed certificates with online revocation checks.

---

## 2. Authoritative Locked Roadmap & Status Ledger

The project strictly follows an immutable, locked sequential roadmap:

$$\mathbf{A0 \longrightarrow A \longrightarrow B \longrightarrow E \longrightarrow F \longrightarrow C \longrightarrow D \longrightarrow E2 \longrightarrow F2 \longrightarrow Stage\ 23}$$

- **A0** — Repository & Environment Reproducibility Audit `[PASS / CLOSED]`
- **A** — Backend In-Depth Integration Audit `[PASS / CLOSED]`
- **B** — Backend Remediation + Regression `[ACCEPTED / CLOSED (with documented evidence gaps)]`
- **E** — Full-Stack Integration / E2E Audit `[PASS WITH GAPS]`
- **F** — Security + Cryptographic Regression Audit `[PASS WITH GAPS / CLOSED]`
- **C** — Frontend Product Architecture `[STATUS CONFLICT: ACTIVE NEXT STEP PENDING AUTHORIZATION vs REPORTED CLOSED]`
- **D** — Frontend Implementation + Hardening `[STATUS CONFLICT: ON HOLD vs REPORTED CLOSED WITH GAPS]`
- **E2** — Final Full-Stack E2E Re-audit `[STATUS CONFLICT: ON HOLD vs REPORTED CLOSED WITH GAPS]`
- **F2** — Final Security Regression `[STATUS CONFLICT: ON HOLD vs REPORTED CLOSED WITH GAPS]`
- **Stage 23** — Production Deployment and Ingress Validation `[STRICTLY BLOCKED / ON HOLD]`

*Rule: Do not reorder, rename, skip, or substitute stages. The status conflict between on-disk governance records (Stage C active) and earlier conversational reports (Stages D/E2/F2 closed with gaps) is unadjudicated. Flag for project-owner decision before proceeding.*

---

## 3. Fresh AI Session Onboarding Sequence

Any new AI session or engineer resuming this project must follow this exact sequence:

1. **Read Canonical Context**: Read [`PROJECT_CONTEXT.md`](../PROJECT_CONTEXT.md) and this file (`.context/canonical_context.md`) to establish project boundaries, constraints, and locked roadmap.
2. **Inspect Repository Working Tree**: Run `git status`. Observe all pre-existing modified, added, and untracked files (e.g. migrations `012`, `013`, `014`, Golden Path scripts, `archive/`, `master_archive/`). **Never discard, clean, or reset them.**
3. **Check Operational Constraints**: Confirm Gate 5R is **STRICTLY BLOCKED** and **SRMIST Wi-Fi / Local-Only mode** is in effect. No live database connections or migrations.
4. **Read Session Handoff (`.context/handoff.md`)**: Determine the exact active milestone, status conflict adjudication requirement, and immediately permitted next action.
5. **Read Authoritative State (`.context/project_state.md`)**: Review the exact status of completed stages, accepted findings (`AUD-A-001..011`), open Stage E defects (`INT-DEF-001..004`), and documented evidence gaps.
6. **Read Execution Map (`.context/execution_map.md`)**: Learn the verified local test commands and their mandatory directory contexts (e.g. running from `backend/` with `--import-mode=importlib`).
7. **Enforce Safety Rules (`.agents/rules/` & `AGENTS.md`)**: Execute only safe, locally available, read-only or authorized documentation tasks.

---

## 4. Current Milestone & Status Summary

- **Current Working Branch**: `chore/final-project-cleanup`
- **Active Operational Boundary**: **LOCAL-ONLY (SRMIST Wi-Fi Constraint; Gate 5R Strictly Blocked)**. Live Supabase/PostgreSQL access is unavailable. All live operational activity is prohibited.
- **Stage Conflict Pending Adjudication**:
  - *On-Disk Governance*: Stage F closed; **Stage C (Frontend Product Architecture)** is the active next step pending authorization.
  - *Conversational Reports*: Stages D, E2, F2 reported closed with gaps based on prototype code in `frontend/`.
- **Immediate Next Authorized Action**: Stand by for project-owner adjudication on the status conflict.

---

## 5. Critical Safety and Security Constraints

- **Preserve Working Tree**: Never use `git reset --hard` or `git clean -fd`. Do not delete untracked migrations (`012`, `013`, `014`), root archives (`archive/`, `master_archive/`), or Golden Path artifacts.
- **Two-Folder Archive Policy**: The repository root must contain exactly `archive/` (reusable assets) and `master_archive/` (historical, excluded from ZIP). Never recreate `archives/` or `backend/archives/`.
- **Fail Closed Cryptography**: Only an explicit Boolean `true` from the pinned `BarretenbergVerifier.verifyProof()` is cryptographic acceptance. `STRUCTURAL_REJECTION`, `RUNTIME_FAILURE`, and `ENVIRONMENT_FAILURE` must remain distinct from `CRYPTOGRAPHIC_FALSE`.
- **Authorization & Metadata Isolation**: Cryptographic validity does not bypass authorization, tenant scoping, or snapshot lifecycle status checks.
- **Separation of Duties**: Vulnerability ingestion is restricted to `trusted_importer`; snapshot approval and freezing are restricted to `admin`.
- **Secrets Protection**: Never print, inspect, or copy `.env` contents, database credentials, JWT secrets, or private keys into context documents, logs, or chat output.
- **External ZIP Distribution Caution**: `dist/zkp-sbom-source.zip` was packaged using filename-only filtering; it is **not verified for external distribution** until a content-level secret audit is completed.

---

## 6. Authoritative Context Directory Structure

- [`PROJECT_CONTEXT.md`](../PROJECT_CONTEXT.md) — Comprehensive canonical root context document.
- [`handoff.md`](handoff.md) — Immediate next objective, active milestone, and continuity notes.
- [`project_state.md`](project_state.md) — Authoritative audit status, findings registers (`AUD-A-*`, `INT-*`, `F2-*`), evidence gaps, and decision log.
- [`execution_map.md`](execution_map.md) — Verified local testing commands, cautions, and directory contexts.
- [`architecture_reference.md`](architecture_reference.md) — System architecture, tenant boundaries, cryptographic topologies, and data flows.
- [`adrs.md`](adrs.md) — Architectural Decision Records for core crypto, lifecycle, and concurrency choices.

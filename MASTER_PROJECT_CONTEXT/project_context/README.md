# Authoritative Project Context Hub

**Project:** Zero-Knowledge Verification for Software Supply Chain Security  
**Workspace Root:** `E:\Main Project`  
**Authoritative Documentation Root:** `E:\Main Project\project_context/`  
**Effective Date:** 14 October 2026  
**Status:** Canonical Source of Truth  

---

## 1. Purpose of This Directory

This directory (`project_context/`) is the **single authoritative source of truth** for all project architecture, security invariants, operational rules, implementation state, and the agreed six-stage development roadmap.

It consolidates and supersedes all prior fragmented notes, resolving past status ambiguities into one cohesive documentation hierarchy. Any fresh AI coding assistant, IDE agent, or engineer must start here to understand the repository's boundaries and state.

---

## 2. Onboarding: Where to Start

If you are an AI session or developer resuming work on this repository:

1. **Step 1 — Understand the Mission & Constraints**: Read [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) and [`REPOSITORY_SAFETY.md`](REPOSITORY_SAFETY.md).
   - *Key Constraints*: Operating in **LOCAL-ONLY** mode. PostgreSQL 16 on `127.0.0.1:5433` (`ZKP_SBOM_LOCAL_DEV`) is the preferred development and testing candidate (subject to explicit authorization before DB operations; present state unverified by this task). PostgreSQL 17 on `127.0.0.1:5432` (`ZKP_SBOM`) is the intended final main-project database, currently protected/frozen during development and validation; will only be considered for operational use after validation, recovery planning, and separate explicit authorization. Strictly no mutations or migrations pre-D1. Never edit or print root `.env`. Never run `git reset --hard` or `git clean -fd`.
2. **Step 2 — Inspect Verified Current State**: Read [`PROJECT_STATE.md`](PROJECT_STATE.md).
   - Review verified test results (861 backend passes, 0 skips; 39 frontend passes), database revisions (001–014), and findings registers.
3. **Step 3 — Inspect the Next Authorized Task**: Read [`HANDOFF.md`](HANDOFF.md) and [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md).
   - All tasks must map strictly to the agreed six-stage sequence and module roadmap.
4. **Step 4 — Review Applicable Rule Sets**:
   - For backend/auth/tenant security: Read [`SECURITY_RULES.md`](SECURITY_RULES.md).
   - For circuits/proofs/crypto verifiers: Read [`CRYPTOGRAPHY_RULES.md`](CRYPTOGRAPHY_RULES.md).
   - For running tests and tools: Read [`EXECUTION_MAP.md`](EXECUTION_MAP.md).

---

## 3. Directory Manifest & Document Guide

| Document | Primary Focus & Purpose |
| :--- | :--- |
| [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md) | **The Locked Six-Stage Roadmap** (`Stage A` through `Stage F`). Detailed subtasks, deliverables, acceptance criteria, tests, and completion conditions. |
| [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | **Core Mission & System Overview**. Problem statement, zero-knowledge concepts, technology stack, system roles, and operational boundaries. |
| [`PROJECT_STATE.md`](PROJECT_STATE.md) | **Verified Current State**. Empirical test accounting, database revision, findings registers (`AUD-A-*`, `INT-DEF-*`, `F2-*`), and active work status. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | **System Architecture & Data Flows**. Microservices topology, database models, circuit decomposition (32-component chunks), and certificate lifecycle. |
| [`STUDENT_RUNBOOK.md`](STUDENT_RUNBOOK.md) | **Student Runbook & Troubleshooting Manual**. Step-by-step workstation setup, service runbooks, 7-phase usage walkthrough, non-destructive troubleshooting matrix, and recovery guide. |
| [`DEMONSTRATIONS_AND_VIVA.md`](DEMONSTRATIONS_AND_VIVA.md) | **Demonstration Scenarios & Viva Defense Guide**. 3 scripted demonstration workflows (Compliant Vendor, Log4Shell CVSS 10.0, Malicious Verifier), 10-slide presentation deck, and 20-question examiner FAQ. |
| [`VIVA_PRESENTATION_SLIDES.md`](VIVA_PRESENTATION_SLIDES.md) | **Viva Defense Presentation Deck Artifact**. Standalone 10-slide visual presentation deck with ASCII architectural diagrams, on-slide cards, verbatim speaker presentation scripts, and examiner defense touchpoints. |
| [`SECURITY_RULES.md`](SECURITY_RULES.md) | **Application Security Invariants**. RBAC roles (`vendor`, `auditor`, `admin`, `trusted_importer`), tenant scoping, input validation, and log redaction. |
| [`CRYPTOGRAPHY_RULES.md`](CRYPTOGRAPHY_RULES.md) | **Cryptographic Invariants & Verification**. BN254 field, Poseidon sponge ($t=2, t=3$), SMT depth 256, legacy ACIR layout, and fail-closed Boolean verifier. |
| [`REPOSITORY_SAFETY.md`](REPOSITORY_SAFETY.md) | **Safety & Preservation Rules**. Working tree preservation, protected DB isolation, root `.env` protection, zero secret persistence, and git diff inspection. |
| [`EXECUTION_MAP.md`](EXECUTION_MAP.md) | **Command & Testing Reference**. Verified test commands, mandatory directory contexts (`backend/` vs root), and blocked operational actions (Gate 5R). |
| [`DECISIONS.md`](DECISIONS.md) | **Architectural Decision Records (ADRs)**. Documented rationale for core crypto, circuit layout, multi-tenant DB design, and symmetric certificate authority. |
| [`HANDOFF.md`](HANDOFF.md) | **Active Session Handoff**. Next authorized objective, immediate prerequisites, recent verified evidence, and instructions for new sessions. |
| [`CHANGELOG.md`](CHANGELOG.md) | **Context Consolidation Log**. Record of consolidation changes, source-to-destination mappings, and document version history. |
| [`archive/`](archive/) | **Historical Archive**. Immutable copies of superseded context files preserved for auditability and zero data loss. |

---

## 4. The Locked Six-Stage Sequence & Modular Roadmap

Work proceeds strictly according to the locked roadmap:

$$\mathbf{Stage\ A \longrightarrow Stage\ B \longrightarrow Stage\ C \longrightarrow Stage\ D \longrightarrow Stage\ E \longrightarrow Stage\ F}$$

- **Stage A** — Re-entry Audit and Project Baseline `[OPERATIONALLY CLOSED / FULL PASS]`
- **Stage B** — Backend, Database, and Security Fixes `[OPERATIONALLY CLOSED / FULL PASS]`
- **Stage C** — Product Experience (Modules C0–C9) `[REPORTED COMPLETE — PENDING OVERALL OWNER ACCEPTANCE]`
- **Stage D** — Backend, Database, and System Integration (Modules D0–D9) `[NOT STARTED — D0 AUDIT REPORTED COMPLETE, D1 UNAUTHORIZED]`
- **Stage E** — Security and Cryptographic Validation `[PENDING]`
- **Stage F** — Final Testing, Documentation, and Submission `[PENDING]`

**Interleaved Execution Sequence**:
`C0–C9 (Reported Complete) → D0 (Read-Only Audit Reported Complete, Pending Owner Review) → D1–D3 (Unauthorized) → D4–D5 → D6–D7 → D8–D9`

Do not reorder, skip, substitute, or invent alternative stages. Refer to [`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md) for task-by-task specifications.

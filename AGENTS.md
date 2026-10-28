# Agent Instructions & Operational Rules

**Project:** Zero-Knowledge Verification for Software Supply Chain Security
**Workspace Root:** `E:\Main Project`
**Authoritative Documentation Root:** [`MASTER_PROJECT_CONTEXT/README.md`](MASTER_PROJECT_CONTEXT/README.md)
**Roadmap:** Official Locked Roadmap V3
**Roadmap Effective Date:** 25 October 2026
**Operating Mode:** LOCAL-ONLY. No remote operations, deployments, or external environment access without explicit authorization.

---

## 1. Single Authoritative Context Root

All project documentation, architecture references, security invariants, operational rules, and the locked roadmap have been consolidated into:

$$\mathbf{E:\backslash Main\ Project\backslash MASTER\_PROJECT\_CONTEXT\backslash}$$

Before proposing or executing any implementation, every fresh AI coding session or engineer must read:
1. [`MASTER_PROJECT_CONTEXT/README.md`](MASTER_PROJECT_CONTEXT/README.md) — Directory index and onboarding guide.
2. [`MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md`](MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md) — Authoritative locked six-stage roadmap.
3. [`MASTER_PROJECT_CONTEXT/project_context/PROJECT_STATE.md`](MASTER_PROJECT_CONTEXT/project_context/PROJECT_STATE.md) — Verified repository state and findings registers.
4. [`MASTER_PROJECT_CONTEXT/project_context/REPOSITORY_SAFETY.md`](MASTER_PROJECT_CONTEXT/project_context/REPOSITORY_SAFETY.md) — Safety and preservation rules.
5. [`MASTER_PROJECT_CONTEXT/project_context/SECURITY_RULES.md`](MASTER_PROJECT_CONTEXT/project_context/SECURITY_RULES.md) — Application security and RBAC invariants.
6. [`MASTER_PROJECT_CONTEXT/project_context/CRYPTOGRAPHY_RULES.md`](MASTER_PROJECT_CONTEXT/project_context/CRYPTOGRAPHY_RULES.md) — Cryptographic invariants and verifier rules.

To bootstrap your context and inspect the verified local environment, run:
`.\bootstrap.ps1`

---

## 2. The Single Locked Six-Stage Roadmap & Module Structure

All implementation tasks follow strictly the locked six-stage sequence (effective 14 October 2026), structured into granular dependency-aware modules:

$$\mathbf{Stage\ A \longrightarrow Stage\ B \longrightarrow Stage\ C \longrightarrow Stage\ D \longrightarrow Stage\ E \longrightarrow Stage\ F}$$

- **Stage A — Re-entry Audit and Project Baseline** `[OPERATIONALLY CLOSED / FULL PASS]` (Baseline documented; native `bb.exe` launcher source preserved in `scripts/bb_launcher.c` and build automated via `scripts/setup_crypto_runtime.ps1`; 24/24 cryptographic tests passing with 0 skips).
- **Stage B — Backend, Database, and Security Fixes** `[OPERATIONALLY CLOSED / FULL PASS]` (RBAC, multi-tenant isolation, DB uniqueness constraints, REST detail routes, 10-worker concurrency probe passed on port 5433, 861/861 backend tests passing).
- **Stage C — Product Experience** `[REPORTED COMPLETE — PENDING OVERALL OWNER ACCEPTANCE]` (Modules C0–C9 reported complete by Antigravity; C6.1 running-state corrected; frontend quality gates reported passing with 80 tests, 0 skips, TS/ESLint clean, 17 Next.js routes).
  - `C0`: Scope, architecture and workflow contract `[COMPLETE]`
  - `C1`: Design system and application shell `[COMPLETE]`
  - `C2`: Public homepage and product presentation `[COMPLETE]`
  - `C3`: Authentication and onboarding experience `[COMPLETE]`
  - `C4`: Workspace, dashboard and navigation `[COMPLETE]`
  - `C5`: Application and SBOM management `[COMPLETE]`
  - `C6`: Proof-generation workflow `[COMPLETE - C6.1 running-state corrected]`
  - `C7`: Buyer verification and certificates `[COMPLETE]`
  - `C8`: Administration, profiles and role-specific workspaces `[COMPLETE]`
  - `C9`: Frontend integration and acceptance `[COMPLETE]`
- **Stage D — Backend, Database and System Integration** `[OPERATIONALLY CLOSED / FORMALLY ACCEPTED BY OWNER WITH DISCLOSED LIMITATIONS]` (Alembic migration 016 applied to PG16 container port 5433; 1,345 backend unit/integration tests passing with 0 skips; D7 snapshot TTL formally accepted by owner with rev 016; D9 Category A live non-proving acceptance PASS verified; D5 full 256-segment live proving deferred as UNVERIFIED).
  - `D0`: API, schema and dependency audit `[COMPLETE & REVIEWED]`
  - `D1`: Database and migration design `[OPERATIONALLY CLOSED / FULL PASS — rev 016 applied]`
  - `D2`: Authentication, onboarding and profiles `[OPERATIONALLY CLOSED / FULL PASS]`
  - `D3`: RBAC and administrative user management `[OPERATIONALLY CLOSED / FULL PASS]`
  - `D4`: Application and SBOM API integration `[OPERATIONALLY CLOSED / FULL PASS]`
  - `D5`: Proof generation and job lifecycle `[OPERATIONALLY CLOSED / PASS (BOUNDED 1-SEGMENT) / UNVERIFIED (256-SEGMENT)]`
  - `D6`: Independent verification and certificate lifecycle `[OPERATIONALLY CLOSED / FULL PASS]`
  - `D7`: Vulnerability intelligence, observability and snapshot TTL `[OPERATIONALLY CLOSED / FORMALLY ACCEPTED BY OWNER WITH LIMITATIONS]`
  - `D8`: Backend security and regression validation `[OPERATIONALLY CLOSED / FULL PASS — 1,345 tests pass]`
  - `D9`: Full end-to-end acceptance `[OPERATIONALLY CLOSED / CATEGORY A PASS (LIVE NON-PROVING WORKFLOW) / CATEGORY B DEFERRED]`
- **Stage E — Security and Cryptographic Validation** `[OPERATIONALLY CLOSED / FULL PASS]` (270 dedicated security and cryptographic tests passed with 0 skips; E1–E7 verified; formal validation report and 20-threat security matrix published in `MASTER_PROJECT_CONTEXT/project_context/SECURITY_VALIDATION_REPORT.md`).
- **Stage F — Final Testing, Documentation, and Submission** `[OPERATIONALLY CLOSED / FULL PASS]` (Full regression suites passing; clean environment build verified; forensic cleanup audit completed; viva demo environment seeded).
- **Stage G — Full-Stack Security Hardening, Role Consolidation & Frontend Simplification** `[OPERATIONALLY CLOSED / FULL PASS]` (Official Locked Roadmap V3: Stage G0–G6 security hardening, role consolidation to vendor/buyer/admin, backend API hardening, frontend simplification, and cross-role regression closed with `G6 PASS` on 2026-10-25 03:48 IST; 348 automated tests passed with 0 skips and 0 failures; `scratch/stage-g/v3_g6/20261025_034800/`).
  - `G0`: Baseline and preservation `[COMPLETE]`
  - `G1`: Security audit and finding register `[COMPLETE]`
  - `G2`: Consolidate visible roles to vendor, buyer and admin `[COMPLETE]`
  - `G3`: Backend/API hardening `[COMPLETE]`
  - `G4`: Frontend simplification and integration `[COMPLETE]`
  - `G5`: Cross-role regression `[COMPLETE]`
  - `G6`: Independent closure `[COMPLETE - G6 PASS]`
- **Follow-On: Stage D Reassessment** `[OPERATIONALLY CLOSED / FULL PASS]` (Reassessment executed 2026-10-25 and audited 2026-10-26 02:45 IST; D9 Category A live non-proving re-validation pass; 256/256 segment proofs verified in 531.826s from proof archive `68c06b8e-c7b8-4402-b98e-f6c1f2236cd9.zip` with 0 proof regeneration; Certificate `81d1a4f0-...` minted; verdict `STAGE D FINAL STATUS: PASS`; `scratch/stage-d/final_evidence_audit_20261026_0236/`).

### Active Execution Sequence
Stages A through F, Stage G (G0–G6), and the Follow-On Stage D Reassessment are formally closed and preserved with complete empirical evidence. The active milestone is **Final Submission Preparation, Context Synchronization & Packaging Verification**. Neither Stage G nor Stage D Reassessment should be rerun without explicit evidence-based justification.

*Rule: Do not reorder, rename, skip, or substitute stages or modules. Map every proposed task to the authoritative roadmap in [`MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md`](MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md).*

---

## 3. Product & Architecture Invariants

1. **Product Objective**: Privacy-preserving software supply-chain verification. A vendor manages SBOMs and generates cryptographic evidence; a buyer independently verifies proofs and public commitments ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$). A valid proof establishes compliance against the specific policy and vulnerability database—never claim it proves the application is free from all vulnerabilities.
2. **Planned 5-Role Model**:
   - `vendor`: Manages authorized applications and private SBOMs; initiates proof generation.
   - `buyer`: Receives evidence and independently verifies proofs and authorized certificates.
   - `auditor`: Accesses authorized verification evidence and audit information in a read-oriented workflow.
   - `admin`: Manages authorized users, policies, vulnerability snapshots, and certificate lifecycle.
   - `trusted_importer`: Restricted vulnerability-ingestion role enforcing separation of duties.
   *Note: In current implementation, `role` is stored on `users` with default `auditor`, with `vendor`, `admin`, and `trusted_importer` checked in code. `buyer` and account status lifecycle are operational in Stage D/G.*
3. **Frontend Design Direction**: Professional, light-first product design inspired by modern SBOM-management information architecture (cool-grey/white surfaces, slate typography, restrained blue/teal accents; optional restrained dark theme). Displays genuine backend metrics—never invent placeholder stats or verification outcomes.
4. **Cryptographic Foundation Frozen**: Noir 0.32.0 ACIR circuits, Barretenberg 0.46.1 verifier contracts, UltraPlonk proof formats (2144 bytes), Poseidon sponge parameters ($t=2, t=3$), and public input bindings are frozen for this roadmap. No modifications without prior authorization.
5. **Authentication & In-Memory Privacy**: Bearer tokens are held strictly in memory (`authTransport.ts`) and cleared on logout or page refresh. Reauthentication is the intentional trade-off for zero persistent browser storage leaks. Use standard browser autocomplete semantics without claiming control over browser password managers.
6. **Vulnerability Intelligence**: Preserve existing CVE, CVSS, NVD-related ingestion, snapshot, and lifecycle functionality (`pending`, `approved`, `frozen`, `revoked`). Do not build a replacement vulnerability scanner.
7. **Auditability**: In scope. Preserve structured logs and diagnostics; assess durable audit trail records in D7 without assuming a dedicated audit table exists. Never log credentials, secrets, or raw SBOM component contents. Dedicated audit analytics dashboard is deferred.
8. **Excluded Scope**: Payment gateways, subscriptions, external identity providers, email verification infrastructure, complex organization hierarchies, replacement vulnerability scanners, new cryptographic circuits, and new proof formats.

---

## 4. Mandatory Operational & Safety Boundaries

1. **Gate 5R Is Strictly Blocked**: No live database mutations on remote/staging environments, no staging inspection or deployment, no container restarts, no production exports, and no secret rotations.
2. **Local-Only Operating Mode**: No remote operations, deployments, or external environment access without explicit authorization. Treat current work mode as **LOCAL-ONLY**. Never attempt remote database connections, remote migrations, or external deployments.
3. **Database Strategy & Environment Policy**:
   - **Supabase PostgreSQL 17 — Authoritative Presentation Target**: Supabase PostgreSQL 17 on `127.0.0.1:5432` (`aws-0-ap-southeast-2.pooler.supabase.com`), Alembic rev `016`. Dedicated target for live presentation and demonstration workflows. Seeded presentation fixtures active. Protected / read-only during non-presentation tasks.
   - **Docker PostgreSQL 17 — Automated Regression Target**: Docker PostgreSQL 17 on `127.0.0.1:5435` (`zkp_sbom_g2_integration`), Alembic rev `016`. Dedicated target for automated regression and security tests (155/155 passed). Preserves Supabase 5432 from mutation.
   - **PostgreSQL 16 — Excluded**: Docker PostgreSQL 16 on `127.0.0.1:5433` is excluded from Stage G and presentation workflows.
   - **Zero-Loss Data Safeguards**: Never drop tables, truncate data, or delete baseline accounts. Preserve migration integrity (linear chain 001 through 016). Never run destructive database operations without verified backup and rollback procedures.
4. **Secret Protection & Root `.env`**: Never print, copy, or expose `.env`, tokens, private keys, or credentials into reports, logs, or context files. The root `.env` must never be modified or used for local development credentials.
5. **Preserve Repository & Working Tree**: Inspect `git status` before and after changes. Never run `git reset --hard` or `git clean -fd`. Untracked migrations `012`, `013`, `014`, `015`, `016`, `archive/`, `master_archive/`, and `MASTER_PROJECT_CONTEXT/` must be preserved.
6. **Narrowly Scoped Work Units**: Use focused prompts and small implementation units. Avoid large batch refactoring.
7. **Empirical Evidence Standards**:
   - Mocks are not live proof (`AUD-A-003`).
   - Skipped tests are not passes (`F2-C-001`).
   - HTTP 200 responses do not prove zero-knowledge cryptographic validity.
   - Report exact commands, test counts, skips, and environmental limitations without double-counting.

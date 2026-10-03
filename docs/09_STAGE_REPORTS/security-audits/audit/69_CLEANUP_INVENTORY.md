# 69 — Comprehensive Repository Cleanup Inventory

## Executive Summary
This document establishes the authoritative pre-cleanup and post-cleanup inventory for the **Zero-Knowledge SBOM Vulnerability Verification Platform**. The objective of this inventory is to classify all repository contents, distinguish production code, test suites, cryptographic assets, and security audit evidence from ephemeral development residue, and provide strict forensic accounting for workspace hygiene.

---

## 1. Classification Methodology

All repository files and directories were inspected and categorized into five formal classes:

| Class | Designation | Retention Policy | Description |
| :--- | :--- | :--- | :--- |
| **A** | **MUST RETAIN** | Mandatory | Core application source, microservices, schemas, models, migrations, test suites, documentation, and configuration. |
| **B** | **SAFE TO REMOVE** | Purged | Ephemeral build caches, Python bytecode, test artifacts, unreferenced installers, redundant archives, and obsolete upstream clones. |
| **C** | **REQUIRES REFERENCE CHECK** | Conditional | Files requiring cross-referencing across all codebase, scripts, Dockerfiles, and documentation before any action. |
| **D** | **CRYPTOGRAPHICALLY SENSITIVE** | Mandatory Retain | Compiled circuit JSON artifacts, verification keys, proving inputs, and security audit proof evidence. |
| **E** | **UNKNOWN** | Retain by Default | Unclassified items retained pending explicit developer/architect review. |

---

## 2. Directory-by-Directory Inventory and Classification

### 2.1 Root Level (`/`)
- `.dockerignore` [Class A — MUST RETAIN]: Docker build exclusion rules.
- `.env.example` [Class A — MUST RETAIN]: Canonical environment variable template.
- `.gitignore` [Class A — MUST RETAIN]: Updated with scoped rules to prevent accidental exclusion of nested `lib/` and properly ignore caches.
- `README.md` [Class A — MUST RETAIN]: Project documentation and onboarding guide.
- `docker-compose.yml` [Class A — MUST RETAIN]: Multi-service orchestration definition.
- `pyproject.toml` [Class A — MUST RETAIN]: Python project metadata and pytest configuration.
- `rustup-init.exe` (9,923,072 bytes) [Class B — SAFE TO REMOVE]: Unreferenced Windows executable installer for Rustup left in the root directory. **(Purged)**
- `pytest_results.txt` (11,687 bytes) [Class B — SAFE TO REMOVE]: Stale test output log from previous test failures. **(Purged)**
- `fix_tests.py` (438 bytes) [Class B — SAFE TO REMOVE]: 8-line scratch script used during early regex replacement. **(Archived to conversation storage & Purged)**
- `test_asgi.py` (2,787 bytes) [Class B — SAFE TO REMOVE]: Scratch experiment testing ASGI middleware in isolation. **(Archived to conversation storage & Purged)**
- `test_f008_real.py` (2,639 bytes) [Class B — SAFE TO REMOVE]: Preliminary scratch harness superseded by `backend/sbom_service/tests/test_f008_real.py`. **(Archived to conversation storage & Purged)**

### 2.2 Local Tooling (`/.bin`)
- `.bin/nargo` (44,603,960 bytes) [Class D — CRYPTOGRAPHICALLY SENSITIVE]: Linux x86_64 ELF binary for Nargo v0.32.0. Verified functional under WSL (`/mnt/e/Main Project/.bin/nargo check` successfully compiles `circuits_dev`). Matches pinned version `0.32.0` in `profile.json`. **(Retained locally; `.bin/` added to `.gitignore`)**
- `.bin/nargo.tar.gz` (12,678,115 bytes) [Class B — SAFE TO REMOVE]: Redundant tarball archive from which `.bin/nargo` was extracted. **(Purged)**

### 2.3 Backend Microservices (`/backend`)
- `backend/shared/` [Class A — MUST RETAIN]: Core libraries including `auth.py`, `database.py`, `security.py`, `app_factory.py`, and `crypto/` (`poseidon_bn254.py`, `smt.py`, `component_hash.py`, `config.py`, `profile.json`).
- `backend/shared/tests/vectors/crypto_vectors.json` [Class A / D — MUST RETAIN]: Authoritative test vector definitions for cryptographic interoperability.
- `backend/alembic/` [Class A — MUST RETAIN]: Database migration engine including `001_initial_schema.py` and `002_add_rbac_ownership_columns.py`.
- `backend/policy_service/` [Class A — MUST RETAIN]: Policy management microservice source, routes, schemas, models, and tests.
- `backend/sbom_service/` [Class A — MUST RETAIN]: SBOM intake, canonicalization, validation, parser, identity, and test suites.
- `backend/verification_service/` [Class A — MUST RETAIN]: Proof verification service, verifier engine, schemas, repository, and tests.
- `backend/vulnerability_service/` [Class A — MUST RETAIN]: Vulnerability DB service, CVSS computation, models, and ingestion tests.
- `backend/zkp_service/` [Class A — MUST RETAIN]: Zero-knowledge proving service, repository, prover engine, and tests.
- `backend/**/__pycache__/` and `*.pyc` [Class B — SAFE TO REMOVE]: Compiled Python bytecode (~1.1 MB across all backend directories). **(Purged)**

### 2.4 Cryptographic Circuits (`/circuits` & `/circuits_dev`)
- `circuits/src/` & `circuits_dev/src/` [Class A — MUST RETAIN]: Noir source files (`main.nr`, `merkle.nr`, `smt.nr`).
- `circuits/Nargo.toml` & `circuits_dev/Nargo.toml` [Class A — MUST RETAIN]: Circuit package manifests.
- `circuits/target/sbom_zkp.json` (54,913,292 bytes) [Class D — CRYPTOGRAPHICALLY SENSITIVE]: Production compiled ACIR circuit. SHA-256 digest tracked in `profile.json`.
- `circuits_dev/target/sbom_zkp.json` (1,086,829 bytes) [Class D — CRYPTOGRAPHICALLY SENSITIVE]: Development compiled ACIR circuit. SHA-256 digest validated at runtime.
- `circuits_dev/target/vk` (1,719 bytes) [Class D — CRYPTOGRAPHICALLY SENSITIVE]: Verification key artifact. SHA-256 digest validated at runtime by `shared.crypto.config`.
- `circuits/Prover.toml` (144,258 bytes) [Class D — CRYPTOGRAPHICALLY SENSITIVE]: Prover input vector for full circuit verification.
- `circuits/proofs/sbom_zkp.proof` (10 bytes) [Class D — AUDIT EVIDENCE]: Placeholder proof artifact documented in Audit Reports 01, 11, 17, 19.
- `circuits_dev/test_fake.proof` (2,000 bytes) [Class D — AUDIT EVIDENCE]: Fake proof artifact documented in Audit Reports 11, 17, 19, 22.
- `circuits_dev/proofs/sbom_zkp.proof.mutated` (2,240 bytes) [Class D — AUDIT EVIDENCE]: Mutated proof artifact used in negative verification tests.
- `circuits_dev/proofs/sbom_zkp.proof.mutated2` (2,240 bytes) [Class D — AUDIT EVIDENCE]: Mutated proof artifact used in negative verification tests.

### 2.5 Frontend (`/frontend`)
- `frontend/src/` [Class A — MUST RETAIN]: Next.js 16 App Router source, pages, layout, and UI components.
- `frontend/src/lib/utils.ts` [Class A — MUST RETAIN]: UI utility library (previously shadowed by legacy `.gitignore` rule).
- `frontend/package.json` & `package-lock.json` [Class A — MUST RETAIN]: Dependency specifications and lockfile.
- `frontend/.next/` (44.94 MB) [Class B — SAFE TO REMOVE]: Transient Next.js build cache. Verified rebuilds in ~3.0s. **(Purged)**
- `frontend/node_modules/` [Class A / Dependency — RETAIN]: Installed packages required for Next.js runtime and build.

### 2.6 Scripts & Reference Materials (`/scripts`)
- `scripts/consts.nr`, `bn254.nr`, `perm.nr`, `mod.nr` [Class A — MUST RETAIN]: Reference Noir Poseidon BN254 mathematical constants and permutations.
- `scripts/extract_consts.py` [Class A — MUST RETAIN]: Generates Python constants from Noir reference files.
- `scripts/generate_crypto_vectors.py` [Class A — MUST RETAIN]: Authoritative test vector generator.
- `scripts/run_noir_compatibility_tests.py` [Class A — MUST RETAIN]: Cross-platform compatibility test harness.
- `scripts/noir_compatibility/` & `scripts/noir_experiment/` [Class A — MUST RETAIN]: Test packages for Noir interoperability.
- `scripts/noir_src/` (35.48 MB, 9,485 files) [Class B — SAFE TO REMOVE]: Full clone of upstream `noir-lang/noir` repository. All required constants were already extracted into `scripts/consts.nr`. Zero external references exist in project code or Dockerfiles. **(Purged)**

### 2.7 Documentation & Audits (`/docs`)
- `docs/security/` [Class A — MUST RETAIN]: All 68 existing security audit reports and remediation logs.
- `docs/MILESTONE_FREEZE_DAY_9.md` [Class A — MUST RETAIN]: Milestone verification record.
- `docs/CRYPTO_INTEROPERABILITY.md` [Class A — MUST RETAIN]: Noir ↔ Python interoperability specification.

---

## 3. Pre-Cleanup vs Post-Cleanup Metrics

| Metric | Pre-Cleanup Baseline | Post-Cleanup Verified | Net Difference |
| :--- | :--- | :--- | :--- |
| **Total Workspace Files** | ~49,350 files | 39,823 files | **-9,527 files** |
| **Total Workspace Size** | ~763 MB | 658.87 MB | **-104.13 MB** |
| **Tracked / Staged Files** | 146 files | 146 files | 0 (No loss) |
| **Untracked Production Files** | All preserved | All preserved | 0 (No loss) |
| **Backend Tests Passing** | 493 / 493 | 493 / 493 | 0 regressions |
| **Frontend Build Status** | Passing (4 pages) | Passing (4 pages) | 0 regressions |

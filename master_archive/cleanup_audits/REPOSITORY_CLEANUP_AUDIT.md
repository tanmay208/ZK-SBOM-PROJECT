# Comprehensive Repository Cleanup Audit & Zero-Loss Master Archive Manifest

**Project:** Zero-Knowledge Verification for Software Supply Chain Security  
**Workspace Root:** [E:\Main Project](file:///E:/Main%20Project)  
**Audit Date:** 23 October 2026  
**Auditor:** AI Agent Pair-Programmer (Antigravity)  
**Safety Stance:** **PRESERVE FUNCTIONALITY AND EVIDENCE FIRST; REDUCE CLUTTER SECOND**  
**Core Policy:** Zero loss of cryptographic evidence, baseline user accounts, database state, release packages, or reproducibility assets.

---

## 1. Executive Summary & Audit Baseline (Phase 1)

A forensic repository cleanup and archive audit was executed to transform the workspace into a clean, well-structured, reproducible environment while ensuring zero disruption to live operations, tests, cryptographic verification, or viva demonstration readiness.

### 1.1 Repository Baseline Coordinates
- **Repository Root:** `E:\Main Project`
- **Current Git Branch:** `chore/final-project-cleanup`
- **HEAD Commit:** `0881f9ecee25618ae7d9420313f17cf1f3d68672`
- **Active Operational Database:** PostgreSQL 16.8 on `127.0.0.1:5433` (`ZKP_SBOM_LOCAL_DEV`) at Alembic revision `016_add_snapshot_ttl_expires_at`
- **Protected Database Instances:** PostgreSQL 17 on `127.0.0.1:5432` (`ZKP_SBOM`) and isolated container on port `5434` (100% untouched)
- **Baseline Users:** Exactly 8 accounts verified intact and active with valid role separation (Admin, Vendor, Trusted Importer, 5 Auditors)
- **Total Audited Archive Assets:** 399 items cataloged in [`master_archive/cleanup_audits/ARCHIVE_CONTENTS_MANIFEST.json`](file:///E:/Main%20Project/master_archive/cleanup_audits/ARCHIVE_CONTENTS_MANIFEST.json)

---

## 2. Deep Audit of `archive/` and `master_archive/` (Phase 2)

Each item was inspected deeply by content, checksum, and dependency references rather than judging by filename alone.

### 2.1 The Critical Distinction: `archive/` vs `master_archive/`

| Metric / Attribute | `archive/` (Active Operational Archive) | `master_archive/` (Historical Cold Storage) |
|:---|:---|:---|
| **Primary Location** | `E:\Main Project\archive\` | `E:\Main Project\master_archive\` |
| **File Count** | 264 files (2.67 MB) | 114 files (300.7 MB) |
| **Source ZIP Status** | **MANDATORY INCLUSION** (Verified by packaging test) | **STRICTLY EXCLUDED** (Verified by packaging test) |
| **Local Disk Requirement** | Required for local verification & packaging | Required on local disk for reproducibility audit |
| **Contents** | 3 completed ProofJob zip bundles + 256 chunk segment proofs + 3 VKs (`segment_init_32.vk`, `segment_mid_32.vk`, `segment_final_32.vk`) + manifest + profile | Historical docs, obsolete monolithic circuits, Stage 21 concurrent worker circuit copies, historical logs, scratch scripts |
| **Classification** | **ACTIVE REQUIRED / REPRODUCIBILITY EVIDENCE** | **HISTORICAL EVIDENCE / SUPERSEDED** |
| **Action** | **RETAINED IN FULL IN `archive/`** | **RETAINED IN FULL IN `master_archive/`** |

### 2.2 Detailed Asset Audit Register

| Directory / File | Size | Hash / Checksum | Classification | Rationale & Reference Findings |
|:---|:---:|:---:|:---:|:---|
| **`archive/proofs/0859e5a5-b449-4ac9-93ad-1f0bb66ed882.zip`** | 636 KB | `c21d00c439...` | **REPRODUCIBILITY EVIDENCE** | Historical 32-chunk ProofJob proof archive bundle. Verified by `scripts/verify_archive.py`. |
| **`archive/proofs/340235b8-71d6-4d6b-84de-284e72a7fb18.zip`** | 647 KB | `4ecddbc9f7...` | **REPRODUCIBILITY EVIDENCE** | Historical 32-chunk ProofJob proof archive bundle. Verified by `scripts/verify_archive.py`. |
| **`archive/proofs/e54521ab-f312-43ab-b442-e2eabca0f260.zip`** | 638 KB | `4b08703ef0...` | **REPRODUCIBILITY EVIDENCE** | Historical 32-chunk ProofJob proof archive bundle. Verified by `scripts/verify_archive.py`. |
| **`archive/proofs/temp/` (256 segment proofs)** | ~580 KB | Various | **REPRODUCIBILITY EVIDENCE** | Uncompressed individual segment UltraPlonk proofs (chunk 0..31, segment 0..7). Referenced by `scripts/project_context.py`. |
| **`archive/proofs/temp/*.vk` (3 keys)** | 5.1 KB | `820a2ac24f...` etc. | **ACTIVE REQUIRED** | Verification keys for `segment_init_32`, `segment_mid_32`, `segment_final_32`. Required by Barretenberg verifier. |
| **`master_archive/obsolete_circuits/segment_mid_32_1` .. `_6`** | 180 MB | `c45a306d8f...` | **HISTORICAL EVIDENCE (DUPLICATE)** | Six concurrent worker copies evaluated in Stage 21 resource saturation testing. Byte-identical to `segment_mid_32`. Retained as documented Stage 21 evaluation evidence. |
| **`master_archive/obsolete_circuits/circuits` & `circuits_dev`** | ~40 MB | Various | **SUPERSEDED** | Pre-segmentation monolithic Noir circuits superseded by 3-segment ACIR circuit topology. |
| **`.cache/backups/backup_zkp_sbom_local_dev_pre_016_*.sql`** | 37.7 KB | `3652f44778...` | **RECOVERY / BACKUP** | Database dump of PostgreSQL 16 `ZKP_SBOM_LOCAL_DEV` prior to revision 016 migration. Critical recovery point. |
| **`.cache/d5_manifests/manifest_d5_live_256_acceptance_20261022.json`** | 520 B | `3ba21e0922...` | **HISTORICAL EVIDENCE** | Record of Stage D5 live 1-segment execution and host RAM safety floor watchdog containment. |
| **`.cache/demo_manifests/manifest_d9_run_20261023_034148_34d279f0.json`** | 1.17 KB | `4d2e1c9448...` | **RECOVERY / BACKUP** | Durable manifest for tonight's completed D9 live non-proving acceptance run. Contains exact IDs for manual rollback. |
| **`dist/zkp-sbom-source.zip`** | 19.8 MB | `3CF91E822F...` | **ACTIVE REQUIRED** | Authoritative accepted source package with all 16 migrations. Bound to D7 owner acceptance record. |
| **`dist/zkp-sbom-source.zip.bak_rev015`** | 19.7 MB | `D222F3C869...` | **RECOVERY / BACKUP** | Pre-016 release package backup. |

---

## 3. Canonical Context Structure Created (Phase 3)

Created the unified canonical documentation structure at [MASTER_PROJECT_CONTEXT/](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT) with three distinct functional tiers:

```text
MASTER_PROJECT_CONTEXT/
├── README.md                          <-- Canonical context index and authority rules
├── .agents/
│   └── rules/                         <-- TIER 1: Agent Behavioral & Safety Rules
│       ├── cryptography.md
│       ├── project-state.md
│       ├── repository-safety.md
│       └── security.md
├── .context/                          <-- TIER 2: Current Working Context & Handoffs
│   ├── adrs.md
│   ├── architecture_reference.md
│   ├── canonical_context.md
│   ├── execution_map.md
│   ├── handoff.md
│   ├── project_state.md
│   └── README.md
└── project_context/                   <-- TIER 3: Authoritative Technical Governance
    ├── ARCHITECTURE.md
    ├── CHANGELOG.md
    ├── CRYPTOGRAPHY_RULES.md
    ├── D7_OWNER_ACCEPTANCE_RECORD.md
    ├── DECISIONS.md
    ├── DEMONSTRATIONS_AND_VIVA.md
    ├── EXECUTION_MAP.md
    ├── HANDOFF.md
    ├── OWNER_ACCEPTANCE_REVIEW_A_B_C_E_F_20261022.md
    ├── PROJECT_CONTEXT.md
    ├── PROJECT_ROADMAP.md
    ├── PROJECT_STATE.md
    ├── README.md
    ├── REPOSITORY_SAFETY.md
    ├── SECURITY_RULES.md
    ├── SECURITY_VALIDATION_REPORT.md
    ├── STUDENT_RUNBOOK.md
    └── VIVA_PRESENTATION_SLIDES.md
```

### Compatibility Discovery Retention
To ensure no agent, script, or automated tool breaks:
- Root `.agents/rules/` preserved for Antigravity IDE auto-discovery.
- Root `AGENTS.md` preserved for top-level IDE instruction discovery.
- Root `.context/` preserved for `bootstrap.ps1`.
- Root `project_context/` preserved for existing script/document relative paths.
- Root `PROJECT_CONTEXT.md` maintained as clean pointer to `MASTER_PROJECT_CONTEXT/`.

---

## 4. Files Relocated to `master_archive/` (Phase 4 & 5)

Root clutter was safely organized into dedicated `master_archive/` directories with zero deletion of unique logic:

| Original Path | Relocated Destination Path | Size | Reason / Classification |
|:---|:---|:---:|:---|
| `container_repo.py` | `master_archive/historical_scripts/container_repo.py` | 8.7 KB | Temporary container debugging script; superseded by active repository code. |
| `continue_golden_path.py` | `master_archive/historical_scripts/continue_golden_path.py` | 2.6 KB | Early manual test script with hardcoded Docker DNS; superseded by pytest suites. |
| `execute_golden_path.py` | `master_archive/historical_scripts/execute_golden_path.py` | 4.4 KB | Early manual test script with hardcoded Docker DNS; superseded by pytest suites. |
| `compose_logs.txt` | `master_archive/logs/compose_logs.txt` | 540 KB | Historical multi-container startup diagnostic log dump; preserved for reference. |
| `verification_logs.txt` | `master_archive/logs/verification_logs.txt` | 104 KB | Historical verification execution log dump; preserved for diagnostic reference. |
| `REPOSITORY_CLEANUP_AUDIT.md` (14 Oct) | `master_archive/cleanup_audits/REPOSITORY_CLEANUP_AUDIT.20261014.md` | 19.8 KB | Preserved historical audit baseline before updating with today's master audit. |

---

## 5. Files Retained in Active Tree for Security, Cryptography, and Operations

The following essential assets were verified and strictly retained in their primary active locations:

1. **Cryptographic Toolchain & Runtime:**
   - [`scripts/bb_launcher.c`](file:///E:/Main%20Project/scripts/bb_launcher.c): Native C launcher source preserving Windows Barretenberg execution.
   - [`scripts/setup_crypto_runtime.ps1`](file:///E:/Main%20Project/scripts/setup_crypto_runtime.ps1): Automated build script for native `bb.exe`.
   - `backend/verification_service/crypto_runtime/`: Native Barretenberg binary and runtime DLLs.
   - `scripts/consts.nr`, `bn254.nr`, `perm.nr`, `mod.nr`: Noir mathematical constants and Poseidon permutation tables.
   - `segment_init_32/`, `segment_mid_32/`, `segment_final_32/`: Production 3-circuit Noir ACIR packages and target artifacts.
2. **Database Migrations & Seed Assets:**
   - `backend/alembic/versions/001` through `016`: Complete, ordered 16-migration chain.
   - `backend/alembic/baseline_users.py`: Deterministic seed script for 8 baseline accounts.
   - `backend/alembic/staging_guard.py`: Safety gate enforcing database port isolation.
3. **Packaging & Acceptance Tooling:**
   - [`scripts/package_source_zip.py`](file:///E:/Main%20Project/scripts/package_source_zip.py): Release archive builder with strict exclusion rules.
   - [`scripts/prepare_d9_demo.py`](file:///E:/Main%20Project/scripts/prepare_d9_demo.py): D9 live demo preparation, preflight, and recovery tool.
   - [`scripts/d9_cleanup_manifest.py`](file:///E:/Main%20Project/scripts/d9_cleanup_manifest.py): Incremental, durable cleanup manifest manager.
   - [`scripts/start_d9_gateway.py`](file:///E:/Main%20Project/scripts/start_d9_gateway.py): Process-isolated gateway runner for port 8080.
   - [`bootstrap.ps1`](file:///E:/Main%20Project/bootstrap.ps1): Session bootstrap and context validator.

---

## 6. Git Ignore and Tooling Integrity (Phase 6)

- `.gitignore` verified: Prohibits active `.env`, credential files (`db.txt`, `d9_credentials.json`), node build artifacts (`.next/`, `node_modules/`), Python caches (`__pycache__/`, `.pytest_cache/`), and binary outputs (`dist/`).
- Safe templates preserved: `.env.example` and `.env.local_dev.example` remain tracked and clean of credentials.
- Zero credentials or tokens committed or exposed.
- Source ZIP packaging rules verified: Excludes `master_archive/`, `.cache/`, `.venv/`, `.env`, and credentials; includes `archive/` (264 files) and all essential sources and migrations.

---

## 7. Validation Results (Phase 7)

Executed validation across all layers:

1. **Packaging Validation (`scripts/package_source_zip.py`):**
   - Result: **FULL PASS** (All 5 assertions passed; 0 private keys, 0 `.env` files, `archive/` included, `master_archive/` excluded from ZIP while remaining intact on local disk).
2. **Backend Regression Test Suite:**
   - 10 targeted test suites executed: **181 passed, 0 failed, 0 skipped**.
3. **Frontend Test Suite:**
   - 96 client/route tests executed: **96 passed, 0 failed, 0 skipped**.
4. **Application Gateway Health:**
   - `GET http://127.0.0.1:8080/api/v1/health` returned `HTTP 200 OK` (`"status": "healthy"`).
5. **Session Bootstrap Script:**
   - `.\bootstrap.ps1` executed cleanly without error.
6. **Database Integrity:**
   - PostgreSQL 16 on `127.0.0.1:5433`: Revision 016 verified; 8/8 baseline users active; 2 apps; 2 SBOMs; 1 active policy; 1 frozen snapshot; 0 fake certificates minted.
   - PostgreSQL 17 on `127.0.0.1:5432`: 100% untouched.
   - Isolated container on port `5434`: 100% untouched.

---

## 8. Final Working-Tree Status & Deliverables (Phase 8)

### 8.1 Deliverables Generated
1. [`MASTER_PROJECT_CONTEXT/README.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/README.md): Master navigation and information architecture index.
2. [`master_archive/cleanup_audits/ARCHIVE_CONTENTS_MANIFEST.json`](file:///E:/Main%20Project/master_archive/cleanup_audits/ARCHIVE_CONTENTS_MANIFEST.json): Machine-readable audit manifest classifying all 399 archive files.
3. [`REPOSITORY_CLEANUP_AUDIT.md`](file:///E:/Main%20Project/REPOSITORY_CLEANUP_AUDIT.md): This authoritative zero-loss audit report.
4. [`master_archive/cleanup_audits/REPOSITORY_CLEANUP_AUDIT.20261014.md`](file:///E:/Main%20Project/master_archive/cleanup_audits/REPOSITORY_CLEANUP_AUDIT.20261014.md): Historical audit archive.

### 8.2 Live Launch Readiness
The project is clean, organized, and primed for viva demonstration:
- **Gateway (Port 8080):** Running as background daemon, connected to PostgreSQL 16 on port 5433.
- **Frontend (Port 3000):** Launch with `cd frontend; npm run dev`.
- **Pre-Seeded Demo Data:** Compliant Payment Gateway (`certifi@2021.5.30`), Vulnerable Payment Gateway (`urllib3@1.26.5`), Strict CVSS 7.0 Policy, and Frozen Vulnerability Snapshot with SMT Merkle root and TTL.

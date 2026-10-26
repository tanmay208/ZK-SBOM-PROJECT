# Stage D7 Formal Owner Acceptance Record

**Project:** Zero-Knowledge Verification for Software Supply Chain Security  
**Workspace:** `E:\Main Project`  
**Document Location:** `project_context/D7_OWNER_ACCEPTANCE_RECORD.md`  
**Status:** `FORMALLY ACCEPTED BY OWNER`  
**Date:** 2026-10-23  
**Timezone:** UTC+05:30 (IST)

---

## 1. Deliverable Artifact Identification

- **Deliverable Path:** [`dist/zkp-sbom-source.zip`](file:///E:/Main%20Project/dist/zkp-sbom-source.zip)
- **Exact Byte Size:** `19,810,356` bytes (~18.89 MiB)
- **SHA-256 Checksum:** `3CF91E822F1A9308B8C37814649AB232FE70CCD9C53E757BC186AA9DEE80FE58`
- **Integrity Validation:** Python `zipfile.ZipFile.testzip()` returned `None` (0 CRC errors, 0 corrupted headers).
- **Packaged Migration Range:** Migrations `001_initial_schema.py` through `016_add_snapshot_ttl_expires_at.py` (all 16 migrations confirmed in order).
- **Historical Pre-Sync Backup:** [`dist/zkp-sbom-source.zip.bak_rev015`](file:///E:/Main%20Project/dist/zkp-sbom-source.zip.bak_rev015) (19,753,988 bytes, SHA-256: `D222F3C86914116E7163C84F30BAC36895C992EA26EA85D4BD68B7000B43FB6D`).

---

## 2. Scope of Stage D7 Accepted

This acceptance record covers strictly the technical scope of Module D7 (Vulnerability Intelligence & Snapshot TTL):
1. **Snapshot TTL Policy & Engine:** Seven locked architectural decisions (`D7-POL-01` through `D7-POL-07`) implemented in [`backend/vulnerability_service/app/core/snapshot_expiry.py`](file:///E:/Main%20Project/backend/vulnerability_service/app/core/snapshot_expiry.py).
   - Default TTL duration: 30 days (`2,592,000` seconds).
   - Configurable range: Strictly bounded between 1 hour (`3,600` seconds) and 365 days (`31,536,000` seconds).
   - Expiration anchoring: Calculated strictly from snapshot freeze time (`frozen_at`), never intake or approval time.
2. **Three Synchronous Enforcement Checkpoints:**
   - **Job Creation Boundary:** [`backend/zkp_service/app/repositories/zkp_repository.py`](file:///E:/Main%20Project/backend/zkp_service/app/repositories/zkp_repository.py#L68-L70) rejects expired snapshots at request intake with HTTP 400.
   - **Prover Preflight Boundary:** [`backend/zkp_service/app/services/prover_service.py`](file:///E:/Main%20Project/backend/zkp_service/app/services/prover_service.py#L172-L176) evaluates snapshot eligibility immediately before witness assembly.
   - **Authoritative Verification Boundary:** [`backend/verification_service/app/repositories/verification_repository.py`](file:///E:/Main%20Project/backend/verification_service/app/repositories/verification_repository.py#L207-L209) blocks certificate issuance if the associated snapshot has expired.
3. **Legacy Grandfathering:** Snapshots with `expires_at = NULL` evaluate as non-expired to ensure backward compatibility with historical baselines.
4. **Database Schema Migration 016:** [`backend/alembic/versions/016_add_snapshot_ttl_expires_at.py`](file:///E:/Main%20Project/backend/alembic/versions/016_add_snapshot_ttl_expires_at.py) adding nullable `expires_at` column and B-tree index `ix_vuln_snapshots_expires_at`.
5. **Source ZIP Packaging Synchronization:** Resolution of conditional finding `COND-01` via [`scripts/package_source_zip.py`](file:///E:/Main%20Project/scripts/package_source_zip.py), ensuring all 16 migrations are verified and packaged without secrets or `master_archive/` leaks.

---

## 3. Evidence Supporting Technical Closure

- **Targeted Test Suite Results (42 passed, 0 failed, 0 skipped, 0 errors):**
  - `backend/vulnerability_service/tests/test_snapshot_expiry.py`: 5 passed.
  - `backend/vulnerability_service/tests/test_d7_ttl_matrix.py`: 37 passed across all 5 verification sections (Configuration & Arithmetic, Lifecycle & Authorization, Proof-Job Concurrency, Verification & Historical Artifacts, Schema Migration compatibility).
- **Packaging Validator Output:**
  `[+] PASS: All essential application sources, migrations 001-016, and Stage E/F deliverables are present.`
  `[+] PASS: Zero private keys or active .env files included in ZIP.`
  `[+] PASS: Local master_archive/ directory remains intact and untouched on disk.`
- **Audit Register Update:** Documented under version `2.5.1` in [`project_context/CHANGELOG.md`](file:///E:/Main%20Project/project_context/CHANGELOG.md).

---

## 4. Documented Evidence Limitations

1. **Isolated Live Migration Test:** Script `scripts/verify_d7_isolated_migration.py` was executed historically on ephemeral port 5434, but was not rerun in the latest technical closure task in order to respect strict safety rules against live database mutations.
2. **Deployment Scope:** This acceptance certifies unit, matrix, and packaging correctness; it does not certify untested multi-replica clustering or cloud staging environments.
3. **Stage Boundaries:** **This acceptance does NOT certify Stage D9 (End-to-End Acceptance) or Stage D5 (256-Segment Proving) as complete.**

---

## 5. Formal Acceptance Confirmation

### Accepted Statement:
> "I accept the D7 technical closure evidence for Snapshot TTL enforcement and source ZIP packaging, identified by SHA-256 `3CF91E822F1A9308B8C37814649AB232FE70CCD9C53E757BC186AA9DEE80FE58`, subject to the documented limitations. I understand that the latest targeted tests passed, but a live database migration test was not performed in that closure task. This acceptance does not certify D9 or D5 as complete."

### Formal Acceptance Record:
- **Confirmation Received:** "I CONFIRM D7 ACCEPTANCE"
- **Status:** `FORMALLY ACCEPTED BY OWNER`
- **Approving Party:** Project owner — confirmation received in project conversation
- **Date Written:** 2026-10-23
- **Timezone:** UTC+05:30 (IST)
- **Retained Documented Limitations:**
  1. The isolated live database migration test (`scripts/verify_d7_isolated_migration.py`) was not executed in the latest closure task to respect local safety rules.
  2. Not all live deployment scenarios have been tested.
  3. This acceptance does not certify Stage D9 (End-to-End Acceptance) or Stage D5 (256-Segment Proving) as complete.

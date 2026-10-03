# Phase 9: Database and Migration Consistency Audit

## Scope
Audit of database referential integrity, Alembic migration state, schema drift, and index utilization across all bounded contexts.

## Findings

### 1. Unmigrated Ownership Columns (Schema Drift)
- **Status:** **FAIL / CRITICAL DEFECT**
- **Location:** `alembic/versions/001_initial_schema.py` vs SQLAlchemy Models
- **Details:** During a previous audit phase (Phase 3), RBAC ownership tracking was implemented by adding `user_id` and `created_by` columns to the SQLAlchemy ORM models (`Application`, `SBOMUpload`, `VerificationRequest`, `ProofJob`, `VulnerabilitySnapshot`). However, no corresponding Alembic migration was generated or executed. The physical database schema is drastically out of sync with the logical ORM models. Any attempt by the application to persist or validate authorization logic will result in a fatal `OperationalError` (Unknown column).

### 2. Missing Inter-Schema Referential Integrity
- **Status:** **FAIL / HIGH DEFECT**
- **Location:** `alembic/versions/001_initial_schema.py`
- **Details:** The initial database migration script deliberately drops `FOREIGN KEY` constraints when relationships span across logical schema boundaries. Specifically:
  - `zkp.proof_jobs` defines `sbom_upload_id`, `snapshot_id`, and `policy_id` as standard `UNIQUEIDENTIFIER` columns without any foreign key constraints.
  - `verification.verification_certificates` lacks a foreign key constraint linking back to `verification_request_id`.
  - `vulnerability.scan_results` lacks a foreign key constraint linking back to `sbom.sbom_uploads.id`.
- **Impact:** This architectural decision completely breaks referential integrity. If an upstream artifact (like an `SBOMUpload` or `VulnerabilitySnapshot`) is deleted, its downstream artifacts (like `ProofJob` or `scan_results`) are permanently orphaned. When the prover service attempts to fetch the upstream models for an orphaned job, it fails abruptly.

### 3. Proper UUID Definitions
- **Status:** **PASS**
- **Location:** SQLAlchemy Models
- **Details:** The backend correctly uses SQL Server's native `UNIQUEIDENTIFIER` for all identifier columns, mapped seamlessly via SQLAlchemy's `mssql.UNIQUEIDENTIFIER`.

## Required Fixes
- **Alembic Alignment:** Generate a new Alembic migration script (`002_add_rbac_ownership_columns.py`) to formally add `user_id` and `created_by` columns to all requisite tables.
- **Foreign Key Restoration:** Generate a migration script to explicitly define foreign key constraints for all cross-schema relations (`proof_jobs`, `verification_certificates`, `scan_results`), enforcing `ON DELETE CASCADE` where appropriate to prevent data orphans.

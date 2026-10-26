# Staging Environmental Readiness Guide (Review-Only)

**Document ID:** `DOC-OPS-STAGING-001`  
**Classification:** Operational / Review-Only  
**Status:** Pre-Inspection Planning & Template Guide (Non-Executable)

---

## 1. Objective and Safety Scope

This document provides secret-free operational templates, query privilege mappings, and an administrative SQL proposal for a future, explicitly authorized read-only inspection of the staging PostgreSQL database.

### Strict Safety Boundaries
- **No Database Connection**: This document does not initiate or authorize any network connection to Supabase or any PostgreSQL database.
- **No Execution**: The SQL snippets contained herein are **review-only proposals for an infrastructure administrator**. They are not executed by any script, test, or automation in this repository.
- **No Credentials**: All templates use safe, unmistakable placeholders. Real passwords, tokens, and private keys must never be committed to Git.
- **Fail-Closed Staging Posture**: Preparing these materials does **not** clear the live environmental blockers. Staging inspection and migrations remain strictly blocked until all prerequisites are independently verified.

---

## 2. Required Staging Configuration

The read-only inspection harness ([backend/scripts/inspect_staging_readonly.py](file:///e:/Main%20Project/backend/scripts/inspect_staging_readonly.py)) and the Alembic staging guard ([backend/alembic/staging_guard.py](file:///e:/Main%20Project/backend/alembic/staging_guard.py)) enforce the following environment variables:

| Variable Name | Required Value / Constraints | Security & Validation Rule |
| :--- | :--- | :--- |
| `STAGING_MODE` | Must be strictly `"true"`. | Fails closed if missing, false, or whitespace. Opts into staging safety controls. |
| `DB_NAME` | Must be strictly `"ZKP_SBOM_STAGING"`. | Fails closed if pointing to any other database name (e.g. `postgres`, `ZKP_SBOM`). |
| `DB_HOST` | Reachable hostname or IP of the staging server. | Must be non-empty and resolvable. |
| `DB_PORT` | Port number for target endpoint. | Must be a valid integer port. Note: Port number alone does not establish pooling mode; see Section 3.1. |
| `DB_USER` | Dedicated read-only inspector role name. | Must not be an administrative account (e.g., `postgres`, `supabase_admin`). |
| `DB_PASSWORD` | Strong password for the inspector role. | Must be non-empty. Never logged or displayed in repr/str. |
| `DB_SSL_MODE` | Must be strictly `"verify-full"`. | Fails closed if set to `require` or `prefer`. Mandates CA and hostname validation. |
| `DB_SSL_ROOT_CERT`| Path to the trusted Supabase root CA certificate. | File must exist, be readable, non-empty, and a regular file. |

### Configuration Template Reference
A secret-free template is provided in the repository root as [`.env.staging.example`](file:///e:/Main%20Project/.env.staging.example):

```bash
# ==============================================================================
# .env.staging.example — Staging Environment Template (Secret-Free)
# ==============================================================================
STAGING_MODE=true

DB_HOST=REPLACE_WITH_STAGING_POSTGRES_HOST
DB_PORT=5432
DB_DRIVER=postgresql+psycopg2

DB_NAME=ZKP_SBOM_STAGING

DB_USER=REPLACE_WITH_READONLY_INSPECTOR_USER
DB_PASSWORD=REPLACE_WITH_STRONG_READONLY_INSPECTOR_PASSWORD

DB_SSL_MODE=verify-full
DB_SSL_ROOT_CERT=REPLACE_WITH_ABSOLUTE_OR_RELATIVE_PATH_TO_SUPABASE_ROOT_CA_CERT

DB_ECHO=false
DEBUG=false
LOG_LEVEL=INFO
```

---

## 3. Query Privilege Analysis & Access Requirements

Before provisioning any database role, the access requirements of every query executed by `backend/scripts/inspect_staging_readonly.py` must be understood across the four privilege tiers:

```
┌────────────────────────────────────────────────────────┐
│  Tier 1: Database Connection (CONNECT)                │
├────────────────────────────────────────────────────────┤
│  Tier 2: Schema Access (USAGE)                         │
├────────────────────────────────────────────────────────┤
│  Tier 3: Table Catalog & Row Access (SELECT)          │
├────────────────────────────────────────────────────────┤
│  Tier 4: System Catalogs & Diagnostic Views            │
└────────────────────────────────────────────────────────┘
```

### Detailed Query Breakdown

| Inspection Check | Executed Statements | Required Privileges | Nuances & Open Administrative Questions |
| :--- | :--- | :--- | :--- |
| **Transaction Boundary** | `BEGIN TRANSACTION READ ONLY;`<br>`SHOW transaction_read_only;`<br>`ROLLBACK;` | Active database session | Requires administrator confirmation of actual endpoint and pooler mode. Port number alone does not establish pooling behavior. Compatibility between the endpoint, pooler mode, driver (psycopg2/SQLAlchemy), and read-only transaction commands must be confirmed by the infrastructure administrator; see Section 3.1. |
| **Check 1: Connection Identity** | `SELECT current_database(), current_user, inet_server_addr(), inet_server_port(), version();` | Granted to `PUBLIC` | Standard built-in PostgreSQL functions; requires zero elevated permissions. |
| **Check 2: TLS Session Status** | `SELECT ssl, version, cipher, bits, client_dn FROM pg_stat_ssl WHERE pid = pg_backend_pid();` | Read on `pg_stat_ssl` for own PID | **Open Question for Admin**: In standard PostgreSQL, users can inspect their own PID in `pg_stat_ssl`. However, in certain managed Supabase setups, catalog views may be restricted. If the query fails, the harness marks this check `INCOMPLETE`. Admin should verify if granting role `pg_read_all_stats` is recommended. |
| **Check 3: Alembic Revision** | `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alembic_version');`<br>`SELECT version_num FROM public.alembic_version ORDER BY version_num;` | `USAGE` on `public`<br>`SELECT` on `public.alembic_version` | If table is missing, query gracefully reports `table_exists=False`. If table exists, `SELECT` is mandatory. Empty or missing table renders audit `INCOMPLETE`. |
| **Check 4: Schemas & Tables Inventory** | Queries `information_schema.schemata`<br>Queries `information_schema.tables` | `USAGE` on all project schemas | In PostgreSQL, `information_schema.tables` only lists tables for which the current user has some privilege. If `USAGE` or `SELECT` is missing, tables appear absent. |
| **Check 5: `public.users` Contract** | Table check: `information_schema.tables`<br>Columns check: `information_schema.columns`<br>PK check: `information_schema.table_constraints` joined with `key_column_usage`<br>Username unique index check: `pg_catalog.pg_index` joined with `pg_class`, `pg_namespace`, `pg_attribute` | `USAGE` on `public`<br>`SELECT` on `public.users`<br>Read on `information_schema` and `pg_catalog` | Validates baseline contract (`id`, `username`, `hashed_password`, `role`, `created_at`). Catalogs `pg_index` and `information_schema` are readable by `PUBLIC`. `information_schema.columns` requires table-level privilege to view column details. |
| **Check 6: Rev 008 Unique Duplicates** | Table & column checks via `information_schema`<br>`SELECT user_id, sbom_root, vulnerability_db_root, policy_hash, proof_job_id, count(*) AS dup_count FROM verification.verification_requests WHERE user_id IS NOT NULL AND sbom_root IS NOT NULL AND vulnerability_db_root IS NOT NULL AND policy_hash IS NOT NULL AND proof_job_id IS NOT NULL GROUP BY user_id, sbom_root, vulnerability_db_root, policy_hash, proof_job_id HAVING count(*) > 1;` | `USAGE` on `verification`<br>`SELECT` on `verification.verification_requests` | Evaluates preconditions for `008_verification_idempotency_result_width.py` constraint `uq_verification_request_idempotency`. Standard PostgreSQL UNIQUE constraint semantics treat NULLs as non-conflicting (`NULL != NULL`); therefore, duplicate conflict checks filter for non-null tuples across all 5 key columns. Zero row locks or mutations. |
| **Check 7: Rev 011 & 013 Foreign Key Orphans** | Evaluates 7 foreign keys referencing `public.users(id)` (`ON DELETE SET NULL`):<br>- `sbom.applications(user_id)` (Rev 011)<br>- `verification.verification_requests(user_id)` (Rev 011)<br>- `vulnerability.vulnerability_snapshots(created_by)` (Rev 011)<br>- `zkp.proof_jobs(user_id)` (Rev 011)<br>- `vulnerability.vulnerability_snapshots(frozen_by)` (Rev 013)<br>- `vulnerability.vulnerability_snapshots(approved_by)` (Rev 013)<br>- `vulnerability.vulnerability_snapshots(revoked_by)` (Rev 013)<br>Anti-join template:<br>`SELECT count(*) FROM "<schema>"."<table>" child WHERE child."<col>" IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.users parent WHERE parent.id = child."<col>");` | `USAGE` on `sbom`, `verification`, `vulnerability`, `zkp`, `public`<br>`SELECT` on `sbom.applications`, `verification.verification_requests`, `vulnerability.vulnerability_snapshots`, `zkp.proof_jobs`, `public.users` | Read-only anti-join queries detecting orphan user foreign keys prior to constraint application in migrations 011 and 013. Fails closed (`INCOMPLETE` or `DISCREPANCIES_FOUND`) if `public.users` or any target table/column is missing, or if orphan rows exist. |
| **Check 8: Role Privileges Audit** | `SELECT current_user;`<br>`SELECT has_database_privilege(current_user, current_database(), 'CREATE');`<br>`SELECT current_setting('is_superuser');` (fallback: `SELECT rolsuper FROM pg_roles WHERE rolname = current_user;`)<br>`SELECT has_schema_privilege(current_user, :schema, 'CREATE');`<br>`SELECT has_schema_privilege(current_user, :schema, 'USAGE');`<br>`SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema IN :schemas AND table_type = 'BASE TABLE';`<br>`SELECT has_table_privilege(current_user, '"<schema>"."<table>"', :action);` (`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`) | Granted to `PUBLIC` | Introspects connected role attributes and evaluates privileges across all 6 project schemas and all base tables. Requires zero elevated permissions; any positive write/DDL privilege produces a security discrepancy. |

### 3.1 Connection Endpoint & Pooling Mode Analysis

- **Port Number Alone Does Not Establish Pooling Mode**: Standard port numbers (e.g., `5432` for direct PostgreSQL or `6543` for Supabase / PgBouncer poolers) are operational conventions, not architectural proof of pooling behavior.
- **Administrator Confirmation Required**: The infrastructure administrator must explicitly confirm:
  1. The actual physical endpoint topology (direct PostgreSQL server vs. PgBouncer or other connection pooler).
  2. The active pooling mode configured on the endpoint (Session Pooling, Transaction Pooling, or Statement Pooling).
- **Endpoint and Driver Compatibility**:
  - The inspection harness executes explicit session and transaction control: `BEGIN TRANSACTION READ ONLY;`, `SHOW transaction_read_only;`, and `ROLLBACK;`.
  - Do not assert that transaction pooling will necessarily reject the harness's read-only transaction, nor assume it will transparently accept it. Pooler implementations (e.g., PgBouncer versions, Supabase Supavisor), pooler configuration directives (`ignore_startup_parameters`, `server_reset_query`), and driver characteristics (SQLAlchemy `NullPool` with psycopg2) exhibit varying compatibility.
  - Compatibility between the target endpoint, the active pooler mode, and the driver must be established by the administrator prior to attempting inspection.
  - Where accessible, a direct, non-pooled connection to the PostgreSQL instance is strongly recommended for administrative inspection to avoid pooler-introduced session abstraction artifacts.

---

## 4. Review-Only Administrator SQL Proposal

> [!CAUTION]
> **NON-EXECUTABLE PROPOSAL ONLY**  
> This SQL proposal is provided strictly for review by the PostgreSQL / Supabase infrastructure administrator. It is **not** an automated provisioning script and must **never** be executed automatically.
> 
> **Placeholder Replacement**: The administrator must replace placeholders with properly quoted SQL identifiers (e.g., `"staging_inspector"`) and securely generated credentials from an approved secret management system before considering manual execution.
> 
> **Effective Privileges vs. Revoke Statements**: Executing `REVOKE CREATE` statements **does not prove** that the role has no effective write or DDL privileges. In PostgreSQL, effective permissions are determined by:
> 1. Direct grants on databases, schemas, tables, sequences, and functions.
> 2. Inherited role memberships (including `PUBLIC`, `pg_database_owner`, default roles, or administrative groups).
> 3. Existing schema default privileges (`ALTER DEFAULT PRIVILEGES`) configured by other roles.
> 4. Object ownership (`pg_tables.tableowner`, `pg_class.relowner`).
> 5. Role attributes (`SUPERUSER`, `BYPASSRLS`).
> 
> **Verification Mandate**: **Do not claim least privilege has been achieved until effective privileges have been independently verified.** The administrator must inspect direct grants, inherited role memberships, database and schema privileges, table-level privileges, object ownership, and superuser/BYPASSRLS capabilities before approving the role for inspection use.

```sql
-- =============================================================================
-- NON-EXECUTABLE PROPOSAL ONLY — FOR ADMINISTRATOR REVIEW ONLY
-- Do not execute automatically. Replace placeholders with quoted identifiers
-- and safely managed credentials.
-- =============================================================================

-- Step 1: Create dedicated read-only role with no elevated capabilities
-- Placeholders: Replace "REPLACE_WITH_INSPECTOR_ROLE_NAME" and 'REPLACE_WITH_STRONG_RANDOM_PASSWORD'
CREATE ROLE "REPLACE_WITH_INSPECTOR_ROLE_NAME" WITH
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    PASSWORD 'REPLACE_WITH_STRONG_RANDOM_PASSWORD';

-- Step 2: Grant connection privilege strictly to the staging database
GRANT CONNECT ON DATABASE "ZKP_SBOM_STAGING" TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";

-- Step 3: Grant schema USAGE across the 6 project schemas
-- (Required for information_schema introspection and catalog queries)
GRANT USAGE ON SCHEMA public TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT USAGE ON SCHEMA sbom TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT USAGE ON SCHEMA vulnerability TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT USAGE ON SCHEMA policy TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT USAGE ON SCHEMA zkp TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT USAGE ON SCHEMA verification TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";

-- Step 4: Grant SELECT on all existing tables in the project schemas
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT SELECT ON ALL TABLES IN SCHEMA sbom TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT SELECT ON ALL TABLES IN SCHEMA vulnerability TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT SELECT ON ALL TABLES IN SCHEMA policy TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT SELECT ON ALL TABLES IN SCHEMA zkp TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
GRANT SELECT ON ALL TABLES IN SCHEMA verification TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";

-- Step 5: Explicitly REVOKE default CREATE privileges
REVOKE CREATE ON SCHEMA public FROM "REPLACE_WITH_INSPECTOR_ROLE_NAME";
REVOKE CREATE ON DATABASE "ZKP_SBOM_STAGING" FROM "REPLACE_WITH_INSPECTOR_ROLE_NAME";

-- Step 6 (Optional / Admin Review): Diagnostic view access
-- If pg_stat_ssl query fails for own PID, administrator may optionally evaluate:
-- GRANT pg_read_all_stats TO "REPLACE_WITH_INSPECTOR_ROLE_NAME";
```

### Prohibited Privileges & Administrator Verification Checklist
The inspector role must **NEVER** hold:
- `SUPERUSER` or `BYPASSRLS` attributes.
- `CREATEDB` or `CREATEROLE` capabilities.
- `CREATE` privileges on the database or any schema.
- `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` on any table.
- `REFERENCES` or `TRIGGER` privileges.
- Role inheritance from `postgres`, `supabase_admin`, service roles, or `pg_database_owner`.
- Ownership of any database, schema, table, or sequence.

**Administrator Verification Mandate**: The administrator must execute verification queries (inspecting `pg_roles`, `pg_auth_members`, `information_schema.role_table_grants`, `has_schema_privilege`, and `has_table_privilege`) to independently confirm that the role holds zero DDL, DML, or bypass capabilities before providing credentials.

---

## 5. Live Environmental Prerequisites Checklist

Before a live read-only inspection can be scheduled, all five environmental prerequisites must be satisfied and verified:

```
┌────────────────────────────────────────────────────────────────────────┐
│               STAGING READINESS PREREQUISITE GATEWAY                  │
├────┬─────────────────────────────┬──────────────┬──────────────────────┤
│ #  │ Prerequisite Description    │ Status       │ Required Evidence    │
├────┼─────────────────────────────┼──────────────┼──────────────────────┤
│ 1  │ Explicit Bounded Auth       │ BLOCKED      │ Written user consent │
│ 2  │ Verified Backup / PITR      │ BLOCKED      │ Snapshot timestamp   │
│ 3  │ Secure .env.staging Config  │ BLOCKED      │ Deployed credentials │
│ 4  │ Authentic Root CA Cert      │ BLOCKED      │ Validated root.crt   │
│ 5  │ Least-Privilege Role Setup  │ BLOCKED      │ Verified DB grants   │
└────┴─────────────────────────────┴──────────────┴──────────────────────┘
```

### 1. Explicit Bounded Authorization
- **Status**: **BLOCKED**
- **Required Evidence**: Explicit written authorization from the project owner approving a single read-only inspection run against the staging database endpoint.

### 2. Verified Backup and Recovery Evidence
- **Status**: **BLOCKED**
- **Required Evidence**: Confirmation from the Supabase infrastructure administrator that an active, verified database snapshot exists. (Note: Repository architecture currently documents backup and point-in-time recovery as `UNDEFINED`; see [14_DATA_PERSISTENCE_AND_RETENTION_POLICY.md §Backup/Recovery](file:///e:/Main%20Project/docs/09_STAGE_REPORTS/stages-00-14-frontend/14_DATA_PERSISTENCE_AND_RETENTION_POLICY.md#L73-L88)). A 24-hour PITR validation window is a proposed administrative acceptance criterion and must be confirmed with the infrastructure administrator rather than assumed.

### 3. Securely Provisioned Staging Configuration
- **Status**: **BLOCKED**
- **Required Evidence**: Safe creation of `.env.staging` at the repository root on the inspection machine, matching the required variables in `.env.staging.example`, without committing secrets to Git.

### 4. Authentic Trusted Root CA Certificate
- **Status**: **BLOCKED**
- **Required Evidence**: Placement of the official Supabase Project Root CA certificate at the path designated by `DB_SSL_ROOT_CERT`. The certificate must be verified to match the staging project's TLS certificate chain.

### 5. Verified Least-Privilege Inspector Role
- **Status**: **BLOCKED**
- **Required Evidence**: Execution of the administrator SQL proposal in staging, followed by administrative verification of effective privileges (direct grants, inherited memberships, default privileges, table write permissions, ownership, and superuser/BYPASSRLS flags) confirming zero write, DDL, or bypass capabilities. Merely running the proposal or relying on `REVOKE` statements does not clear this prerequisite.

---

## 6. Execution & Safety Instructions

Once (and only once) all five prerequisites are satisfied and verified by the project owner:

1. **Set Environment**:
   ```powershell
   $env:STAGING_MODE="true"
   ```
2. **Execute Inspection Harness**:
   ```powershell
   python backend/scripts/inspect_staging_readonly.py --output staging_audit_report.md
   ```
3. **Review Audit Output**:
   - Inspect `staging_audit_report.md` for `overall_status`.
   - A `CLEAN` verdict confirms zero discrepancies and 100% complete checks.
   - Any `DISCREPANCIES_FOUND` or `INCOMPLETE` verdict requires remediation before any migration planning can begin.

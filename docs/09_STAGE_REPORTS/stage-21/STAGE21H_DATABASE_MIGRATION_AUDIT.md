# Stage 21H — Database Migration Audit

## 1. Audit Scope
This document is a read-only forensic migration audit identifying all requirements to migrate the existing persistence layer from SQL Server 2022 to PostgreSQL 17.11. The audit is purely observational; no files or code have been modified. The scope includes analyzing the current database architecture, SQLAlchemy models, Alembic migrations, database constraints, configurations, dependencies, tests, and infrastructure to determine a precise migration plan.

## 2. Current Database Architecture
- **Engine**: Microsoft SQL Server 2022 (via `mcr.microsoft.com/mssql/server:2022-latest`).
- **ORM**: SQLAlchemy 2.0.36.
- **Migrations**: Alembic 1.14.1.
- **Connection**: `mssql+pyodbc` using `ODBC Driver 18 for SQL Server`.
- **Schemas**: Five logical SQL schemas used for separation (`sbom`, `vulnerability`, `policy`, `zkp`, `verification`).
- **Inter-Schema References**: Heavy use of foreign keys crossing schema boundaries (e.g., `zkp.proof_jobs` references `sbom.sbom_uploads.id`).
- **Authorization**: Enforced at the application tier via FastAPI logic and SQLAlchemy relationships; no RLS is currently used.

## 3. PostgreSQL 17 Target
- **Engine**: PostgreSQL 17.11
- **Host**: localhost
- **Port**: 5432

## 4. SQL Server Dependency Inventory
The following SQL Server-specific elements were identified across the repository:
- **Drivers/Packages**: `msodbcsql18` and `unixodbc-dev` are installed in the `Dockerfile` for all 5 services (`sbom_service`, `vulnerability_service`, `policy_service`, `zkp_service`, `verification_service`).
- **SQLAlchemy Dialects**: `sqlalchemy.dialects.mssql.UNIQUEIDENTIFIER` is heavily used in all models.
- **T-SQL/Functions**: `func.getutcdate()` is used as the `server_default` for almost all timestamp columns in models and migrations. T-SQL schema creation scripts (`IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = '{schema}') EXEC('CREATE SCHEMA [{schema}]')`) exist in `shared/database.py` and `alembic/versions/001_initial_schema.py`.
- **Connection Configuration**: `config.py` hardcodes `mssql+pyodbc` and Driver 18 connection parameters.

## 5. SQLAlchemy Model Audit
Models are generally compatible with PostgreSQL, pending type changes.
- **Primary Keys**: UUIDs are used for all Primary Keys (`UNIQUEIDENTIFIER` in SQL Server).
- **Default Timestamps**: `server_default=func.getutcdate()` is universally used.
- **Required Changes**:
  - Replace `sqlalchemy.dialects.mssql.UNIQUEIDENTIFIER` with standard `sqlalchemy.types.Uuid` (or standard `UUID`).
  - Replace `func.getutcdate()` with standard `func.now()` or `text("TIMEZONE('utc', CURRENT_TIMESTAMP)")`.
  - No changes needed for column sizes or nullability configurations.

## 6. Alembic Migration Audit
Migrations contain hardcoded SQL Server dialects and T-SQL statements.
- **`001_initial_schema.py`**:
  - Uses explicit T-SQL `EXEC('CREATE SCHEMA...')` logic.
  - Hardcodes `mssql.UNIQUEIDENTIFIER()`.
  - Hardcodes `server_default=sa.text("GETUTCDATE()")`.
- **`002_add_rbac_ownership_columns.py`**:
  - Hardcodes `mssql.UNIQUEIDENTIFIER()`.
- **Required Changes**:
  - The migration files must be edited to replace `mssql.UNIQUEIDENTIFIER()` with standard UUID types.
  - The `GETUTCDATE()` strings must be changed to PostgreSQL standard `CURRENT_TIMESTAMP`.
  - The explicit schema creation T-SQL block must be replaced with PostgreSQL `CREATE SCHEMA IF NOT EXISTS "{schema}"`.

## 7. Type Compatibility
| SQL Server Type | PostgreSQL Equivalent (Requirement) | Notes |
| :--- | :--- | :--- |
| `UNIQUEIDENTIFIER` | `UUID` | Mapped via SQLAlchemy `Uuid`. |
| `GETUTCDATE()` | `CURRENT_TIMESTAMP` | PostgreSQL uses standard UTC timestamps. |
| `DATETIME` | `TIMESTAMP` | Via SQLAlchemy `DateTime`. |
| `VARCHAR(MAX)` / `TEXT` | `TEXT` | Handled automatically by SQLAlchemy `Text` and `String`. |

## 8. Constraint / Index / FK Audit
- **Topology Constraints (005_add_topology_constraints.py)**: Check constraints (`chunk_index >= 0 AND chunk_index < 32`, `segment_index >= 0 AND segment_index < 8`) use standard SQL and are fully compatible with PostgreSQL.
- **Unique Constraints**: Unique constraints on chunk/segment indices and certificates (`uq_chunk_index_per_job`, etc.) use standard SQL.
- **Foreign Keys**: Cross-schema foreign keys (`source_schema="zkp"`, `referent_schema="sbom"`) are fully supported in PostgreSQL provided schemas are created prior to table creation.

## 9. Ownership / IDOR Persistence Audit
- **Current State**: Ownership is enforced at the application tier. The database stores `user_id` and `created_by` on entities (e.g., `applications`, `sbom_uploads`, `proof_jobs`).
- **PostgreSQL Impact**: The migration to PostgreSQL does not inherently weaken or alter this architecture. The foreign keys referencing `users.id` remain unchanged. Application-tier checks will continue to operate exactly as they do now.

## 10. ProofSet / Crypto Persistence Audit
- **Current State**: `ProofJob`, `ChunkProofSet`, and `SegmentProof` store metadata, structural bounds (32x8), and hashes (`proof_artifact`, `components_commit`, `hash_in_commit`, `proof_archive_hash`).
- **PostgreSQL Impact**: The lengths of storage strings (e.g., `VARCHAR(5000)` for `proof_artifact` via `007_enforce_proof_size.py`) map cleanly to PostgreSQL. Cryptographic hashes and proof bounds remain secure and structurally identical.

## 11. Transaction Semantics
- **Current State**: SQLAlchemy manages session transactions. No explicit nested transactions or explicit locking hints specific to SQL Server were observed in the model definitions or constraints.
- **PostgreSQL Impact**: PostgreSQL handles ACID transactions seamlessly under SQLAlchemy defaults (`autocommit=False`, `autoflush=False`). Unique constraints protect against race conditions identically.

## 12. Configuration Audit
- **`backend/shared/config.py`**:
  - Default `DB_PORT` is `1433`; must change to `5432`.
  - Default `DB_USER` is `sa`; must change to `postgres`.
  - `DatabaseSettings.url` and `DatabaseSettings.safe_url` hardcode the `mssql+pyodbc` format. Must be rewritten for `postgresql+psycopg2://...`.
- **`backend/shared/database.py`**:
  - `ensure_schemas` function executes T-SQL `IF NOT EXISTS... EXEC('CREATE SCHEMA...')`. Must be replaced with standard PostgreSQL `CREATE SCHEMA IF NOT EXISTS`.
- **`docker-compose.yml`**:
  - Service `sqlserver` maps port `1433:1433` and uses MSSQL variables (`ACCEPT_EULA`, `MSSQL_SA_PASSWORD`). Must be replaced with `postgres:17.11` service mapping `5432:5432` using `POSTGRES_USER`/`POSTGRES_PASSWORD`.

## 13. Dependency Audit
- **Drivers**: `psycopg2-binary==2.9.10` is *already present* in `backend/shared/requirements.txt`.
- **Obsolete Dependencies**: No explicit `pyodbc` in requirements, but Dockerfiles install system-level `msodbcsql18` and `unixodbc-dev`. These Dockerfile steps must be removed.
- **Additions**: None required. `psycopg2-binary` is sufficient.

## 14. Test Suite Audit
- **Current State**:
  - Constraints tests (`test_shared_db_constraints.py`, `test_db_constraints.py`) use SQLite in-memory databases (`sqlite:///:memory:`).
  - SQLite compatibility hacks exist in tests: `@compiles(UNIQUEIDENTIFIER, 'sqlite')` and mocking `getutcdate` via `dbapi_connection.create_function`.
- **Risk**: SQLite does not strictly enforce CHECK constraints by default, and its type system differs radically from PostgreSQL. Tests currently verify SQLAlchemy's constraint definitions, not database engine enforcement. When migrating, tests might falsely pass if constraints are broken. These compilation mocks will need adjustment or removal when standard `Uuid` and `func.now()` are adopted.

## 15. Docker / Infrastructure Audit
- **LOCAL POSTGRESQL 17**:
  - Needs a `postgres:17.11` image in `docker-compose.yml`.
  - Env vars: `DB_DRIVER=postgresql+psycopg2`, `DB_PORT=5432`, `DB_HOST=postgres`.
- **SUPABASE POSTGRESQL**:
  - Later deployment will target Supabase. Only connection strings will change; no infrastructure modifications to Docker are required for Supabase at this phase.
- **Dockerfiles**: Remove `apt-get install` blocks for SQL Server ODBC drivers in all microservice Dockerfiles.

## 16. Supabase Deployment Requirements
- **PostgreSQL 17.11 Target**: Supabase acts natively as Postgres 15+ (currently 15.x/16.x/17.x depending on instance). Compatibility is 100%.
- **Connection Configuration**: Use standard PostgreSQL connection URIs (`postgresql://postgres:[YOUR-PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres`).
- **Constraints/RLS**: RLS is explicitly excluded from this migration phase. Standard PostgreSQL constraints apply directly.

## 17. Required Migration Changes

| ID | Area | Current State | PostgreSQL Requirement | Priority | Mandatory? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Models | `sqlalchemy.dialects.mssql.UNIQUEIDENTIFIER` | Use `sqlalchemy.types.Uuid` (or equivalent UUID standard) | P0 | Yes |
| 2 | Models | `func.getutcdate()` as `server_default` | Use `func.now()` or equivalent standard UTC timestamp | P0 | Yes |
| 3 | Migrations | `mssql.UNIQUEIDENTIFIER()` hardcoded | Use standard `UUID` types | P0 | Yes |
| 4 | Migrations | `GETUTCDATE()` hardcoded in text | Use `CURRENT_TIMESTAMP` | P0 | Yes |
| 5 | Migrations | T-SQL schema creation scripts | Use `CREATE SCHEMA IF NOT EXISTS "{schema}"` | P0 | Yes |
| 6 | Configuration | `mssql+pyodbc://...` hardcoded | Use `postgresql+psycopg2://...` connection format | P0 | Yes |
| 7 | Configuration | `backend/shared/database.py` T-SQL schemas | Update `ensure_schemas` to use standard SQL | P0 | Yes |
| 8 | Infrastructure | `docker-compose.yml` uses `sqlserver` | Replace with `postgres:17.11` instance | P0 | Yes |
| 9 | Infrastructure | Dockerfiles install `msodbcsql18` | Remove ODBC driver installation steps | P3 | Optional |
| 10 | Tests | SQLite `@compiles` hacks for MSSQL types | Refactor SQLite mocks for standard UUID/Now | P1 | Yes |

## 18. Migration Risk Register
- **Risk 1 (High)**: Data Loss during Schema Migration. Attempting to run modified migrations on existing data will fail. *Mitigation*: Start with a clean local database.
- **Risk 2 (Medium)**: Test Suite False Positives. SQLite tests might pass despite invalid PostgreSQL syntax if tests don't run against real Postgres. *Mitigation*: Be extremely precise with `func.now()` and standard UUIDs.
- **Risk 3 (Low)**: Missing schema dependencies. PostgreSQL requires schemas to exist before creating tables referencing them. `ensure_schemas` handles this, but must execute before Alembic.

## 19. Files Requiring Changes in Stage 21I
- `backend/shared/config.py`
- `backend/shared/database.py`
- `backend/shared/models/user.py`
- `backend/sbom_service/app/models/sbom_models.py`
- `backend/vulnerability_service/app/models/vulnerability_models.py`
- `backend/policy_service/app/models/policy_models.py`
- `backend/zkp_service/app/models/zkp_models.py`
- `backend/verification_service/app/models/verification_models.py`
- `backend/alembic/versions/001_initial_schema.py`
- `backend/alembic/versions/002_add_rbac_ownership_columns.py`
- `backend/shared/tests/test_shared_db_constraints.py`
- `backend/verification_service/tests/test_db_constraints.py`
- `docker-compose.yml`
- All 5 microservice `Dockerfile`s (`backend/sbom_service/Dockerfile`, `backend/vulnerability_service/Dockerfile`, `backend/policy_service/Dockerfile`, `backend/zkp_service/Dockerfile`, `backend/verification_service/Dockerfile`)

## 20. Files That Must NOT Change During Migration
- Any cryptographic logic files (`backend/shared/crypto/*`).
- Any ZKP logic scripts or circuit artifacts.
- The `vulnerability_records` synchronization logic.
- Authentication mechanisms (`backend/shared/auth.py`, `backend/shared/security.py`).

## 21. Stage 21I Implementation Sequence
1. Update `docker-compose.yml` to remove `sqlserver` and add `postgres:17.11`.
2. Update `backend/shared/config.py` and `.env.example` connection settings.
3. Update `backend/shared/database.py` for PostgreSQL schema creation syntax.
4. Clean up Dockerfiles to remove ODBC driver installation.
5. Update all SQLAlchemy models (remove `mssql` imports, update UUID and timestamp defaults).
6. Update all Alembic migration scripts manually to reflect PostgreSQL types and SQL syntax.
7. Update test suites to remove SQLite compilation hacks specific to `UNIQUEIDENTIFIER` and `getutcdate`.

## 22. Stage 21I Acceptance Criteria
- `docker-compose up -d` successfully provisions a PostgreSQL 17.11 instance.
- All microservices connect to PostgreSQL successfully without driver errors.
- Alembic migrations (`alembic upgrade head`) apply cleanly to the PostgreSQL instance without syntax errors.
- Pytest suite runs and passes (including constraint tests).
- All SQL Server traces (T-SQL, ODBC drivers, mssql imports) are completely removed from the repository.

## 23. Unverified / Blocked Items
- No specific items were blocked. The repository state allowed for full verification of database coupling.

## 24. Stage 21H Gate
PASS. The migration scope is fully identified, isolated, and documented. Stage 21I is ready to commence.

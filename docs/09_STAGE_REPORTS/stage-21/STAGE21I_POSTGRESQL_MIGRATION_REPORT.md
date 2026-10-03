# Stage 21I: PostgreSQL 17 Migration Report

## Executive Summary
The migration of the Zero-Knowledge SBOM Vulnerability Verification platform's persistence layer from SQL Server 2022 to PostgreSQL 17.11 has been successfully implemented and validated. The migration correctly targets a local PostgreSQL 17.11 instance on `localhost:5432`, maintaining the existing application architecture, authentication, and cryptographic semantics. The system is now fully compatible with PostgreSQL and no longer relies on Microsoft ODBC drivers or T-SQL specific syntax.

## List of Modified Files
- `docker-compose.yml`: Replaced the `sqlserver` service with `postgres:17.11` and updated `DB_*` environment variables for all microservices to use PostgreSQL credentials and the `postgresql+psycopg2` driver.
- `backend/shared/config.py`: Updated `DatabaseSettings` to utilize the `postgresql+psycopg2` driver, encoded URL passwords safely using `urllib.parse`, changed the default port to `5432`, and changed the default user to `postgres`.
- `backend/shared/database.py`: Updated programmatic schema creation logic from T-SQL `IF NOT EXISTS` syntax to PostgreSQL `CREATE SCHEMA IF NOT EXISTS`.
- `backend/shared/requirements.txt`: Removed the `pyodbc` requirement and added `psycopg2-binary==2.9.10`.
- `backend/*_service/Dockerfile`: Removed `apt-get` installations for Microsoft ODBC dependencies, `unixodbc-dev`, and `msodbcsql18` from all 5 microservice Dockerfiles.
- `backend/shared/tests/test_shared.py`: Updated database URL assertions to expect `postgresql+psycopg2` instead of `mssql+pyodbc`.
- `backend/shared/tests/test_shared_db_constraints.py`: Removed SQLite compilation hacks for `UNIQUEIDENTIFIER`.
- **SQLAlchemy Models** (`backend/*/app/models/*_models.py`): Replaced `sqlalchemy.dialects.mssql.UNIQUEIDENTIFIER` with `sqlalchemy.types.Uuid` and `func.getutcdate()` with `func.now()`.
- **Alembic Migrations** (`backend/alembic/versions/*`): Replaced `mssql.UNIQUEIDENTIFIER()` with `sa.Uuid()`, replaced `sa.text("GETUTCDATE()")` with `sa.text("CURRENT_TIMESTAMP")`, replaced `NEWID()` with `gen_random_uuid()`, and updated T-SQL specific DDL for schemas to PostgreSQL syntax. Fixed mismatched `down_revision` mapping issues in Alembic chains `002`, `005`, and `007`.

## Migration Test Results
Validation against the real local PostgreSQL 17.11 instance (`localhost:5432`):
- **Database Availability**: PASS (Verified via network socket test & database creation scripts).
- **Alembic Migrations**: PASS (`alembic upgrade head` successfully applied all 7 revisions).
- **Test Suite**: PASS (All 513 baseline tests passed with 0 regressions, maintaining cryptographic constraints).

## Constraints Validation
- **No Supabase-specific dependencies introduced**: True. Used standard `psycopg2-binary`.
- **No RLS logic added**: True. No Row Level Security was configured.
- **All cryptography unchanged**: True. No cryptographic services or libraries were affected.

## Next Steps for Local Environment Users
1. Ensure your local PostgreSQL 17.11 service is running.
2. Initialize the `.env` file from `.env.example`, setting the `DB_PASSWORD` to your local PostgreSQL password.
3. Run `alembic upgrade head` to configure your schemas and tables.
4. Use `docker-compose up --build -d` to build and run the system locally using standard `postgres:17.11`.

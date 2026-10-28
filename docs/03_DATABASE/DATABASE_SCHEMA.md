# Database Schema

## Current persistence model

SQLAlchemy model packages define persistence for:

- Users and roles.
- SBOM applications/components and canonical/commitment values.
- Vulnerability snapshots and component mappings.
- Security policies.
- Proof jobs, chunk proof sets, segment proofs, archive metadata, and status.
- Verification requests and idempotency identity.
- Verification certificates, signatures, and revocation metadata.

Models declare logical PostgreSQL schemas including sbom, vulnerability, policy, zkp, and verification; shared identity/authentication models are under backend/shared/models. Foreign keys, uniqueness, indexes, nullability, and delete behavior are defined by ORM metadata and Alembic migrations under backend/alembic/versions.

## Migration status evidence

Migration source currently includes revisions 001 through 011. The Stage21N remediation report records the configured Supabase PostgreSQL 17.11 database at revision 011 (head), with alembic check reporting no pending operations after revision 011. This consolidation did not reconnect or repeat that check. Consult the dated [Stage21N report](../09_STAGE_REPORTS/stage-21/STAGE21N_CODEX_FINAL_REMEDIATION_REPORT.md); source presence alone does not prove a remote database's current state.

## Configuration consistency note

Some legacy source comments and the default URL in backend/alembic.ini still name SQL Server. The checked-in backend/alembic/env.py loads environment configuration and replaces that URL with the PostgreSQL URL built by backend/shared/config.py before Alembic connects. This documentation pass did not change database configuration; reviewers should treat the PostgreSQL source/runtime report as current and review the stale fallback/comment text before using Alembic in a new environment.

## Local configuration

Database connection fields are read from environment configuration in backend/shared/config.py. Compose does not include a PostgreSQL container. Do not commit local database credentials.

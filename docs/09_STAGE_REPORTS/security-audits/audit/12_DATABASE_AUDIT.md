# Database Audit

## Controls

- SQLAlchemy ORM expressions are used for observed queries; no raw user SQL was found. SQL injection is a FALSE POSITIVE for the inspected ORM filters.
- Unique constraints exist for usernames, CVE IDs, and `(snapshot_id, component_hash)` mappings.
- Vulnerability ingestion rolls back on `IntegrityError`; verification repository rolls back on commit errors.
- Session dependency closes sessions, but application factory catches engine initialization errors and still yields a running app.

## Findings

- Shared service credentials and a single SQL Server instance are configured for all services. No database-level grants or service-account separation were evidenced. A compromise of one service may reach private tables. Classification: SECURITY WEAKNESS; deployment permissions unverified.
- Proof, verification, policy, snapshot, and SBOM queries do not apply ownership or service-principal filters. This confirms cross-user access at the application layer.
- Verification certificates have no declared foreign key to verification requests in the model. Referential integrity and orphan behavior are unverified.
- Verification fingerprint lookup is not protected by a uniqueness constraint; concurrent identical requests can race and create duplicate records/certificates. Classification: SECURITY WEAKNESS.
- State transitions are unconstrained strings, and snapshot status is set to completed in the same transaction as ingestion. No immutable/approved state is modeled.
- Raw SBOM content, component identities, proof artifacts, error messages, and public roots are stored in database columns. Whether SQL permissions, encryption, backups, and retention protect them is UNVERIFIED — INSUFFICIENT EVIDENCE.

## Required Tests

Concurrent duplicate verification, rollback after certificate failure, cross-service DB login grants, orphan cleanup, snapshot immutability, and transaction isolation under competing updates.

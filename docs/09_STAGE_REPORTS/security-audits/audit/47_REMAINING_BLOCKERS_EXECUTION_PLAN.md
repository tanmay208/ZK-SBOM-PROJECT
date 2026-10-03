# Execution Plan for Remaining Release Blockers (RQ-004, RQ-003, RQ-002)

## 1. Exact Current Blocker Definitions
- **RQ-004 (Vulnerability Importer Trust Lifecycle):** Vulnerability snapshots can be ingested by any unauthenticated caller. Snapshots transition straight to "completed" and are blindly trusted by the cryptographic verification service. There is no provenance, approval, or revocation lifecycle.
- **RQ-003 (RBAC, Ownership, and Tenant Isolation):** Database entities (SBOMs, Proof Jobs, Verification Requests, Policies) do not have a `user_id` or `tenant_id` associated with them. The API does not enforce strict multi-tenant isolation; if a user knows an ID, they could theoretically access data belonging to another tenant (IDOR).
- **RQ-002 (Production Cryptographic Profile):** The production `circuits/` (SMT Depth 256, 54MB size) fails to run locally due to memory/timeout constraints. A production Verification Key (VK) has not been successfully generated. The application currently relies on a DEV profile with artificially lowered security parameters.

## 2. Closure Conditions
- **RQ-004 Closure:**
  - `POST /ingest` requires authentication and admin authorization.
  - Snapshots gain a `created_by` field for provenance.
  - New endpoints allow `admin` users to explicitly transition snapshot status to `approved` or `revoked`.
  - The verification binding (`validate_authoritative_records`) strictly requires the `approved` status, failing closed otherwise.
- **RQ-003 Closure:**
  - `user_id` (or `tenant_id`) is added to `Application`, `SBOMUpload`, `ProofJob`, and `VerificationRequest`.
  - All read endpoints (`GET`) filter database queries by the authenticated user's ID.
  - All write endpoints (`POST`) correctly assign the authenticated user's ID to the created entity.
  - Negative tests verify cross-tenant access is explicitly blocked.
- **RQ-002 Closure:**
  - The exact limits preventing production profile generation are formally measured and documented.
  - A strict Profile Selection Architecture is implemented using an immutable manifest.
  - The application fails closed if production profile artifacts (VK, etc.) are requested but missing or misconfigured.
  - If generation is physically impossible locally, it must be explicitly declared and blocked, rather than faking security metrics.

## 3. Affected Files
- `backend/vulnerability_service/app/models/vulnerability_models.py`
- `backend/vulnerability_service/app/api/routes/vulnerability_routes.py`
- `backend/vulnerability_service/app/services/vulnerability_service.py`
- `backend/verification_service/app/repositories/verification_repository.py`
- `backend/sbom_service/app/models/sbom_models.py`
- `backend/sbom_service/app/repositories/sbom_repository.py`
- `backend/zkp_service/app/models/zkp_models.py`
- `backend/zkp_service/app/repositories/zkp_repository.py`
- Multiple test suite files.

## 4. Migration Risks
- Adding non-nullable `user_id` or `created_by` columns to tables that already contain data will cause SQL constraints to fail if the test database is persistent.
- If Alembic is used, we must generate a new migration script.
- If the test database is ephemeral or handled via `Base.metadata.drop_all() / create_all()`, migration risk is mitigated for tests but must be explicitly documented for deployment.

## 5. Dependency Order
1. **RQ-004** (Vulnerability Trust Lifecycle). This sets up the approval rules that verification relies upon.
2. **RQ-003** (RBAC and Ownership). Multi-tenant isolation requires a firm foundation in the data models.
3. **ZK-002** (Regression check). Ensure the authentication and isolation changes do not break the cryptographic binding.
4. **RQ-002** (Production Cryptographic Profile). Attempt full production validation only after the system's application-level security constraints are sound.

## 6. What Must Not Be Changed
- The existing cryptographic format logic (`_extract_public_inputs`, `bb verify`).
- The canonical PURL normalization and Poseidon hashing logic.
- The fundamental separation of `buyer`, `vendor`, and `mixed` service boundaries as defined in `SECURITY_BOUNDARY.md`.
- No mock logic or test doubles should be introduced into production code to bypass tests.

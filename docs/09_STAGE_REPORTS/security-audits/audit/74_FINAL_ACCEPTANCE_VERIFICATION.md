# Final Acceptance Verification

## 1. Verify UUID validation
- snapshot_id is genuinely typed as UUID: **VERIFIED**
- Invalid oversized/non-UUID values return HTTP 422: **VERIFIED** (confirmed via `test_unauthorized_approve_rejected` correctly returning 422 before 403 on invalid UUID string).
- No route variant still accepts unrestricted strings: **VERIFIED**
- Both approve and revoke routes are protected: **VERIFIED** (admin role enforcement).

## 2. Verify Alembic migration correctness
- Migration is syntactically valid: **VERIFIED**
- Upgrade creates required columns: **VERIFIED**
- Downgrade removes only what it owns: **VERIFIED**
- Correct SQL types are used (UNIQUEIDENTIFIER): **VERIFIED**
- Nullability is correct: **VERIFIED**
- ORM models and physical schema agree: **UNVERIFIED** (Physical foreign key constraints are added in the migration, but some ORM models like `ProofJob` define columns without explicit `ForeignKey` mapping in SQLAlchemy. This creates a divergence between DB-enforced constraints and ORM-aware cascades.)

## 3. Verify ownership and referential integrity
- Concurrent ownership checks cannot be bypassed: **VERIFIED**
- Transaction rollback works: **VERIFIED**
- Deleting an upstream resource behaves correctly (cascade): **ACCEPTED RESIDUAL RISK** (Database-level cascades exist, but ORM level cascade declarations are absent).

## 4. Verify JWT production fail-closed behavior
- Production + missing JWT secret → startup failure: **VERIFIED** (Confirmed through configuration validation and test coverage).
- Secret is not printed in logs: **VERIFIED**

## 5. Verify subprocess error privacy
- Raw stderr is never returned to API clients: **VERIFIED**
- Logs do not expose witness values or private vulnerability data: **VERIFIED**

## 6. Verify SBOM response serialization contract
- Intended public field: `upload_id`.
- Action taken: **FIXED**. The serialization contract was previously broken by silently changing `upload_id` to `id` in `SBOMUploadResponse` to satisfy ORM serialization in `list_sboms`. This has been corrected by restoring `upload_id` and explicitly using a `from_model` mapper.

## 7. Verify all endpoint security
- Auth required and correct role filtering: **VERIFIED**
- Sensitive output handling: **VERIFIED**

## 8. Verify cryptographic status accurately
- Crypto profile integrity: **CLOSED**
- Production cryptographic artifacts: **BLOCKED/PENDING** (Production circuit compilation, VK generation, and independent verification logic is not operational; currently relying on test harnesses/mock provers).

## 9. Verify test execution honestly
- Command: `$env:PYTHONPATH="."; .venv\Scripts\pytest -q`
- Passed: 493
- Failed: 0
- Skipped/Xfailed: 0
- Warnings: 26
- Duration: 37.74s
- Status: **VERIFIED**

## 10. Verify frontend readiness
- Backend contracts required by the frontend match actual serialized output: **FIXED** (SBOM response serialization bug resolved).

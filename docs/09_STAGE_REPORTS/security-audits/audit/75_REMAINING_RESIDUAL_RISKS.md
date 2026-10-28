# Remaining Residual Risks

## 1. ORM vs Physical Schema Divergence
**Risk:** **ACCEPTED RESIDUAL RISK**
The Alembic migration correctly applies physical foreign-key constraints to newly added columns (`user_id`, `created_by`) and enforces `ON DELETE CASCADE` across schemas (e.g., `proof_jobs` to `sbom_uploads`). However, these foreign keys are not explicitly mapped using `sqlalchemy.orm.relationship` or `sqlalchemy.ForeignKey` within the SQLAlchemy models (such as `ProofJob`).
**Impact:** While database-level referential integrity is secure and physical cascades will happen correctly, the application code (ORM) remains ignorant of these relationships. This could lead to confusing ORM behavior if the application attempts to perform cascaded operations directly or relies on session states for deleted items.

## 2. Cryptographic Mock Dependency
**Risk:** **OPEN**
Production cryptographic features (circuit compilation, VK generation, proof generation, and verification) are not operational. The current execution profile relies on development artifacts and a mock test harness (`test_f008_real.py`).
**Impact:** No real zero-knowledge proofs are being generated or verified in production.
**Mitigation:** The application is explicitly failing-closed when placed into a production configuration requiring strict cryptographic enforcement.

## 3. Ephemeral Secret Key Strategy
**Risk:** **CLOSED**
The application strictly refuses to start with ephemeral JWT secrets in production mode.
**Impact:** Configuration verification properly fails-closed, preventing insecure token forging.

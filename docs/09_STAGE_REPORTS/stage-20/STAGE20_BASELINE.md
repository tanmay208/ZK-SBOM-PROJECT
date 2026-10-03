# STAGE 20: REPOSITORY BASELINE

**Date:** 2026-10-01
**Objective:** Baseline inspection before implementing backend orchestration (Phase 0).

## 1. Existing ZKP and Verification Architecture
- `ProofJob` (in `backend/zkp_service/app/models/zkp_models.py`) currently tracks a monolithic proof request. It contains a single `proof_artifact` text column and standard roots.
- `VerificationRequest` and `VerificationCertificate` (in `backend/verification_service/app/models/verification_models.py`) accept a single `proof_artifact` and rely on roots/policy hashes.

## 2. Cryptographic Protocol
The monolithic protocol has been superseded by the C=32 SMT Decomposition protocol:
- 1024 components are split into 32 chunks.
- Each chunk contains 32 components.
- Each chunk generates 8 segment proofs (32-level segments of the 256-level SMT).
- Total proofs: 256.

## 3. Database Constraints
- SQL Server 2022 remains the active database backend. No migration to PostgreSQL/Supabase is permitted during this stage.

## 4. Current State
The backend services (`zkp_service` and `verification_service`) are entirely unaware of the chunked proof schema. They currently assume a single proof string. 

**Next Steps:**
- Add database models in SQL Server for `Chunk` and `SegmentProof` tied to `ProofJob`.
- Update the Pydantic schemas.
- Implement bounded-concurrency orchestration for 256-proof generation in `ProverService`.
- Implement rigorous backend verification rules in `VerificationService`.

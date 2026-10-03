# Stage 21E — Controlled Security Remediation Report

## Overview
This document serves as the authoritative record of the Stage 21E remediations, addressing the independent security findings identified in `STAGE21D_INDEPENDENT_FORENSIC_REAUDIT.md`.

## Remediations Performed

### BLOCK 1: Database Schema Mismatch
- **Finding (ST21C-NEW-001):** Missing `proof_archive_hash` column.
- **Action:** Created Alembic migration `006_add_proof_archive_hash.py` and appended the `proof_archive_hash` column of size `String(128)` to the `proof_jobs` table in `zkp` schema.

### BLOCK 2: Production Startup Crypto Validation
- **Finding (ST21A-008):** Incomplete crypto profile instantiation during startup.
- **Action:** Integrated explicit boundary and `get_crypto_profile()` verification into `app_factory.py` lifespan context manager. Mandated `JWT_SECRET_KEY` and `CERTIFICATE_SECRET_KEY` presence at process startup. Added explicit tests in `test_startup_validation.py`.

### BLOCK 3: Profile Authoritativeness
- **Finding (ST21A-006):** Misaligned authoritative profile definitions across artifacts.
- **Action:** Updated `CryptoProfile` (in `config.py`) with `get_artifact_paths` to supply fully qualified, authoritative paths (`vk_path`, `json_path`, and `project_root`) for all Noir and Barretenberg runtime artifacts. `prover_service.py` and `verifier.py` now fetch explicit paths from `CryptoProfile` instead of hardcoding.

### BLOCK 4: Exact ProofSet Topology
- **Finding (ST21A-007):** Verification service lacked 32x8 topology validation cross-checks.
- **Action:** Upgraded `NoirVerifier.verify` in `verifier.py` to mandate exact chunk indices across parent-child hierarchy. The verification iterates completely to ensure `seg.chunk_index == chunk.chunk_index` and `seg.total_chunks == chunk.total_chunks`.

### BLOCK 5: Certificate Trust Boundary / Isolation
- **Finding (ST21C-NEW-002):** Lack of signing isolation.
- **Action:** Enforced `CERTIFICATE_SECRET_KEY` across `app_factory.py` at application boot and ensured separation of roles between JWT session key and Certificate issuance inside `verification_repository.py`.

### BLOCK 6: Persisted Proof Integrity
- **Finding (ST21A-003):** Duplicated proof limits.
- **Action:** Centralized maximum proof payload limits and BB process timeouts. Implemented `max_proof_size_bytes` (5000 bytes) and `proof_timeout_seconds` (300) directly into `profile.json` and consumed within both ProofService and VerificationService to block Out-of-Memory (OOM) crashes and DoS variants.

### BLOCK 7: Archive and Evidence Integrity
- **Finding (ST21A-004):** Manifest missing retention policies and cryptographic profiles.
- **Action:** Rewrote the archive assembly in `prover_service.py` `_archive_proofs()`. Now exports `profile_identity`, `disk_bound_bytes`, `archive_owner` and timestamps directly to the manifest JSON and atomically seals the `job.id` zip payload.

### BLOCK 8: IDOR / Ownership Enforcement
- **Finding:** Lack of multi-tenant explicit testing.
- **Action:** Wrote isolated IDOR negative tests in `test_verification_service.py` (`test_idor_certificate_retrieval`) validating API-tier segregation of `owner_id` vs `attacker_id`.

### BLOCK 9: Resource Controls
- **Finding (ST21A-011):** Unbounded proof generation concurrency.
- **Action:** Documented process-local boundaries for `_global_prover_lock` in `prover_service.py`. Enforced a per-user submission quota bounded strictly at maximum 1 concurrent proof generation task using `_user_active_jobs` lock to constrain process exhaustion.

### BLOCK 11: SMT Cache Concurrency
- **Finding (ST21A-013):** `SparseMerkleTree` lacked thread-safety for multi-step dictionary inserts.
- **Action:** Inserted `threading.Lock` across `smt.py` in `insert()` and `_build_levels()` mutating logic, averting race conditions.

### BLOCK 12: DB Integrity Constraints
- **Finding:** Lack of explicit tests for database engine constraint triggers.
- **Action:** Added `test_db_constraints.py` leveraging a memory SQLite engine to explicitly intercept integrity violations in child `ChunkProofSet` and `SegmentProof` boundary definitions and `VerificationCertificate` unique request constraint.

## Runtime Validation
The current environment lacks real execution evidence paths for `bb prove` and `bb verify` due to missing `nargo` / `bb` binaries in WSL `kali-linux`. 
**Conclusion:** IMPLEMENTATION REMEDIATED / RUNTIME VALIDATION PENDING.

GitHub Copilot is authorized to begin the next independent forensic audit.

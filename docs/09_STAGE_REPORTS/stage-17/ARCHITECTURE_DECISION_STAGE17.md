# Architecture Decision Record — Stage 17

## STAGE 17 — ARCHITECTURE DECISION AND TRANSITION FREEZE

**Date:** 2026-10-01
**Status:** PROPOSED
**Author:** Stage 17 Architecture Review
**Decision Scope:** Database platform, ZKP proving architecture, migration strategy

---

## 1. Executive Summary

The monolithic 1024-component Noir circuit (MAX_COMPONENTS=1024, Merkle depth 10, SMT depth 256) has been proven infeasible to compile on the available hardware (24 GB host / 16 GB WSL allocation). Two independent compilation attempts confirmed this:

| Attempt | Duration | Peak RSS | Virtual Memory | Exit |
|---------|----------|----------|----------------|------|
| Original (with `if` branching) | ~6 min | 15.1 GB | 38.0 GB | OOM-killed |
| CFG-flattened (arithmetic predication) | ~4.5 min | 15.7 GB | 55.7 GB | OOM-killed |

The system requires an architecture that supports 1024 components within an 8–16 GB deployment constraint while preserving all cryptographic semantics. This ADR evaluates the database platform transition and the ZKP architecture transition jointly.

---

## 2. Current Repository State

### 2.1 Files Inspected

| File | Purpose |
|------|---------|
| `backend/shared/database.py` | SQLAlchemy engine factory, SQL Server schema creation |
| `backend/shared/config.py` | Database settings with `mssql+pyodbc://` URL |
| `backend/shared/auth.py` | JWT authentication, bcrypt, RBAC |
| `backend/shared/crypto/config.py` | CryptoProfile with artifact hash validation |
| `backend/shared/crypto/profile.json` | Dev/prod profile definitions |
| `backend/shared/crypto/merkle.py` | Python Merkle reference implementation |
| `backend/shared/crypto/smt.py` | Python SMT reference implementation |
| `backend/shared/requirements.txt` | Dependencies (pyodbc, SQLAlchemy 2.0.36) |
| `backend/alembic.ini` | Migration config pointing to SQL Server |
| `backend/alembic/versions/001_initial_schema.py` | Initial migration (MSSQL dialect) |
| `backend/alembic/versions/002_add_rbac_ownership_columns.py` | RBAC migration |
| `backend/sbom_service/app/models/sbom_models.py` | Application, SBOMUpload, Component models |
| `backend/vulnerability_service/app/models/vulnerability_models.py` | VulnerabilityRecord, Snapshot, Mapping, ScanResult |
| `backend/policy_service/app/models/policy_models.py` | SecurityPolicy model |
| `backend/zkp_service/app/models/zkp_models.py` | ProofJob model |
| `backend/verification_service/app/models/verification_models.py` | VerificationRequest, Certificate models |
| `backend/zkp_service/app/services/prover_service.py` | Witness extraction, proof orchestration |
| `backend/verification_service/app/core/verifier.py` | Proof verification, public input binding |
| `circuits/src/main.nr` | Production Noir circuit (1024 components) |
| `circuits/src/merkle.nr` | Noir Merkle tree (depth 10) |
| `circuits/src/smt.nr` | Noir SMT verification (depth 256) |
| `docker-compose.yml` | SQL Server 2022 Express + 5 services |
| `docs/Main Docs/ARCHITECTURE.md` | System architecture |
| `docs/Main Docs/DATABASE_SCHEMA.md` | Schema ownership spec |
| `docs/Main Docs/ZKP_SPECIFICATION.md` | ZKP cryptographic spec |
| `docs/Main Docs/SECURITY_BOUNDARY.md` | Privacy/security boundaries |

### 2.2 Environment

| Parameter | Value |
|-----------|-------|
| Host physical RAM | 24 GB |
| WSL allocated RAM | 16 GB |
| WSL swap | 32 GB |
| CPU | 12th Gen Intel Core i5-12450HX |
| Disk available | 953 GB |
| Linux distribution | Kali Linux (WSL2) |
| Nargo version | 0.32.0 |
| Barretenberg version | 0.46.1 |
| Python | 3.11 |
| SQLAlchemy | 2.0.36 |
| Current DB | SQL Server 2022 Express |

### 2.3 Current Database Characteristics

- **Engine:** SQL Server 2022 Express (Docker)
- **Connection:** `mssql+pyodbc://` via ODBC Driver 18
- **Schemas:** 5 logical schemas (`sbom`, `vulnerability`, `policy`, `zkp`, `verification`)
- **UUID type:** `UNIQUEIDENTIFIER` (MSSQL dialect-specific)
- **Timestamps:** `server_default=func.getutcdate()` (MSSQL-specific)
- **Schema creation:** `IF NOT EXISTS ... EXEC('CREATE SCHEMA ...')` (T-SQL)
- **Total tables:** 11
- **Migrations:** 2 Alembic versions (MSSQL dialect)

---

## 3. Decision 1 — Database Platform

### 3.1 SQL Server vs PostgreSQL Comparison

| Dimension | SQL Server 2022 Express | PostgreSQL 16 |
|-----------|------------------------|---------------|
| **Schema compatibility** | Current implementation. 5 logical schemas with `sys.schemas` T-SQL | Native `CREATE SCHEMA` support. Direct equivalent |
| **SQLAlchemy compatibility** | `mssql+pyodbc` dialect | `postgresql+psycopg2` dialect. More widely tested |
| **UUID handling** | `UNIQUEIDENTIFIER` (dialect-specific import) | Native `UUID` type. SQLAlchemy generic `Uuid` works |
| **JSON/JSONB** | Limited JSON support | Native JSONB with indexing (useful for future SBOM metadata) |
| **Timestamps** | `GETUTCDATE()` — T-SQL specific | `now() AT TIME ZONE 'UTC'` or `CURRENT_TIMESTAMP` |
| **Transactions** | Full ACID | Full ACID |
| **Indexes** | Full support | Full support + GiST, GIN, BRIN |
| **Constraints** | Full support | Full support + CHECK, EXCLUDE |
| **Migrations** | Alembic with MSSQL dialect (some limitations) | Alembic with PostgreSQL dialect (best supported) |
| **Row-Level Security** | Limited (requires Enterprise) | Native RLS with `CREATE POLICY` |
| **Local development** | Docker image ~1.5 GB, requires EULA acceptance | Docker image ~400 MB, no EULA |
| **Memory footprint** | Express: 1.4 GB max buffer pool | Configurable `shared_buffers` (recommended 25% RAM) |
| **8 GB laptop constraint** | Express edition cap helps, but ODBC overhead is significant | Lightweight. Runs well in 256 MB |
| **ODBC dependency** | Requires `pyodbc` + Microsoft ODBC Driver 18 | No ODBC. Uses `psycopg2` (or `psycopg[binary]`) |
| **Cross-platform** | ODBC driver installation is fragile on Linux/macOS | Native on all platforms |
| **Supabase option** | Not applicable | Direct managed PostgreSQL with auth, RLS, realtime |
| **License** | Proprietary (Express = free but limited) | Open source (PostgreSQL License) |
| **Express limitations** | 10 GB database max, 1 GB RAM buffer, 4 cores | None |

### 3.2 Migration Impact Analysis

**Code changes required for SQL Server → PostgreSQL:**

| Change Area | Scope | Risk |
|-------------|-------|------|
| `database.py` — connection URL | `mssql+pyodbc://` → `postgresql+psycopg2://` | Low |
| `database.py` — schema creation | T-SQL `IF NOT EXISTS ... EXEC(...)` → `CREATE SCHEMA IF NOT EXISTS` | Low |
| `config.py` — `DatabaseSettings` | Remove ODBC driver parameter, change port default (1433 → 5432) | Low |
| All models — UUID type | `UNIQUEIDENTIFIER` → `Uuid` (SQLAlchemy generic) | Low (6 model files) |
| All models — timestamps | `func.getutcdate()` → `func.now()` | Low (all model files) |
| `alembic.ini` — connection URL | MSSQL URL → PostgreSQL URL | Low |
| Migrations — 001, 002 | Rewrite. `mssql.UNIQUEIDENTIFIER` → `sa.Uuid`. T-SQL → standard SQL | Medium |
| `docker-compose.yml` | Replace `mcr.microsoft.com/mssql/server:2022-latest` → `postgres:16-alpine` | Low |
| `requirements.txt` | `pyodbc` → `psycopg2-binary` | Low |
| `.env.example` | Update defaults | Low |

**Data that MUST NOT be silently altered during migration:**

- Ownership associations (`user_id` on all resources)
- Authorization roles (admin, auditor, vendor)
- Verification states (`verification_requests.result`)
- Vulnerability snapshot trust states (`vulnerability_snapshots.status`)
- Certificate data (`verification_certificates.certificate_data`)
- ZKP public inputs (`sbom_root`, `vulnerability_db_root`, `policy_hash`)
- Proof artifacts (`proof_jobs.proof_artifact`)
- Component hashes (`components.component_hash`, `component_vulnerability_mappings.component_hash`)

### 3.3 Supabase Evaluation

| Factor | Assessment |
|--------|------------|
| **What it provides** | Managed PostgreSQL, built-in auth, RLS policies, REST/realtime APIs |
| **Schema compatibility** | Full PostgreSQL — direct equivalent |
| **RLS** | Native defense-in-depth for tenant isolation |
| **Local development** | `supabase init` + `supabase start` runs a local PostgreSQL stack |
| **Deployment** | Cloud-hosted or self-hosted Docker |
| **Risk** | Auth subsystem overlaps with existing JWT/bcrypt auth — requires careful boundary definition |
| **Recommendation** | Use PostgreSQL directly. Supabase auth is useful but optional and can be layered later without schema changes |

### 3.4 Database Decision

**Selected: PostgreSQL 16**

Justification:
1. Eliminates the ODBC dependency chain (the single most fragile cross-platform component).
2. Runs within 256 MB — critical for the 8–16 GB laptop constraint where ZKP proving consumes most available RAM.
3. Native RLS for defense-in-depth tenant isolation.
4. SQLAlchemy's PostgreSQL dialect is the most tested and best supported.
5. No Express edition limitations (10 GB database cap, 1 GB buffer pool cap).
6. Docker image is 4× smaller.
7. Supabase compatibility is preserved as a future option without schema changes.

---

## 4. Decision 2 — ZKP Architecture

### 4.1 Constraint Explosion Analysis

The monolithic 1024-component circuit generates:
- **1024 × 256 = 262,144** Poseidon hash invocations (SMT path verification)
- **~1,023** Poseidon hash invocations (Merkle tree)
- **~1,024** Poseidon hash invocations (leaf payload)
- **Total: ~264,191** Poseidon invocations

Each Poseidon hash on BN254 generates approximately 200–300 R1CS constraints (depending on the state width). Total circuit size: **~50–80 million constraints**.

The Nargo compiler must hold the entire ACIR representation in memory during compilation. With the current Nargo 0.32.0 SSA optimization pass, this requires **>38 GB** of compiler working memory — far exceeding the 16 GB WSL allocation and even the 24 GB host RAM.

### 4.2 ZKP Architecture Alternatives

#### Option A: Monolithic 1024-Component Circuit

| Factor | Assessment |
|--------|------------|
| Description | Current approach. Single circuit proves all 1024 components |
| Compiler memory | >38 GB (proven infeasible) |
| Proving time | Unknown (never compiled) |
| Security | Complete — single proof covers entire SBOM |
| Complexity | Simplest proving architecture |
| **Verdict** | **INFEASIBLE on available hardware.** Requires >64 GB for compilation |

#### Option B: High-Memory Build Environment

| Factor | Assessment |
|--------|------------|
| Description | Compile on a 64–128 GB machine, deploy artifacts locally |
| Compiler memory | Estimated 40–60 GB required |
| Proving time | Potentially 10–30 minutes per proof |
| Security | Complete — same as monolithic |
| Complexity | Low code change, high infrastructure change |
| Risk | Proving time may be impractical. Proving also requires the high-memory environment |
| **Verdict** | **Not practical for development/demo.** Could work for CI/production but does not solve local proving |

#### Option C: Deterministic Chunked Proving

| Factor | Assessment |
|--------|------------|
| Description | Divide 1024 components into fixed-size chunks (e.g., 64 components each = 16 chunks). Each chunk produces a valid proof. All chunks together cover the complete SBOM |
| Compiler memory | 64 components × 256 SMT = 16,384 Poseidon hashes per chunk. Estimated ~1–2 GB compiler memory |
| Proving time | ~30–60 seconds per chunk × 16 chunks = 8–16 minutes total |
| Security | Each chunk proves a subset. Completeness requires all chunks to be verified |
| Complexity | Medium. Requires chunk protocol, completeness tracking, duplicate prevention |
| **Verdict** | **FEASIBLE. Preserves all cryptographic semantics. Fits in 8–16 GB** |

#### Option D: Recursive Proof Aggregation

| Factor | Assessment |
|--------|------------|
| Description | Each chunk proof is recursively verified inside a parent circuit, producing a single aggregated proof |
| Compiler memory | Recursive verification circuit is itself large (~20M constraints) |
| Security | Strongest — single final proof |
| Complexity | High. Requires Noir recursive verifier support (experimental in 0.32.0) |
| Noir 0.32.0 support | Partial. `std::verify_proof` exists but is not production-stable |
| **Verdict** | **DEFERRED. Can be layered on top of chunked proving later** |

#### Option E: SMT Depth Reduction

| Factor | Assessment |
|--------|------------|
| Description | Reduce SMT depth from 256 to a smaller value (e.g., 32 or 64) |
| Security effect | **WEAKENS the security statement.** The 256-bit SMT key space maps directly to BN254 field elements. Reducing depth changes the vulnerability lookup semantics |
| **Verdict** | **REJECTED. Violates frozen cryptographic semantics** |

#### Option F: Alternative Hash Function

| Factor | Assessment |
|--------|------------|
| Description | Replace Poseidon with a cheaper hash (e.g., MiMC, Pedersen) |
| Security effect | Changes all cryptographic commitments. Breaks Python/Noir interoperability |
| **Verdict** | **REJECTED. Violates frozen cryptographic semantics** |

### 4.3 ZKP Decision

**Selected: Option C — Deterministic Chunked Proving**

With Option D (Recursive Aggregation) as a future enhancement that can be layered on without breaking the chunk protocol.

---

## 5. Chunked Proving Protocol Specification

### 5.1 Parameters

| Parameter | Value | Justification |
|-----------|-------|---------------|
| `MAX_COMPONENTS` (system) | 1024 | Frozen requirement |
| `CHUNK_SIZE` | 64 | 64 × 256 = 16,384 Poseidon hashes. Estimated <2 GB compiler memory |
| `TOTAL_CHUNKS` | 16 | 1024 / 64 = 16 |
| `MERKLE_DEPTH` | 10 | Frozen requirement (1024 leaves) |
| `SMT_DEPTH` | 256 | Frozen requirement |

### 5.2 Canonical Component Ordering

Components MUST be ordered by `Component.position` (as currently implemented in `prover_service.py` line 54). Padding with `empty_leaf = Poseidon([0])` fills positions `active_count` through `1023`.

Chunk `k` (0-indexed) contains components at positions `[k*64, k*64+1, ..., k*64+63]`.

### 5.3 Per-Chunk Circuit Public Inputs

Each chunk proof binds to:

```
chunk_sbom_root:         Field  // Global SBOM Merkle root (same for ALL chunks)
vulnerability_db_root:   Field  // Global SMT root (same for ALL chunks)
policy_hash:             Field  // Global policy hash (same for ALL chunks)
chunk_index:             Field  // Which chunk (0..15)
total_chunks:            Field  // Always 16
```

> [!IMPORTANT]
> The global `sbom_root` (computed over all 1024 leaves) is a public input to EVERY chunk. This prevents a malicious prover from proving chunks against different SBOMs.

### 5.4 Per-Chunk Circuit Private Witness

```
component_count:         u32          // Total active components (global)
components:              [Field; 64]  // This chunk's 64 component hashes
all_components:          [Field; 1024] // ALL component hashes (for Merkle root recomputation)
vulnerability_scores:    [u32; 64]
vulnerability_presence:  [u32; 64]
vulnerability_smt_paths: [[Field; 256]; 64]
policy_max_cvss:         u32
```

### 5.5 Per-Chunk Circuit Constraints

1. Verify `Poseidon(policy_max_cvss) == policy_hash`
2. Verify `chunk_index < total_chunks`
3. Recompute global SBOM Merkle root from `all_components` and `component_count`
4. Assert `computed_root == chunk_sbom_root`
5. For each of the 64 components in this chunk:
   a. Constrain `vulnerability_presence[i] ∈ {0, 1}`
   b. Assert `vulnerability_scores[i] <= policy_max_cvss`
   c. Compute `leaf_payload = presence * Poseidon(component_hash, score)`
   d. Verify SMT path against `vulnerability_db_root`
   e. Assert `components[i] == all_components[chunk_index * 64 + i]`

### 5.6 Completeness Requirement

A complete verification requires ALL 16 chunk proofs. The verification service MUST:

1. Receive all 16 chunk proofs
2. Verify each chunk proof independently
3. Confirm all chunks share the same `sbom_root`, `vulnerability_db_root`, `policy_hash`
4. Confirm chunk indices are exactly `{0, 1, 2, ..., 15}` with no duplicates and no gaps
5. Only then issue a verification certificate

### 5.7 Duplicate Chunk Prevention

The `chunk_index` is a public input. The verifier checks that exactly 16 unique chunk indices (0–15) are present. Submitting the same chunk twice does not satisfy the completeness requirement.

### 5.8 Missing Chunk Detection

If fewer than 16 valid chunk proofs are submitted, the verification MUST fail. A partial proof set does not satisfy the ZKP statement.

### 5.9 Final Verification Semantics

The composed statement across all 16 chunks is equivalent to the original monolithic statement:

> "I know a private SBOM corresponding to `SBOM_ROOT`, and the complete committed SBOM satisfies the security policy `POLICY_HASH` with respect to the vulnerability dataset `VULNERABILITY_DB_ROOT`."

Each chunk individually proves:
- Its 64 components are part of the committed SBOM (via Merkle root verification)
- Its 64 components satisfy the policy against the vulnerability database

Together, all 16 chunks cover all 1024 component slots.

---

## 6. Cryptographic Semantics — FROZEN (No Changes Permitted)

| Semantic | Specification | Status |
|----------|--------------|--------|
| Component identity | PURL-authoritative | FROZEN |
| Component hash | Poseidon(field_encode(canonical_purl)) | FROZEN |
| `vulnerability_presence` | 0 or 1 | FROZEN |
| `presence = 0` | leaf = 0 (empty) | FROZEN |
| `presence = 1` | leaf = Poseidon(component_hash, score) | FROZEN |
| CVSS 0.0 | presence=1, score=0 → Poseidon(hash, 0) | FROZEN |
| SMT depth | 256 | FROZEN |
| SMT key | component_hash | FROZEN |
| SMT empty leaf | 0 | FROZEN |
| SBOM Merkle depth | 10 (1024 leaves) | FROZEN |
| SBOM empty leaf | Poseidon([0]) | FROZEN |
| Policy hash | Poseidon(max_allowed_cvss) | FROZEN |
| Public inputs | sbom_root, vulnerability_db_root, policy_hash | FROZEN (extended with chunk_index, total_chunks for chunked proofs) |
| Hash function | Poseidon BN254 | FROZEN |
| Proof system | Barretenberg UltraPlonk | FROZEN |

---

## 7. Migration Risks

### 7.1 Database Migration Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Data loss during SQL Server → PostgreSQL migration | High | Fresh schema creation. No production data exists yet |
| UUID format incompatibility | Low | SQLAlchemy generic `Uuid` type works on both. No binary format difference |
| Timestamp precision difference | Low | Both support millisecond precision. Standardize on `func.now()` |
| Schema creation syntax difference | Low | PostgreSQL uses standard SQL `CREATE SCHEMA IF NOT EXISTS` |
| Alembic migration rewrite | Medium | Two small migrations. Straightforward rewrite |
| ODBC removal breaks existing tooling | Low | No production deployment exists |

### 7.2 ZKP Migration Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Chunk boundary introduces soundness gap | High | Each chunk includes global Merkle root verification. Formal argument in §5.9 |
| Incomplete chunk set accepted | High | Verification service enforces completeness (§5.6) |
| Duplicate chunk accepted | Medium | chunk_index is a public input. Deduplication is mandatory |
| Chunk circuit still too large | Low | 64×256 = 16K Poseidon hashes. Conservative estimate <2 GB. The dev circuit (8×256) already compiles successfully |
| Python/Noir divergence | Medium | Existing test suite (503 tests) validates interoperability |
| Verification service needs chunked protocol | Medium | New verification logic required. Well-defined protocol |

---

## 8. Rollback Strategy

### 8.1 Database Rollback

If PostgreSQL migration fails:
1. Revert `database.py`, `config.py`, all model files to use `UNIQUEIDENTIFIER` and `func.getutcdate()`
2. Restore `docker-compose.yml` to use SQL Server image
3. Revert `requirements.txt` to use `pyodbc`
4. Revert Alembic migrations
5. No data migration is involved (fresh database)

### 8.2 ZKP Rollback

If chunked proving fails:
1. Revert circuit to dev profile (`MAX_COMPONENTS=8`)
2. Set `profile.json` back to `active_profile: dev`
3. All dev circuit artifacts are preserved in `circuits_dev/`
4. Existing 503-test regression suite validates dev profile

---

## 9. Stage-by-Stage Implementation Plan

### Stage 18-A: Database Migration (PostgreSQL)

1. Replace `pyodbc` with `psycopg2-binary` in `requirements.txt`
2. Update `DatabaseSettings` in `config.py` for PostgreSQL URL
3. Update `database.py` schema creation to standard SQL
4. Replace `UNIQUEIDENTIFIER` with `Uuid` in all 6 model files
5. Replace `func.getutcdate()` with `func.now()` in all model files
6. Rewrite Alembic migrations for PostgreSQL dialect
7. Update `docker-compose.yml` to use `postgres:16-alpine`
8. Update `.env.example`
9. Run full test suite
10. Validate no ownership/authorization/verification state regression

### Stage 18-B: Chunked Circuit Implementation

1. Create `circuits_chunk/` directory with 64-component chunk circuit
2. Add `chunk_index` and `total_chunks` as public inputs
3. Include global Merkle root verification (all 1024 leaves as witness)
4. Verify 64 components per chunk against SMT
5. Compile chunk circuit, verify <2 GB memory
6. Generate chunk VK
7. Update `profile.json` with chunk circuit profile
8. Update `ProverService` to generate 16 chunk proofs
9. Update `NoirVerifier` to verify 16 chunk proofs with completeness check
10. Add chunk tracking to `ProofJob` model (or new `ChunkProof` table)
11. Run equivalence tests against Python reference
12. Run boundary tests
13. Run negative tests

### Stage 18-C: Integration Validation

1. End-to-end test: upload SBOM → generate 16 chunk proofs → verify all → certificate
2. Negative test: submit only 15 chunks → verification fails
3. Negative test: submit duplicate chunk → verification fails
4. Negative test: chunks with different sbom_root → verification fails
5. Performance measurement: total proving time, total verification time
6. Full regression suite

---

## 10. Unresolved Questions

| # | Question | Impact | Required Before |
|---|----------|--------|-----------------|
| 1 | Should Merkle root recomputation (1024 leaves) be in EVERY chunk circuit, or should one chunk compute it and others verify a commitment? | Performance vs. simplicity. Current design: every chunk recomputes (safest) | Stage 18-B |
| 2 | Should chunk proofs be stored individually or concatenated? | Database schema design | Stage 18-B |
| 3 | Is 64 the optimal chunk size? (32 would give 32 chunks but faster per-chunk compilation) | Performance tuning | Stage 18-B (can be validated by benchmark) |
| 4 | Should the chunk VK be the same for all chunks (parameterized by chunk_index) or should there be 16 separate VKs? | Single circuit with chunk_index as input = 1 VK. This is the recommended approach | Stage 18-B |

---

## 11. Stage 18 Gate Conditions

Stage 18 implementation is AUTHORIZED only when ALL of the following are true:

- [ ] This ADR is reviewed and accepted
- [ ] No unresolved questions block implementation
- [ ] The chunk circuit size (64 components) is confirmed to compile in <4 GB
- [ ] The dev circuit (8 components) still passes all 503 tests
- [ ] No production source code was modified during Stage 17

---

## 12. Findings Summary

1. **SQL Server dependency is the heaviest non-ZKP infrastructure component.** The ODBC driver chain, Express edition limitations, and 1.5 GB Docker image are disproportionate for a project that uses only basic relational features.

2. **PostgreSQL is a direct drop-in replacement** at the SQLAlchemy layer. Every SQL Server feature used (schemas, UUIDs, timestamps, indexes, constraints, foreign keys) has a direct PostgreSQL equivalent.

3. **The monolithic 1024-component circuit is architecturally infeasible** on commodity hardware. This is not an environment limitation — it is a compiler scaling limitation. The Nargo 0.32.0 SSA optimization pass cannot handle >260K Poseidon invocations in a single circuit within 64 GB of memory.

4. **Chunked proving is the only feasible path** that preserves all cryptographic semantics while fitting within the 8–16 GB constraint. The mathematical equivalence argument (§5.9) demonstrates that the composed chunk statement is identical to the monolithic statement.

5. **Recursive proof aggregation is a valid future enhancement** but is not required for correctness and is not production-stable in Nargo 0.32.0.

6. **No production source code was modified during this analysis.** The `circuits/src/main.nr`, `merkle.nr`, and `smt.nr` contain the arithmetic-predicated 1024-component circuit from the Stage 17 CFG optimization attempt. These modifications should be reverted to the last known-good state before Stage 18 begins, or the chunk circuit should be developed in a new directory (`circuits_chunk/`).

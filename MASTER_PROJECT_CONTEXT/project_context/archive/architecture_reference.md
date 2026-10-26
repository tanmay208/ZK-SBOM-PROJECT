# Architecture & Technology Reference

**Freshness Date:** 2026-10-12  
**Purpose:** Technical reference covering system topology, security boundaries, cryptographic specifications, and data lifecycle.

---

## 1. Technology Stack

- **Frontend**: Next.js 16.3.5 (App Router), React 19.2.8, TypeScript, TanStack React Query, Vanilla CSS / Tailwind (where configured).
- **Backend Services**: Python 3.11 / 3.12, FastAPI 0.115.6, SQLAlchemy 2.0.36, Uvicorn 0.34.0, Alembic 1.14.1.
- **Persistence Layer**: PostgreSQL 15, psycopg2.
- **Zero-Knowledge Runtime**: Noir (Nargo 0.32.0 ACIR), Barretenberg UltraPlonk backend (`@noir-lang/backend_barretenberg@0.32.0` / `@aztec/bb.js` 0.46.1).
- **Gateway & Infrastructure**: Docker Compose, Nginx reverse proxy.

---

## 2. Directory Layout & Boundaries

- `backend/`: Python microservices, shared crypto libraries, migrations, and test suites.
  - `verification_service/`: Security-critical service. Binds proof jobs to authoritative database records; calls pinned Barretenberg verifier runtime; issues and validates certificates.
  - `zkp_service/`: Proving orchestration service. Manages proof-generation jobs, 32-component chunks, segment witness generation, and advisory locks.
  - `sbom_service/`: SBOM ingestion, normalization, component parsing, and Merkle tree root commitment generation.
  - `vulnerability_service/`: Vulnerability database ingestion, Sparse Merkle Tree (SMT) management, snapshot approval, and snapshot freezing.
  - `policy_service/`: Vulnerability policy creation, evaluation rules, and canonical policy hash commitments.
  - `shared/`: Shared DB models, auth guards, crypto primitives (`poseidon`, `merkle`, `smt`, `config`).
- `frontend/`: Next.js web application (Dashboard, SBOM Upload, Policy, Vulnerabilities, Proof Generation, Verification).
- `circuits/`, `segment_*/`: Noir circuit definitions for 32-component segments (`init`, `mid`, `final`).
- `archives/`: Evidence-bearing immutable proof bundles, verification keys (VKs), and manifest files.
- `docker/`: Nginx gateway configuration (`docker/nginx.conf`).
- `scripts/`: Benchmark harnesses, circuit size analyzers, and Golden Path automation.

---

## 3. Security Boundaries & Authorization Model

### A. Tenant Isolation (`AUD-A-001`)
- **Application Ownership**: Application records are strictly scoped by `(name, vendor, user_id)` with a database-level `UniqueConstraint`. Lookups never attach an upload to a different tenant's application record.
- **SBOM & Proof Job Scoping**: Queries for SBOMs, proof jobs, and verification requests filter on the authenticated user's `tenant_id` / `user_id` (or require `admin` role).

### B. Separation of Duties (`AUD-A-009`)
- **Vulnerability Ingestion**: Requires the `trusted_importer` role. Ingestion creates `pending` snapshots.
- **Snapshot Approval & Freezing**: Restricted to `admin` role. An importer cannot approve or freeze their own snapshot.
- **Snapshot Lifecycle State Machine**:
  $$\text{pending} \xrightarrow{\text{admin approve}} \text{approved} \xrightarrow{\text{admin freeze}} \text{frozen} \xrightarrow{\text{admin revoke}} \text{revoked}$$
- **Verification Prerequisite**: The backend verification service strictly validates that `snapshot.status == "frozen"` and matches on `authoritative_smt_root`. Proofs evaluated against unfrozen snapshots fail closed with `authoritative_record_mismatch`.

### C. Certificate Issuance & Revocation Model (`AUD-A-006`)
- **Issuance**: Issued only when `BarretenbergVerifier.verifyProof()` returns explicit Boolean `true`.
- **Signing**: Signed symmetrically using HS256 by the verification service authority.
- **Online Revocation**: Every verification or certificate lookup queries the database in real time. If `revoked_at` is set, the certificate is rejected immediately, overriding valid cryptographic signatures.

---

## 4. Cryptographic Specifications & Invariants

| Invariant | Specification | Enforcement Point |
|---|---|---|
| **Field Representation** | Canonical 32-byte big-endian BN254 scalar field elements | `backend/shared/crypto/poseidon.py` |
| **Hash Function** | Poseidon Sponge ($t=3$ for 2-to-1 Merkle nodes; $t=2$ for leaf commitments) | Circuit constraints and backend crypto primitives |
| **SBOM Tree Topology** | Binary Merkle Tree, Depth 10 (Capacity: $2^{10} = 1024$ components) | `backend/shared/crypto/merkle.py` |
| **Vulnerability SMT Topology** | Sparse Merkle Tree, Depth 256. Dynamic depth hash precomputation (`AUD-A-010`) | `backend/shared/crypto/smt.py` |
| **Circuit Decomposition** | 32 components per segment proof. Init $\rightarrow$ Mid* $\rightarrow$ Final sequential chain | `circuits/`, `backend/zkp_service` |
| **Legacy ACIR Proof Body** | Exactly 2144 bytes, pinned to `@noir-lang/backend_barretenberg@0.32.0` | `backend/verification_service/app/core/legacy_acir.py` |
| **Verification Strictness** | Only explicit Boolean `true` from `verifyProof()` constitutes valid proof | `backend/verification_service/app/core/verifier.py` |

### Public Input Binding Order
1. **`segment_init_32`** (5 inputs / 2304 bytes):  
   `[global_sbom_root, policy_hash, chunk_index, components_commit, hash_out_commit]`
2. **`segment_mid_32`** (4 inputs / 2272 bytes):  
   `[segment_index, components_commit, hash_in_commit, hash_out_commit]`
3. **`segment_final_32`** (3 inputs / 2240 bytes):  
   `[vulnerability_db_root, components_commit, hash_in_commit]`

---

## 5. Gateway Routing & Known Integration Caveat

`docker/nginx.conf` proxies upstream FastAPI services. Note trailing-slash configuration (`INT-DEF-004`):
- `/api/v1/auth/` $\rightarrow$ `auth-service`
- `/api/v1/sbom/` $\rightarrow$ `sbom-service`
- `/api/v1/policy/` $\rightarrow$ `policy-service`
- `/api/v1/vulnerability/` $\rightarrow$ `vulnerability-service`
- `/api/v1/zkp/` $\rightarrow$ `zkp-service`
- `/api/v1/verification/` $\rightarrow$ `verification-service`
- `/api/v1/metrics/` $\rightarrow$ `metrics-service`

*Frontend API client calls must harmonize trailing slashes in Stage C to prevent HTTP 404 proxy routing failures.*

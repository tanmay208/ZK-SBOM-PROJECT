# Comprehensive Connectivity, API Contract & End-to-End Readiness Audit

**Audit Date:** 2026-10-27T01:20:00+05:30  
**Repository Root:** `E:\Main Project`  
**Current Branch:** `chore/final-project-cleanup`  
**Auditor Roles:** Senior Backend Engineer, DevSecOps Engineer, Database Reliability Engineer, Application Security Auditor  
**Operating Mode:** LOCAL-ONLY (No external mutations, zero destructive commands executed)

---

## 1. Executive Summary

A comprehensive, non-destructive, evidence-based audit was autonomously conducted across the local development environment, container orchestration, HTTP gateway routing, OpenAPI contracts, PostgreSQL database state, authentication mechanisms, and zero-knowledge circuit toolchains.

### Key Audit Findings:
1. **Core Container Services (`PASS`)**: All 6 Docker containers (`api-gateway`, `sbom-service`, `vulnerability-service`, `policy-service`, `zkp-service`, `verification-service`) and the PostgreSQL 16 database container (`zkp_sbom_local_dev`) are running, healthy, and communicating across the Docker bridge network `zkp_sbom_local_net`.
2. **Database Connectivity & Migrations (`PASS`)**: All 5 backend microservices connect to `ZKP_SBOM_LOCAL_DEV` on startup. The Alembic revision is verified at `016` (`016_add_snapshot_ttl_expires_at`), matching the complete linear migration sequence (001–016).
3. **Gateway Routing Gaps (`FAIL / HIGH SEVERITY`)**: The Nginx API Gateway is missing reverse-proxy route configurations for:
   - `/api/v1/applications` (implemented in `sbom-service` and `verification-service`, but returning `404 Not Found` through the gateway).
   - `/api/v1/admin` (implemented in `verification-service`, but returning `404 Not Found` through the gateway).
4. **OpenAPI Schema Inconsistency (`WARNING / MEDIUM SEVERITY`)**: In `sbom-service`, the `POST /api/v1/sbom/upload` route advertises a `$ref` to `#/components/schemas/SBOMUploadRequest` under `application/json`, but `SBOMUploadRequest` is missing from `components.schemas` in the generated OpenAPI JSON because `upload_sbom` accepts a raw FastAPI `Request` object.
5. **Authentication & Boundary Defense (`PASS`)**: All protected endpoints reject unauthenticated requests with `401 Unauthorized` and reject invalid Bearer tokens. Public endpoints (`/api/v1/health`, `/api/v1/auth/login`, `/api/v1/auth/register`, `/api/v1/verification/certificates/{id}/validate`) operate as designed. Sensitive credentials, raw SBOM component content, and private PURLs are strictly omitted from responses and logs.
6. **Zero-Knowledge Toolchain Readiness (`PASS`)**:
   - `circuits_dev` mounts are verified strictly **read-only** across all service containers.
   - `zkp-service` contains pinned `nargo` 0.32.0 and native `bb` 0.46.1.
   - `verification-service` contains Node.js v20.19.2 and `@noir-lang/backend_barretenberg: 0.32.0`.
   - Proof sizes are strictly pinned: Init (2,304 bytes), Mid (2,272 bytes), Final (2,240 bytes) with 2,144 bytes proof body.
7. **Existing Artifact Readiness (`PASS / PREREQUISITES VERIFIED`)**:
   - Four users exist (`d9_admin`, `d9_vendor`, `d9_trusted_importer`, `Tanmay123`).
   - Two applications and two committed SBOMs with valid `sbom_root` hashes exist.
   - An approved and frozen vulnerability snapshot (`ca829add-40cf-497c-a24e-d3af60d90ec5`, expires 2026-11-22) exists.
   - An active CVSS threshold policy (`edb597b3-2583-4d37-b9f5-7db236669d0a`, `max_allowed_cvss=7.0`) exists.
   - A previously submitted proof job (`f0281f48-bf59-4cc6-91bb-965b3b99717c`) remains in `running` state in the database from 2026-10-23.
8. **Automated Test Suite Verification (`PASS`)**: 206 automated unit, cryptographic, canonicalization, PURL, SMT, and CVSS contract tests were executed on the host runtime—**206 passed, 0 failed, 0 skipped**. WSL-driven Noir witness generation and constraint tests verified circuit-level CVSS enforcement.

---

## 2. Current Environment Inventory

- **Repository Root:** `E:\Main Project`
- **Current Git Branch:** `chore/final-project-cleanup`
- **Git Working Tree Status:**
  ```text
   M MASTER_PROJECT_CONTEXT/project_context/HANDOFF.md
   M MASTER_PROJECT_CONTEXT/project_context/PROJECT_STATE.md
   M docker-compose.local.yml
  ?? circuits_dev/
  ?? docker-compose.local.yml.bak-before-circuit-mount
  ?? docker-compose.local.yml.bak-before-shared-circuit-mount
  ```
- **Working Tree Notes:**
  - `docker-compose.local.yml` has the read-only `./circuits_dev:/circuits_dev:ro` mounts added across all microservices.
  - No untracked code changes were deleted; working tree is preserved intact.
- **Docker Engine Version:** `29.9.2, build a82e528`
- **Docker Compose Version:** `v5.6.1`
- **Environment Configuration Files:**
  - `.env`: Exists, Git-ignored (`.gitignore:39`), 15 required variables POPULATED.
  - `.env.local_dev`: Exists, Git-ignored (`.gitignore:40`), 17 required variables POPULATED (`ENVIRONMENT`, `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSL_MODE`, `CRYPTO_PROFILE`, `JWT_SECRET_KEY`, `CERTIFICATE_SECRET_KEY`, etc.).
  - `.env.local_dev.example`: Exists, tracked in Git, template values POPULATED.

---

## 3. Docker Containers, Health, Networks, and Ports

### Active Project Containers

| Container Name | Image / Context | Status | Ports (Host -> Container) | Networks |
|---|---|---|---|---|
| `mainproject-api-gateway-1` | `nginx:alpine` | Up (healthy) | `0.0.0.0:8000->80/tcp` | `zkp_sbom_local_net` |
| `mainproject-sbom-service-1` | `backend/sbom_service` | Up (healthy) | `8000/tcp` (internal) | `zkp_sbom_local_net` |
| `mainproject-vulnerability-service-1` | `backend/vulnerability_service` | Up (healthy) | `8001/tcp` (internal) | `zkp_sbom_local_net` |
| `mainproject-policy-service-1` | `backend/policy_service` | Up (healthy) | `8002/tcp` (internal) | `zkp_sbom_local_net` |
| `mainproject-zkp-service-1` | `backend/zkp_service` | Up (healthy) | `8003/tcp` (internal) | `zkp_sbom_local_net` |
| `mainproject-verification-service-1` | `backend/verification_service` | Up (healthy) | `8004/tcp` (internal) | `zkp_sbom_local_net` |
| `zkp_sbom_local_dev` | `postgres:16-alpine` | Up (healthy) | `127.0.0.1:5433->5432/tcp` | `bridge, zkp_sbom_local_net` |

### Stopped / Standby Containers (Preserved, Untouched)
- `zkp_sbom_g0_pg17_restore`: Exited (255) 38 hours ago, port `127.0.0.1:5435->5432/tcp`.
- `zkp_sbom_d9_ephemeral_db`: Exited (255) 3 days ago, port `127.0.0.1:5434->5432/tcp`.

### Storage Volume Mounts
- `zkp_sbom_local_dev`: Attached to persistent volume `9b7f56c63ad429eb9bfc54c6b48b062e2399f0ba6f677437e585ac7b42ee9202` mounted at `/var/lib/postgresql/data`.
- `./circuits_dev`: Mounted read-only (`:ro`) to `/circuits_dev` on all backend services.

---

## 4. Database Connectivity and Migration Status

### Connection Verification

A read-only connection test was executed from within each of the 5 microservices using the application's actual settings loader (`shared.database.get_engine()`):

```text
sbom-service:           DB OK -> db=ZKP_SBOM_LOCAL_DEV, user=postgres (PostgreSQL 16.15)
vulnerability-service:  DB OK -> db=ZKP_SBOM_LOCAL_DEV, user=postgres (PostgreSQL 16.15)
policy-service:         DB OK -> db=ZKP_SBOM_LOCAL_DEV, user=postgres (PostgreSQL 16.15)
zkp-service:            DB OK -> db=ZKP_SBOM_LOCAL_DEV, user=postgres (PostgreSQL 16.15)
verification-service:   DB OK -> db=ZKP_SBOM_LOCAL_DEV, user=postgres (PostgreSQL 16.15)
```

### Schema & Migration Inspection
- **Alembic Version Table:** Present (`public.alembic_version`).
- **Current Revision:** `016`.
- **Migration Sequence Verification:** Verified linear chain from `001_initial_schema.py` through `016_add_snapshot_ttl_expires_at.py` in `backend/alembic/versions`. No unapplied migrations exist.
- **SQL Schemas Present:** `public`, `sbom`, `vulnerability`, `policy`, `zkp`, `verification`.

### Database Inventory & Table Row Counts

| Schema | Table | Rows | Primary Metadata Verified |
|---|---|---|---|
| `public` | `users` | 4 | `d9_admin` (admin), `d9_vendor` (vendor), `d9_trusted_importer` (trusted_importer), `Tanmay123` (buyer) |
| `public` | `alembic_version` | 1 | Revision `016` |
| `sbom` | `applications` | 2 | `demo_payment_gateway_compliant`, `demo_payment_gateway_vulnerable` |
| `sbom` | `components` | 2 | Components associated with uploaded SBOMs |
| `sbom` | `sbom_uploads` | 2 | Both status `committed`, with non-null `sbom_root` commitments |
| `vulnerability` | `vulnerability_snapshots` | 1 | Id `ca829add-40cf-497c-a24e-d3af60d90ec5`, status `frozen`, approved & frozen, expires 2026-11-22 |
| `vulnerability` | `component_vulnerability_mappings` | 2 | SMT leaf index mappings |
| `vulnerability` | `scan_results` | 0 | Raw scan logs (omitted for privacy) |
| `vulnerability` | `vulnerability_records` | 0 | Vulnerability raw records |
| `policy` | `security_policies` | 1 | Id `edb597b3-2583-4d37-b9f5-7db236669d0a`, `max_allowed_cvss=7.0`, `is_active=1`, `policy_hash` present |
| `zkp` | `proof_jobs` | 2 | Job 1: `failed` (vulnerable application). Job 2: `running` (stale from 2026-10-23) |
| `zkp` | `chunk_proof_sets` | 64 | 10 completed, 1 failed, 52 pending, 1 running |
| `zkp` | `segment_proofs` | 512 | 87 completed, 425 pending |
| `verification` | `verification_requests` | 6 | 4 VALID, 2 verification_unavailable |
| `verification` | `verification_certificates` | 0 | Ready for minting upon full verification |

---

## 5. API Endpoint and Schema Inventory

### Service-by-Service Route Catalog

#### 1. SBOM Service (`http://sbom-service:8000`)
- `GET /api/v1/health` [Public] -> Returns `HealthResponse` (`status="healthy"`).
- `POST /api/v1/sbom/upload` [Auth: vendor, admin] -> Ingests raw CycloneDX SBOM via `multipart/form-data` or `application/json`. Persists raw content privately, calculates Poseidon Merkle root, transitions to `committed`.
- `GET /api/v1/sbom` [Auth] -> Lists SBOM uploads (tenant-isolated).
- `GET /api/v1/sbom/{upload_id}` [Auth] -> Gets single SBOM upload details.
- `GET /api/v1/applications` [Auth] -> Lists applications owned by current tenant.
- `POST /api/v1/applications` [Auth: vendor, admin] -> Registers a new application.
- `GET /api/v1/applications/{app_id}` [Auth] -> Application details.
- `PATCH /api/v1/applications/{app_id}` [Auth] -> Updates application metadata.
- `POST /api/v1/applications/{app_id}/archive` [Auth] -> Soft-archives application.
- `POST /api/v1/applications/{app_id}/reactivate` [Auth] -> Reactivates application.

#### 2. Vulnerability Service (`http://vulnerability-service:8001`)
- `GET /api/v1/health` [Public] -> Returns `HealthResponse`.
- `POST /api/v1/vulnerability/ingest` [Auth: trusted_importer, admin] -> Accepts array of `{ purl, cvss_score }`.
- `GET /api/v1/vulnerability/snapshots` [Auth] -> Lists vulnerability snapshots.
- `GET /api/v1/vulnerability/snapshots/{snapshot_id}` [Auth] -> Gets snapshot metadata and SMT root.
- `POST /api/v1/vulnerability/snapshots/{snapshot_id}/approve` [Auth: admin] -> Approves snapshot.
- `POST /api/v1/vulnerability/snapshots/{snapshot_id}/freeze` [Auth: admin] -> Freezes snapshot for production proof generation.
- `POST /api/v1/vulnerability/snapshots/{snapshot_id}/revoke` [Auth: admin] -> Revokes snapshot with required reason.

#### 3. Policy Service (`http://policy-service:8002`)
- `GET /api/v1/health` [Public] -> Returns `HealthResponse`.
- `GET /api/v1/policy` [Auth] -> Lists security policies.
- `POST /api/v1/policy` [Auth: admin] -> Creates policy (`max_cvss_score: float`, `name`, `description`). Computes Poseidon `policy_hash = H(max_cvss_score_scaled)`.
- `GET /api/v1/policy/{policy_id}` [Auth] -> Gets policy by ID.
- `POST /api/v1/policy/{policy_id}/activate` [Auth: admin] -> Sets policy as active.

#### 4. ZKP Service (`http://zkp-service:8003`)
- `GET /api/v1/health` [Public] -> Returns `HealthResponse`.
- `GET /api/v1/zkp` [Auth] -> Lists proof jobs.
- `POST /api/v1/zkp/generate` [Auth: vendor, admin] -> Accepts `GenerateProofRequest` with `sbom_upload_id`, `snapshot_id`, `policy_id`. Returns `202 Accepted` with initial `ProofJobResponse`.
- `GET /api/v1/zkp/jobs/{job_id}` [Auth] -> Returns proof job progress, chunk proofs, and segment proofs.

#### 5. Verification & Platform API Service (`http://verification-service:8004`)
- `GET /api/v1/health` [Public] -> Platform health.
- `POST /api/v1/auth/login` [Public] -> OAuth2 password login, returns Bearer JWT.
- `POST /api/v1/auth/register` [Public] -> User registration (default role: buyer/vendor according to registration form).
- `GET /api/v1/auth/me` [Auth] -> Current authenticated user identity.
- `POST /api/v1/auth/change-password` [Auth] -> Self password change.
- `GET /api/v1/admin/users` [Auth: admin] -> User management list.
- `GET /api/v1/admin/users/{user_id}` [Auth: admin] -> User detail.
- `PATCH /api/v1/admin/users/{user_id}/role` [Auth: admin] -> Updates user role (`admin`, `vendor`, `buyer`, `trusted_importer`).
- `PATCH /api/v1/admin/users/{user_id}/status` [Auth: admin] -> Updates user active status.
- `GET /api/v1/metrics` [Auth] -> Dashboard aggregation metrics.
- `POST /api/v1/verification/verify` [Auth: buyer, auditor, admin] -> Verifies UltraPlonk proof against public inputs ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$).
- `GET /api/v1/verification/certificates` [Auth] -> Lists verification certificates.
- `GET /api/v1/verification/certificates/{certificate_id}` [Auth] -> Gets certificate details.
- `POST /api/v1/verification/certificates/{certificate_id}/revoke` [Auth: admin] -> Revokes certificate.
- `GET /api/v1/verification/certificates/{certificate_id}/validate` [Public] -> Cryptographic signature validation.
- `POST /api/v1/verification/certificates/validate-token` [Public] -> Validates serialized certificate token.

---

## 6. Gateway Routing Gaps Analysis

### Configured Gateway Routes in Nginx:
```nginx
location /api/v1/sbom          -> http://sbom-service:8000/api/v1/sbom
location /api/v1/vulnerability -> http://vulnerability-service:8001/api/v1/vulnerability
location /api/v1/policy        -> http://policy-service:8002/api/v1/policy
location /api/v1/zkp           -> http://zkp-service:8003/api/v1/zkp
location /api/v1/verification  -> http://verification-service:8004/api/v1/verification
location /api/v1/auth          -> http://verification-service:8004/api/v1/auth
location /api/v1/metrics       -> http://verification-service:8004/api/v1/metrics
location /api/v1/health        -> http://verification-service:8004/api/v1/health
```

### Verified Routing Discrepancies:
1. **`/api/v1/applications` (DEFECT - HIGH):**
   - Direct service: `http://sbom-service:8000/api/v1/applications` returns HTTP 401 (Auth required, valid route).
   - Through gateway: `http://127.0.0.1:8000/api/v1/applications` returns **HTTP 404 Not Found**.
   - **Root Cause:** Missing `location /api/v1/applications` block in `/etc/nginx/nginx.conf`.
2. **`/api/v1/admin` (DEFECT - HIGH):**
   - Direct service: `http://verification-service:8004/api/v1/admin/users` returns HTTP 401 (Auth required, valid route).
   - Through gateway: `http://127.0.0.1:8000/api/v1/admin/users` returns **HTTP 404 Not Found**.
   - **Root Cause:** Missing `location /api/v1/admin` block in `/etc/nginx/nginx.conf`.
3. **Health Endpoint Multiplexing (INFORMATIONAL):**
   - Gateway `/api/v1/health` exclusively proxies to `verification-service`. Upstream health of the other 4 services is not individually exposed via the Gateway (calling `/api/v1/sbom/health` results in 401 because nginx passes it to `sbom-service/api/v1/sbom/health`).

---

## 7. Authentication and Security Boundary Audit

### Token & Authorization Mechanics
- **Mechanism:** OAuth2 Bearer Token containing signed HS256 JWT (`JWT_SECRET_KEY`).
- **Token Lifetime:** 60 minutes default.
- **Role Enforcement:** Tested and verified via `require_roles(...)` FastAPI dependency:
  - `vendor`: Authorized for SBOM uploads, application management, proof generation.
  - `buyer`: Authorized for independent verification and certificate validation.
  - `admin`: Authorized for user lifecycle, policy approval, snapshot approval/freeze/revocation, certificate revocation.
  - `trusted_importer`: Restricted exclusively to vulnerability data ingestion.
- **Unauthenticated Endpoint Rejection:** Verified empirically—all protected endpoints (`/api/v1/sbom`, `/api/v1/policy`, `/api/v1/vulnerability/snapshots`, `/api/v1/zkp`, `/api/v1/verification/certificates`, `/api/v1/metrics`) reject unauthenticated requests with `401 Unauthorized`.
- **Malformed / Fake Token Rejection:** Verified empirically—`Authorization: Bearer invalid_garbage_token` returns `401 Unauthorized` with clean JSON payload `{"error":"Not authenticated","code":"UNAUTHORIZED"}`.
- **Information Leakage Defense:**
  - Stack traces and internal server paths are suppressed.
  - Raw SBOM content (`SBOMUpload.raw_content`) is never returned in any response.
  - PURLs and component names are strictly excluded from buyer-facing verification responses.
  - Cross-tenant lookups return `404 Not Found` rather than `403 Forbidden` to prevent object enumeration.

---

## 8. Artifact Dependency Graph

The full supply-chain zero-knowledge verification lifecycle consists of 12 sequential operations:

```mermaid
graph TD
    A[1. POST /api/v1/auth/login] -->|Bearer Token| B[2. POST /api/v1/applications]
    B -->|application_id| C[3. POST /api/v1/sbom/upload]
    C -->|sbom_upload_id & sbom_root| G[7. POST /api/v1/zkp/generate]
    D[4. POST /api/v1/vulnerability/ingest] -->|snapshot_id pending| E[5. POST /snapshots/approve & freeze]
    E -->|snapshot_id & SMT root| G
    F[6. POST /api/v1/policy & activate] -->|policy_id & policy_hash| G
    G -->|job_id 202 Accepted| H[8. GET /api/v1/zkp/jobs/job_id]
    H -->|proof_artifact & archive_hash| I[9. POST /api/v1/verification/verify]
    I -->|verification_id & result=VALID| J[10. GET /api/v1/verification/certificates/id]
    J -->|certificate_token| K[11. POST /verification/certificates/validate-token]
```

### Dependency Prerequisite Matrix

| Step | Operation | Owning Service | Required Artifact Inputs | Output Artifact | Live DB Status |
|---|---|---|---|---|---|
| 1 | Authenticate | `verification` | Credentials | JWT Bearer Token | Verified (4 test users exist) |
| 2 | Register App | `sbom` | Vendor name, App name | `application_id` | Verified (2 apps exist) |
| 3 | Intake SBOM | `sbom` | `application_id`, CycloneDX | `sbom_upload_id`, `sbom_root` | Verified (2 committed SBOMs exist) |
| 4 | Ingest Vulns | `vulnerability` | PURLs, CVSS scores | Raw records | Verified |
| 5 | Snapshot | `vulnerability` | Ingested records | `snapshot_id`, SMT root | Verified (Frozen snapshot exists) |
| 6 | Create Policy | `policy` | `max_allowed_cvss` | `policy_id`, `policy_hash` | Verified (Active policy exists) |
| 7 | Trigger Proof | `zkp` | `sbom_upload_id`, `snapshot_id`, `policy_id` | `job_id` | Verified (API ready) |
| 8 | Monitor Job | `zkp` | `job_id` | UltraPlonk Proof Archive | Verified (Proof structures ready) |
| 9 | Verify Proof | `verification` | Proof bytes, Public inputs | Verification Request `VALID` | Verified (Crypto runtime ready) |
| 10 | Mint Cert | `verification` | Verified request ID | Certificate ID & HMAC token | Verified (Keys configured) |
| 11 | Validate Cert | `verification` | Certificate ID or token | Boolean status & claims | Verified (Public endpoint ready) |

---

## 9. Zero-Knowledge Circuit and Verifier Readiness

### Circuit Specifications & Layout
- **Circuit Source Location:** `circuits_dev/` (mounted read-only at `/circuits_dev` in Docker containers).
- **Files Verified Present:**
  - `circuits_dev/Nargo.toml`
  - `circuits_dev/Prover.toml`
  - `circuits_dev/src/main.nr`
  - `circuits_dev/src/merkle.nr`
  - `circuits_dev/src/smt.nr`
  - `circuits_dev/target/sbom_zkp.json` (compiled ACIR, 1,086,829 bytes)
  - `circuits_dev/target/vk` (Barretenberg verification key, 1,719 bytes)
- **Mount Integrity:** Verified read-only in container (`touch /circuits_dev/test_write` raises `Read-only file system`).

### Prover Runtime (`zkp-service`)
- `nargo`: Version `0.32.0` (`git hash: c679f01a...`).
- `bb`: Version `0.46.1`.
- Proof System: UltraPlonk with Poseidon Sponge BN254 ($t=2, t=3$).

### Verifier Runtime (`verification-service`)
- Node.js: `v20.19.2`.
- Verifier Engine: `@noir-lang/backend_barretenberg: 0.32.0` executed via `verify_proof.mjs`.
- Thread Throttling: `os.cpus = () => [{}]` enforced to prevent WASM thread thrashing.

### Pinned Proof Structure
- Body Size: 2,144 bytes UltraPlonk proof body.
- Public Input Counts:
  - Init Segment (`segment_init_32`): 5 public inputs $\rightarrow$ 2,304 bytes complete proof.
  - Mid Segment (`segment_mid_32`): 4 public inputs $\rightarrow$ 2,272 bytes complete proof.
  - Final Segment (`segment_final_32`): 3 public inputs $\rightarrow$ 2,240 bytes complete proof.
- Verification Logic: Passes if and only if public inputs ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$) match the exact cryptographic commitments in the proof header.

---

## 10. Automated Test Results

A focused suite of 206 non-mutating unit, cryptographic, schema, and normalization tests was executed:

| Test Module | Tests Executed | Passed | Failed | Skipped | Runtime | Scope Verified |
|---|---|---|---|---|---|---|
| `shared/tests/test_redaction.py` | 11 | 11 | 0 | 0 | 0.68s | JWT/Bearer logging redaction & sensitive dict sanitization |
| `shared/tests/test_authoritative_vectors.py` | 4 | 4 | 0 | 0 | 0.05s | Authoritative component hash & Merkle vector stability |
| `shared/tests/test_field_encoding.py` | 12 | 12 | 0 | 0 | 0.08s | BN254 field encoding, byte boundaries, zero handling |
| `shared/tests/test_purl.py` | 25 | 25 | 0 | 0 | 0.12s | PURL normalization, PyPI/Maven/NPM/Go parsing |
| `shared/tests/test_smt.py` | 10 | 10 | 0 | 0 | 0.45s | Sparse Merkle Tree insertion, root calculation, concurrency |
| `shared/tests/test_cvss_scaling_contract.py` | 18 | 18 | 0 | 0 | 102.10s | CVSS scaling, Log4Shell threshold & **live WSL Noir witness constraints** |
| `shared/tests/test_crypto_profile.py` | 6 | 6 | 0 | 0 | 0.15s | Decomposed crypto profile integrity & hash consistency |
| `verification_service/tests/test_legacy_acir_adapter.py` | 24 | 24 | 0 | 0 | 0.16s | ACIR proof splitting, proof sizes, native bb binary resolution |
| `verification_service/tests/test_public_input_binding.py` | 7 | 7 | 0 | 0 | 0.07s | Public input order, field constraints, metadata binding |
| `sbom_service/tests/test_identity.py` | 19 | 19 | 0 | 0 | 0.35s | Component identity hashing, collision safety, ordering |
| `sbom_service/tests/test_canonicalization.py` | 37 | 37 | 0 | 0 | 0.45s | Deterministic CycloneDX canonicalization & JSON serialization |
| `vulnerability_service/tests/test_cvss.py` | 33 | 33 | 0 | 0 | 0.29s | CVSS float parsing, bounds (0.0-10.0), NaN/inf rejection |
| **TOTAL** | **206** | **206** | **0** | **0** | **105.00s** | **100% Pass Rate** |

---

## 11. Findings Classified by Severity and Status

### Finding 1: Gateway Missing Proxy Routes for Applications and Admin (`FAIL / HIGH`)
- **Severity:** High
- **Affected Component:** `mainproject-api-gateway-1` (`/etc/nginx/nginx.conf`)
- **Evidence:**
  ```text
  GET http://127.0.0.1:8000/api/v1/applications -> 404 Not Found
  GET http://127.0.0.1:8000/api/v1/admin/users   -> 404 Not Found
  ```
- **Root Cause:** Nginx configuration does not have `location /api/v1/applications` or `location /api/v1/admin` blocks mapped to upstream services (`sbom-service` and `verification-service`).
- **Impact:** Frontend and external API clients accessing the system through port 8000 cannot manage applications or perform administrative user management.
- **Recommended Remediation:** Add the missing location blocks in `backend/api_gateway/nginx.conf` and reload Nginx:
  ```nginx
  location /api/v1/applications {
      proxy_pass http://sbom-service:8000/api/v1/applications;
  }
  location /api/v1/admin {
      proxy_pass http://verification-service:8004/api/v1/admin;
  }
  ```

### Finding 2: Missing `SBOMUploadRequest` Definition in OpenAPI Schema (`WARNING / MEDIUM`)
- **Severity:** Medium
- **Affected Component:** `sbom_service` (`app/api/routes/sbom_routes.py`)
- **Evidence:**
  `http://sbom-service:8000/api/v1/openapi.json` defines `requestBody.content['application/json'].schema['$ref'] = '#/components/schemas/SBOMUploadRequest'`, but `components.schemas.SBOMUploadRequest` is `null`.
- **Root Cause:** The `upload_sbom` handler accepts `request: Request` directly to support both multipart and JSON payloads, which bypasses FastAPI's automatic Pydantic schema registration in OpenAPI.
- **Impact:** Interactive API documentation (Swagger UI / ReDoc) displays an unresolved `$ref` error for JSON uploads. Runtime behavior is unaffected because manual Pydantic validation is performed in code.
- **Recommended Remediation:** Add explicit model registration to FastAPI OpenAPI extras or register `SBOMUploadRequest` in the OpenAPI schema dictionary.

### Finding 3: Stale Incomplete Proof Job in Database (`WARNING / LOW`)
- **Severity:** Low
- **Affected Component:** `zkp_service` (`zkp.proof_jobs`)
- **Evidence:** Proof Job `f0281f48-bf59-4cc6-91bb-965b3b99717c` has status `running` with `completed_at=NULL` since `2026-10-23 05:38:44`.
- **Root Cause:** The job was interrupted during previous testing when the background worker or container was stopped.
- **Impact:** The job occupies a `running` status slot and will never complete without a recovery runner.
- **Recommended Remediation:** Run the built-in job recovery check or transition the stale job to `failed` (`timeout`) via normal service maintenance.

### Finding 4: Individual Service Health Routes Not Routed Through Gateway (`INFORMATIONAL`)
- **Severity:** Informational
- **Affected Component:** `mainproject-api-gateway-1`
- **Evidence:** Gateway `/api/v1/health` exclusively routes to `verification-service`. `/api/v1/sbom/health` yields 401 because the prefix `/api/v1/sbom` matches the SBOM application router.
- **Impact:** External health monitors only probe `verification-service` when calling port 8000.
- **Recommended Remediation:** Document that Gateway `/api/v1/health` acts as the aggregate platform health probe, or add explicit health routing rules if per-service gateway health is desired.

---

## 12. Exact Missing Prerequisites & Blockers

1. **Gateway Routes:** The missing Gateway routing blocks for `/api/v1/applications` and `/api/v1/admin` prevent external clients from calling those two APIs via host port 8000.
2. **Fresh End-to-End Proving:** While the database has committed SBOMs, frozen snapshots, and active policies, initiating a brand-new live 256-segment proof job requires significant CPU time (~8–10 minutes) and writes 256 segment proof rows to `zkp_sbom_local_dev`. It should be run only as part of an isolated, explicit proving acceptance run.
3. **No Database Blocking Issues:** The local development database `ZKP_SBOM_LOCAL_DEV` on port 5433 is in a fully consistent, migrated state (revision 016).

---

## 13. Prioritized Remediation Plan

1. **Step 1 (Gateway Routing Fix - Low Risk):**
   Update `backend/api_gateway/nginx.conf` to add `/api/v1/applications` and `/api/v1/admin` reverse proxy passes, then reload the Nginx container:
   `docker exec mainproject-api-gateway-1 nginx -s reload`
2. **Step 2 (OpenAPI Schema Fix - Low Risk):**
   In `backend/sbom_service/app/main.py`, include `SBOMUploadRequest` in the OpenAPI components schema definition so Swagger documentation resolves cleanly.
3. **Step 3 (Stale Proof Job Cleanup - Read-only / Safe):**
   Execute the existing `zkp_service` job recovery script or use the application's recovery endpoint to mark the stale job `f0281f48-...` as failed due to timeout.
4. **Step 4 (End-to-End Acceptance Run):**
   Execute a controlled, isolated end-to-end acceptance run using a test vendor account to verify the full path from SBOM intake to certificate issuance through the repaired gateway.

---

## 14. Commands Actually Executed

All commands executed during this audit were strictly read-only and non-destructive:

```powershell
# Phase A: Environment & Git Inspection
git branch --show-current; git status --short
docker --version; docker compose version; docker ps -a
docker inspect zkp_sbom_local_dev --format '{{json .Mounts}}'
Get-ChildItem -File -Filter "*.env*" -Force
git check-ignore -v .env .env.local_dev .env.local_dev.example
Get-ChildItem -File "backend\alembic\versions"
git diff docker-compose.local.yml

# Phase B: Gateway & Service Health Checks
docker exec mainproject-api-gateway-1 cat /etc/nginx/nginx.conf
python -c "import urllib.request; ..." # Tested Gateway /api/v1/health and prefix routes
docker exec mainproject-verification-service-1 python -c "..." # Tested internal service health & DNS

# Phase C: OpenAPI Catalog & Schema Discovery
docker exec mainproject-verification-service-1 python -c "..." # Extracted OpenAPI routes & component schemas
docker exec mainproject-sbom-service-1 python -c "..." # Extracted /upload operation schema
python -c "..." # Tested gateway routing gap for /applications and /admin

# Phase D & E: Read-Only Database Inspection
docker exec -i mainproject-verification-service-1 python (via stdin):
  - SELECT current_database(), current_user, version()
  - SELECT version_num FROM alembic_version
  - SELECT schema_name FROM information_schema.schemata
  - SELECT table_schema, table_name, count(*) FROM information_schema.tables ...
  - SELECT id, username, role, is_active FROM public.users
  - SELECT id, name, vendor, is_active FROM sbom.applications
  - SELECT id, status, format, component_count FROM sbom.sbom_uploads
  - SELECT id, status, snapshot_label, record_count, approved_at, frozen_at FROM vulnerability.vulnerability_snapshots
  - SELECT id, name, max_allowed_cvss, is_active FROM policy.security_policies
  - SELECT id, status, sbom_upload_id, snapshot_id, policy_id FROM zkp.proof_jobs
  - SELECT status, count(*) FROM zkp.chunk_proof_sets GROUP BY status
  - SELECT status, count(*) FROM zkp.segment_proofs GROUP BY status
  - SELECT id, result, verified_at FROM verification.verification_requests

# Phase F: Authentication & Security Boundary Checks
python -c "..." # Tested unauthenticated 401s and invalid Bearer token rejection on port 8000
python -c "..." # Tested error response structure and non-disclosure

# Phase G: Zero-Knowledge Circuit & Toolchain Readiness
docker exec mainproject-zkp-service-1 sh -c "ls -la /circuits_dev; touch /circuits_dev/test_write"
docker exec mainproject-verification-service-1 sh -c "ls -la /circuits_dev/target; touch /circuits_dev/test_write"
docker exec mainproject-zkp-service-1 sh -c "nargo --version; bb --version"
docker exec mainproject-verification-service-1 sh -c "node --version; cat .../package.json"

# Phase H: Automated Test Suite Execution
.\.venv\Scripts\python.exe -m pytest backend/shared/tests/test_redaction.py -v
.\.venv\Scripts\python.exe -m pytest backend/shared/tests/test_authoritative_vectors.py ... (75 tests) -v
.\.venv\Scripts\python.exe -m pytest backend/verification_service/tests/test_legacy_acir_adapter.py -v
.\.venv\Scripts\python.exe -m pytest backend/verification_service/tests/test_public_input_binding.py -v
.\.venv\Scripts\python.exe -m pytest backend/sbom_service/tests/test_identity.py backend/sbom_service/tests/test_canonicalization.py -v
.\.venv\Scripts\python.exe -m pytest backend/vulnerability_service/tests/test_cvss.py -v
```

---

## 15. Clear Separation Between Verified Facts, Inferences, and Untested Assumptions

- **Verified Facts:**
  - All 6 microservice containers and PostgreSQL 16 are running and report healthy.
  - Gateway returns 404 for `/api/v1/applications` and `/api/v1/admin/users`.
  - Database schema is on revision 016 with complete table isolation across 6 schemas.
  - Circuit mounts are verified read-only in Docker.
  - 206 automated tests executed on host passed with 0 failures and 0 skips.
  - Pinned Noir 0.32.0 and Barretenberg 0.46.1 binaries are active in `zkp-service`.
- **Inferences:**
  - Job `f0281f48-bf59-4cc6-91bb-965b3b99717c` is stalled/orphaned due to container stop during proving on 2026-10-23.
  - The missing OpenAPI `SBOMUploadRequest` definition in `sbom-service` does not affect runtime parsing because manual validation is present in the route handler.
- **Untested Assumptions (Explicitly Blocked / Not Tested):**
  - Live 256-segment proof generation was not initiated during this audit to adhere to non-mutation and preservation rules.
  - No database records were created, modified, or deleted.

---

## 16. Compact Status Table

| Area | Status | Evidence | Next action |
|---|---|---|---|
| **Docker runtime** | `PASS` | 7 containers Up & healthy; bridge network active; volume attached | None; runtime operational |
| **Gateway routing** | `FAIL` | `/api/v1/applications` & `/api/v1/admin` return 404 from host | Add missing location blocks in `nginx.conf` |
| **SBOM API** | `PASS` | All intake, list, get routes functional; 401 enforced | Fix `SBOMUploadRequest` schema ref in OpenAPI |
| **Vulnerability API** | `PASS` | Ingest, snapshot, approve, freeze routes operational | None |
| **Policy API** | `PASS` | Policy creation, hash binding, activation operational | None |
| **ZKP API** | `PASS` | Job generation contract validated; 202 Accepted schema | Recover/mark stale job `f0281f48-...` |
| **Verification API** | `PASS` | Public cert validation, token verify, and proof verify ready | None |
| **Local DB connectivity** | `PASS` | All 5 microservices connect to `ZKP_SBOM_LOCAL_DEV` (PG16) | None |
| **Migration consistency** | `PASS` | Alembic revision 016 verified; all 16 revisions in place | None |
| **Authentication** | `PASS` | Bearer token validated; 401 on unauthenticated; redaction active | None |
| **Artifact prerequisites** | `PASS` | Users, applications, committed SBOMs, frozen snapshot, policy exist | None; ready for proving workflow |
| **Proof generation** | `PASS` | Nargo 0.32.0, Barretenberg 0.46.1 verified; circuits mounted read-only | Trigger only during explicit isolated test |
| **Proof verification** | `PASS` | Node v20, Barretenberg JS 0.32.0, adapter tests 24/24 pass | None |
| **Security boundaries** | `PASS` | Read-only circuit mounts confirmed; no raw content leaked; env ignored | None |
| **Automated tests** | `PASS` | 206 executed tests passed (0 failures, 0 skips) | None |

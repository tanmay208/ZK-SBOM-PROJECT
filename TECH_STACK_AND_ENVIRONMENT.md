# Technical Stack, Runtime Environment & Architecture Specification

**Project:** Zero-Knowledge Verification for Software Supply Chain Security  
**Workspace Root:** `E:\Main Project`  
**Authoritative Documentation Root:** [`MASTER_PROJECT_CONTEXT/`](MASTER_PROJECT_CONTEXT/)  
**Roadmap Baseline:** [Official Locked Roadmap V3](MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md)  
**Effective Date:** 26 October 2026  
**Document Status:** Canonical Technical Specification  


---

## 1. Project Overview

### 1.1 Purpose and Principal Workflow
This system is an academic research and engineering prototype enabling privacy-preserving software supply-chain compliance verification. A software vendor proves that their Software Bill of Materials (SBOM) complies with a specific security policy against an authoritative vulnerability database snapshot using zero-knowledge proofs (UltraPlonk / ACIR circuits).

The verification binds to three public cryptographic commitments:
1. $R_{\text{SBOM}}$: Sparse Merkle Tree (SMT) root commitment of the private SBOM component identities.
2. $R_{\text{VulnDB}}$: SMT root commitment of the authoritative vulnerability intelligence snapshot.
3. $H_{\text{Policy}}$: Cryptographic hash commitment of the security policy rules (CVSS threshold, severity limits, excluded package versions).

A buyer or third-party auditor independently verifies the zero-knowledge proof and consults an authorized verification certificate **without receiving, viewing, or leaking the supplier's private component inventory**.

### 1.2 Implemented Scope vs. Deferred Boundaries
- **Implemented Scope:** 5 backend FastAPI services, Next.js 15 App Router frontend consolidated into 3 roles (Vendor, Buyer, Admin), 32-attribute decomposed SMT Noir circuits (`segment_init_32`, `segment_mid_32`, `segment_final_32`), UltraPlonk proof verification via Barretenberg 0.46.1, linear database migrations 001 through 016, in-memory bearer authentication, token revocation, snapshot TTL enforcement, and cross-role automated regressions.
- **Explicitly Deferred Scope:** Production cloud deployment, external TLS/HTTPS certificate termination, production ingress/load balancing, payment infrastructure, third-party SSO/OAuth providers, and email verification.

---

## 2. Technology Stack Inventory

| Component / Layer | Technology | Version / Constraint | Responsibility | Classification | Evidence Path |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Circuit Language** | Noir | `0.32.0` | SMT zero-knowledge circuit definitions | Core Crypto | [`segment_init_32/Nargo.toml`](segment_init_32/Nargo.toml) |
| **Proving Backend** | Barretenberg | `0.46.1` | UltraPlonk proof generation & verification | Core Crypto | [`scripts/setup_crypto_runtime.ps1`](scripts/setup_crypto_runtime.ps1) |
| **Crypto Runtime Launcher** | Native C | Native binary (`bb.exe`) | High-performance ACVM/witness execution | Runtime Tooling | [`scripts/bb_launcher.c`](scripts/bb_launcher.c) |
| **Elliptic Curve** | BN254 (Alt-bn128) | $r \approx 2^{254}$ | Scalar field arithmetic and SMT commitments | Core Crypto | [`scripts/bn254.nr`](scripts/bn254.nr) |
| **Hash Function** | Poseidon Sponge | $t=2, t=3$ | SMT node hashing & policy commitment | Core Crypto | [`scripts/perm.nr`](scripts/perm.nr), [`scripts/mod.nr`](scripts/mod.nr) |
| **Backend Framework** | FastAPI | `0.115.6` | REST API service definitions & middleware | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **ASGI Server** | Uvicorn | `0.34.0` | High-performance async ASGI web server | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **Data Validation** | Pydantic | `2.10.4` | Request/response schema validation | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **Database ORM** | SQLAlchemy | `2.0.36` | Relational object modeling & query builder | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **Database Driver** | psycopg2-binary | `2.9.10` | PostgreSQL database connection driver | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **Database Engine** | PostgreSQL | `17.x` | Relational data persistence & tenant isolation | Infrastructure | [`docker-compose.local.yml`](docker-compose.local.yml) |
| **Database Migrations** | Alembic | `1.14.1` | Linear schema migrations (001 to 016) | Direct Runtime | [`backend/alembic/env.py`](backend/alembic/env.py) |
| **Password Hashing** | bcrypt | `5.0.0` | Cryptographic password hashing for user accounts | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **Token Authentication** | PyJWT | `2.12.1` | HMAC-SHA256 JWT bearer token creation & validation | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **Multipart Parsing** | python-multipart | `0.0.32` | File upload streaming for SBOM JSON ingestion | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **SBOM PURL Parser** | packageurl-python | `0.16.0` | Package URL (PURL) normalization & matching | Direct Runtime | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **Environment Tooling** | python-dotenv | `1.2.3` | Local `.env` loading for development & CLI | Development/CLI | [`requirements.txt`](requirements.txt) |
| **Backend Testing** | pytest | `8.3.4` | Automated test runner & assertions | Development/Test | [`requirements-dev.txt`](requirements-dev.txt) |
| **HTTP Test Client** | httpx | `0.28.1` | Async HTTP client for FastAPI integration tests | Development/Test | [`requirements-dev.txt`](requirements-dev.txt) |
| **Frontend Framework** | Next.js | `15.x` | App Router server-side & client-side rendering | Direct Frontend | [`frontend/package.json`](frontend/package.json) |
| **Frontend UI Library** | React | `19.x` | Component view library | Direct Frontend | [`frontend/package.json`](frontend/package.json) |
| **Styling** | Vanilla CSS / Tailwind | `Version not pinned` | Layout, slate theme, responsive surfaces | Direct Frontend | [`frontend/src/app/globals.css`](frontend/src/app/globals.css) |
| **Icons** | Lucide React | `^1.16.0` | UI icon set | Direct Frontend | [`frontend/package.json`](frontend/package.json) |
| **Reverse Proxy** | Nginx | `alpine` | Internal gateway routing `/api/v1/...` on port 8000 | Containerization | [`docker/nginx.conf`](docker/nginx.conf) |

---

## 3. Languages and Runtime Versions

- **Python Runtime:** Python `3.11.x` (Targeted in all backend Dockerfiles via `python:3.11-slim`). Compatible with Python 3.11 through 3.12.
- **Node.js Runtime:** Node.js `20.x` or `22.x` LTS.
- **Package Managers:**
  - Python: `pip >= 24.0`
  - JavaScript: `npm >= 10.0` (using `package-lock.json`)
- **Native C Compiler:** `gcc` (MinGW-w64 on Windows or `build-essential` on Linux) or MSVC `cl.exe` (for compiling native `bb_launcher.c`).
- **Noir Toolchain:** `nargo 0.32.0` (installed via `noirup -v 0.32.0`).
- **Barretenberg Toolchain:** `bb 0.46.1` (installed via `bbup -v 0.46.1`).

---

## 4. Python Dependency Management

### 4.1 Dependency File Structure
- [`backend/shared/requirements.txt`](backend/shared/requirements.txt): Authoritative list of pinned core service dependencies. Referenced during Docker layer builds for all 5 services to maximize layer caching.
- [`requirements.txt`](requirements.txt): Root developer runtime manifest. Includes `-r backend/shared/requirements.txt` and `python-dotenv==1.2.3` for CLI scripts and local database migrations.
- [`requirements-dev.txt`](requirements-dev.txt): Testing and development manifest. Includes `-r requirements.txt`, `pytest==8.3.4`, and `httpx==0.28.1`.

### 4.2 Non-Python Tools Excluded from Requirements
System binaries (`nargo`, `bb`, `gcc`), Node.js packages (`next`, `react`), and container images (`postgres`, `nginx`) are strictly managed outside Python manifests.

---

## 5. Frontend & JavaScript Tooling

### 5.1 Architecture & Role Consolidation
The frontend is built on **Next.js 15 App Router** under `frontend/src/app/`. Under Stage G, visible product surfaces were consolidated into 3 operational roles:
- `/dashboard`: Consolidated role workspace and metrics overview.
- `/sboms` & `/sboms/upload`: Vendor SBOM upload, component inspection, and commitment generation.
- `/proofs` & `/proofs/generate`: Vendor UltraPlonk proof job dispatching and progress monitoring.
- `/verify`: Independent Buyer proof verification and commitment matching.
- `/certificates`: Buyer and auditor cryptographic certificate inspection.
- `/admin/policies`: Security policy management ($H_{\text{Policy}}$ thresholds).
- `/admin/vulnerabilities`: Vulnerability snapshot inspection and TTL status.
- `/admin/users`: User role management and active account controls.

### 5.2 Authentication & In-Memory Privacy
Bearer tokens are held strictly in memory (`authTransport.ts`) and cleared on page refresh or logout. This guarantees zero residual token exposure in `localStorage` or `sessionStorage`. Client-side route access is enforced via [`RouteGuard.tsx`](frontend/src/auth/RouteGuard.tsx).

---

## 6. Database and Migrations

### 6.1 Database Engine & Target Isolation
- **Presentation Target:** Supabase PostgreSQL 17 on `127.0.0.1:5432` (`aws-0-ap-southeast-2.pooler.supabase.com`). Contains seeded presentation fixtures; read-only during regression tests.
- **Automated Regression Target:** Docker PostgreSQL 17 on `127.0.0.1:5435` (`zkp_sbom_g2_integration`). Dedicated target for automated test suites.
- **Excluded Target:** Docker PostgreSQL 16 on `127.0.0.1:5433` is excluded from Stage G.

### 6.2 Relational Schemas
The database is partitioned into 6 distinct PostgreSQL schemas:
1. `public`: User accounts, authentication status, and `alembic_version`.
2. `sbom`: Applications, SBOM uploads, components, and package identifiers.
3. `vulnerability`: Ingested CVE records, CVSS scores, vulnerability mappings, and snapshots.
4. `policy`: Security policies, vulnerability thresholds, and policy hashes.
5. `zkp`: Proof jobs, segment proofs, chunk proof sets, and execution locks.
6. `verification`: Verification requests, verification certificates, and revocation state.

### 6.3 Linear Migration Chain (001 through 016)
Database migrations are strictly linear without branching:
- `001_initial_schema.py` through `011_consolidate_schema.py`: Baseline tables and schemas.
- `012_vulnerability_ingestion_provenance.py`: Provenance metadata on ingested vulnerabilities.
- `013_add_vuln_lifecycle.py`: Vulnerability lifecycle states (`pending`, `approved`, `frozen`, `revoked`).
- `014_application_tenant_isolation.py`: Strict multi-tenant isolation linking applications to vendors.
- `015_auth_lifecycle_and_revocation.py`: User account statuses and database-backed token revocations.
- `016_add_snapshot_ttl_expires_at.py`: Time-to-live (`expires_at`) expiration on vulnerability snapshots.

---

## 7. Zero-Knowledge Proof Architecture

### 7.1 Decomposed SMT Circuit Topology
To overcome memory limits when verifying large SBOMs (up to 1,024 components), the verification is partitioned across 32 chunks, each containing 8 Sparse Merkle Tree (SMT) segments, totaling **256 UltraPlonk segment proofs**:
1. [`segment_init_32/`](segment_init_32/): Initializes state, binds chunk parameters, verifies the first component inclusion proof against $R_{\text{SBOM}}$ and $R_{\text{VulnDB}}$.
2. [`segment_mid_32/`](segment_mid_32/): Accumulator circuit; chains intermediate hashes and verifies sequential component compliance against policy rules.
3. [`segment_final_32/`](segment_final_32/): Terminal circuit; checks accumulated results against the final threshold, verifies non-membership proofs, and outputs public commitments ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$).

### 7.2 Proof Verification Pipeline
- **Proof Format:** Barretenberg 0.46.1 UltraPlonk proof (2,144 bytes per segment proof).
- **Verification API:** [`verification_service`](backend/verification_service) verifies proofs using the native Barretenberg runtime and generates signed verification certificates.

---

## 8. Docker and Container Infrastructure

### 8.1 Services in `docker-compose.yml`
```
             ┌────────────────────────┐
             │ nginx-gateway (:8000)  │
             └───────────┬────────────┘
                         │
     ┌───────────────────┼───────────────────┐
     │                   │                   │
┌────▼──────────┐ ┌──────▼─────────┐ ┌───────▼────────┐
│ sbom-service  │ │ vuln-service   │ │ policy-service │
│ (:8001)       │ │ (:8002)        │ │ (:8003)        │
└───────────────┘ └────────────────┘ └────────────────┘
     │                   │                   │
     └───────────────────┼───────────────────┘
                         │
     ┌───────────────────┴───────────────────┐
     │                                       │
┌────▼──────────┐                     ┌──────▼────────┐
│  zkp-service  │                     │ verif-service │
│  (:8004)      │                     │ (:8005)       │
└───────────────┘                     └───────────────┘
```

1. `nginx-gateway`: Reverse proxy exposing port 8000. Routes `/api/v1/sbom/` to port 8001, `/api/v1/vulnerabilities/` to port 8002, `/api/v1/policies/` to port 8003, `/api/v1/zkp/` to port 8004, and `/api/v1/verification/` to port 8005.
2. `sbom-service`: Ingestion, parsing, and commitment computation.
3. `vulnerability-service`: CVE ingestion, snapshotting, and TTL management.
4. `policy-service`: Policy rules and canonical JSON hashing.
5. `zkp-service`: Prover execution with Noir 0.32.0 and Barretenberg 0.46.1.
6. `verification-service`: Independent UltraPlonk proof verification and certificate issuance.

---

## 9. Development Environment Setup

### 9.1 Local Workstation Bootstrap
Run the automated environment setup from PowerShell:
```powershell
.\bootstrap.ps1
```

### 9.2 Native Cryptographic Runtime Setup
Compile the native `bb_launcher` and verify toolchain availability:
```powershell
.\scripts\setup_crypto_runtime.ps1
```

### 9.3 Environment Configuration
Copy the development template and configure distinct secrets:
```bash
cp .env.local_dev.example .env.local_dev
```
Ensure `JWT_SECRET_KEY` and `CERTIFICATE_SECRET_KEY` are distinct 32-character random strings.

---

## 10. Testing and Quality Assurance

| Test Suite | Execution Command | Coverage & Scope | Verified Status |
| :--- | :--- | :--- | :--- |
| **Backend Unit & Integration** | `pytest backend/` | All 5 microservices, models, repositories, and schemas | 1,345 passing (0 skips) |
| **Stage G Cross-Role Regression** | `pytest backend/shared/tests/` | Cross-role security, tenant isolation, and API hardening | 348 passing (0 skips) |
| **Database Migrations** | `pytest backend/alembic/tests/` | Chain validation, downgrade/upgrade consistency 001–016 | 100% passing |
| **Cryptographic Runtime** | `pytest backend/verification_service/tests/test_b1_live_crypto.py` | Native `bb.exe` launcher, ACVM execution, and UltraPlonk | 24/24 passing (0 skips) |
| **Frontend Tests** | `npm test` (in `frontend/`) | Route guards, in-memory auth transport, UI components | 80 passing (0 skips) |
| **TypeScript Typecheck** | `npx tsc --noEmit` (in `frontend/`) | Next.js 15 App Router strict type checking | Clean (0 errors) |
| **ESLint Validation** | `npx eslint .` (in `frontend/`) | Code quality and React hook rules | Clean (0 warnings) |

---

## 11. Security and Operational Controls

1. **Gate 5R Invariant:** Strict **LOCAL-ONLY** governance. No remote database mutations, secret rotations, staging deployments, or production pushes without explicit owner sign-off.
2. **Secret Redaction:** Logging filters scrub passwords, bearer tokens, and private keys.
3. **In-Memory Transport:** Bearer tokens are never stored in browser disk storage.
4. **Data Isolation:** Vendor SBOMs and component lists are never shared across tenants or disclosed to buyers.

---

## 12. Build and Deployment Readiness

- **Repository Hygiene:** **PASS (Remediated locally in commit `b4c1c7f`)**.
- **Forensic Audit Readiness:** **PASS (Ready for audit)**. All circuits, 256 segment proofs, verification keys, and architecture decisions are verifiable.
- **Local Demonstration Readiness:** **PASS (Ready for candidate defense viva)**.
- **Production Deployment Readiness:** **NOT READY / NOT VERIFIED**.
  - Production cloud infrastructure is unprovisioned.
  - External TLS/HTTPS termination is absent.
  - Production ingress, firewall rules, and DNS are unconfigured.
  - Operating mode is strictly restricted to local-only development.

---

## 13. Authoritative Configuration Reference

| Purpose | File Path |
| :--- | :--- |
| **Locked Roadmap** | [`MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md`](MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md) |
| **Project State Register** | [`MASTER_PROJECT_CONTEXT/project_context/PROJECT_STATE.md`](MASTER_PROJECT_CONTEXT/project_context/PROJECT_STATE.md) |
| **Security Rules** | [`MASTER_PROJECT_CONTEXT/project_context/SECURITY_RULES.md`](MASTER_PROJECT_CONTEXT/project_context/SECURITY_RULES.md) |
| **Cryptography Rules** | [`MASTER_PROJECT_CONTEXT/project_context/CRYPTOGRAPHY_RULES.md`](MASTER_PROJECT_CONTEXT/project_context/CRYPTOGRAPHY_RULES.md) |
| **Student Runbook** | [`MASTER_PROJECT_CONTEXT/project_context/STUDENT_RUNBOOK.md`](MASTER_PROJECT_CONTEXT/project_context/STUDENT_RUNBOOK.md) |
| **Defense Viva Slides** | [`MASTER_PROJECT_CONTEXT/project_context/VIVA_PRESENTATION_SLIDES.md`](MASTER_PROJECT_CONTEXT/project_context/VIVA_PRESENTATION_SLIDES.md) |
| **Python Core Manifest** | [`requirements.txt`](requirements.txt) |
| **Python Shared Manifest** | [`backend/shared/requirements.txt`](backend/shared/requirements.txt) |
| **Python Dev Manifest** | [`requirements-dev.txt`](requirements-dev.txt) |
| **Frontend Manifest** | [`frontend/package.json`](frontend/package.json) |
| **Nginx Reverse Proxy** | [`docker/nginx.conf`](docker/nginx.conf) |
| **Compose Topology** | [`docker-compose.yml`](docker-compose.yml) |
| **Local Compose DB** | [`docker-compose.local.yml`](docker-compose.local.yml) |

---

## 14. Known Limitations

1. **Production Infrastructure:** Cloud deployment, TLS termination, and production ingress are not provisioned or verified.
2. **256-Segment Proving Workload:** Real-time generation of 256 segment proofs requires ~532s of CPU time. Demonstrations rely on precomputed verified proof archives to avoid regeneration delay.
3. **In-Memory Authentication:** Page refresh in the browser requires re-authentication by design to guarantee zero persistent storage leaks.
4. **Snapshot Expiration:** Vulnerability snapshots expire according to TTL rules (Alembic rev 016) and must be refreshed for continuing verification.

---

## 15. Maintenance Instructions

1. **Updating Python Dependencies:** Modify [`backend/shared/requirements.txt`](backend/shared/requirements.txt) and propagate to [`requirements.txt`](requirements.txt). Test in a clean virtual environment using `pytest`.
2. **Updating Frontend Dependencies:** Run `npm install <package>@version` in `frontend/` and commit both `package.json` and `package-lock.json`.
3. **Database Changes:** Never modify existing migrations (001–016). Always create a new linear Alembic revision via `alembic revision -m "..."`.
4. **Preventing Repository Bloat:** Never commit `.cache/`, `scratch/`, `dist/`, or `.sql` database dumps. Keep all local test runs and diagnostic evidence in `scratch/`.

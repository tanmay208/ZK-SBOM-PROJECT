# Student Runbook, Setup Guide & Troubleshooting Manual

**Project:** Zero-Knowledge Verification for Software Supply Chain Security  
**Workspace Root:** `E:\Main Project`  
**Document Status:** Canonical Student Runbook & Operational Manual (Stage F4 Deliverable)  
**Target Environment:** Local Workstation (Windows 10/11 x64, Linux, or WSL2)  
**Operating Mode:** LOCAL-ONLY (No remote deployments or staging mutations permitted)  
**Effective Date:** 22 October 2026  
**Document Version:** 1.0.0-final-stage-f4  

---

## Table of Contents

1. [Project Overview & Architectural Blueprint (§F4.1)](#1-project-overview--architectural-blueprint-f41)
   - [1.1 Problem Statement & Core Value Proposition](#11-problem-statement--core-value-proposition)
   - [1.2 System Components & Responsibilities](#12-system-components--responsibilities)
   - [1.3 Supported Operating Environment & Prerequisites](#13-supported-operating-environment--prerequisites)
   - [1.4 Repository Structure & Key Directories](#14-repository-structure--key-directories)
2. [Setup & Configuration Guide (§F4.2)](#2-setup--configuration-guide-f42)
   - [2.1 Python Virtual Environment & Pinned Dependencies](#21-python-virtual-environment--pinned-dependencies)
   - [2.2 Frontend Dependencies Setup](#22-frontend-dependencies-setup)
   - [2.3 Cryptographic Runtime & Native Barretenberg Setup](#23-cryptographic-runtime--native-barretenberg-setup)
   - [2.4 Environment Configuration (`.env.local_dev`)](#24-environment-configuration-envlocal_dev)
   - [2.5 Database Prerequisites & Migration Baseline](#25-database-prerequisites--migration-baseline)
   - [2.6 Verifying Setup Success](#26-verifying-setup-success)
3. [Service Startup & Shutdown Runbook (§F4.3)](#3-service-startup--shutdown-runbook-f43)
   - [3.1 Startup Order & Dependency Flow](#31-startup-order--dependency-flow)
   - [3.2 Service Execution Commands & Working Directories](#32-service-execution-commands--working-directories)
   - [3.3 Service Readiness & Health Check Procedures](#33-service-readiness--health-check-procedures)
   - [3.4 Log Inspection & Failure Diagnosis](#34-log-inspection--failure-diagnosis)
   - [3.5 Graceful Shutdown Runbook](#35-graceful-shutdown-runbook)
4. [Student Usage Walkthrough (§F4.4)](#4-student-usage-walkthrough-f44)
   - [Phase 1: User Onboarding & Authentication](#phase-1-user-onboarding--authentication)
   - [Phase 2: Application Management](#phase-2-application-management)
   - [Phase 3: SBOM Ingestion & Commitment Generation](#phase-3-sbom-ingestion--commitment-generation)
   - [Phase 4: Vulnerability Snapshot Ingestion & Policy Binding](#phase-4-vulnerability-snapshot-ingestion--policy-binding)
   - [Phase 5: Zero-Knowledge Proof Generation](#phase-5-zero-knowledge-proof-generation)
   - [Phase 6: Independent Proof Verification](#phase-6-independent-proof-verification)
   - [Phase 7: Compliance Certificate Validation & Revocation](#phase-7-compliance-certificate-validation--revocation)
5. [Practical Troubleshooting Guide (§F4.5)](#5-practical-troubleshooting-guide-f45)
   - [5.1 Comprehensive Troubleshooting Matrix](#51-comprehensive-troubleshooting-matrix)
   - [5.2 Diagnostic Commands Reference](#52-diagnostic-commands-reference)
6. [Safe Shutdown, Data Preservation & Recovery (§F4.6)](#6-safe-shutdown-data-preservation--recovery-f46)
   - [6.1 Authoritative Local State vs. Ephemeral Artifacts](#61-authoritative-local-state-vs-ephemeral-artifacts)
   - [6.2 Secret Sanitization Rules](#62-secret-sanitization-rules)
   - [6.3 Standardized Reproducible Bug Report Template](#63-standardized-reproducible-bug-report-template)

---

## 1. Project Overview & Architectural Blueprint (§F4.1)

### 1.1 Problem Statement & Core Value Proposition

In modern software supply chains, software consumers (buyers, auditors, regulators) require assurance that third-party applications do not harbor critical vulnerabilities or violate organizational security policies. Traditionally, vendors must share their complete, unredacted Software Bill of Materials (SBOM) listing every proprietary component, library, and exact version.

This requirement creates a severe conflict between **transparency** and **intellectual property / trade secret protection**:
1. **Vendor Risk**: Full SBOM disclosure reveals proprietary architecture, internal toolchains, and proprietary dependency graphs.
2. **Attacker Reconnaissance**: Exposing the full component tree provides attackers with a precise blueprint for targeted exploits.
3. **Binary Trust Problem**: Today's verification relies either on blindly trusting vendor assertions or fully inspecting private vendor source artifacts.

**The Solution:** This project implements a **Privacy-Preserving Zero-Knowledge Verification Platform**. By utilizing Noir Zero-Knowledge circuits and Barretenberg UltraPlonk proofs over the BN254 elliptic curve, a vendor can prove mathematically that an SBOM complies with a specified security policy against an authoritative vulnerability database snapshot, **without revealing the private list of SBOM components**.

```
  VENDOR DOMAIN (Private)                    BUYER / AUDITOR DOMAIN (Public)
┌─────────────────────────┐               ┌─────────────────────────────────┐
│ Private SBOM Inventory  │               │ Independent Verifier Service    │
│  - components           │               │                                 │
│  - dependency graph     │               │ Public Commitments:             │
│  - internal versions    │               │  - SBOM Root (R_sbom)           │
└────────────┬────────────┘               │  - Vuln DB Root (R_vulndb)      │
             │                            │  - Policy Hash (H_policy)       │
             ▼                            └────────────────┬────────────────┘
┌─────────────────────────┐                                │
│ Sparse Merkle Tree      │                                │
│ & Noir Circuit Prover   │                                │
│ (Private Witness Ingest)│                                │
└────────────┬────────────┘                                │
             │ UltraPlonk Proof (2,144 bytes)              │
             └───────────────────────┬─────────────────────┘
                                     ▼
                      ┌─────────────────────────────┐
                      │ Barretenberg Verification   │
                      │ Outcome: PASS / FAIL        │
                      │ (Zero Component Disclosure) │
                      └──────────────┬──────────────┘
                                     ▼
                      ┌─────────────────────────────┐
                      │ HMAC-SHA256 Compliance Cert │
                      │ Public ID Validation API    │
                      └─────────────────────────────┘
```

> [!IMPORTANT]
> **What a Proof Actually Proves**: A valid cryptographic proof certifies strictly that the committed SBOM ($R_{\text{SBOM}}$) satisfies the committed policy ($H_{\text{Policy}}$) when evaluated against the committed vulnerability snapshot ($R_{\text{VulnDB}}$). It does **never** claim that the software is free from all vulnerabilities, that the vulnerability feed is exhaustive, or that uncommitted code is secure.

---

### 1.2 System Components & Responsibilities

The system consists of five distinct architectural tiers:

1. **Frontend Web Application (`frontend/`)**:
   - Built on **Next.js 16.3.5** and **React 19.2.8** using the App Router.
   - Provides role-aware interfaces for vendors, buyers, auditors, and administrators.
   - Strictly manages authentication tokens in **browser memory** (`authTransport.ts`); tokens are never written to `localStorage`, `sessionStorage`, or cookies.
2. **Unified Platform API Gateway / Verification Service (`backend/`)**:
   - Built with **FastAPI 0.115.6** and Python 3.12/3.11.
   - Unified development entrypoint: `verification_service.app.main:app` running on port `8000`.
   - Incorporates modular domain sub-routers:
     - `auth_router` & `admin_user_router`: Token generation, credential hashing via bcrypt, user lifecycle.
     - `application_router` & `sbom_router`: Application definitions, SBOM ingestion, CycloneDX/SPDX normalization, Poseidon leaf hashing, and Merkle tree generation.
     - `vulnerability_router`: CVE/NVD snapshot management, approval workflows, two-person integrity.
     - `policy_router`: Security policy authoring, rule evaluation, policy hashing.
     - `zkp_router`: Proof job lifecycle, asynchronous proving status, witness packaging.
     - `verification_router`: Independent UltraPlonk proof verification, certificate issuance, public validation.
3. **Database Layer (`PostgreSQL 16`)**:
   - Dedicated local development instance running in Docker on host loopback port **`127.0.0.1:5433`** (`ZKP_SBOM_LOCAL_DEV`).
   - Governed by Alembic migrations through revision **`015`** (`015_add_profile_to_users.py`).
   - Strictly isolated from the protected host PostgreSQL 17 instance on port `5432`.
4. **Cryptographic Prover & Circuits (`circuits/`, `circuits_dev/`, `segment_*`)**:
   - Implemented in **Noir 0.32.0**.
   - Sparse Merkle Tree (SMT) membership and non-membership circuits using Poseidon sponge hashing ($t=2$ and $t=3$ on the BN254 scalar field $\mathbb{F}_r$).
   - Decomposed chunking topology (32 components per chunk, 8 SMT segments per chunk) to operate within bounded workstation memory.
5. **Cryptographic Verifier Runtime (`backend/verification_service/crypto_runtime/`, `.bin/`)**:
   - Pinned **Barretenberg 0.46.1** runtime (`@noir-lang/backend_barretenberg@0.32.0`).
   - Dual execution mechanism:
     - Primary on Windows: Native Win32 PE launcher `.bin/bb.exe` compiled from `scripts/bb_launcher.c` via GCC.
     - Fallback: Node.js WASM execution wrapper (`.bin/bb.cmd` on Windows, `.bin/bb` on Linux/POSIX).

---

### 1.3 Supported Operating Environment & Prerequisites

The following software versions have been verified on the development workstation:

| Runtime / Tool | Verified Version | Purpose | Mandatory Check Command |
| :--- | :--- | :--- | :--- |
| **Operating System** | Windows 10/11 x64 (or Linux / WSL2) | Host Execution Environment | `[System.Environment]::OSVersion.Version` |
| **Python** | **3.12.x** (or 3.11.x) | Backend Services & Alembic | `python --version` |
| **Node.js** | **>= 18.0.0** (verified: `v24.1.0`) | Crypto Runtime & Next.js | `node --version` |
| **npm** | **>= 9.0.0** (verified: `10.9.0`) | Package Management | `npm --version` |
| **Docker** | Docker Desktop (Engine 24+) | PostgreSQL 16 Isolation | `docker --version` |
| **C Compiler** (Optional) | MinGW-w64 GCC (verified: `14.2.0`) | Native `.bin/bb.exe` Compilation | `gcc --version` |

---

### 1.4 Repository Structure & Key Directories

```
E:\Main Project\
├── .bin/                               # Native & script wrappers (bb.exe, bb.cmd, bb)
├── backend/                            # FastAPI microservices and shared libraries
│   ├── alembic/                        # Database migration scripts (001 through 015)
│   ├── policy_service/                 # Policy management & evaluation engine
│   ├── sbom_service/                   # SBOM normalization, parsing & Merkle root computation
│   ├── shared/                         # Common models, database sessions, auth & crypto helpers
│   ├── verification_service/           # Verification API & crypto verifier runtime
│   │   └── crypto_runtime/             # Pinned Barretenberg WASM & package.json
│   ├── vulnerability_service/          # Vulnerability ingestion, snapshots & approval
│   └── zkp_service/                    # Noir witness preparation & proof job coordination
├── circuits/                           # Canonical Noir ACIR circuit definitions
├── circuits_dev/                       # Development-profile circuit definitions
├── frontend/                           # Next.js 16.3.5 App Router application
│   ├── src/app/                        # Next.js route handlers and UI views
│   ├── src/components/                 # Reusable UI component library
│   └── src/lib/                        # API client, auth transport & utilities
├── project_context/                    # Single Authoritative Documentation Root
│   ├── ARCHITECTURE.md                 # Full technical architecture specification
│   ├── PROJECT_ROADMAP.md              # Authoritative locked six-stage roadmap
│   ├── PROJECT_STATE.md                # Verified empirical findings and test registers
│   ├── SECURITY_RULES.md               # Application security & RBAC invariants
│   ├── CRYPTOGRAPHY_RULES.md           # Cryptographic rules, curve parameters & circuit invariants
│   └── STUDENT_RUNBOOK.md              # THIS DOCUMENT (F4 student runbook & troubleshooting manual)
├── scripts/                            # Operational, setup, verification & recovery scripts
│   ├── bb_launcher.c                   # Source code for native Windows bb.exe PE binary
│   ├── bootstrap_local_db.py           # Fail-closed local DB DDL initialization tool
│   ├── setup_crypto_runtime.ps1        # Crypto runtime validation & wrapper generation script
│   └── project_context.py              # Repository snapshot & inventory utility
├── bootstrap.ps1                       # Context onboarding & safety audit script (Read-Only)
├── requirements.txt                    # Production runtime Python dependencies
├── requirements-dev.txt                # Development & testing Python dependencies (pytest, httpx)
└── .env.local_dev.example              # Template configuration for local development
```

---

## 2. Setup & Configuration Guide (§F4.2)

### 2.1 Python Virtual Environment & Pinned Dependencies

> [!CAUTION]
> Always install Python dependencies within an isolated virtual environment (`.venv`). Never install packages globally.

1. Open PowerShell and navigate to the project root:
   ```powershell
   cd "E:\Main Project"
   ```
2. Create a dedicated virtual environment using Python 3.12 or 3.11:
   ```powershell
   python -m venv .venv
   ```
3. Activate the virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   *(On Linux/macOS/WSL: `source .venv/bin/activate`)*
4. Upgrade `pip` to the latest version:
   ```powershell
   python -m pip install --upgrade pip
   ```
5. Install development and backend runtime dependencies:
   ```powershell
   pip install -r requirements-dev.txt
   ```
   *Verified dependencies installed: `fastapi==0.115.6`, `uvicorn[standard]==0.34.0`, `pydantic==2.10.4`, `sqlalchemy==2.0.36`, `psycopg2-binary==2.9.10`, `alembic==1.14.1`, `bcrypt==5.0.0`, `PyJWT==2.12.1`, `pytest==8.3.4`, `httpx==0.28.1`.*

---

### 2.2 Frontend Dependencies Setup

1. Navigate to the `frontend/` directory:
   ```powershell
   cd "E:\Main Project\frontend"
   ```
2. Install frontend dependencies using pinned package locks:
   ```powershell
   npm ci
   ```
   *Verified frontend stack: Next.js 16.3.5, React 19.2.8, TanStack React Query 5.104.0, TailwindCSS 4.*
3. Verify TypeScript type-checking without emitting files:
   ```powershell
   npm run typecheck
   ```
4. Verify code linting rules:
   ```powershell
   npm run lint
   ```
5. Return to the workspace root:
   ```powershell
   cd "E:\Main Project"
   ```

> [!NOTE]
> `npm test` inside `frontend/` invokes `npx tsx --test`. The package `tsx` is executed on-demand via `npx`. If running in an offline environment without an internet connection, tests requiring `tsx` may fail unless pre-cached in npm's cache.

---

### 2.3 Cryptographic Runtime & Native Barretenberg Setup

The verification subsystem requires Barretenberg 0.46.1. The repository provides an automated verification script: `scripts/setup_crypto_runtime.ps1`.

1. Run the non-mutating environment check:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\setup_crypto_runtime.ps1 -CheckOnly
   ```
2. Expected output for a healthy system:
   ```text
   [INFO] Evaluating local cryptographic runtime environment...
   [PASS] Node.js runtime discovered: v24.1.0 (minimum >= 18 met)
   [PASS] npm CLI discovered: 10.9.0
   [PASS] Verified pinned dependency: @noir-lang/backend_barretenberg@0.32.0
   [PASS] Discovered cryptographic runtime lockfile: package-lock.json
   [PASS] Verified Barretenberg entrypoint: E:\Main Project\backend\verification_service\crypto_runtime\node_modules\@aztec\bb.js\dest\node\main.js
   [PASS] Barretenberg CLI verification passed via .bin/bb.exe (exit code 0; commands available: verify, prove, etc.)
   [PASS] Cryptographic runtime reproducibility check complete. Ready for local proof verification.
   ```
3. If entrypoints or wrappers are missing, generate them without `-CheckOnly`:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\setup_crypto_runtime.ps1
   ```
   *(If MinGW GCC is available on PATH, this automatically compiles `scripts/bb_launcher.c` into native PE binary `.bin/bb.exe`. Otherwise, `.bin/bb.cmd` is used).*

---

### 2.4 Environment Configuration (`.env.local_dev`)

The backend validates configuration at startup via `backend/shared/config.py::validate_config()`. It operates under a **fail-closed** policy: invalid, empty, or placeholder secrets cause the server to terminate immediately.

1. Create your local development environment file from the template:
   ```powershell
   Copy-Item .env.local_dev.example .env.local_dev
   ```
2. Open `.env.local_dev` in your editor and configure the variables according to this specification:

| Environment Variable | Required Setting for Local Dev | Security Invariant / Rule |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `local_dev` | Mandatory guard enforcing local development constraints. |
| `DB_HOST` | `127.0.0.1` | Loopback client host. Connecting to remote hosts is blocked. |
| `DB_PORT` | `5433` | **MUST strictly be 5433** (Docker PG16). **Port 5432 is strictly prohibited!** |
| `DB_NAME` | `ZKP_SBOM_LOCAL_DEV` | **MUST strictly be ZKP_SBOM_LOCAL_DEV**. Main DB `ZKP_SBOM` is prohibited! |
| `DB_USER` | `postgres` | Local PostgreSQL superuser / owner. |
| `DB_PASSWORD` | `<your-local-docker-password>` | Must not be empty or whitespace. |
| `DB_SSL_MODE` | `disable` | Local Docker container uses non-TLS loopback. |
| `CRYPTO_PROFILE` | `dev` (or `c32`) | Selects circuit artifact topology (`dev` enables fast local testing). |
| `JWT_SECRET_KEY` | *(Random $\ge 32$ chars)* | Must be $\ge 32$ characters, non-trivial, non-repeated. |
| `CERTIFICATE_SECRET_KEY` | *(Random $\ge 32$ chars)* | **MUST be distinct from JWT_SECRET_KEY**; $\ge 32$ characters. |
| `CERTIFICATE_ACTIVE_KID` | `v1` | Active key identifier for HMAC-SHA256 certificates. |
| `CERTIFICATE_SECRET_KEYS` | `{"v1": "<same-as-above>"}` | JSON map of active and historical signing keys. |
| `CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000` | Allowed browser origins. |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | API base URL consumed by Next.js frontend. |

> [!CAUTION]
> **Database Isolation Guard**: The backend code in `backend/shared/config.py` (lines 234–260) will raise a fatal `ConfigurationError` if `ENVIRONMENT=local_dev` and `DB_PORT != 5433` or `DB_NAME != ZKP_SBOM_LOCAL_DEV`. This prevents any accidental connection to the protected PostgreSQL 17 instance on port 5432.

---

### 2.5 Database Prerequisites & Migration Baseline

The platform relies on a PostgreSQL 16 container running on port 5433.

1. Ensure your PostgreSQL 16 Docker container is running:
   ```powershell
   docker ps --filter "name=zkp_sbom_local_dev"
   ```
   If starting fresh via Docker CLI:
   ```powershell
   docker run -d --name zkp_sbom_local_dev -p 5433:5432 -e POSTGRES_PASSWORD=your_password -e POSTGRES_DB=ZKP_SBOM_LOCAL_DEV postgres:16
   ```
2. Verify Alembic migration status (target revision is `015`):
   ```powershell
   cd "E:\Main Project\backend"
   alembic current
   ```
   *Expected output*: `015 (head)`
3. Distinction between helper scripts:
   - `bootstrap.ps1`: Strictly a **read-only session onboarding tool**. It checks context documentation, prints safety rules, and generates a context snapshot. It **does not** install software or mutate the database.
   - `scripts/bootstrap_local_db.py`: A **fail-closed development bootstrap utility** that applies DDL for `public.users` if absent. It strictly validates that `DB_PORT == 5433` and rejects PostgreSQL 17.

---

### 2.6 Verifying Setup Success

Execute the backend unit test suite in offline mode to confirm that Python, cryptography libraries, and circuit parsing are functioning:
```powershell
cd "E:\Main Project"
python -m pytest backend/verification_service/tests/test_crypto_runtime.py -v
```
If this test passes with `1 passed`, your local Python virtual environment, Barretenberg runtime wrappers, and Noir circuit profiles are fully verified and ready for service execution.

---

## 3. Service Startup & Shutdown Runbook (§F4.3)

### 3.1 Startup Order & Dependency Flow

Services must be started in strict dependency order:

```
┌──────────────────────────────────────────────┐
│ STEP 1: PostgreSQL 16 Docker Container       │
│ Endpoint: 127.0.0.1:5433                     │
└──────────────────────┬───────────────────────┘
                       │ Ready for TCP connections
                       ▼
┌──────────────────────────────────────────────┐
│ STEP 2: FastAPI Platform API Service         │
│ Working Dir: E:\Main Project\backend         │
│ Endpoint: http://127.0.0.1:8000              │
└──────────────────────┬───────────────────────┘
                       │ Health endpoint responds 200 OK
                       ▼
┌──────────────────────────────────────────────┐
│ STEP 3: Next.js Frontend Web Application     │
│ Working Dir: E:\Main Project\frontend        │
│ Endpoint: http://localhost:3000              │
└──────────────────────────────────────────────┘
```

---

### 3.2 Service Execution Commands & Working Directories

Open two separate PowerShell terminal windows.

#### Terminal 1: Backend Platform API Service
1. Navigate to the `backend/` directory:
   ```powershell
   cd "E:\Main Project\backend"
   ```
2. Activate your virtual environment:
   ```powershell
   ..\.venv\Scripts\Activate.ps1
   ```
3. Load the environment configuration:
   ```powershell
   $env:ENV_FILE = "..\.env.local_dev"
   ```
4. Launch Uvicorn with hot-reload enabled:
   ```powershell
   python -m uvicorn verification_service.app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

#### Terminal 2: Frontend Web Application
1. Navigate to the `frontend/` directory:
   ```powershell
   cd "E:\Main Project\frontend"
   ```
2. Launch the Next.js development server:
   ```powershell
   npm run dev
   ```

---

### 3.3 Service Readiness & Health Check Procedures

Open a third terminal window to verify that both services are ready to accept traffic.

1. **Verify Backend Health Endpoint**:
   ```powershell
   curl.exe -s http://127.0.0.1:8000/api/v1/health
   ```
   *Expected Response:*
   ```json
   {"service":"verification_service","status":"healthy","version":"0.1.0"}
   ```
2. **Verify OpenAPI Documentation**:
   ```powershell
   curl.exe -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/api/v1/openapi.json
   ```
   *Expected Response:* `200`
3. **Verify Frontend Reachability**:
   ```powershell
   curl.exe -s -o /dev/null -w "%{http_code}" http://localhost:3000
   ```
   *Expected Response:* `200`

---

### 3.4 Log Inspection & Failure Diagnosis

- **Backend Logs**: Stream directly to Terminal 1. Structured JSON logs are formatted with timestamp, service name, and event name:
  ```json
  {"timestamp": "2026-10-22T08:00:00Z", "service": "verification_service", "event": "startup", "message": "Starting verification_service"}
  ```
- **Configuration Errors at Startup**: If `ConfigurationError` appears, inspect the logged message. Common causes:
  - `DB_PASSWORD is not set` $\rightarrow$ Add `DB_PASSWORD` to `.env.local_dev`.
  - `JWT_SECRET_KEY must be at least 32 characters` $\rightarrow$ Generate a longer random secret.
  - `Connecting to protected port 5432 is strictly prohibited` $\rightarrow$ Ensure `DB_PORT=5433`.
- **Frontend Logs**: Stream to Terminal 2. Watch for Next.js compilation errors or missing component imports.

---

### 3.5 Graceful Shutdown Runbook

1. **Stop Frontend**: In Terminal 2, press `Ctrl + C`. Type `Y` if prompted to terminate the batch job.
2. **Stop Backend**: In Terminal 1, press `Ctrl + C`. Uvicorn will broadcast a graceful shutdown signal, execute the lifespan shutdown hook (`audit_log("verification_service", "shutdown")`), and close database connection pools.
3. **Stop Database (Optional)**:
   ```powershell
   docker stop zkp_sbom_local_dev
   ```
   > [!WARNING]
   > Do **NOT** run `docker rm` or `docker compose down -v` unless you intentionally wish to destroy your local database and wipe stored applications, proofs, and certificates.

---

## 4. Student Usage Walkthrough (§F4.4)

This section provides a complete end-to-end walkthrough of the platform workflow across the seven implemented functional phases.

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Phase 1    │     │   Phase 2    │     │   Phase 3    │     │   Phase 4    │
│ Registration │────▶│ Application  │────▶│ SBOM Upload  │────▶│ Snapshot &   │
│   & Login    │     │  Definition  │     │ & Merkle DB  │     │ Policy Bind  │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                                       │
┌──────────────┐     ┌──────────────┐     ┌──────────────┐             │
│   Phase 7    │     │   Phase 6    │     │   Phase 5    │             │
│ Certificate  │◀────│ Independent  │◀────│ Zero-Knowl.  │◀────────────┘
│  Validation  │     │ Verification │     │ Proof Gen.   │
└──────────────┘     └──────────────┘     └──────────────┘
```

---

### Phase 1: User Onboarding & Authentication

1. Open your browser and navigate to `http://localhost:3000`.
2. Click **Get Started** or navigate to `/register`.
3. Submit a new account registration (e.g., username `alice_buyer`, password `SecurityPassword123!`).
   - *Security Invariant*: Registration via `POST /api/v1/auth/register` strictly assigns the base role **`buyer`**. Roles cannot be escalated in the request payload.
   - *Password Rules*: 8 to 72 bytes (enforced by bcrypt).
4. Navigate to `/login` and authenticate.
5. **In-Memory Token Semantics**:
   - The received JWT bearer token is stored strictly in memory via `frontend/src/lib/authTransport.ts`.
   - **Refreshing the page (F5) clears the token by design**. This intentional architectural decision eliminates persistent browser token leakage (`XSS` extraction from `localStorage`).

> [!NOTE]
> **Role Elevation for Testing**: To perform vendor actions (creating applications, generating proofs) or admin actions (managing vulnerability snapshots), an administrator must update the user's role in the database:
> ```sql
> UPDATE users SET role = 'vendor' WHERE username = 'alice_buyer';
> ```
> *(Or use `admin` / `trusted_importer` as appropriate).*

---

### Phase 2: Application Management

1. Log in with a user possessing the `vendor` or `admin` role.
2. In the navigation sidebar, click **Applications** (`/applications`).
3. Click **Register Application**:
   - **Name**: `CloudEdge Gateway`
   - **Version**: `2.4.0`
   - **Description**: `Edge API gateway and authentication reverse proxy`
4. Submit the form. The system executes `POST /api/v1/applications/`, assigning a UUIDv4 `application_id` and binding it to your authenticated vendor identity.

---

### Phase 3: SBOM Ingestion & Commitment Generation

1. In the sidebar, select **SBOMs** (`/sboms`).
2. Click **Upload SBOM** and select your application (`CloudEdge Gateway`).
3. Select an SBOM file (supports CycloneDX 1.4/1.5 JSON or SPDX 2.3 JSON).
4. Submit the upload. The backend executes `POST /api/v1/sboms/upload`:
   - Parses components and normalizes Package URLs (`purl`).
   - Computes canonical SHA-256 hashes for each component.
   - Computes Poseidon leaf hashes over the BN254 scalar field.
   - Constructs a Sparse Merkle Tree (SMT) of depth 256.
   - Calculates and persists the public **SBOM Merkle Root** ($R_{\text{SBOM}}$).
5. The UI displays the calculated $R_{\text{SBOM}}$ hexadecimal commitment.

---

### Phase 4: Vulnerability Snapshot Ingestion & Policy Binding

The system maintains cryptographic integrity between the vulnerability feed and organizational policy:

1. **Vulnerability Snapshot Ingestion** (Role: `trusted_importer`):
   - The importer ingests a vulnerability snapshot containing CVE records and CVSS scores via `POST /api/v1/vulnerability/snapshots`.
   - The snapshot is hashed into an SMT vulnerability commitment ($R_{\text{VulnDB}}$) and enters the `pending` state.
2. **Two-Person Integrity Approval & Automated TTL** (Role: `admin`):
   - An administrator reviews the pending snapshot in `/admin`.
   - The admin approves the snapshot via `POST /api/v1/vulnerability/snapshots/{snapshot_id}/approve`.
   - *Security Invariant*: The approving admin **cannot be the same user** who created the snapshot (`vulnerability_routes.py` line 162).
   - *Snapshot Freshness & TTL Configuration*: TTL duration is configured globally via the environment variable `VULNERABILITY_SNAPSHOT_TTL_SECONDS` (default: 30 days = 2,592,000 seconds; valid bounds: 3,600s [1 hour] to 31,536,000s [365 days]; invalid configuration fails closed). When frozen, `expires_at` is set to `frozen_at + timedelta(seconds=ttl_seconds)`. The system evaluates snapshot freshness synchronously at proof-job creation, immediately before proving, and at authoritative verification: expired snapshots (`now_utc >= expires_at`) immediately fail closed with `SNAPSHOT_EXPIRED`. Legacy snapshots (`expires_at IS NULL`) are grandfathered, and historical certificates remain valid.
3. **Policy Definition** (Role: `admin`):
   - In `/admin`, create a policy specifying rules:
     - Maximum allowed CVSS score (e.g., `7.0`).
     - Prohibited vulnerability severity classes (e.g., `CRITICAL`, `HIGH`).
     - Blacklisted CVE IDs.
   - The policy rules are canonicalized and hashed to produce $H_{\text{Policy}}$.

---

### Phase 5: Zero-Knowledge Proof Generation

1. In the sidebar, navigate to **Proofs** (`/proofs`).
2. Click **Initiate Proof Job**:
   - Select your **Application** and specific **SBOM**.
   - Select the approved, unexpired **Vulnerability Snapshot** ($R_{\text{VulnDB}}$).
   - Select the active **Security Policy** ($H_{\text{Policy}}$).
3. Click **Generate Proof**. The backend creates a proof job in `zkp_service`:
   - Prepares the private circuit witness (component leaves and Merkle inclusion/exclusion paths).
   - Invokes the Barretenberg prover using the configured chunk topology.
   - Produces an UltraPlonk proof (2,144-byte raw proof body; 2,304 bytes serialized with 5 public inputs for initial segments).
4. The UI displays the job lifecycle: `queued` $\rightarrow$ `running` $\rightarrow$ `completed`.

> [!IMPORTANT]
> **Proving Workload & Watchdog Safeguards**: For standard demonstration and testing, dev/C32 chunking mode operates across 32 components. In the live 256-segment acceptance probe, Segment 0 passed live in 83.25 seconds, generating and verifying an UltraPlonk proof in-flight within temporary execution storage (2,144 bytes raw proof body / 2,304 bytes serialized with public inputs); no standalone binary proof file was retained on disk. During Segment 1, the runtime resource watchdog detected available host RAM dropping to 1.54 GiB (< 2.0 GiB safety floor) and cleanly terminated guest worker PID 757 via SIGTERM within 1.0 second, preserving workstation stability without data loss. The full 256-segment run remains classified as **`BLOCKED ON PHYSICAL RAM SAFETY FLOOR`** (1 verified, 1 aborted, 254 unattempted).

---

### Phase 6: Independent Proof Verification

Proof verification can be executed by buyers, auditors, or automated compliance agents:

1. Navigate to **Verify** (`/verify`).
2. Enter the verification parameters:
   - **SBOM Root** ($R_{\text{SBOM}}$)
   - **Vulnerability DB Root** ($R_{\text{VulnDB}}$)
   - **Policy Hash** ($H_{\text{Policy}}$)
   - Attach the **Proof Artifact** (or provide `proof_job_id`).
3. Click **Execute Verification**. The verification service executes `POST /api/v1/verification/verify`:
   - Passes the proof and public inputs to Barretenberg (`bb verify`).
   - Validates that the public commitments match the proof witness.
   - Evaluates the verifier result: `is_valid: true`.
4. The page displays the green **VERIFIED** outcome card.

---

### Phase 7: Compliance Certificate Validation & Revocation

Upon successful verification, the platform issues an authoritative compliance certificate:

1. In the sidebar, select **Certificates** (`/certificates`).
2. View your issued certificate:
   - Contains: `certificate_id` (UUIDv4), `application_id`, `sbom_root`, `policy_hash`, `issued_at`, and an HMAC-SHA256 signature signed by `CERTIFICATE_SECRET_KEY` using active key `v1`.
3. **Public Independent Validation**:
   - External auditors without platform accounts can query the unauthenticated validation endpoint:
     ```powershell
     curl.exe -s http://localhost:8000/api/v1/verification/certificates/<certificate_id>/validate
     ```
   - *Expected Response:*
     ```json
     {"valid": true, "certificate_id": "<certificate_id>", "revoked": false}
     ```
4. **Certificate Revocation**:
   - An authorized vendor or admin can revoke a certificate (e.g., if a 0-day vulnerability is subsequently discovered) via `POST /api/v1/verification/certificates/{certificate_id}/revoke`.
   - Once revoked, the validation endpoint immediately returns `{"valid": false, "revoked": true}`.

---

## 5. Practical Troubleshooting Guide (§F4.5)

### 5.1 Comprehensive Troubleshooting Matrix

| Category | Symptom / Error | Likely Cause | Safe Diagnostic Procedure | Recommended Corrective Action | Safety / Escalation Warning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Dependencies** | `ModuleNotFoundError: No module named 'fastapi'` | Python virtual environment not activated or dependencies not installed. | Run `python -c "import fastapi; print(fastapi.__version__)"`. Check active environment: `where.exe python`. | Run `.\.venv\Scripts\Activate.ps1` and `pip install -r requirements-dev.txt`. | Never run `pip install` without an active virtual environment. |
| **Dependencies** | `Node.js version is unsupported. Requires >= 18.0.0` | Node.js runtime on host PATH is obsolete (< 18). | Run `node --version`. | Install or update Node.js to LTS (v20+ or v24) and update system PATH. | Do not attempt to bypass runtime version checks in `setup_crypto_runtime.ps1`. |
| **Frontend** | `npm run dev` fails with `EADDRINUSE: port 3000` | A stale Next.js process or other local web server is occupying port 3000. | In PowerShell: `Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue`. | Identify PID and terminate the specific orphaned process: `Stop-Process -Id <PID>`. | Do not blindly kill all Node processes. Verify process identity first. |
| **Frontend** | `npm test` fails with `Cannot find package 'tsx'` | Network-isolated environment where `npx` cannot fetch `tsx`. | Run `npx --no-install tsx --version`. | If offline, install `tsx` locally in devDependencies or run with network access once to cache. | Frontend code builds cleanly via `npm run build` regardless of test runner cache. |
| **Backend Startup** | `ConfigurationError: DB_PORT is prohibited` | Backend configured with port `5432` instead of `5433`. | Inspect `DB_PORT` in `.env.local_dev` or environment: `$env:DB_PORT`. | Set `DB_PORT=5433` in `.env.local_dev`. Ensure `ENVIRONMENT=local_dev`. | **NEVER connect to port 5432!** Port 5432 hosts the protected PostgreSQL 17 instance. |
| **Backend Startup** | `ConfigurationError: JWT_SECRET_KEY must be at least 32 characters` | JWT or Certificate secret is missing, too short (< 32 chars), or trivial. | Inspect secret lengths in `.env.local_dev`: `$env:JWT_SECRET_KEY.Length`. | Set distinct, high-entropy secrets of at least 32 characters in `.env.local_dev`. | Never commit `.env.local_dev` to Git or share secrets in logs/tickets. |
| **Database** | `psycopg2.OperationalError: connection to 127.0.0.1:5433 failed` | Docker container `zkp_sbom_local_dev` is not running. | Run `docker ps -a --filter "name=zkp_sbom_local_dev"`. | Run `docker start zkp_sbom_local_dev` to restart the existing container. | Do **NOT** run `docker rm` or create a new container without migrating. |
| **Database** | `Alembic revision mismatch` or missing tables | Database has not been migrated to head revision `015`. | Run `cd backend; alembic current` to check active revision. | Run `alembic upgrade head` targeting the container on port 5433. | Never run migrations against port 5432. Verify target port is 5433. |
| **Crypto Runtime** | `Barretenberg CLI verification check failed` | Pinned WASM entrypoint missing or `.bin/bb.exe` launcher missing. | Run `powershell -File scripts\setup_crypto_runtime.ps1 -CheckOnly`. | Run `powershell -File scripts\setup_crypto_runtime.ps1` to restore entrypoints and wrappers. | Do not modify files in `crypto_runtime/` directly. |
| **Authentication** | `401 Unauthorized` immediately after browser page refresh | Expected behavior of in-memory token architecture (`authTransport.ts`). | Check browser developer console Network tab on API call. | Re-authenticate via `/login`. Explain that in-memory tokens clear on reload for security. | Do not modify code to store bearer tokens in `localStorage`. |
| **Authorization** | `403 Forbidden: Insufficient permissions` | Authenticated user role is `buyer`, attempting vendor/admin action. | Inspect token payload or query database: `SELECT username, role FROM users;`. | Update user role in database to `vendor` or `admin` as required for the scenario. | Self-registration intentionally defaults to `buyer`. |
| **SBOM Parsing** | `422 Unprocessable Entity: Unsupported SBOM format` | Uploaded SBOM JSON is neither valid CycloneDX nor SPDX format. | Validate JSON schema using `python -m json.tool <sbom_file.json>`. | Use CycloneDX 1.4/1.5 JSON or SPDX 2.3 JSON specification with valid `purl` attributes. | Malformed components are rejected fail-closed to protect Merkle trees. |

---

### 5.2 Diagnostic Commands Reference

Use these non-destructive PowerShell commands during diagnosis:

```powershell
# 1. Check Python version and active virtual environment
python -c "import sys; print(sys.executable, sys.version)"

# 2. Check Node and npm runtime versions
node -v; npm -v

# 3. Test Barretenberg launcher execution
& .\.bin\bb.exe --help

# 4. Check whether port 8000 or 5433 is listening
Get-NetTCPConnection -LocalPort 8000, 5433 -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, State, OwningProcess

# 5. Check Docker container status
docker ps --filter "name=zkp_sbom_local_dev" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# 6. Verify backend health endpoint (requires backend running)
curl.exe -s http://127.0.0.1:8000/api/v1/health
```

---

## 6. Safe Shutdown, Data Preservation & Recovery (§F4.6)

### 6.1 Authoritative Local State vs. Ephemeral Artifacts

To prevent catastrophic project data loss or working tree corruption, understand which directories are authoritative and which are disposable:

```
AUTHORITATIVE DATA (MUST PRESERVE)         EPHEMERAL DATA (SAFE TO DELETE)
├── backend/alembic/versions/              ├── .venv/ (Virtual environment)
│   ├── 012_*.py, 013_*.py, 014_*.py       ├── frontend/.next/ (Next.js build cache)
│   └── 015_add_profile_to_users.py        ├── frontend/node_modules/
├── project_context/ (All documentation)   ├── .pytest_cache/
├── scripts/ (All utility & setup scripts) ├── __pycache__/
├── circuits/ & circuits_dev/              └── .cache/ (Temporary proving manifests)
└── archive/ & master_archive/
```

> [!CAUTION]
> **Git Preservation Rule**: **NEVER** run `git reset --hard`, `git clean -fd`, or `git checkout .`!
> The repository working tree contains essential untracked migrations, local scripts, and archived research records. Running `git clean` will permanently destroy critical project artifacts.

---

### 6.2 Secret Sanitization Rules

When collecting logs, screenshots, or bug reports:
1. **Never Print `.env` or `.env.local_dev`**: These files contain database passwords and cryptographic HMAC keys.
2. **Never Post Raw Bearer Tokens**: JWT strings contain encoded user identity and role claims.
3. **Database Passwords**: The backend database engine masks passwords in string representations (`safe_url` replaces credentials with `:****@`). Ensure manual console outputs follow this convention.

---

### 6.3 Standardized Reproducible Bug Report Template

If you encounter an unexpected defect, file an issue using this standardized template:

```markdown
### 1. Bug Summary
Brief 1-2 sentence description of the unexpected behavior.

### 2. Environment Information
- **Operating System**: Windows 11 x64 / Ubuntu 22.04 / WSL2
- **Python Version**: 3.12.x
- **Node.js Version**: v24.1.0
- **Docker PG16 Status**: Container `zkp_sbom_local_dev` listening on port 5433
- **Alembic Revision**: `015 (head)`
- **Crypto Profile**: `dev`

### 3. Steps to Reproduce
1. Launch backend using `python -m uvicorn verification_service.app.main:app --port 8000`
2. Submit POST request to `/api/v1/sboms/upload` with payload `sample_sbom.json`
3. Observe HTTP status code and server console output

### 4. Expected vs. Actual Behavior
- **Expected**: HTTP 201 Created with JSON response containing `sbom_root`
- **Actual**: HTTP 500 Internal Server Error with error trace in logs

### 5. Diagnostic Command & Exit Code
- Command: `python -m pytest backend/verification_service/tests/test_crypto_runtime.py -v`
- Exit Code: `1`

### 6. Sanitized Log Output
```text
[PASTE SANITIZED LOGS HERE - ENSURE PASSWORDS AND SECRETS ARE MASKED]
```
```

---

*End of Student Runbook & Operational Troubleshooting Manual.*

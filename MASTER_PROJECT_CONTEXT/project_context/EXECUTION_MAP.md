# Repository Execution Map & Command Reference

**Document Version:** 2.0.0-consolidated
**Workspace Root:** `E:\Main Project`
**Authoritative Location:** `project_context/EXECUTION_MAP.md`
**Effective Date:** 14 October 2026
**Operating Mode:** LOCAL-ONLY. No remote operations, deployments, or external environment access without explicit authorization.

---

## 1. Process Environment & Database Configuration

The owner has designated Docker PostgreSQL 16 on port `5433` (`ZKP_SBOM_LOCAL_DEV`) as the preferred development and testing candidate (intended for dev, test, migration validation, debugging, and integration testing, subject to explicit authorization before DB operations; present state unverified by this task). Local PostgreSQL 17 on port `5432` (`ZKP_SBOM`) is the intended final main-project database, currently protected/frozen during development and validation; do not access or modify without separate, explicit authorization. PostgreSQL 17 will only be considered for operational use after validation, recovery planning, and separate explicit authorization. Local development commands default to ephemeral process variables targeting port `5433`. Strictly no migrations, write queries, seed data, table drops, or container resets prior to authorized D1 work. Stage D1 remains unauthorized.

```powershell
$env:DB_HOST="127.0.0.1"
$env:DB_PORT="5433"
$env:DB_NAME="ZKP_SBOM_LOCAL_DEV"
$env:DB_USER="postgres"
$env:DB_PASSWORD="<ephemeral_container_password>"
$env:DB_SSL_MODE="disable"
$env:LOCAL_DEV_MODE="true"
# Ephemeral local-development signing secrets (generate random keys; do not use predictable keys):
# Example generator: python -c "import secrets; print(secrets.token_hex(32))"
$env:JWT_SECRET_KEY="***REMOVED***"
$env:CERTIFICATE_SECRET_KEY="***REMOVED***"
```

> [!IMPORTANT]
> **Secret Management Boundary**: Signing keys are strictly for ephemeral local development and testing. Production deployments must inject high-entropy secrets (minimum 256 bits) from a secure secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault, or encrypted deployment environment variables). Never commit literal secret values to documentation or repository files.


---

## 2. Verified Local Test Suites & Mandatory Directory Contexts

Different test suites require specific working directory contexts to prevent module shadowing or name collisions:

### A. Core Cryptographic & Security Suite
- **Working Directory**: Root (`E:\Main Project`)
- **Command**:
  ```powershell
  .\.venv\Scripts\python.exe -m pytest backend/shared/tests/test_stage3_security.py backend/shared/tests/test_smt.py backend/shared/tests/test_shared.py backend/verification_service/tests/test_verifier.py backend/verification_service/tests/test_legacy_acir_adapter.py backend/verification_service/tests/test_public_input_binding.py backend/verification_service/tests/test_certificate_rotation.py
  ```
- **Observed Result**: 102 passed, 0 failed.

### B. Tenant Isolation & Proof Job Recovery Suite
- **Working Directory**: `backend/` (`E:\Main Project\backend`)
- **Mandatory Flag**: `--import-mode=importlib` (Prevents pytest collision between `sbom_service` and `zkp_service` test files named `test_tenant_isolation.py`).
- **Command**:
  ```powershell
  $env:PYTHONPATH="."
  ..\.venv\Scripts\python.exe -m pytest --import-mode=importlib sbom_service/tests/test_tenant_isolation.py zkp_service/tests/test_tenant_isolation.py zkp_service/tests/test_job_recovery.py
  ```
- **Observed Result**: 20 passed, 0 failed.

### C. Vulnerability Ingestion & Separation of Duties Suite
- **Working Directory**: `backend/` (`E:\Main Project\backend`)
- **Command**:
  ```powershell
  $env:PYTHONPATH="."
  ..\.venv\Scripts\python.exe -m pytest vulnerability_service/tests/test_vulnerability_ingestion.py
  ```
- **Observed Result**: 37 passed, 0 failed.

### D. Alembic Migration Suite (Chain 001–014)
- **Working Directory**: `backend/` (`E:\Main Project\backend`)
- **Mandatory Reason**: Must run from `backend/` so that the local `backend/alembic` package does not shadow the third-party `alembic` CLI tool.
- **Command**:
  ```powershell
  $env:PYTHONPATH="."
  ..\.venv\Scripts\python.exe -m pytest alembic/tests/
  ```
- **Observed Result**: 161 passed in 1.20s.

### E. PostgreSQL Concurrency & Idempotency Probe
- **Working Directory**: `backend/` (`E:\Main Project\backend`)
- **Target**: Live Docker PostgreSQL 16 on `127.0.0.1:5433`
- **Command**:
  ```powershell
  $env:PYTHONPATH="."
  ..\.venv\Scripts\python.exe test_concurrency_db.py
  ```
- **Observed Result**: `PASS: 10 concurrent identical requests converged to 1 VerificationRequest and 1 Certificate`.

### F. Frontend Unit Tests, Typecheck, & Build
- **Working Directory**: `frontend/` (`E:\Main Project\frontend`)
- **Commands**:
  ```powershell
  npm test
  npm run typecheck
  npm run lint
  npm run build
  ```
- **Observed Result**:
  - *Historical baseline (15 Oct)*: 39 passed in 569ms; 0 TypeScript errors; 0 lint errors; 15 pages compiled via Turbopack.
  - *Stage C9 quality gates (17 Oct)*: 80 passed in 1.54s with 0 skips; 0 TypeScript compilation errors; 0 ESLint errors/warnings; 17 application routes generated via Turbopack.
  - *Stage D4.4 gate (Empirically Verified, 19 Oct)*: 96 passed in 1.00s with 0 skips; 0 TypeScript compilation errors (`npm run typecheck`); 0 ESLint errors/warnings (`npm run lint`); 19 application routes generated (17 static prerendered, 2 dynamic server-rendered) via Turbopack (`npm run build`).

---

## 3. Roadmap Stage Execution Mapping

| Stage | Target Modules & Directories | Key Entrypoints | Primary Verification Commands | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Stage A** | Repository root, `.venv`, `frontend/node_modules`, Docker | `bootstrap.ps1` | `git status`, `docker ps`, `Invoke-RestMethod /health` | `FULL PASS (CLOSED)` |
| **Stage B** | `backend/shared/`, `backend/alembic/`, `backend/verification_service/` | `backend/verification_service/app/main.py` | `pytest backend/`, `python backend/test_concurrency_db.py` | `FULL PASS (CLOSED)` |
| **Stage C** | `frontend/src/app/`, `frontend/src/components/`, `frontend/src/api/` | Modules C0–C9 (Product Experience) | `npm test`, `npm run typecheck`, `npm run build` | `REPORTED COMPLETE (PENDING OVERALL OWNER ACCEPTANCE)` |
| **Stage D** | `backend/`, `backend/alembic/`, microservice routes | Modules D0–D9 (Backend, DB & Integration) | Read-only audit (`D0`), offline modular validation (`D4`–`D8`), E2E planning | `IN PROGRESS (D0–D8 REPORTED PASS FOR OFFLINE SCOPES; D9 BLOCKED FOR LIVE EXECUTION / READY FOR PLANNING)` |
| **Stage E** | `backend/verification_service/tests/`, `circuits/` | Security test suite | Tamper tests in `test_public_input_binding.py` & `legacy_acir` | `PENDING` |
| **Stage F** | Documentation, build scripts, packaging | Final demo harness | Full regression suites, `next build`, viva script dry-run | `PENDING` |

*Interleaved Execution Sequence:* `C0–C9 (Reported Complete) → D0 (Audit Complete) → D1–D3 (Planning Adopted) → D4–D8 (Offline Acceptance Full Pass) → D9 (Blocked for Live Execution / Ready for Planning)`


---

## 4. Operational Commands (STRICTLY BLOCKED — Gate 5R)

The following operational actions are **STRICTLY BLOCKED**:
- `docker-compose up -d` or restarting staging containers.
- `alembic upgrade head` targeting remote Supabase or staging.
- Executing `python execute_golden_path.py` against live staging.
- Packaging external distribution ZIPs without content-level secret clearance.

---

## 5. Destructive Commands (NEVER RUN)

- `git clean -fd` or `git clean -f` (Destroys untracked migrations `012..014` and local archives).
- `git reset --hard` (Discards uncommitted security fixes).
- `docker-compose down -v` (Destroys database volume data).

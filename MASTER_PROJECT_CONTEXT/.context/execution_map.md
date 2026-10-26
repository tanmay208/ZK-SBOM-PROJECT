# Execution Map

**Freshness Date:** 2026-10-13  
**Documentation Cutoff:** October 13, 2026  
**Operating Mode:** LOCAL-ONLY (SRMIST Wi-Fi Constraint; Gate 5R Strictly Blocked)  
**Purpose:** Verified reference of commands for repository inspection, local non-operational testing, and operational boundaries.

---

## 1. Read-Only / Inspection Commands

- **Repository Status:** `git status` or `git status --short --branch`
- **Context Bootstrap:** `.\bootstrap.ps1`
- **Generate Context Snapshot:** `python scripts/project_context.py --markdown` (Demonstrably read-only, secret-safe)
- **Check Two-Folder Archive Structure:** `Get-ChildItem -Directory -Force | Where-Object { $_.Name -match "archive" }`
- **Docker Status (Inspection Only):** `docker-compose ps` (Read-only status check; do not start or restart containers)

---

## 2. Local & Non-Operational Testing (Safe / Explicitly Authorized Only)

*Note: In the current documentation synchronization turn, zero tests are run. When local tests are authorized in subsequent turns, execute only in the verified directory contexts below:*

### A. Core Cryptographic & Security Suite
Run from repository root (`E:\Main Project`):
```powershell
.\.venv\Scripts\python.exe -m pytest backend/shared/tests/test_stage3_security.py backend/shared/tests/test_smt.py backend/shared/tests/test_shared.py backend/verification_service/tests/test_verifier.py backend/verification_service/tests/test_legacy_acir_adapter.py backend/verification_service/tests/test_public_input_binding.py backend/verification_service/tests/test_certificate_rotation.py
```
*Observed Evidence: 102 passed, 71 warnings in 14.63s.*

### B. Tenant Isolation & Proof Job Recovery Suite
Run from `backend/` directory (`E:\Main Project\backend`):
```powershell
..\.venv\Scripts\python.exe -m pytest --import-mode=importlib sbom_service/tests/test_tenant_isolation.py zkp_service/tests/test_tenant_isolation.py zkp_service/tests/test_job_recovery.py
```
*Observed Evidence: 20 passed. Mandatory: Must include `--import-mode=importlib` to avoid duplicate `test_tenant_isolation.py` module name collision.*

### C. Vulnerability Ingestion & Separation of Duties Suite
Run from `backend/` directory (`E:\Main Project\backend`):
```powershell
..\.venv\Scripts\python.exe -m pytest vulnerability_service/tests/test_vulnerability_ingestion.py
```
*Observed Evidence: 37 passed in 2.18s.*

### D. Alembic Migration Suite (Isolated In-Memory Chain 001–014)
Run from `backend/` directory (`E:\Main Project\backend`):
```powershell
..\.venv\Scripts\python.exe -m pytest alembic/tests/
```
*Observed Evidence: 161 passed in 1.20s. Mandatory: Run from `backend/` to prevent `backend/alembic` from shadowing the installed third-party `alembic` library.*

### E. Frontend Testing & Typechecking
Run from `frontend/` directory (`E:\Main Project\frontend`):
```powershell
npm test
npx tsc --noEmit
npx eslint .
```
*Observed Evidence: 39 tests passed in 405ms; 0 TypeScript compilation errors.*

---

## 3. SRMIST Wi-Fi / Local-Only Constraint (October 13, 2026)

Live database connectivity (including Supabase) is unavailable on SRMIST Wi-Fi:
- **No Remote Database Commands**: Do not invoke commands that attempt to reach Supabase or remote PostgreSQL instances.
- **Labeling**: Label all database behaviors as **NOT VERIFIED AGAINST LIVE SUPABASE/POSTGRESQL**.
- **No Workarounds**: Do not modify Supabase pooling or TLS parameters to bypass connection failures.

---

## 4. Operational & Service Commands (STRICTLY BLOCKED — Gate 5R)

The following operational actions require explicit project-owner authorization and are **STRICTLY BLOCKED**:

- **Starting Docker Services:** `docker-compose up -d`
- **Rebuilding Containers:** `docker-compose build <service_name>`
- **Restarting Services:** `docker-compose restart <service_name>`
- **Database Migrations on Live Staging DB:** `alembic upgrade head`
- **Live Golden Path Proving Execution:** `python execute_golden_path.py`
- **Source ZIP Packaging / External Distribution:** `python scripts/package_source_zip.py`

---

## 5. Forbidden / Irreversible Commands (NEVER RUN)

- `git clean -fd` or `git clean -f` (Deletes untracked migrations `012..014`, local archives, and governance files).
- `git reset --hard` or `git checkout -- .` (Destroys uncommitted Stage B and context improvements).
- `docker-compose down -v` (Destroys persistent PostgreSQL volume data).
- Regenerating circuit verification keys or ACIR binaries without explicit authorization.

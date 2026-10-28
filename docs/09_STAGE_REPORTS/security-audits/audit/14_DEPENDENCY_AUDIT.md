# Dependency and Supply-Chain Audit

## Pinned Dependencies

Backend pins FastAPI 0.115.6, Uvicorn 0.34.0, Pydantic 2.10.4, SQLAlchemy 2.0.36, pyodbc 5.2.0, Alembic 1.14.1, pytest 8.3.4, and httpx 0.28.1 in `backend/shared/requirements.txt`; service manifests include that file. Frontend pins direct versions in `package.json` ranges and records the resolved tree in `frontend/package-lock.json`. Circuit packages declare Noir compiler version 0.32.0 and no Nargo dependencies.

## Executed Scans

- `npm audit --audit-level=moderate` from `frontend/` -> 0 vulnerabilities.
- `gitleaks detect --no-banner --redact --source .` -> no leaks found.
- Semgrep 1.165.0 installed, but auto config failed due metrics mode and Python rules failed before analysis while parsing the repository ignore configuration. No Semgrep result is claimed.

## Unavailable Scans

- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `pip-audit`.
- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `safety`.
- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `bandit`.
- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `trivy`.
- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `grype`.
- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `syft`.
- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `osv-scanner`.
- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `cyclonedx-py`.
- TOOL NOT AVAILABLE — SCAN NOT EXECUTED: `nargo` and `bb`.

## Supply-Chain Gaps

No CI workflow was found. Dockerfiles use floating `python:3.11-slim`, `nginx:alpine`, and `mcr.microsoft.com/mssql/server:2022-latest` tags; package apt repositories are accessed during build. No image digest pinning, SBOM attestation, signature verification, or reproducible build evidence was found. Classification: HARDENING RECOMMENDATION.

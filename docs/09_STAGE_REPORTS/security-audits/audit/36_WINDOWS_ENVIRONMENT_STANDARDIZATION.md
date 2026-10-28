# Windows Environment Standardization

Date: 2026-09-14

## Decision

Native Windows development is standardized on:

- Windows x64 host.
- Python 3.12.10 in the project-local `.venv`.
- Node.js 24.19.0 and npm 11.17.0.
- SQL Server 2022 as the declared Compose target; the installed SQL Server 2025 Express instance is retained only as a compatibility sanity check.
- WSL2 or Docker Linux for Noir and Barretenberg.
- Nargo/Noir 0.32.0 and candidate Barretenberg 0.46.1.

Python 3.11 is not required by the Python dependency graph. It appeared only in service Dockerfiles (`python:3.11-slim`). Python 3.12 installed all declared and discovered dependencies, passed `pip check`, imported all services, and passed the complete backend suite. Python 3.12 is therefore the authoritative native development runtime. No downgrade was performed.

## Environment-only changes

1. Created `.venv` with the installed Python 3.12 interpreter.
2. Added directly imported missing dependencies to `backend/shared/requirements.txt`: `bcrypt==5.0.0`, `PyJWT==2.12.1`, `python-multipart==0.0.32`, and test dependency `requests==2.34.2`.
3. Corrected only the archive extraction path in `docker/Dockerfile.noir`; the official Nargo 0.32.0 archive contains a root-level `nargo` binary.
4. Removed measured generated caches only. See reports 40 and 41.

No application behavior, API contract, schema, migration, circuit, proof semantics, authentication logic, or test expectation was modified.

## Validation result

- Python 3.12: verified.
- Backend dependency consistency: verified.
- Backend imports/startup imports: verified.
- Backend tests: `480 passed`, warnings only.
- Frontend lockfile installation/build: verified.
- Database driver and local server reachability: verified.
- Docker/Compose: verified.
- WSL2: verified.
- Nargo Docker provisioning: verified after the archive-layout correction.
- Production cryptographic readiness: not verified; production VK/proof and public-input experiment remain unavailable.

## Configuration decision

The repository's SQL Server 2022 Compose strategy remains the canonical project strategy. The local SQL Server 2025 Express instance is not silently promoted to the project target because the application configuration expects SQL authentication, while the available non-destructive check used Windows authentication against `master`. No `.env` or credentials were created.

# Complete Environment Inventory

Date: 2026-09-13  
Scope: Discovery and non-destructive verification only. No application, circuit, test, schema, or API behavior was changed.

## Executive status

## Environment Status: Partially Ready

The host can run the Python tests, build the frontend, reach a local SQL Server instance, run Docker, and execute the repository compiler check through WSL. The environment is not fully ready because the declared SQL Server 2022 target is not the reachable local server, the project has no configured database credentials, the production verification key is absent, the checked-in production proof is a 10-byte placeholder, and the Dockerfile Nargo installation step is broken against the downloaded archive layout. Full proof generation, verification, and public-input binding remain unvalidated.

## Inventory

| Component | Why required | Required version/range | Detected version/path | Environment | Status | Executable/compatible result | Recommended action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Windows OS | Current host and Docker/WSL integration | Windows x64 with WSL2 support | Windows 10 Pro build 26200, AMD64 | Windows | VERIFIED | Host commands execute | Preserve host; use Linux path for ZK tools |
| WSL | Backend explicitly invokes WSL and `kali-linux` | WSL2 | `kali-linux`, version 2, running; default distribution | Windows/WSL | VERIFIED | `wsl -l -v`, `wsl --status` pass | Keep distribution/tool paths documented |
| Python | Backend services and tests | Service images pin 3.11; host needs supported 3.x | 3.12.10, `C:\Program Files\Python312\python.exe` | Windows | VERIFIED | Imports and tests pass; host differs from image pin | Use a project 3.11 environment for deployment parity |
| Virtual environment | Isolation and reproducibility | Project-local environment expected operationally | No `.venv` found; global Python used | Windows | MISSING | No project venv | Create a controlled venv manually before development; do not commit it |
| pip | Python package installation | Compatible with Python | 26.1.2 | Windows | VERIFIED | `pip --version` executes | Preserve |
| FastAPI/Uvicorn/Pydantic/SQLAlchemy/pyodbc/Alembic | Backend runtime | Exact pins in `backend/shared/requirements.txt` | 0.115.6 / 0.34.0 / 2.10.4 / 2.0.36 / 5.2.0 / 1.14.1 | Windows Python | VERIFIED | All import; exact pins observed | Reinstall only inside controlled venv if needed |
| pytest/httpx | Backend tests | 8.3.4 / 0.28.1 | Exact versions observed | Windows Python | VERIFIED | 480 tests passed | Preserve |
| Node.js | Next.js frontend | Next 16 requires modern supported Node; no repo pin | v24.19.0, `C:\Program Files\nodejs\node.exe` | Windows | VERIFIED | Build passes | Pin via project toolchain documentation if release reproducibility requires it |
| npm | Frontend dependency management | Lockfile-compatible npm | 11.17.0 | Windows | VERIFIED | `npm ci` completed | Preserve lockfile |
| Frontend packages | Next/React application | `frontend/package-lock.json` | 598 packages installed from lockfile | Windows | VERIFIED | `npm run build` passes; no missing modules | Preserve lockfile and installed tree |
| Frontend lint | Quality check | ESLint configured in package scripts | ESLint 9 tree | Windows | VERIFIED_WITH_WARNING | One existing unused `CardDescription` warning; zero errors | Record warning; no behavior change in this task |
| SQL Server | Declared database backend | SQL Server 2022 container | Local `MSSQL$SQLEXPRESS`, server 17.0.1135.8 (SQL Server 2025 Express) | Windows | WRONG_VERSION | Windows-authenticated `SELECT @@VERSION` succeeds, but target version differs | Provision/use SQL Server 2022 target for project validation |
| SQL client | Database health/migrations | sqlcmd compatible with ODBC 18 image | sqlcmd 15.0.1300.359; paths include ODBC 17 and 18 tools | Windows | VERIFIED | `sqlcmd -?` executes | Use matching ODBC 18 sqlcmd for container checks |
| ODBC drivers | pyodbc database connection | ODBC Driver 18 for SQL Server | ODBC 17 and 18 installed; pyodbc 5.2.0 | Windows | VERIFIED | Driver enumeration succeeds | Use Driver 18 explicitly |
| Git | Source/version evidence | Any supported Git | 2.55.0.windows.3 | Windows | VERIFIED | Executes | Preserve |
| Docker Engine | Compose and pinned Linux tooling | Linux daemon | 29.7.2, Docker Desktop Linux, x86_64 | Windows/WSL | VERIFIED | `docker info` succeeds | Preserve |
| Docker Compose | Multi-service deployment | Compose v2+ | v5.5.1 | Windows/WSL | VERIFIED | `docker compose config --quiet` succeeds | Build blockers remain separate |
| Rust/Cargo | Not referenced by application build | Not required | rustc/cargo 1.98.1 | Windows | NOT_REQUIRED | Executes | No action |
| Nargo/Noir | Circuit compiler and witness generation | Exactly 0.32.0 | `/home/kali/.nargo/bin/nargo`; no Windows PATH entry; no direct WSL PATH entry | WSL | VERIFIED_FOR_CHECK_ONLY | Version and temporary-copy `nargo check` pass | Make path/provisioning part of approved Linux setup |
| Barretenberg CLI | Proving/verifying commands | Candidate 0.46.1 | `/home/kali/.bb/bb`, SHA-256 `22a4f456b7f8d2eebf7e2b5a8d51984628f867c3763feb6793fcd8372d6ced1f` | WSL | INSTALLED_BUT_NOT_FUNCTIONAL_FOR_PROJECT | `--version` works; no valid project proof/VK verification | Approve provenance and validate with real matching artifacts |
| NoirJS / bb.js | Only required if structured public-input API is selected | Vendored backend 0.32.0; bb.js 0.46.1 | Source metadata present under `scripts/noir_src`; not built/executed | Repository | UNKNOWN | Capability is source-evidenced only | Execute isolated supported API experiment before approval |
| OpenSSL | Linux crypto/system utility | Any supported version | WSL OpenSSL 3.6.2 | WSL | VERIFIED | Executes | Preserve |
| curl | Dockerfile downloads and utility checks | Any supported version | Windows curl 8.21.0; WSL curl available through base system | Windows/WSL | VERIFIED | Executes | Preserve |
| wget | Optional download utility | Not used by project | Missing on Windows; not required by declared files | Windows | NOT_REQUIRED | Not used | No action |
| jq | Dockerfile and Linux inspection utility | Any supported version | WSL jq 1.8.1 | WSL | VERIFIED | Executes | Preserve |
| make/gcc/clang | Generic build utilities | Required only if a native build path uses them | WSL make/gcc/clang missing; Windows MinGW GCC 6.3.0 | Windows/WSL | NOT_REQUIRED_FOR_CURRENT_DECLARED_BUILD | No current project command requires them; native toolchain is incomplete | Install only for an approved native build path |
| bash/core Linux utilities | WSL subprocesses and Docker image | Bash and standard utilities | WSL bash 5.3.9; core utilities present | WSL | VERIFIED | Bash executes | Preserve |
| Required system libraries | pyodbc and Docker services | ODBC Driver 18, unixODBC in image | Windows ODBC 18 present; Docker image declares unixodbc-dev/msodbcsql18 | Windows/Docker | VERIFIED_FOR_HOST_DRIVER | Host driver available; service image not built | Validate service image after deployment decision |
| Alembic | Database migrations | 1.14.1 | 1.14.1 importable | Windows Python | VERIFIED_TOOL_ONLY | Migration CLI/package available; no project DB migration executed | Run only against approved non-destructive target |
| Ports | Gateway, DB, frontend, services | 80, 1433, 3000, service ports as configured | No project listener evidence; local SQL uses named instance rather than declared 1433 target | Windows | BLOCKED | Target topology not established | Provision controlled Compose environment |

## Artifact inventory

| Artifact | Result |
| --- | --- |
| Production target JSON | Present, 54,913,292 bytes; SHA-256 `2E493E08116BFA26CB9EAD989F65D901DE9BEC122CDEA04E797B46A0E2DAC747` |
| Development target JSON | Present, 1,086,829 bytes; SHA-256 `C6293324EE020F32A1FFFD7303C52F88E1297C5E56A52D98DFEB6A25D171CD5D` |
| Production VK `circuits/target/vk` | Missing |
| Development VK `circuits_dev/target/vk` | Present, 1,719 bytes; SHA-256 `A8733E6CA6434360FAC2C91A7E94D9B4FF70A74ED4A0D392D6517032AFC29E75`; must not be treated as production |
| Production proof | Present, 10 bytes; SHA-256 `5FCE5F5878415A3BAE17DB60A69B08D51F0F962228BFDBB462993A3AC16171E4`; not a validated proof |

## Configuration

No `.env`, frontend env file, or relevant process-level variables were present. `.env.example` requires a database password but does not provide one. No secret values were printed or generated. JWT, CORS, API URL, proving path, profile, and verification-key configuration are therefore not operationally loaded.

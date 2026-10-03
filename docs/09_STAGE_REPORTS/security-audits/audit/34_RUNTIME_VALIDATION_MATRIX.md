# Runtime Validation Matrix

Date: 2026-09-13

Status values follow the requested vocabulary. `VERIFIED_WITH_WARNING` is used only for the lint result and does not mean a required component is fully approved.

| Component | Required Version | Detected Version | Status | Verified Command | Notes |
| --- | --- | --- | --- | --- | --- |
| Windows/architecture | Windows x64 | Windows 10 Pro build 26200, AMD64 | VERIFIED | `Get-ComputerInfo` | Host operational |
| Python | Service pin 3.11 | 3.12.10 | WRONG_VERSION | `python.exe --version` | All tests pass, but host does not match image pin |
| Project venv | Isolated environment | None | MISSING | `Test-Path .venv` | Global interpreter was used |
| pip | Compatible package manager | 26.1.2 | VERIFIED | `pip.exe --version` | Operational |
| Shared Python packages | Exact requirements pins | Exact pins observed | VERIFIED | Python import/version probe | Includes FastAPI, Uvicorn, Pydantic, SQLAlchemy, pyodbc, Alembic |
| Backend tests | Test suite | 480 passed, 25 warnings | VERIFIED | `python -m pytest -q` | Warnings are deprecations only |
| Node.js | Next-compatible modern Node | 24.19.0 | VERIFIED | `node.exe --version` | Build passes |
| npm | Lockfile install | 11.17.0 | VERIFIED | `npm.cmd --version` | `npm ci` completed |
| Frontend dependency tree | package-lock exact tree | 598 packages | VERIFIED | `npm ci --ignore-scripts` | Lockfile not changed |
| Frontend build/typecheck | Configured Next build | Next 16.3.5; TypeScript completed | VERIFIED | `npm run build` | Static pages generated |
| Frontend lint | ESLint | 0 errors, 1 warning | VERIFIED_WITH_WARNING | `npm run lint` | Existing unused import warning |
| SQL Server | 2022 | 17.0.1135.8, SQL Server 2025 Express | WRONG_VERSION | `sqlcmd -S localhost\\SQLEXPRESS -E -Q ...` | Reachable, wrong target version |
| SQL database target | `ZKP_SBOM` | Not checked/created | BLOCKED | Configuration absent | No destructive action taken |
| SQL client | Compatible sqlcmd | 15.0.1300.359 | VERIFIED | `sqlcmd -?` | Executes |
| ODBC Driver | Driver 18 | Driver 18 installed | VERIFIED | `pyodbc.drivers()` | Driver 17 also present |
| Docker Engine | Linux daemon | 29.7.2 | VERIFIED | `docker info` | Server reachable |
| Docker Compose | Compose v2+ | v5.5.1 | VERIFIED | `docker compose config --quiet` | Syntax/interpolation valid with validation-only value |
| WSL | WSL2 Kali | Kali Linux WSL2 running | VERIFIED | `wsl -l -v` | Operational |
| Nargo | 0.32.0 | 0.32.0+c679f01... | VERIFIED | `/home/kali/.nargo/bin/nargo --version` | Direct WSL path; no production proof claim |
| Nargo circuit check | `circuits` compiler 0.32.0 | Constraint system built | VERIFIED | Temporary-copy `nargo check` | Repository untouched |
| Nargo Docker recipe | Pinned 0.32.0 image | Build failed | INSTALLED_BUT_NOT_FUNCTIONAL | `docker build -f docker/Dockerfile.noir ...` | Archive path assumption fails |
| Barretenberg CLI | Candidate 0.46.1 | 0.46.1 | INSTALLED_BUT_NOT_FUNCTIONAL | `/home/kali/.bb/bb --version` | No valid production artifact pair |
| Barretenberg hash | Approved binary hash | `22a4f456...6ced1f` | UNKNOWN | `sha256sum /home/kali/.bb/bb` | Provenance not approved for project |
| NoirJS/bb.js | 0.32.0/0.46.1 if selected | Vendored metadata only | UNKNOWN | Source inspection | Not built/executed |
| Production VK | Matching selected circuit | Absent | MISSING | `Test-Path circuits/target/vk` | Dev VK must not be substituted |
| Production proof | Real matching proof | 10-byte file | BLOCKED | Artifact size/hash inspection | Not cryptographically validated |
| OpenSSL | Required Linux utility | 3.6.2 WSL | VERIFIED | `openssl version` | Operational |
| curl | Docker/download utility | 8.21.0 Windows | VERIFIED | `curl --version` | Operational |
| jq | Docker/Linux utility | 1.8.1 WSL | VERIFIED | `jq --version` | Operational |
| bash/core utilities | WSL subprocess path | bash 5.3.9 | VERIFIED | `bash --version` | Operational |
| make/gcc/clang in WSL | Native build only | Missing | NOT_REQUIRED | `command -v` probes | Not required by current declared build |
| Rust/Cargo | No project usage found | 1.98.1 | NOT_REQUIRED | `rustc --version`, `cargo --version` | Installed but not required |
| Git | Source operations | 2.55.0.windows.3 | VERIFIED | `git --version` | Operational |

## Acceptance result

The acceptance rules are not met. Required dependencies remain missing, wrong-version, unknown, or cryptographically blocked. The backend and frontend validation slices pass, but the environment cannot be declared fully ready.

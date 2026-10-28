# Native Windows Components

Date: 2026-09-14

| Component | Required by | Required version | Detected/path | Status | Verification |
| --- | --- | --- | --- | --- | --- |
| Windows | Host development | x64 with WSL2 | Windows 10 Pro build 26200, AMD64 | VERIFIED | `Get-ComputerInfo` |
| Python | Backend/tests | 3.12 authoritative | 3.12.10; `E:\Main Project\.venv\Scripts\python.exe` | VERIFIED | `.venv\Scripts\python.exe --version` |
| venv/pip | Python isolation | Python 3.12 compatible | pip 25.0.1 in `.venv` | VERIFIED | `python -m pip --version` |
| Backend packages | Requirements and imports | Exact pins in shared requirements | All declared/discovered pins installed | VERIFIED | `python -m pip check`; import probe |
| Node.js | Next frontend | Next-compatible modern Node | v24.19.0 | VERIFIED | `node --version` |
| npm | Frontend lockfile | Lockfile-compatible npm | 11.17.0 | VERIFIED | `npm --version`; `npm ci` |
| Git | Repository | Supported Git | 2.55.0.windows.3 | VERIFIED | `git --version` |
| Docker Desktop | Compose/Linux image | Running Linux daemon | 29.7.2, Linux daemon | VERIFIED | `docker info` |
| Docker Compose | Compose deployment | v2+ | v5.5.1 | VERIFIED | `docker compose config --quiet` |
| SQL client | Database checks | sqlcmd available | 15.0.1300.359 | VERIFIED | `sqlcmd -?` |
| SQL Server | Local sanity check | Declared target is 2022 | SQL Server 2025 Express 17.0.1135.8 | WRONG_VERSION | `sqlcmd -S localhost\\SQLEXPRESS -E -Q ...` |
| ODBC | Python DB driver | Driver 18 | ODBC Driver 18 installed; pyodbc 5.2.0 | VERIFIED | `pyodbc.drivers()` and connection |
| Rust/Cargo | No actual project command | Not required | 1.98.1 | NOT_REQUIRED | Version commands execute |
| Windows OpenSSL | Not used by declared native path | Not required | Not on PATH | NOT_REQUIRED | WSL OpenSSL used instead |
| Windows curl | Docker/download utility | Supported | 8.21.0 | VERIFIED | `curl --version` |
| Windows wget | No project usage | Not required | Missing | NOT_REQUIRED | Requirement search |
| WSL make/gcc/clang | No declared current build | Not required | Missing in Kali | NOT_REQUIRED | `command -v` probes |
| WSL bash/jq/OpenSSL | Linux toolchain support | Supported | bash 5.3.9, jq 1.8.1, OpenSSL 3.6.2 | VERIFIED | Version probes |

## Exact Python package set

`fastapi 0.115.6`, `uvicorn 0.34.0`, `pydantic 2.10.4`, `sqlalchemy 2.0.36`, `pyodbc 5.2.0`, `alembic 1.14.1`, `bcrypt 5.0.0`, `PyJWT 2.12.1`, `python-multipart 0.0.32`, `pytest 8.3.4`, `httpx 0.28.1`, and `requests 2.34.2` are installed in `.venv` and pass `pip check`.

## Frontend result

`npm ci` installed 598 lockfile-resolved packages. `npm run build` passed with TypeScript completion. `npm run lint` completed with zero errors and one existing unused `CardDescription` warning. Package versions were not changed.

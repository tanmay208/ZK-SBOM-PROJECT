# Installation and Configuration Report

Date: 2026-09-13

## Actions performed

1. Read repository manifests, Dockerfiles, Compose configuration, circuit manifests, scripts, and prior audit records.
2. Verified host and WSL executables and paths.
3. Ran `npm ci --prefix frontend --ignore-scripts` from the committed lockfile. It completed with 598 packages and did not change the lockfile.
4. Ran backend imports and the complete pytest suite.
5. Ran the frontend build and lint.
6. Ran a non-destructive Windows-authenticated SQL query against the existing named SQL Express instance.
7. Ran `docker compose config --quiet` with a process-local validation-only interpolation value; no secret was persisted.
8. Built the repository-pinned Nargo Docker image. The build reached the download step and failed because the Dockerfile expected `nargo-x86_64-unknown-linux-gnu/nargo`, which was not present in the downloaded archive.
9. Verified existing WSL Nargo and Barretenberg binaries directly. No installation or upgrade was performed.

## Installation results

### Already installed and verified

- Python dependencies at the exact shared requirement pins import successfully.
- Node.js/npm and the frontend lockfile dependency tree are operational.
- Docker Engine and Compose are operational.
- WSL2 Kali is operational.
- WSL Nargo `0.32.0` and Barretenberg `0.46.1` execute directly.
- ODBC Driver 18 and pyodbc are installed.
- SQL client, Git, curl, Rust/Cargo, Windows MinGW GCC, WSL OpenSSL, jq, and bash execute where required.

### Installed but not project-functional

- Barretenberg can report its version, but there is no production VK/proof pair to exercise. Project verification therefore remains unvalidated.
- Local SQL Server is reachable but is SQL Server 2025 Express, not the declared SQL Server 2022 target, and the project database/configuration was not established.

### Missing or blocked

- Project-local Python virtual environment.
- Production verification key.
- Operational `.env` configuration and non-secret database connection configuration.
- A successful repository-pinned Nargo Docker image build.
- A real production proof and completed public-input binding experiment.

## Configuration audit

| Configuration | Presence | Security/validity | Loaded result |
| --- | --- | --- | --- |
| Database password | Missing from files/process | Cannot validate; no secret generated | Not loaded |
| Database host/name/driver | Declared in `.env.example` and Compose defaults | Driver declaration is appropriate; target server not established | Not loaded |
| JWT secret | No value in environment/files | Secure absence is preferable to committing a value, but runtime is not configured | Not loaded |
| JWT expiry | Not present in `.env.example` | Must be reviewed from application settings before deployment | Not operationally validated |
| CORS | Application default exists in source | Runtime deployment value not loaded | Not operationally validated |
| Frontend API URL | No frontend env file found | No runtime frontend API configuration | Not loaded |
| Nargo path | Service code references WSL paths; `/home/kali/.nargo/bin/nargo` exists | Direct executable works, but PATH/provisioning is not uniform | Partially loaded by direct path only |
| Barretenberg path | `/home/kali/.bb/bb` exists | Version works; production integration not approved | Partially available |
| Circuit profile | `DEV_MODE`-based application selection found in source | No immutable approved production profile | Not approved |
| Verification-key path | Development path exists; production path absent | Development VK cannot satisfy production use | Not loaded for production |
| Network ports | Compose declares 80, 1433, 3000; services use internal ports | Full topology not started | Not validated |

No secrets were exposed, created, or committed. No database reset, destructive migration, or service restart was performed.

## Provisioning recommendation

Use a controlled Python 3.11 virtual environment and a SQL Server 2022 target matching Compose. Repair or replace the Nargo Docker provisioning recipe only after confirming the official release archive layout and checksum. Keep the WSL binaries isolated until a real matching VK/proof and negative-test evidence exists.

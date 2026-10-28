# Remaining Environment Blockers

Date: 2026-09-13

## Environment Status: Partially Ready

## Blocking items

1. **Production cryptographic artifacts are unavailable.** `circuits/target/vk` does not exist. The only VK is `circuits_dev/target/vk` and is explicitly development-only. The checked-in production proof is 10 bytes and has not verified.
2. **Proof generation and verification are incomplete.** Nargo `0.32.0` checks the circuit in a temporary copy, and Barretenberg `0.46.1` reports its version, but no real production proof/VK pair has been generated and verified. Nargo/Barretenberg compatibility for the production profile is therefore unknown.
3. **Public-input binding is not validated.** No supported structured public-input extraction/comparison experiment completed. Do not treat `nargo check`, witness generation, a proof file, or a Barretenberg exit code as proof of `PROOF == REQUEST == AUTHORITY`.
4. **The repository Nargo Docker recipe is not currently buildable.** The pinned Docker build fails at `mv nargo-x86_64-unknown-linux-gnu/nargo` because the downloaded archive does not contain that expected directory. This report does not alter the recipe.
5. **Database target mismatch.** The reachable local instance is SQL Server 2025 Express 17.0.1135.8, while the project declares SQL Server 2022. The `ZKP_SBOM` database and project credentials were not verified. No database was created or modified.
6. **Runtime isolation/configuration is incomplete.** There is no project `.venv`, no `.env`, no frontend env file, and no loaded database password/JWT/API/proving configuration. No secrets were generated.
7. **Deployment files are incomplete.** `docker-compose.yml` references `docker/nginx.conf` and `frontend/Dockerfile`, but those paths are absent. Compose syntax passes; a full deployment build was not claimed.

## Non-blocking findings

- Backend suite: 480 passed with 25 deprecation warnings.
- Frontend production build: passed; TypeScript completed.
- Frontend lint: zero errors and one unused-import warning.
- Docker daemon and Compose client: operational.
- WSL2 Kali, OpenSSL, jq, bash, ODBC Driver 18, Git, curl, and required Python packages: operational.
- WSL make/gcc/clang are missing, but no declared current project build requires them.

## Required manual actions

1. Select and provision the approved SQL Server 2022 environment and non-secret configuration values; supply secrets through the operator’s secret-management process.
2. Establish a controlled Python 3.11 environment matching the service images.
3. Repair or replace the Nargo provisioning recipe using an official, checksum-verified release archive without changing application behavior.
4. Approve the Barretenberg binary provenance and interface for the chosen integration path.
5. Select one production circuit profile, generate a matching production VK and real proof in disposable isolated storage, and record hashes.
6. Execute positive, tampered, malformed, wrong-VK, wrong-profile, and altered-public-input tests through the supported interface.
7. Resolve the missing Compose build inputs before claiming full deployment readiness.

## Readiness decision

The project is **not ready to resume Phase 5B cryptographic runtime recovery**. It may resume only after the cryptographic toolchain, production artifacts, database target, and public-input binding evidence are completed and independently recorded.

## Final categorization

- Installed successfully: Python packages, frontend packages, Node/npm, Docker/Compose, WSL2, ODBC Driver 18, SQL client, Git, curl, WSL OpenSSL/jq/bash, Nargo direct WSL check path.
- Already installed and verified: backend tests, frontend build, Docker daemon, Compose syntax, database reachability to the wrong-version local SQL instance.
- Installed but malfunctioning: repository Nargo Docker recipe; Barretenberg project validation due to absent matching artifacts.
- Missing: project venv, production VK, configured project database target, frontend/service deployment files referenced by Compose.
- Wrong version: local SQL Server target; host Python differs from service image pin.
- Blocked by environment/resource constraints: production proof/VK generation and public-input binding experiment.
- Requires manual user action: provision approved SQL Server 2022 and secrets, approve/provision cryptographic artifacts, and resolve deployment file/toolchain decisions.

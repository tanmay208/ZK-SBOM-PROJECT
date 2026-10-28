# A0 — Repository & Environment Reproducibility Audit

**Date:** 2026-10-04  
**Project:** Privacy-Preserving Zero-Knowledge SBOM Vulnerability Verification Platform  
**Auditor:** Automated (Antigravity IDE)

---

## 1. Executive Summary

**Verdict: CONDITIONALLY REPRODUCIBLE**

The repository contains a well-structured, deeply documented full-stack ZKP-SBOM application with backend microservices, a Next.js frontend, Noir circuits, and comprehensive tests. However, a **fresh checkout cannot currently be fully reproduced** due to:

1. **Critical cryptographic artifacts (segment circuit compiled JSON, VKs, proofs) are `.gitignore`d** — they exist locally but are excluded from the repository by `target/`, `Prover.toml`, and other ignore rules. The backend startup validates these artifacts by hash and will fail without them.
2. **No lockfile or pinned dependency management** for Python (no `pip-compile` output, no `poetry.lock`, no `uv.lock`).
3. **`tsx` is not declared as a frontend dependency** — `npm test` relies on `npx tsx` to fetch it at runtime.
4. **`.env` (secrets) is required but not tracked** — as designed, but no automated way to generate valid secrets.
5. **Alembic configuration references MSSQL/pyodbc** while the runtime code and Docker use PostgreSQL — this is a historical residue that creates confusion.
6. **`init_db.py` references MSSQL `master` database and `settings.driver`** which doesn't exist in the current `DatabaseSettings` class.
7. **Many local-only files (archives, segment_* directories, experiment scripts) are untracked** — some are historical evaluation evidence, some are generated artifacts.
8. **The GitHub repository appears private or inaccessible** (404 from API) — remote reachability cannot be independently verified.

---

## 2. Repository State

| Property | Value |
|---|---|
| **Absolute path** | `E:\Main Project` |
| **Git root** | `E:\Main Project` |
| **Current branch** | `chore/final-project-cleanup` |
| **Current commit** | `0881f9e` — *"chore: publish project snapshot before frontend and deployment"* |
| **Commit date** | 2026-10-03 23:22:17 +0530 |
| **Remote** | `origin` → `https://github.com/tanmay208/Zero-knowledge-sbom-vulnerability-verification.git` |
| **Remote HEAD** | `origin/chore/final-project-cleanup` → same commit `0881f9e` (in sync) |
| **Local `main` branch** | `733fd63` (tag: `day-01-architecture`) |
| **Remote `main`** | Not published (only `chore/final-project-cleanup` exists remotely) |
| **Total commits** | 3 on `main` + 1 on `chore/final-project-cleanup` |
| **Stash** | Empty |
| **Working tree** | 2 modified tracked files, 16 staged-but-uncommitted new files, 26+ untracked items |

### Git Status Detail

**Modified (unstaged):**
- `backend/verification_service/app/main.py`
- `frontend/src/app/login/page.tsx`

**Staged (new, not yet committed):**
- 16 files under `scripts/` (`.nr`, `.py`, Noir experiments)

**Untracked:**
- `archives/` — proof archive evidence (ZIP + 250+ `.proof` files)
- `circuits_dev/` — development-profile Noir circuits with mutated proofs
- `segment_final/`, `segment_final_32/`, `segment_init/`, `segment_init_32/`, `segment_mid/`, `segment_mid_32/`, `segment_mid_32_1/` through `segment_mid_32_6/` — Noir circuit source + compiled artifacts
- `docs/09_STAGE_REPORTS/REPOSITORY_CLEANUP_AUDIT.md`, `REPOSITORY_CLEANUP_FINAL.md`
- Various scripts under `scripts/` (benchmarks, stage generators, measurement scripts)
- `staged_files.txt`

**Ignored (by `.gitignore`):**
- `.env`, `.venv/`, `.bin/`, `.vscode/`, `node_modules/`, `target/`, `Prover.toml`, `data/*`
- All compiled circuit artifacts inside `segment_*/target/` directories
- All `Prover.toml` files in segment directories
- `frontend/node_modules/`, `frontend/tsconfig.tsbuildinfo`

### Dangling Commits

Reflog shows 7 unreachable commits from "Agent host session 4410165f…" above HEAD. These are orphaned — not on any branch, not reachable from HEAD. They appear to be from a previous automated agent session.

---

## 3. Local vs GitHub Differences

| Item | Exists Locally | Git Tracked | Git Ignored | Classification | Evidence |
|---|---|---|---|---|---|
| `.env` | ✅ | ❌ | ✅ | **LOCAL-ONLY (by design)** | Contains secrets; `.gitignore` excludes `.env` |
| `.env.example` | ✅ | ✅ | ❌ | **REQUIRED** | Template for `.env` creation |
| `.bin/nargo` | ✅ | ❌ | ✅ | **LOCAL-ONLY / REPRODUCIBLE** | 44MB Nargo binary; `.gitignore` excludes `.bin/` |
| `.venv/` | ✅ | ❌ | ✅ | **LOCAL-ONLY / REPRODUCIBLE** | Python virtual environment |
| `.vscode/settings.json` | ✅ | ❌ | ✅ | **LOCAL-ONLY** | IDE settings |
| `archives/` | ✅ | ❌ | ❌ (untracked) | **HISTORICAL/EVALUATION EVIDENCE** | Contains proof ZIP + 250+ proof files from Stage21 run |
| `circuits_dev/` | ✅ | ❌ | ❌ (untracked) | **HISTORICAL/EVALUATION EVIDENCE** | Dev-profile circuit with mutated proofs for negative testing |
| `segment_init_32/` | ✅ | ❌ | ❌ (untracked, but `target/` and `Prover.toml` within are ignored) | **REQUIRED (source) + GENERATED (artifacts)** | Circuit source is required; `target/` is generated by Nargo; docker-compose mounts this |
| `segment_mid_32/` | ✅ | ❌ | Partially | **REQUIRED (source) + GENERATED (artifacts)** | Same as above |
| `segment_final_32/` | ✅ | ❌ | Partially | **REQUIRED (source) + GENERATED (artifacts)** | Same as above |
| `segment_init/`, `segment_mid/`, `segment_final/` | ✅ | ❌ | Partially | **HISTORICAL/EVALUATION EVIDENCE** | 8-component topology (non-C32), likely from earlier stages |
| `segment_mid_32_1/` through `segment_mid_32_6/` | ✅ | ❌ | Partially | **HISTORICAL/EVALUATION EVIDENCE** | Appear to be variant/numbered mid-segments for multi-chunk workloads |
| `data/` | ✅ (empty) | ❌ | ✅ | **LOCAL-ONLY** | `.gitignore` excludes `data/*` |
| `frontend/node_modules/` | ✅ | ❌ | ✅ | **REPRODUCIBLE** | Installed by `npm ci` |
| `staged_files.txt` | ✅ | ❌ | ❌ | **UNKNOWN** | 28KB file listing 516 filenames — appears to be a snapshot inventory |
| `scripts/benchmarks/` | ✅ | ❌ | ❌ | **HISTORICAL/EVALUATION EVIDENCE** | SMT scaling benchmarks and test scripts |
| `scripts/execute_stage21.py` | ✅ | ❌ | ❌ | **HISTORICAL/EVALUATION EVIDENCE** | Stage21 execution driver |
| `scripts/generate_c32_circuits.py` | ✅ | ❌ | ❌ | **REQUIRED (if reproducing circuits)** | Generates the C32 segment circuit source code |
| `scripts/stage21_payload.json` | ✅ | ❌ | ❌ | **HISTORICAL/EVALUATION EVIDENCE** | 129KB test payload for Stage21 |
| `docs/09_STAGE_REPORTS/REPOSITORY_CLEANUP_AUDIT.md` | ✅ | ❌ | ❌ | **UNKNOWN** | Recent cleanup audit reports not yet tracked |
| `docs/09_STAGE_REPORTS/REPOSITORY_CLEANUP_FINAL.md` | ✅ | ❌ | ❌ | **UNKNOWN** | Same |

### GitHub-Only Items

Local HEAD matches remote HEAD (`0881f9e`). No items exist on GitHub that are absent locally.

### Tracked-but-Generated Items

The following items are tracked in Git but contain generated/compiled artifacts that could technically be regenerated:

| Item | Evidence |
|---|---|
| `scripts/noir_compatibility/Prover.toml` | Ignored by root `.gitignore` (`Prover.toml` rule) but listed as **ignored** in `git ls-files --ignored` |
| `scripts/noir_compatibility/target/noir_compatibility.json` | Compiled circuit artifact listed in ignored output |
| `segment_*/target/*` files | All `target/` contents (proof, vk, JSON, .gz) are generated by Nargo compile/prove — these are listed in git ignored output, meaning they exist locally only |

> [!IMPORTANT]
> The segment circuit **target/** directories (containing `.json`, `vk`, `proof` files) are **critical for backend startup** — the crypto profile validator checks their SHA-256 hashes. They are generated by Nargo but are NOT tracked and NOT in the repository.

---

## 4. Required Project Components

### Backend ([backend/](file:///e:/Main%20Project/backend))
- **5 microservices**: sbom_service, vulnerability_service, policy_service, zkp_service, verification_service
- **Shared module**: `backend/shared/` — config, auth, crypto, database, models, security, utils
- **Alembic migrations**: 11 migration files (`001` through `011`)
- **Tests**: ~55+ test files across all services and shared module
- **Scripts**: `init_db.py` for database initialization

### Frontend ([frontend/](file:///e:/Main%20Project/frontend))
- **Framework**: Next.js 16.3.5, React 19.2.8, TypeScript
- **UI library**: shadcn + Tailwind CSS 4 + Lucide icons
- **State management**: TanStack React Query
- **API client**: Custom service layer under `src/api/`
- **Auth**: Custom `AuthProvider` + `RouteGuard`
- **Tests**: 8 test files under `src/**/__tests__/`

### Database
- **Technology**: PostgreSQL (runtime) — but `alembic.ini` and `init_db.py` reference MSSQL
- **Migrations**: Alembic with 11 sequential migrations
- **Schema**: 5 logical SQL schemas (sbom, vulnerability, policy, zkp, verification + shared models)

### Circuits/ZKP ([circuits/](file:///e:/Main%20Project/circuits))
- **Production circuit**: `circuits/` — monolithic Noir circuit (Nargo 0.32.0)
- **Dev circuit**: `circuits_dev/` — smaller 8-component development profile
- **Decomposed segments**: `segment_init_32/`, `segment_mid_32/`, `segment_final_32/` — 32-chunk production topology
- **Tooling**: Nargo 0.32.0, Barretenberg (bb) for proof generation

### Infrastructure
- **Docker Compose**: 5 backend services + nginx gateway (no DB, no frontend container)
- **Noir Dockerfile**: `docker/Dockerfile.noir` — installs Nargo 0.32.0
- **nginx**: Internal API gateway routing

### Documentation ([docs/](file:///e:/Main%20Project/docs))
- 11 documentation subdirectories with 236 tracked files
- Structured index with clear AUTHORITATIVE vs HISTORICAL labels

---

## 5. Environment Requirements

| Requirement | Details | Evidence |
|---|---|---|
| **Python** | 3.12.10 available locally; Dockerfiles use `python:3.11-slim` | [pyproject.toml](file:///e:/Main%20Project/pyproject.toml), Dockerfiles |
| **Node.js** | v24.19.0 locally; frontend uses Next.js 16.3.5 | `node --version` |
| **npm** | 11.17.0 | `npm --version` |
| **PostgreSQL** | Required externally (not in docker-compose) | [docker-compose.yml](file:///e:/Main%20Project/docker-compose.yml), [config.py](file:///e:/Main%20Project/backend/shared/config.py) |
| **Nargo** | 0.32.0 — binary in `.bin/nargo` locally | [Nargo.toml](file:///e:/Main%20Project/circuits/Nargo.toml), [Dockerfile.noir](file:///e:/Main%20Project/docker/Dockerfile.noir) |
| **Barretenberg (bb)** | 0.46.1 historically (Stage21 report) | README, not installed locally (not found in `.bin/`) |
| **Docker** | Required for containerized deployment | [docker-compose.yml](file:///e:/Main%20Project/docker-compose.yml) |

> [!WARNING]
> **Python version mismatch**: Local is 3.12.10, Dockerfiles pin `python:3.11-slim`. This could cause compatibility issues.

---

## 6. Environment Variables

### Actual `.env` (variable names only — **no secrets exposed**):

```
DB_DRIVER = PRESENT
DB_HOST = PRESENT
DB_PORT = PRESENT
DB_USER = PRESENT
DB_PASSWORD = PRESENT
DB_NAME = PRESENT
DB_SSL_MODE = PRESENT
DB_ECHO = PRESENT
SERVICE_HOST = PRESENT
SERVICE_PORT = PRESENT
DEBUG = PRESENT
LOG_LEVEL = PRESENT
JWT_SECRET_KEY = PRESENT
CERTIFICATE_SECRET_KEY = PRESENT
CRYPTO_PROFILE = PRESENT
```

### `.env.example` Variables:

```
DB_DRIVER, DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSL_MODE, DB_ECHO
JWT_SECRET_KEY, CERTIFICATE_SECRET_KEY
SERVICE_HOST, SERVICE_PORT, LOG_LEVEL, DEBUG, CRYPTO_PROFILE, CORS_ORIGINS
NEXT_PUBLIC_API_URL (frontend, optional)
```

### Variable Analysis:

| Variable | In .env | In .env.example | Used in Code | Status |
|---|---|---|---|---|
| `DB_DRIVER` | ✅ | ✅ | ❌ (config uses hardcoded `postgresql+psycopg2`) | **STALE in .env.example** — driver is no longer configurable in `DatabaseSettings` |
| `DB_HOST` | ✅ | ✅ | ✅ | OK |
| `DB_PORT` | ✅ | ✅ | ✅ | OK |
| `DB_USER` | ✅ | ✅ | ✅ | OK |
| `DB_PASSWORD` | ✅ | ✅ | ✅ | OK |
| `DB_NAME` | ✅ | ✅ | ✅ | OK |
| `DB_SSL_MODE` | ✅ | ✅ | ✅ | OK |
| `DB_ECHO` | ✅ | ✅ | ✅ | OK |
| `JWT_SECRET_KEY` | ✅ | ✅ | ✅ | OK |
| `CERTIFICATE_SECRET_KEY` | ✅ | ✅ | ✅ | OK |
| `SERVICE_HOST` | ✅ | ✅ | ✅ | OK |
| `SERVICE_PORT` | ✅ | ✅ | ✅ | OK |
| `LOG_LEVEL` | ✅ | ✅ | ✅ | OK |
| `DEBUG` | ✅ | ✅ | ✅ | OK |
| `CRYPTO_PROFILE` | ✅ | ✅ | ✅ | OK |
| `CORS_ORIGINS` | ❌ | ✅ | **UNKNOWN** | Present in .env.example but NOT in .env — needs investigation |
| `NEXT_PUBLIC_API_URL` | ❌ | ✅ (comment) | ✅ (frontend) | OK — optional, defaults to `localhost:8000` |

---

## 7. Source ZIP Requirements

### Must be included:

| Category | Items |
|---|---|
| **Backend source** | `backend/` (all services, shared, tests, migrations, alembic.ini, conftest.py, pytest.ini, Dockerfiles) |
| **Frontend source** | `frontend/` (all source, package.json, package-lock.json, config files; NOT node_modules) |
| **Circuit source** | `circuits/` (Nargo.toml + src/), `segment_init_32/`, `segment_mid_32/`, `segment_final_32/` (Nargo.toml + src/ only, NOT target/) |
| **Configuration** | `.env.example`, `.gitignore`, `.dockerignore`, `docker-compose.yml`, `pyproject.toml`, `requirements.txt`, `requirements-dev.txt` |
| **Docker** | `docker/Dockerfile.noir`, `docker/nginx.conf` |
| **Scripts** | `scripts/` tracked scripts (vector generation, circuit testing, archive verification) |
| **Documentation** | `docs/` (full directory), `README.md` |

### Must NOT be included:

| Category | Items | Reason |
|---|---|---|
| **Secrets** | `.env` | Contains real credentials |
| **Binaries** | `.bin/nargo` | 44MB platform-specific binary; reproducible via download |
| **Virtual env** | `.venv/` | Reproducible via `pip install` |
| **Node modules** | `frontend/node_modules/` | Reproducible via `npm ci` |
| **Compiled artifacts** | `segment_*/target/`, `circuits/Prover.toml` | Generated by Nargo compile |
| **IDE config** | `.vscode/` | Machine-specific |
| **Generated proofs** | `archives/proofs/temp/`, individual `.proof` files | Generated runtime artifacts |

### Questionable / Requires Decision:

| Item | Size | Rationale |
|---|---|---|
| `archives/proofs/340235b8-…zip` | 647KB | Historical evaluation evidence — could be valuable for reproducibility of Stage21 claims |
| `circuits_dev/` | Small | Dev-profile circuits + mutated proofs — useful for negative testing |
| `segment_init/`, `segment_mid/`, `segment_final/` (non-32) | Small | Earlier 8-component topology — historical |
| `segment_mid_32_1/` through `segment_mid_32_6/` | Small | Numbered mid-segment variants — unclear if they're required or historical |
| `staged_files.txt` | 28KB | Inventory snapshot — possibly useful as manifest evidence |
| `scripts/stage21_payload.json` | 129KB | Test payload — potentially useful for reproduction |

---

## 8. Files That Should NOT Be Included

See table in Section 7 "Must NOT be included". All classifications are supported by `.gitignore` rules, code evidence, or tool-generated nature.

---

## 9. Generated Artifacts

| Artifact | Location | Generated By | Can Regenerate? | Required For |
|---|---|---|---|---|
| Circuit compiled JSON | `segment_*/target/*.json` | `nargo compile` | ✅ With Nargo 0.32.0 | Backend startup (hash-validated) |
| Verification keys | `segment_*/target/vk` | `nargo compile` | ✅ With Nargo 0.32.0 | Backend startup + proof verification |
| Proofs | `segment_*/target/proof` | `nargo prove` + `bb prove` | ✅ With Nargo + bb | Historical evidence |
| Witnesses | `segment_*/target/*.gz` | `nargo execute` | ✅ With Nargo | Proof generation input |
| `Prover.toml` files | `segment_*/Prover.toml` | Python witness-generation scripts | ✅ | Nargo prove input |
| `frontend/node_modules/` | `frontend/node_modules/` | `npm ci` | ✅ | Frontend build/dev |
| `.venv/` | `.venv/` | `python -m venv` + pip | ✅ | Backend runtime |
| Proof archive ZIP | `archives/proofs/*.zip` | Stage21 execution script | ✅ (if inputs available) | Historical evidence only |
| `scripts/consts.nr` | `scripts/consts.nr` | `scripts/extract_consts.py` | ✅ | Noir Poseidon constants |
| `frontend/tsconfig.tsbuildinfo` | `frontend/` | TypeScript compiler | ✅ | Build cache only |

---

## 10. Reproducibility Gaps

### Critical Gaps

1. **Missing compiled circuit artifacts in repository**  
   The `prod` crypto profile requires `segment_init_32/target/segment_init_32.json`, `segment_mid_32/target/segment_mid_32.json`, `segment_final_32/target/segment_final_32.json` and their corresponding `vk` files. These are hash-validated at startup. A fresh checkout has NONE of these files. Without them, the backend **will not start** in `prod` mode.

2. **No Python lockfile**  
   Only `requirements.txt` → `backend/shared/requirements.txt` chain with pinned versions. No `pip-compile` output or lock mechanism. Dependency resolution could produce different results.

3. **Alembic config vs runtime database mismatch**  
   [alembic.ini](file:///e:/Main%20Project/backend/alembic.ini) line 6 configures `mssql+pyodbc://...` while runtime uses `postgresql+psycopg2://...`. The `env.py` overrides this at runtime via `get_db_settings()`, but the ini file is misleading. `init_db.py` also references MSSQL-specific concepts (`master` database, `settings.driver`).

4. **`tsx` not declared as frontend dependency**  
   `package.json` test script: `"test": "npx tsx --test src/**/*.test.ts"` — `tsx` is fetched by `npx` at runtime, not in `dependencies` or `devDependencies`.

5. **Segment circuit source not tracked**  
   `segment_init_32/src/main.nr`, `segment_mid_32/src/main.nr`, `segment_final_32/src/main.nr` are untracked. These are the actual circuit source code that must be compiled. Without them, the circuits cannot be regenerated.

6. **`generate_c32_circuits.py` not tracked**  
   This script (untracked) appears to generate the C32 segment circuit source files. If included, circuits could be regenerated from it.

### Non-Critical Gaps

7. **`CORS_ORIGINS` in .env.example but not in .env** — may cause CORS issues in local dev.

8. **Python 3.12 vs 3.11 Docker images** — local dev uses 3.12, containers use 3.11.

9. **No `.env.local` for frontend** — `NEXT_PUBLIC_API_URL` defaults to `localhost:8000` but this is not documented in a frontend `.env.example`.

10. **`BB_PATH` or Barretenberg binary not documented** — the README mentions bb 0.46.1 historically but no installation instructions or path configuration exist.

---

## 11. Documentation Gaps

| Gap | Location | Detail |
|---|---|---|
| **MSSQL references in Alembic** | [alembic.ini](file:///e:/Main%20Project/backend/alembic.ini) L6, [env.py](file:///e:/Main%20Project/backend/alembic/env.py) L1-3 | Comments and ini URL reference "SQL Server 2022" but the system uses PostgreSQL |
| **MSSQL in init_db.py** | [init_db.py](file:///e:/Main%20Project/backend/scripts/init_db.py) L29 | References MSSQL `master` database and `settings.driver` (which doesn't exist) |
| **Missing Barretenberg setup docs** | README, docs/ | `bb` CLI is referenced in historical reports but no installation/version pinning guide exists |
| **Missing circuit regeneration docs** | docs/ | No documented procedure for regenerating circuit artifacts from source |
| **Missing segment source tracking docs** | README L87 | README mentions `segment_*` as "decomposed segment circuit artifacts" but doesn't explain they're untracked |
| **`npm test` offline limitation** | README L104, [package.json](file:///e:/Main%20Project/frontend/package.json) L10 | Documented as a known limitation but not resolved |
| **Docker Compose completeness** | README L111, [docker-compose.yml](file:///e:/Main%20Project/docker-compose.yml) | Documented that Compose has no DB/frontend — accurate |
| **Service port inconsistency** | [nginx.conf](file:///e:/Main%20Project/docker/nginx.conf) | nginx routes to ports 8000-8004 but each Dockerfile EXPOSE 8000 — unclear how distinct ports are assigned |

---

## 12. Unknown / Requires Human Decision

| Item | Question |
|---|---|
| `staged_files.txt` | What is the purpose of this 28KB file listing 516 tracked filenames? Is it an intermediate artifact from the cleanup process? Should it be tracked or discarded? |
| `segment_mid_32_1/` through `segment_mid_32_6/` | Are these all required for the production 32-chunk topology, or are some historical? The docker-compose only mounts `segment_mid_32`, not the numbered variants. |
| `segment_init/`, `segment_mid/`, `segment_final/` (non-32) | Are these historical (8-component topology) or still used somewhere? |
| `archives/` | Should the Stage21 proof archive (ZIP + individual proofs) be tracked as evaluation evidence? |
| `circuits_dev/` + mutated proofs | Should dev circuits be tracked for negative-testing reproducibility? |
| Dangling "Agent host session" commits | 7 orphaned commits from a previous agent session exist in the reflog. Safe to leave, but their purpose and content are unclear. |
| `DB_DRIVER` in `.env.example` | Is this still needed? The `DatabaseSettings` class hardcodes `postgresql+psycopg2` and doesn't read `DB_DRIVER`. |
| Docker port routing | How do the 5 services listen on distinct ports (8000-8004) when all Dockerfiles use `EXPOSE 8000`? Is there a compose-level port mapping or environment override missing? |

---

## 13. Recommended Actions

> [!CAUTION]
> These are recommendations for future phases. **NONE of these should be executed during A0.**

### Priority 1 — Blocking Reproducibility

1. **Track segment circuit source files** (`segment_init_32/src/`, `segment_mid_32/src/`, `segment_final_32/src/` and their `Nargo.toml` files) OR include `generate_c32_circuits.py` in the repo so circuits can be regenerated.

2. **Document circuit artifact regeneration procedure** — explain how to run `nargo compile` for each segment to produce the required `target/*.json` and `target/vk` files.

3. **Fix or document Alembic/init_db MSSQL residue** — either update `alembic.ini` and `init_db.py` to use PostgreSQL, or document that `env.py` overrides the ini file at runtime.

4. **Add `tsx` to frontend `devDependencies`** to make `npm test` work offline.

5. **Create a Python lockfile** — use `pip-compile` or similar to ensure deterministic dependency resolution.

### Priority 2 — Clarity & Completeness

6. **Classify and decide on segment variants** — determine which `segment_*` directories are required vs historical.

7. **Add `CORS_ORIGINS` to `.env`** if it's required for local development.

8. **Create a frontend `.env.example`** or document `NEXT_PUBLIC_API_URL` setup.

9. **Document Barretenberg (bb) version and installation** for proof generation.

10. **Resolve Docker port routing** — document or fix how 5 services bind to distinct ports.

### Priority 3 — Housekeeping (for later phases)

11. **Decide on `archives/` tracking** — commit as historical evidence or add to `.gitignore`.

12. **Decide on `circuits_dev/` tracking** — useful for negative test reproducibility.

13. **Remove or explain `staged_files.txt`** — appears to be a cleanup artifact.

14. **Decide on cleanup docs tracking** — `REPOSITORY_CLEANUP_AUDIT.md` and `REPOSITORY_CLEANUP_FINAL.md` are untracked.

---

## 14. A0 Acceptance Status

```
A0 STATUS:
[ ] NOT COMPLETE
[ ] COMPLETE — NO BLOCKERS
[x] COMPLETE — BLOCKERS IDENTIFIED
```

**Reason:** The audit is complete. All 18 steps have been executed with evidence-based findings. Critical blockers are identified:

1. **Circuit artifacts not in repository** — backend cannot start from fresh checkout in `prod` mode
2. **Circuit source files not tracked** — cannot regenerate artifacts without them
3. **Alembic/init_db database engine mismatch** — PostgreSQL runtime vs MSSQL configuration residue
4. **No Python lockfile** — non-deterministic dependency resolution
5. **`tsx` not declared** — `npm test` requires network access

These blockers must be addressed in subsequent phases (A/B) before the project can be considered reproducible from a fresh checkout.

---

## 16. Fresh-Checkout Reproducibility Procedure (Theoretical)

If an evaluator receives only the published source repository:

```
1.  git clone https://github.com/tanmay208/Zero-knowledge-sbom-vulnerability-verification.git
2.  git checkout chore/final-project-cleanup

3.  Prerequisites:
    - Python 3.11+
    - Node.js 24.x + npm
    - PostgreSQL (external, accessible)
    - Docker + Docker Compose (for containerized deployment)
    - Nargo 0.32.0 (for circuit compilation)
    - Barretenberg bb 0.46.1 (for proof generation — version/source unclear)

4.  Backend setup:
    a. cp .env.example .env  (then fill in real values)
    b. python -m venv .venv && .venv/Scripts/activate
    c. pip install -r requirements-dev.txt
    d. ❌ BLOCKED: Need circuit artifacts that don't exist in repo
       → Must obtain segment_init_32, segment_mid_32, segment_final_32
         source + compile with nargo compile
    e. cd backend && python -m alembic upgrade head  (⚠️ alembic.ini points to MSSQL)
    f. python -m pytest -q  (tests may pass without live DB using mocks)

5.  Frontend setup:
    a. cd frontend && npm ci
    b. npm run build  (should work)
    c. npm test  (⚠️ requires network to fetch tsx via npx)
    d. npm run dev

6.  Docker deployment:
    a. docker compose up --build
    b. ❌ BLOCKED: Requires PostgreSQL externally
    c. ❌ BLOCKED: Requires circuit artifact volumes

7.  ZKP operations:
    a. Install nargo 0.32.0
    b. Compile each segment circuit
    c. ❌ BLOCKED: Barretenberg version/source unclear
```

**Steps that cannot currently be reproduced from repository contents:**
- Step 4d: Circuit artifact generation (source not tracked)
- Step 4e: Alembic ini references wrong DB engine
- Step 5c: `tsx` not in dependencies
- Step 6b: No PostgreSQL in compose
- Step 7c: Barretenberg not documented

---

## Safety Verification

```
NO FILES WERE MODIFIED.
NO FILES WERE DELETED.
NO FILES WERE MOVED.
NO DEPENDENCIES WERE CHANGED.
NO DATABASE DATA WAS MODIFIED.
NO GIT HISTORY WAS MODIFIED.
NO REMOTE REPOSITORY CHANGES WERE MADE.
```

---

*End of A0 — Repository & Environment Reproducibility Audit*

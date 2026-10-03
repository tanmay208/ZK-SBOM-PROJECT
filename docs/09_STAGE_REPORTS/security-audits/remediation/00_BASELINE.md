# Phase 0 Baseline

Date: 2026-09-13
Repository: `E:\Main Project`

## Scope and change control

This report records the pre-remediation baseline. No source code, tests, configuration, cryptographic artifacts, or existing uncommitted work was modified during Phase 0. The only new file is this report and its containing directory.

## Repository state

Commands executed:

```text
Get-Location
git status --short --branch
git branch --show-current
git rev-parse HEAD
```

Actual results:

```text
Path: E:\Main Project
Branch: main
Commit: 733fd637b176adc059096e9b85c79bab9bcbdeb1
```

The worktree was already substantially uncommitted. Git reported existing added files (`A`) across the backend, frontend, circuits, scripts, and documentation, plus untracked paths including `.bin/`, `backend/shared/api/`, `backend/shared/auth.py`, `backend/shared/models/`, multiple service routes/services/tests, `circuits/`, `circuits_dev/`, `frontend/`, `docs/security/`, `rustup-init.exe`, and root integration tests. These changes predate this remediation and were preserved.

## Audit documents

`docs/security/audit/` contains 22 Markdown documents, including the requested reports `04_AUTHENTICATION_AUDIT.md`, `05_AUTHORIZATION_RBAC_AUDIT.md`, `06_API_SECURITY_AUDIT.md`, `08_VULNERABILITY_INTELLIGENCE_AUDIT.md`, `09_CRYPTOGRAPHIC_ZK_AUDIT.md`, `10_RUNTIME_SUBPROCESS_AUDIT.md`, `14_DEPENDENCY_AUDIT.md`, `16_TEST_ASSURANCE_AUDIT.md`, `18_VULNERABILITY_REGISTER.md`, `20_FINAL_VERDICT.md`, and `21_SELF_CHALLENGE_REPORT.md`.

The existing register marks these open findings as confirmed or security-relevant: RBAC-001, API-001, VI-001, ZK-001, ZK-002, API-002, DB-001, CFG-001, CFG-002, AUTH-001, PARSER-001, and ART-001. The existing final verdict reports no production proof/VK execution and identifies authorization, unauthenticated high-impact routes, vulnerability trust, profile/VK alignment, and caller-supplied commitment binding as the principal risks.

## Runtime and dependency baseline

Commands executed:

```text
python --version              -> Python 3.12.10
python -m pytest --version    -> pytest 8.3.4
node --version                -> v24.19.0
npm --version                 -> 11.17.0
docker --version              -> Docker version 29.7.2, build a7dcaa6
docker compose version       -> Docker Compose version v5.5.1
nargo --version               -> command not found on PATH
bb --version                  -> command not found on PATH
```

The repository contains `.bin/nargo`, but invoking it directly produced no usable version or check output in this Windows environment. The Docker Noir image declares `NOIR_VERSION=v0.32.0` and installs Nargo in the image. No Barretenberg executable was found. `circuits/` and `circuits_dev/` both contain `Nargo.toml`, `src/`, `target/`, and proof-related artifacts.

## Test commands and results

## Baseline blocker investigation

### Duplicate pytest module collision

Exact files found:

```text
E:\Main Project\test_f008_real.py
E:\Main Project\backend\sbom_service\tests\test_f008_real.py
```

The files are not byte-for-byte duplicates. They are complementary F-008 harnesses:

- The root file is a standalone script. It starts Uvicorn on port 8001 and immediately executes five HTTP upload checks when imported or run.
- The backend file is a pytest module. It defines a Uvicorn server fixture on port 8124 and a collection of pytest test methods for request-size and transport behavior.

Pytest reports an import mismatch because both files have the same basename and are imported as the top-level module `test_f008_real`. `pyproject.toml` contains only `pythonpath = ["backend"]`; it does not set `testpaths` or `import_mode`. The relevant directories do not have package `__init__.py` boundaries, so pytest's default `prepend` import mode places the test directories on `sys.path` and reuses the same module name. The first imported module's `__file__` then differs from the second path pytest is collecting.

No files were renamed, deleted, or modified. The safest minimal remediation is to define the intended pytest collection root explicitly, for example `testpaths = ["backend"]`, while retaining the root harness as an explicitly invoked standalone script. Renaming the root script alone would be less conservative because its import-time execution should also be reviewed before treating it as a pytest module. This remains a recommendation only; no configuration change was made during blocker investigation.

### Backend KeyboardInterrupt investigation

Commands and results:

```text
python -m pytest backend -vv -x --tb=short --durations=0
```

The bounded 30-second invocation continued beyond the terminal timeout and later completed:

```text
collected 480 items
====================== 480 passed, 25 warnings in 41.21s ======================
```

The earlier run that stopped after 251 passes reported `KeyboardInterrupt` at `backend/shared/crypto/poseidon_bn254.py:60`. A targeted follow-up isolated the suspected cryptographic path:

```text
python -m pytest backend/shared/tests/test_poseidon_bn254.py -vv --durations=20
```

Result: 3 passed in 0.04s. The interruption is therefore not reproducible as a persistent hang. The verbose run completed without evidence of a subprocess, Nargo, Barretenberg, database lock, or network dependency causing the stop. The F-008 live Uvicorn tests ran as part of the completed backend suite. The most likely explanation is an external/intermittent interruption or timing condition in the earlier run; this is not proven and remains an unknown for later investigation.

### Environment verification

```text
Python: Python 3.12.10
pytest: pytest 8.3.4
Node: v24.19.0
npm: 11.17.0
Windows nargo on PATH: unavailable
Windows bb/barretenberg on PATH: unavailable
WSL: available; kali-linux running, version 2
WSL nargo: command not found
WSL bb: command not found
WSL barretenberg: command not found
HEAD: 733fd637b176adc059096e9b85c79bab9bcbdeb1
```

The repository's `.bin/nargo` file is present at 44,603,960 bytes, but direct Windows invocation produced no version or check output and was not usable as circuit validation. No Barretenberg executable was found. The frontend build was rerun from `frontend/` and passed: Next.js compiled successfully, TypeScript completed, and 4 static pages were generated.

### Change integrity check

The current worktree continues to contain the pre-existing broad added/untracked inventory recorded above, plus the remediation baseline report. No application source, security logic, circuit, dependency, or test path was modified by this blocker investigation. No destructive Git command was used.

The one controlled configuration change made during this investigation was the approved pytest discovery change in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
pythonpath = ["backend"]
testpaths = ["backend"]
```

This prevents pytest from collecting the standalone root harness while preserving both complementary F-008 files. No test content was changed.

### Controlled collection closure

Before the change, `python -m pytest --collect-only -q` failed with the same `test_f008_real` import mismatch described above. After the change:

```text
python -m pytest --collect-only -q
480 tests collected in 1.54s
```

The complete intended suite was then rerun with `python -m pytest`:

```text
testpaths: backend
collected 480 items
====================== 480 passed, 25 warnings in 41.83s ======================
```

Importlib mode, package-boundary changes, and test renaming were not needed and were not applied. The root harness remains available for explicit standalone execution.

### Cryptographic environment expectation

Repository evidence identifies the following expected environment:

- `circuits/Nargo.toml`, `circuits_dev/Nargo.toml`, and the Docker Noir setup specify Noir/Nargo `0.32.0`.
- `docker/Dockerfile.noir` is the only reproducible tool installation artifact found. It is Linux-based (`ubuntu:24.04`) and installs Nargo `v0.32.0`.
- The application proof and verification code explicitly invokes WSL distribution `kali-linux`. Proving expects Nargo plus `~/.bb/bb`; verification expects the same Barretenberg path.
- The repository does not identify or pin a Barretenberg version. The Docker Noir image does not install Barretenberg.
- The current Windows host has no `nargo`, `bb`, or `barretenberg` on PATH. The bundled `.bin/nargo` did not produce usable Windows version/check output. WSL `kali-linux` is available and running, but `nargo`, `bb`, and `barretenberg` are absent there.

Therefore the intended execution model is Linux tooling, currently wired through WSL Kali, with Docker/Linux as the safer reproducible enablement target. The safest next installation plan is to obtain the approved Noir `0.32.0` Nargo artifact and an explicitly approved Barretenberg release compatible with that Noir/ACIR version, install them in a controlled Linux/WSL or purpose-built container, record executable hashes and versions, then run circuit compile, witness, proof, and verification checks. No arbitrary version was installed and no circuit/prover logic was changed. Until the Barretenberg version and real artifact path are approved and validated, production cryptographic validation remains blocked.

### Classification of current baseline state

Completed checks: duplicate paths and contents compared; pytest configuration and package boundaries inspected; bounded verbose backend run completed; isolated Poseidon path completed; Python, pytest, Node, npm, WSL, Nargo, Barretenberg, frontend build, Git status, and HEAD checked.

Incomplete checks: full repository pytest collection remains blocked by the duplicate module name; production circuit compilation, proof generation, and proof verification remain unexecuted.

Environmental limitations: Nargo and Barretenberg are unavailable on Windows PATH and inside the running WSL distribution; the bundled Windows Nargo did not provide usable output.

Test infrastructure blockers: duplicate top-level pytest module names; the earlier interruption cannot currently be reproduced.

Application defects: none newly established by this baseline blocker investigation. Existing audit findings remain open and are not remediated here.

Unknowns requiring later investigation: cause of the earlier intermittent KeyboardInterrupt; production toolchain/profile compatibility; real proof interoperability.

### Full repository pytest

Command:

```text
python -m pytest
```

Actual result:

```text
collected 481 items / 1 error
ERROR collecting test_f008_real.py
import file mismatch: imported module 'test_f008_real' ... backend\\sbom_service\\tests\\test_f008_real.py ... root test_f008_real.py
Interrupted: 1 error during collection
```

The collection failure is caused by duplicate test module basenames. No test collection naming change was made in Phase 0.

### Backend-scoped pytest

Command:

```text
python -m pytest backend
```

Actual result:

```text
collected 480 items
251 passed, 2 warnings in 21.84s
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! KeyboardInterrupt !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
backend\\shared\\crypto\\poseidon_bn254.py:60: KeyboardInterrupt
```

This is not a passing baseline. The run was interrupted in the existing cryptographic test path; the remaining tests did not complete. Warnings were deprecations from `websockets` and Uvicorn.

### Frontend production build

Command:

```text
Push-Location frontend; npm run build; Pop-Location
```

Actual result: PASS. Next.js 16.3.5 compiled successfully, TypeScript completed, page data was collected, and 4 static pages were generated.

### Circuit/toolchain baseline

Command:

```text
\.bin\\nargo --version
Push-Location circuits; \.bin\\nargo check; Pop-Location
```

Actual result: no usable output was produced by the bundled executable invocation. Because Nargo and Barretenberg are unavailable on `PATH`, no production circuit compile, proof generation, or proof verification was validated.

## Configuration observations

`docker-compose.yml` defines five backend services, an Nginx gateway, SQL Server, and a frontend. The backend service environments include database settings but do not visibly include a shared JWT secret. The compose file references `./docker/nginx.conf`; that path was not present in the top-level inventory. SQL Server uses the mutable `2022-latest` image tag and exposes port 1433, which is relevant to later deployment hardening but was not changed in this phase.

## Baseline limitations

- Full pytest collection is now clean after the explicit backend `testpaths` configuration.
- The complete configured backend suite passed all 480 tests with 25 warnings; the earlier interruption remains unexplained but was not reproduced.
- Nargo is not available on `PATH`; the bundled executable did not yield actionable output.
- Barretenberg, production proof generation, production proof verification, SQL Server deployment, and the Compose topology were not executed.
- WSL is available, but Nargo and Barretenberg are absent from the running Kali distribution.
- No dependency, container, secret, or static security scan was claimed in this phase.
- The frontend build was run successfully from its correct project directory; running `npm run build` at the repository root failed because no root `package.json` exists.

## Phase report

PHASE: Phase 0 - Pre-change baseline
STATUS: INCOMPLETE
FILES INSPECTED: `pyproject.toml`, `README.md`, `frontend/package.json`, backend requirements files, `docker-compose.yml`, `docker/Dockerfile.noir`, `circuits/Nargo.toml`, `circuits_dev/Nargo.toml`, all 22 audit documents
FILES MODIFIED: `pyproject.toml`, `docs/security/remediation/00_BASELINE.md`
SECURITY FINDINGS ADDRESSED: None; baseline only
TESTS ADDED: None
COMMANDS EXECUTED: Git status/branch/hash, pytest full/backend verbose/backend targeted, frontend build, runtime/toolchain checks, WSL checks, Docker version checks, circuit/config inventory
ACTUAL RESULTS: Explicit backend testpaths resolved collection; 480 tests collected and 480 passed with 25 warnings; frontend build passed; Nargo 0.32.0 expectation identified; Barretenberg version and executable unavailable
UNRESOLVED ISSUES: Production cryptographic toolchain/version validation, unexplained earlier interruption, existing audit findings
ASSUMPTIONS: Existing uncommitted files are user/repository work and must remain untouched
RESIDUAL RISK: High; no security remediation has started and production cryptographic paths remain unvalidated
NEXT PHASE: Phase 1 - Finding reconciliation, after cryptographic environment blocker is resolved or explicitly accepted

BASELINE STATUS: INCOMPLETE
Remaining blockers: production cryptographic validation cannot run because usable Nargo is unavailable in the intended Linux/WSL execution environment and no approved Barretenberg version or binary is available. The earlier intermittent KeyboardInterrupt remains an investigation unknown, but it is not blocking the now-passing configured suite.

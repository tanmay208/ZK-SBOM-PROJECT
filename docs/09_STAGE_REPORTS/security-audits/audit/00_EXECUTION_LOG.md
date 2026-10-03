# Pass 0-16 Execution Log

Audit mode: discovery-only. No source, test, circuit, dependency, or configuration files were modified. The only intended writes are the audit documents in this directory.

## Evidence Preservation

- `Get-Location` -> `E:\Main Project`. Interpretation: audit workspace confirmed.
- `git status --short --branch` -> branch `main`; worktree contains many staged additions and untracked files, including `frontend/`, `circuits/`, `circuits_dev/`, `.bin/`, root tests, and service implementations. Limitation: these changes predate this audit and were not reverted.
- `git rev-parse HEAD` -> `733fd637b176adc059096e9b85c79bab9bcbdeb1`.
- `git log -8 --oneline --decorate` -> `733fd63` tagged `day-01-architecture`, parent `59a4e6b`; only the two recent commits were present in the displayed history.

## Environment

- `python --version` -> Python 3.12.10.
- `node --version` -> v24.19.0; `npm --version` -> 11.17.0.
- `nargo --version` -> command unavailable.
- `bb --version` -> command unavailable.
- `docker --version` -> Docker 29.7.2; Compose v5.5.1.
- `wsl --status` -> default distribution `kali-linux`, default version 2.
- `semgrep --version` -> 1.165.0.
- `gitleaks version` -> 8.30.1.
- `pip-audit`, `safety`, `bandit`, `trivy`, `grype`, `syft`, `osv-scanner`, and `cyclonedx-py` were not found.

## Executed Validation

- `gitleaks detect --no-banner --redact --source .` -> 1 commit, about 36.59 KB scanned, no leaks found. Limitation: scanner coverage is not proof of absence; current untracked/generated state and scanner configuration still matter.
- `semgrep scan --config auto --error --metrics off ...` -> failed before analysis because auto configuration rejected metrics-off mode.
- `semgrep scan --config p/python ...` -> failed before analysis while parsing the repository ignore configuration (`lexing: empty token`). No Semgrep findings are claimed.
- `python -m pytest -q` -> collection failed due duplicate module name `test_f008_real` at repository root and `backend/sbom_service/tests`.
- `python -m pytest backend -q` -> 480 passed, 25 warnings in 39.07 seconds. This demonstrates those tests ran; it does not demonstrate production security.
- `Push-Location frontend; npm audit --audit-level=moderate` -> 0 vulnerabilities. Scope is the frontend lockfile only.
- `npm run lint` in `frontend/` -> 0 errors, 1 unused-import warning in `src/app/page.tsx`.
- `npm run build` in `frontend/` -> production Next.js build succeeded; only static dashboard routes were generated.

## Material Limitations

- No production database was initialized or connected.
- No production Nargo compilation, witness execution, Barretenberg proving, or Barretenberg verification was executed because `nargo` and `bb` are not on PATH; only local artifacts and code were inspected.
- No Docker image build or Compose deployment was executed.
- No authenticated multi-user integration test against a live service was executed.
- One direct app-import route probe failed because `verification_service` was not importable without setting the repository `backend` Python path. Route conclusions therefore come from source tracing, not that probe.
- No dependency scanner other than npm audit and gitleaks produced a completed scan.

# Safe Cleanup Execution Report

Date: 2026-09-14

## Cleanup Status: Completed

## Executed deletions

- Removed backend `__pycache__` directories generated during validation.
- Removed root `.pytest_cache`.
- Removed `frontend/.next` generated build output.

Measured space reclaimed: **49,193,896 bytes** before subsequent validation regenerated temporary caches.

The deletion used explicit paths and categories only. No `git clean`, reset, broad recursive repository deletion, database deletion, or history rewrite was used.

## Retention verification

Retained and rechecked: `.venv`, `frontend/package-lock.json`, `backend/shared/requirements.txt`, Nargo manifests, circuit source, both target directories, both proof directories, `.bin/nargo`, `scripts/noir_src`, audit reports, migrations, and configuration templates.

## Post-cleanup note

Running the required post-cleanup tests/builds will recreate ignored bytecode, pytest, and Next build caches. These are reproducible and remain safe cleanup candidates; they do not indicate source or artifact loss.

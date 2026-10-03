# STAGE 21 — BASELINE

Before executing the full 1024-component authoritative dataset through the backend orchestrator, the following system state was verified:

## Environment State
- **Branch:** `chore/final-project-cleanup`
- **Nargo Version:** `0.32.0` (validated via `profile.json` and prior stage constraints)
- **Barretenberg Version:** Compatible with Nargo `0.32.0`
- **Python Version:** `3.12.10`
- **Database Connectivity:** SQL Server connection is functional and SQLAlchemy models are verified.

## Backend Tests (Stage 20A Closure)
The backend test suite was run locally prior to full E2E execution.
- **Total Tests:** 508
- **Passed:** 508
- **Failed:** 0
- **Skipped:** 0
- **Warnings:** 27 (deprecation warnings primarily tied to `datetime.utcnow()`)

## Frontend Tests
The frontend checks were executed sequentially:
- `npm run typecheck`: Passed (0 errors).
- `npm run lint`: Passed (0 errors, 19 unused variable warnings).
- `npm run build`: Compiled successfully and generated static pages successfully.

## Crypto Profile & Circuits
- **Active Profile:** `prod`
- **Max Components:** 1024
- **SMT Depth:** 256
- **Chunk Size:** 32
- **Circuit Artifacts:** Validated presence of `segment_init_32.json`, `segment_mid_32.json`, and `segment_final_32.json` within their respective `target/` directories, alongside their `vk` files and compressed `.gz` proving assets.

With a fully green baseline established, we are cleared to construct the deterministic 1024-component input dataset for Stage 21 cryptographic generation.

# STAGE 17 — RECOVERY REPORT

**Date:** 2026-10-01
**Status:** BLOCKED

## 1. Interrupted-Agent Recovery Findings
The previous agent (Opus) aborted during the implementation/benchmark phase of Stage 17. It successfully drafted the Architecture Decision Record (`docs/ARCHITECTURE_DECISION_STAGE17.md`) but did not complete the PostgreSQL migration. It also wrote a benchmark script (`benchmark.py`) but aborted before recording any valid measurements.

## 2. Actual Git State
- `docs/*.md` files were moved to `docs/Main Docs/` (staged as deleted at root).
- `backend/shared/config.py` and `requirements.txt` were modified and staged.
- Numerous untracked files existed, including `circuits_bench_*` and `circuits/`.

## 3. Actual Source Modifications
- **PostgreSQL Migration:** Partially implemented. `requirements.txt` and `config.py` were modified. However, all Alembic migrations and SQLAlchemy models still use the SQL Server specific `UNIQUEIDENTIFIER` and `func.getutcdate()`.
- **ZKP Circuit:** `circuits/src/main.nr` was modified to use an experimental, arithmetic-predicated 1024-component circuit that is known to OOM.

## 4. Benchmark Artifacts
The directories `circuits_bench_8` through `circuits_bench_1024` did not contain valid benchmarks. They contained identical 54.9 MB `sbom_zkp.json` artifacts copied from the development environment, with timestamps from September 13. The `benchmark.py` script failed to run to completion or overwrite these targets.

## 5. Cleanup Performed
- **Removed:** All `circuits_bench_*` directories and `benchmark.py`.
- **Removed:** `circuits/target/` to eliminate the dangerous presence of a 54.9 MB dev-sized artifact masquerading as a production artifact.

## 6. Preserved Evidence
- `circuits_dev/` remains intact as the last-known-good 8-component circuit.
- The ADR in `docs/ARCHITECTURE_DECISION_STAGE17.md` is preserved.

## 7. Current Cryptographic State
- Frozen semantics (Poseidon BN254, PURL identity, CVSS zero handling, SMT depth 256) are preserved in the Python reference implementation.
- The production circuit (`circuits/`) is currently unsafe/OOM-prone.
- The dev circuit (`circuits_dev/`) is functional but restricted to 8 components and an SMT depth of 3.

## 8. Current PostgreSQL State
Incomplete and broken. The application currently mixes PostgreSQL connection settings with SQL Server `UNIQUEIDENTIFIER` column types.

## 9. Current Chunked-ZKP State
Not implemented.

## 10. Completed Stage 17 Actions
- Architecture Decision Record written.
- Feasibility test for the proposed 64-component chunk created and executed.

## 11. Incomplete Stage 17 Actions
- PostgreSQL code migration (models, migrations, docker-compose).
- Chunked proving architecture (circuits, prover, verifier).

## 12. Next Exact Implementation Action
The next action MUST address the compiler scaling limitation, as the 64-component chunked architecture is infeasible.

## 13. Risks / Blockers

**CRITICAL BLOCKER:** The 64-component feasibility test FAILED.

An isolated compilation test for 64 components (preserving SMT depth 256 and Poseidon semantics) was executed.
- **Peak RSS:** 15.4 GB
- **Peak VM:** 40.2 GB
- **Time:** Timeout (Killed after 300s)

The 64-component chunk consumed virtually the same memory (15.4 GB RSS / 40.2 GB VM) as the monolithic 1024-component circuit (15.1 GB RSS / 38 GB VM). This indicates that the Nargo 0.32.0 compiler memory overhead is scaling destructively with the SMT depth (256 iterations per component) or hitting a fundamental memory ceiling rather than scaling linearly with component count.

We cannot proceed with chunked implementation because even a 64-component chunk cannot compile on the target hardware.

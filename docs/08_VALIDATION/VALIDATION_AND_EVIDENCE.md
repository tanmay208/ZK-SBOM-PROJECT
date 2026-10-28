# Validation and Evidence

This page is an evidence boundary. It distinguishes checks run during this consolidation from historical results.

| Area | Recorded evidence | Classification / limit |
| --- | --- | --- |
| This consolidation: backend suite | Python 3.12.10 virtual environment, 533 passed, 0 failed, 56 warnings in 34.49s | TEST VERIFIED on 2026-10-03; no Stage21L workload or standalone DB probe was run |
| This consolidation: frontend checks | TypeScript, ESLint, and Next.js build succeeded; build generated 15 routes | TEST/BUILD VERIFIED on 2026-10-03 |
| This consolidation: frontend tests | Node 24.19.0/npm 11.17.0; npm test passed 32 tests after npx fetched undeclared tsx with network access | TEST VERIFIED on 2026-10-03; clean/offline reproducibility remains limited because tsx is not in the package manifest |
| Stage22 frontend tests | Stage22.9 reports npm test: 32 passed, 0 failed, 0 skipped | TEST VERIFIED in that audit environment |
| Frontend static checks | Stage22.9 reports TypeScript typecheck, ESLint, and production build succeeded | TEST/BUILD VERIFIED in that audit environment |
| Browser | Stage22.9 reports a limited local smoke at 390 px: login rendering, protected-route redirect, public-certificate page | LIVE VERIFIED for those interactions only; not a live backend workflow or full accessibility audit |
| Backend suite | Stage21N remediation report records 533 passed, 0 failed, 0 skipped, with warnings | Historical TEST VERIFIED; historical test-count/tree reconciliation was not established |
| PostgreSQL schema | Stage21N follow-up records revision 011 (head) and clean alembic check on configured PostgreSQL 17.11 | Historical database evidence; not reconnected during documentation consolidation |
| PostgreSQL idempotency | Stage21N report records ten concurrent identical requests converging to one request and one certificate | Historical database test; verifier intentionally stubbed, so not proof-validity evidence |
| Stage21L workload | Historical report records 1,024 components and 256 proof generations/verifications with an archive digest | Historical runtime evidence only; not rerun and no fresh proof verification is claimed |
| TLS/deployment | Compose has no host-published gateway/app port or TLS terminator; no external ingress/firewall evidence in repository | Static source inspection; actual deployment boundary NOT VERIFIED and deferred to Stage23 |

## Commands

Frontend checks from frontend/: npm test, npx tsc --noEmit, npx eslint ., npm run build.

Backend checks from repository root: python -m pytest -q (the root pyproject.toml configures backend as its test path). The Stage21L workload runner is not part of this command.

See [Stage22 final audit](../09_STAGE_REPORTS/STAGE_22_FINAL.md), [Stage21N remediation report](../09_STAGE_REPORTS/stage-21/STAGE21N_CODEX_FINAL_REMEDIATION_REPORT.md), and [Stage21L runtime report](../09_STAGE_REPORTS/stage-21/STAGE21L_CRYPTOGRAPHIC_RUNTIME_VALIDATION_REPORT.md).

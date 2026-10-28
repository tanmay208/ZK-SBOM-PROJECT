# Test Assurance Audit

## Results

- Full `python -m pytest -q`: collection failure due duplicate `test_f008_real` module names at root and under SBOM tests.
- `python -m pytest backend -q`: 480 passed, 25 warnings.
- Frontend lint: 0 errors, one unused `CardDescription` warning.
- Frontend production build: succeeded and generated only static dashboard routes.

## What Tests Demonstrate

The backend tests exercise many unit/service paths, schema bounds, privacy response expectations, crypto vectors, request-size behavior, and mocked verification/proving behavior. They establish that those tested cases pass under test fixtures.

## What Tests Do Not Demonstrate

- No live production SQL Server authorization or least-privilege behavior.
- No cross-user or role matrix; one test documents RBAC is unforced.
- No authenticated enforcement for every route.
- No live Nargo/Barretenberg production proof, production VK, or dev/prod rejection test.
- No certificate forgery test against authoritative root lookup because no lookup exists.
- No rate, concurrency, child-process timeout, output-limit, symlink, cleanup, or stale-artifact tests.
- No oversized component/deep JSON corpus or complete canonicalization equivalence test.
- No Docker Compose or nginx build/deploy test.
- Mocks/test doubles can return `verified`; this proves repository gating logic, not cryptographic validity.

## Assurance Classification

Passing backend tests do not establish security or production readiness. The collection failure and missing integration tests are assurance gaps.

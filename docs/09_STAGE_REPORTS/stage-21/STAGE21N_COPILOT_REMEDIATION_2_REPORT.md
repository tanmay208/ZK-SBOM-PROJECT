# Stage21N Remediation-2 Report

**Date:** 2026-10-03  
**Disposition:** Remediation evidence report; not a production-readiness declaration.

## 1. Executive summary

Remediation-2 adds meaningful controls for secret validation, tenant-scoped
verification, archive semantic checks, honest cryptographic status, snapshot
visibility, proof-job admission, and direct plaintext Compose exposure.
The complete local Python suite now passes:

```text
526 passed
526 tests collected
```

This result is not equivalent to the previously claimed `472/472`, nor does it
prove PostgreSQL concurrency, applied migrations, or a real Nargo/Barretenberg
cryptographic run. The Stage21L archive and workload were not modified or
rerun. The security gate therefore remains **BLOCKED** pending the evidence
gaps listed below.

## 2. Scope and constraints

The remediation pass did not change circuit semantics, Poseidon parameters,
Merkle or SMT construction, C32 decomposition, production verification keys,
cryptographic artifacts, or the authoritative Stage21L archive. No replacement
proofs were generated and the 10,667-second workload was not rerun.

## 3. Evidence inventory

| Evidence | Result |
|---|---|
| `pytest --collect-only -q` | 526 tests collected |
| Full pytest suite | 526 passed |
| Certificate-signing focused tests | 9 passed |
| Stage21L archive | Not modified |
| Stage21L archive SHA-256 | Preserved: `362be7463b3af52fb499a9bf95d64a69d1dac44e64d48f52cb197a5b48bb7e3d` |
| PostgreSQL concurrency execution | Not available |
| Applied migration inspection | Not independently executed |
| Nargo/Barretenberg execution | Not performed during remediation |
| Historical claimed count | 472/472, not reproduced |
| Historical Stage21G count | 513 passed |

## 4. A-N remediation matrix

| Area | Classification | Evidence and remaining limitation |
|---|---|---|
| A. Secret security | PARTIALLY CLOSED | `backend/shared/config.py` rejects missing, blank, whitespace-only, short, placeholder, trivial/repeated, and equal JWT/certificate secrets in all modes. Focused tests pass. Production startup and secret non-disclosure still require deployment validation. |
| B. Cross-tenant ProofJob verification | PARTIALLY CLOSED | Route/service verification uses owner-scoped lookup and an explicit owner mismatch defense. Local tests cover tenant isolation. A two-user PostgreSQL integration run and a persisted public-sharing authorization model are absent. |
| C. Idempotency race | PARTIALLY CLOSED | Existing model/migration uniqueness and `IntegrityError` retry handling are exercised by source/tests. Concurrent PostgreSQL convergence, rollback behavior, and duplicate-certificate prevention remain unverified without the target database. |
| D. Proof archive integrity | PARTIALLY CLOSED | Archive generation and validation bind job metadata, roots, profile, topology, exact members, duplicate/traversal rules, and persisted proof hashes. Adversarial local coverage exists, but no real production archive revalidation or cryptographic runtime evidence was added. |
| E. Manifest binding | PARTIALLY CLOSED | Manifest values and member hashes are checked against authoritative expectations. The historical archive remains `pending`, and no new cryptographic verification is claimed. |
| F. Cryptographic verification status | PARTIALLY CLOSED | Generation now records `pending`; verification remains responsible for producing `verified`. The lifecycle was not validated with a real Barretenberg execution. |
| G. Certificate lifecycle/revocation | PARTIALLY CLOSED | Signing uses the independent certificate secret and persistence is guarded against duplicate creation. Revocation authorization and current-validity consumer behavior still need PostgreSQL-backed and endpoint-level acceptance evidence. |
| H. Database schema | NOT INDEPENDENTLY VALIDATED | Migration and model definitions are present, including result width and uniqueness. Applied PostgreSQL schema, indexes, nullability, cascades, and revision state were not queried. |
| I. Resource exhaustion | PARTIALLY CLOSED | Proof/archive bounds and per-user active-job admission are present; Compose limits remain deployment controls. There is no demonstrated durable global admission, multi-worker quota, or disk budget under repeated distributed requests. |
| J. TLS/network boundary | PARTIALLY CLOSED | Host-published plaintext gateway mapping was removed and nginx is internal-only in Compose. nginx remains HTTP-only; an external TLS terminator and the control preventing direct public plaintext access must be supplied by deployment evidence. |
| K. Anti-enumeration | PARTIALLY CLOSED | Owner-scoped unauthorized job retrieval returns 404 and verification ownership checks occur early. All alternate production endpoints and deployment behavior need integrated indistinguishability testing. |
| L. Strict hex validation | CLOSED (source/local-test boundary) | Public roots require `0x` plus exactly 64 hexadecimal characters before expensive processing. Production integration execution was not available. |
| M. Timestamp/metadata integrity | PARTIALLY CLOSED | Archive timestamps use timezone-aware UTC event creation and manifest metadata is validated structurally. Full event provenance and historical semantics remain unverified. |
| N. Authoritative re-evaluation | PARTIALLY CLOSED | Verification reads authoritative records and avoids generation-time false `verified` status. Replay and stale-state behavior across updated approvals require an end-to-end authoritative database test. |

## 5. Test-suite forensic comparison

The current collection is 526 tests and the full suite passes. This is higher
than both the historical Stage21G report (`513 passed`) and the claimed
Stage21N result (`472/472`). The discrepancy is not explained by the passing
result alone. The current tree contains the collected test directories and no
collection failure after `backend/test_db.py` was changed to avoid database
access at import time.

The count difference must still be reconciled against the historical commit
and a clean diff of test additions, deletions, renames, fixture changes, and
discovery configuration. Local mocks are not evidence of PostgreSQL or
cryptographic integration behavior.

## 6. Changes made

- Hardened shared JWT and certificate secret validation.
- Added owner-scoped ProofJob verification and service-level owner defense.
- Added PostgreSQL uniqueness conflict handling and certificate duplicate
  protection in the verification repository.
- Added archive manifest/member binding and persisted proof-hash checks.
- Changed proof-generation archive status to honest `pending`.
- Restricted snapshot listing to approved snapshots.
- Added per-user active proof-job admission.
- Removed the host plaintext nginx port publication from Compose.
- Isolated the live database probe from pytest collection.
- Updated affected tests and fixtures without weakening the new security
  requirements.

## 7. Exact remaining blockers

1. Run the migration set against the target PostgreSQL version and verify the
   applied revision, constraints, indexes, result width, and cascade behavior.
2. Execute a PostgreSQL-backed concurrent idempotency test proving one
   canonical request and one certificate.
3. Execute two-user integration tests across verification, request retrieval,
   certificate retrieval, and all alternate ProofJob identifiers.
4. Establish and evidence the production TLS termination boundary, including
   forwarded-header trust and prevention of direct public plaintext access.
5. Execute real cryptographic verification for a controlled fixture or rely on
   the preserved Stage21L evidence without representing the pending archive as
   newly verified.
6. Reconcile the 472/513/526 test counts using historical git inventories and
   explain every test discovery change.
7. Demonstrate durable distributed resource admission and disk/subprocess
   limits under the intended deployment topology.

## 8. Final gate

**BLOCKED**

The remediation is materially stronger and the local suite is reproducible,
but the unavailable PostgreSQL, deployment-network, and cryptographic runtime
evidence prevents an independent security-gate pass.

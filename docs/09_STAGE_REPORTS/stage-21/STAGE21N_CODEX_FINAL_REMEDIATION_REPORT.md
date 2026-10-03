# Stage21N Codex Final Remediation Evidence Report

**Assessment date:** 2026-10-03  
**Scope:** Read-only forensic acceptance of the current Remediation-3 repository state, except for this report and the documented local audit-harness/test-isolation changes. No remote schema changes, cryptographic workload, proof regeneration, or Stage21L archive modification was performed.

## 1. Executive summary

Several claimed remediation controls are supported by executable evidence. A one-shot test against the configured PostgreSQL 17.11 instance created ten concurrent identical verification requests and observed one canonical `VerificationRequest` and one `VerificationCertificate`; the test removed its temporary records. The existing Stage21L archive was compared read-only with persisted proof records: its preserved digest matches, and all 256 proof payloads correspond to persisted hashes.

Stage21N is **blocked**. Live `alembic check` reports unapplied schema differences, including missing ownership/proof-job foreign keys and other constraints/indexes. The repository prevents direct host publication of the gateway but owns no TLS listener, and the external ingress, firewall, and public reachability controls were not supplied for independent verification. This report does not claim fresh Barretenberg verification: the historical archive records `cryptographic_verification_status = pending`.

## 2. Opus changes inherited

The current tree contains the Remediation-3 certificate lifecycle behavior and tests, the archive inspection script, the TLS-boundary documentation, and the other changes represented by the current checkout. Git attribution is not reliable in this checkout: the working tree contains a broad imported project tree (over 150 files in the diff summary) while `HEAD` is an architecture-only baseline. I therefore classify changes by observed current behavior, not by author.

The `db.txt` file is absent and is now covered by `.gitignore`; `.env` is ignored. `scripts/verify_archive.py` obtains connection settings from environment/configuration and does not contain a literal connection credential. `backend/run_stage21L.py` constructs its connection from environment variables; its source does not embed the database password. Searches for the known Supabase host and URI forms found only historical documentation references and configuration/template references; no credential value is reproduced here. The configured database password has not been rotated, as instructed. Prior exposure means it must not be described as safe or unexposed.

## 3. Additional Codex audit changes

- Added `db.txt` to `.gitignore`.
- Reworked `backend/test_concurrency_db.py` into a one-shot, environment-configured PostgreSQL concurrency acceptance harness with deterministic assertions, cleanup, and non-zero failure behavior. Its expensive cryptographic verifier is stubbed; this is an idempotency/database test, not a cryptographic verification test.
- Loaded the User model and excluded externally managed schemas from Alembic autogeneration comparison so `alembic check` could compare project metadata to the actual PostgreSQL catalog.
- Repaired SQLite test fixture schema isolation without changing assertions; the tests now use SQLAlchemy `schema_translate_map` rather than mutating shared model table metadata.
- Added `docs/DEPLOYMENT_TLS_BOUNDARY.md` to distinguish repository controls from external deployment responsibilities.

## 4. PostgreSQL and migration evidence

**Classification: PARTIALLY VERIFIED; migration parity is a blocker.**

Read-only inspection of the configured target database observed PostgreSQL **17.11** and `alembic_version` **010**. `alembic current` and `alembic heads` both reported `010 (head)`. Thus revisions 008, 009, and 010 are represented by the current database revision.

Catalog inspection confirmed `uq_verification_request_idempotency`, `uq_cert_per_request`, primary keys, the certificate revocation check, and the certificate-to-request cascading foreign key. It also confirmed `verification_requests.result` is `varchar(50)`, sufficient for the currently declared result enum values. Revocation columns exist with `is_revoked NOT NULL`, nullable `revoked_at`, and nullable `revoked_reason`.

`alembic check` did **not** report schema parity. It detected project metadata objects absent from the live database:

- `ix_sbom_applications_user_id`;
- foreign keys from `sbom.applications.user_id`, `verification.verification_requests.proof_job_id`, `verification.verification_requests.user_id`, `vulnerability.vulnerability_snapshots.created_by`, `zkp.chunk_proof_sets.proof_job_id`, `zkp.proof_jobs.user_id`, and `zkp.segment_proofs.chunk_id`;
- unique constraint `uq_vuln_mapping_snapshot_comp` on vulnerability component mappings;
- a policy column comment difference.

The live `verification_requests` table has no foreign keys for its `proof_job_id` or `user_id`. No migrations were applied during this audit. These are concrete schema-drift findings; source migration presence or revision number does not establish that all expected objects are applied.

## 5. Concurrency and idempotency

**Classification: VERIFIED for PostgreSQL request/certificate convergence under the tested service path; cryptographic verification is outside this test.**

The harness connected to actual PostgreSQL, checked server version and the two required unique constraints, and used ten concurrent SQLAlchemy sessions calling the verification service with identical request identity. All successful callers resolved to one request identifier; database counts showed exactly one verification request and one certificate. Test rows were deleted, and follow-up counts for the test-specific users/applications/snapshots/policies were zero. The verifier was intentionally stubbed so this test does not claim proof validity. The test exits non-zero on failed assertions.

## 6. Certificate revocation

**Classification: VERIFIED for the tested application validation paths; deployment and broader authorization review remain separate.**

Source inspection found that certificate validation loads authoritative database state, rejects revoked certificates, and checks the associated verification request result. Token validation also resolves the token to a certificate record and checks its revocation state; possession of a previously copied signed token does not bypass that check. Revocation persists `is_revoked`, `revoked_at`, and `revoked_reason`; the revocation path locks the row and retains the first revocation metadata. Response serialization masks `certificate_data` for revoked certificates while preserving revocation metadata. Ownership checks remain on private retrieval/revocation paths. The lifecycle tests cover active validation, revoked rejection, audit metadata, unauthorized revocation, and revoked-token replay. The targeted verification suite passed 58 tests.

Public validation endpoints intentionally expose validation results. Their public behavior is not evidence of private certificate-data retrieval. No policy for certificate validity after later policy/snapshot changes is inferred here.

## 7. Stage21L archive integrity

**Classification: VERIFIED for byte/archive-to-database correspondence; NOT TESTABLE for fresh cryptographic proof verification.**

The existing archive was opened read-only. Its SHA-256 was `362be7463b3af52fb499a9bf95d64a69d1dac44e64d48f52cb197a5b48bb7e3d`, matching the preserved digest. The manifest described 32 chunks × 8 segments; the archive contained 256 proof members among 261 total members. The validator found no duplicate names, traversal paths, missing or unexpected proof members, and all 256 proof bytes matched persisted `SegmentProof` digests. The persisted proof-job archive digest matched the file digest. No archive or historical database status was changed. The manifest's `cryptographic_verification_status` remains `pending`; no fresh Barretenberg verification was performed and none is claimed.

## 8. TLS and network boundary

**Classification: PARTIALLY VERIFIED; external TLS boundary is a blocker.**

Compose declares `expose: 80` for `api-gateway` and no host `ports` mapping for it; application service ports are not host-published in the checked-in Compose file. `docker/nginx.conf` listens on HTTP port 80 only. The repository therefore provides no public TLS termination. It also provides no actual external ingress configuration, firewall/network policy, or external reachability evidence. The documentation correctly identifies these as deployment responsibilities, but documentation cannot establish the deployed boundary. Forwarded headers are not trusted by the checked-in Uvicorn command, and nginx does not supply forwarded-protocol headers.

## 9. Test suite and historical count reconciliation

`pytest --collect-only -q -p no:cacheprovider`: **533 collected**.  
Full `pytest -q -p no:cacheprovider`: **533 passed, 0 failed, 0 skipped, 55 warnings**.  
Targeted verification service suite: **58 passed, 37 warnings**.

The collection count exceeds the reported Stage21G result of 513 passed and the previous Stage21N claim of 472/472. Current collection includes 533 tests. The exact delta cannot be reconstructed from this checkout: the Git baseline is architecture-only, the working tree contains the broad project import, and no trusted historical collection manifest or complete historical test tree is available for a file-by-file comparison. The current runs provide no evidence of tests removed in this remediation, but do not prove no earlier tests were removed, renamed, disabled, or weakened. Test-count reconciliation is therefore **NOT VERIFIED**. Warnings include an unknown pytest `env` option and dependency deprecations; all collected tests executed and passed.

## 10. Secret hygiene

**Classification: PARTIALLY VERIFIED.**

`db.txt` is absent, ignored if recreated, `.env` remains ignored, and the inspected scripts use configured environment values rather than literal credentials. Search results were reviewed without emitting credential contents. No password is included in this report. The former external credential was previously exposed; this audit did not rotate it. Rotation remains required after Stage21N closure per the task instructions, and this report does not claim that the old credential is safe.

## 11. Crypto preservation and limitations

The archive digest is unchanged. This audit did not run the Stage21L workload, regenerate proofs, modify the archive, or intentionally alter circuit semantics, Poseidon parameters, Merkle/SMT construction, C32 decomposition, or production verification-key artifacts. The broad imported-tree baseline limits reliable historical diff attribution; exact unchanged status of every cryptographic source/artifact relative to earlier stages is **NOT INDEPENDENTLY VERIFIED** by this checkout. No new cryptographic execution claim is made.

## 12. Evidence classification summary

| Area | Classification | Evidence / limitation |
|---|---|---|
| PostgreSQL revision and required unique constraints | VERIFIED | Live PostgreSQL 17.11 catalog and revision 010 inspected |
| PostgreSQL schema parity | NOT VERIFIED | `alembic check` reports concrete unapplied diffs |
| Concurrent idempotency | VERIFIED | 10 concurrent service calls, one request and certificate; verifier stubbed |
| Certificate authoritative revocation | VERIFIED | DB-backed validation/token paths and lifecycle tests |
| Stage21L archive byte/DB correspondence | VERIFIED | Digest, topology, filenames, membership, and 256 DB proof hashes |
| Fresh Stage21L cryptographic verification | NOT TESTABLE | Not run by design; historical status is pending |
| Repository Docker host exposure | VERIFIED | No gateway host port mapping in Compose |
| Actual deployed TLS ingress | NOT VERIFIED | Ingress/firewall/reachability evidence unavailable |
| Current full test run | VERIFIED | 533 collected and passed |
| Historical test-tree reconciliation | NOT VERIFIED | No trustworthy historical inventory in this checkout |
| Current script/config secret hygiene | PARTIALLY VERIFIED | No literal found in inspected current files; previously exposed credential not rotated |
| Exact crypto source preservation against historical baseline | NOT VERIFIED | Current checkout baseline does not support reliable complete comparison |

## 13. Remaining concrete blockers

1. **Live PostgreSQL schema drift:** `alembic check` identifies missing foreign keys, an index, a uniqueness constraint, and a column-comment difference. The actual catalog does not match declared metadata. Resolve and independently verify through an authorized migration process before gate acceptance.
2. **TLS/network deployment boundary:** repository Compose does not publish the gateway and has no TLS listener, but the real external TLS terminator, firewall restrictions, direct-access prevention, and forwarded-header handling have not been evidenced.
3. **Previously exposed credential lifecycle:** the secret-bearing project-file/source exposure was removed from the inspected current paths, but the external credential was not rotated. Do not treat it as safe; rotate it as planned and confirm the replacement is deployed without exposing it.

## 14. Final gate

**BLOCKED** — schema parity, deployed TLS boundary, and rotation of the previously exposed external credential remain unresolved or unevidenced. The passing test suite and archive byte-integrity checks do not close these blockers.

## 15. Schema parity remediation follow-up — 2026-10-03

This section supersedes the schema-drift and credential-rotation status above.

Revision `011` (`backend/alembic/versions/011_schema_parity.py`) was applied to the configured Supabase PostgreSQL 17.11 database. A read-only preflight found four dangling nullable `sbom.applications.user_id` references, one dangling `vulnerability_snapshots.created_by`, and one dangling `zkp.proof_jobs.user_id`; it found no orphaned verification/job/chunk references and no duplicate `(snapshot_id, component_hash)` groups. To preserve rows and match the models' `ON DELETE SET NULL` semantics, revision 011 cleared only those six stale references before adding constraints. Post-migration inspection confirms zero remaining dangling owner references and all added constraints report `convalidated = true`.

The migration added `ix_sbom_applications_user_id`; the seven model-declared foreign keys for applications, verification requests, vulnerability snapshots, chunk proof sets, segment proofs, and proof jobs; unique constraint `uq_vuln_mapping_snapshot_comp`; and the exact ORM comment on `policy.security_policies.max_allowed_cvss_int`. No table rows were deleted.

Post-migration results: `alembic current` = `011 (head)`; `alembic heads` = `011 (head)`; `alembic check` = `No new upgrade operations detected.` The complete pytest suite passed **533 tests** with **0 failures** and **54 warnings**. The PostgreSQL concurrency probe passed with ten concurrent requests converging to one verification request and one certificate; its test-specific user/application records were cleaned up. The archive validator again matched the preserved archive digest and all 256 persisted proof hashes; the historical manifest remains `pending`, and no fresh cryptographic verification was run.

The rotated database credential is now reported by the user as independently verified, and the configured connection used for this migration and read-only catalog checks succeeded. No credential value was printed. This follow-up closes the PostgreSQL schema-parity blocker. The external TLS ingress/firewall/reachability evidence remains unavailable, so the overall Stage21N gate remains blocked on that deployment boundary.

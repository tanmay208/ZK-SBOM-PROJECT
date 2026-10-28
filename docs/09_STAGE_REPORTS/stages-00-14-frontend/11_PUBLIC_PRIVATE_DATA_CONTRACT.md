# Public and Private Data Contract

Date: 2026-09-25
Stage: 1.5

## Scope

Freeze the data classes that may cross the frontend/API boundary. This document does not change cryptographic primitives or public-input definitions.

## Public

The following are public only where returned by an approved response schema: `SBOM_ROOT`, approved vulnerability database commitments when explicitly frozen, `POLICY_HASH`, proof artifacts, verification result, certificate metadata, policy metadata, shared snapshot status/labels/counts, and service health/version. Public does not mean unauthenticated in every route.

## Authenticated or Owner-Only

- SBOM upload metadata, upload/application IDs, status, filename, component count, and committed root: authenticated vendor/admin owner workflow.
- Proof job IDs, lifecycle status, public roots, and proof artifact: authenticated vendor/admin owner workflow.
- Verification requests and certificate lists: authenticated users under current route policy.
- Metrics: authenticated, but counts are current-user scoped.
- Policy and snapshot metadata: authenticated shared resources; snapshot governance is admin-only.

## Admin-Only

Vulnerability ingestion, snapshot approval, snapshot revocation, and policy creation require the `admin` role. The server enforces these controls; no UI gate is relied upon.

## Private / Never Expose

Raw SBOM content, raw database fields, component names/versions/identities, PURLs, dependency graphs, private component hashes where classified by the security boundary, Merkle/SMT paths, private witness data, `Prover.toml`, database credentials, JWT secrets, subprocess commands/stderr, filesystem paths, stack traces, and internal exception details.

## Changes

`VulnerabilitySnapshotResponse` no longer serializes `provisional_smt_root`; the existing executable test and schema documentation already required that omission. `ProofJobResponse.error_message` is normalized to `Proof generation failed`, and prover persistence uses the same generic external message for unexpected failures. Certificate responses remain explicit public metadata schemas rather than raw ORM responses.

## Tests

Existing SBOM and vulnerability privacy tests cover raw content, PURL, and provisional-root non-disclosure. New proof response tests assert that paths and stderr markers cannot appear. Existing global exception tests assert no stack traces, passwords, or connection details in 500 responses.

## Unresolved Items

Whether a finalized `VULNERABILITY_DB_ROOT` should be exposed by a future snapshot response is UNKNOWN and requires cryptographic contract approval. Database retention/encryption, witness file cleanup, and live logs/backups were not validated. Public certificate accessibility has been selected, but live deployment and identifier exposure were not tested.

## Residual Risks

Pattern-based logging redaction is not a complete data-loss prevention system. Public commitments can still be sensitive in context; frontend display must follow approved route schemas, not field names alone. Existing proof artifact storage and database retention remain deployment/security work.

# Threat Model

## Assets

- Private SBOM component inventory and related application records.
- Database credentials, JWT signing material, certificate signing material, and proof witnesses.
- Proof jobs, public inputs, proof archives, verification outcomes, and certificate lifecycle records.
- Vulnerability snapshots, policy records, and audit metadata.

## Trust boundaries

- Browser ↔ API transport.
- Authentication/role checks ↔ tenant-owned database resources.
- API service ↔ PostgreSQL persistence.
- ZKP service ↔ filesystem artifacts and Nargo/Barretenberg subprocesses.
- Public certificate-validation response ↔ private certificate retrieval.
- Internal HTTP gateway ↔ any external deployment ingress (not defined by this repository).

## Threats addressed in project controls

Source and historical audit materials address unauthorized resource access, cross-tenant access, replay/stale verification state, idempotency races, certificate revocation, malformed/oversized proof archives, path traversal, subprocess limits, secret leakage, and proof/context substitution. The presence of tests or controls does not prove every threat is eliminated; consult dated reports for evidence and residual findings.

## Assumptions and deferred areas

- The configured vulnerability snapshot and policy are authoritative inputs for a verification; completeness and freshness of their external source are operational questions.
- PostgreSQL and environment secrets must be provisioned and protected outside checked-in source.
- Production ingress, HTTPS/TLS, firewalling, and origin isolation are deferred to Stage23.
- Frontend checks do not replace backend authorization.

This threat model avoids claiming that all attack paths have been eliminated.

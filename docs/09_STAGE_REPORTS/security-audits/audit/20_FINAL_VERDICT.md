# Final Verdict

## Verdict

**CRITICAL/HIGH RISKS IDENTIFIED**

## Verified Areas

- Python backend unit/service test slice executed: 480 passed.
- SQLAlchemy ORM was used for inspected data queries; no SQL injection finding is claimed for those paths.
- JWT decode restricts HS256 and requires expiration and subject; malformed/expired tokens are rejected in code.
- Password hashes are excluded from inspected auth responses.
- Request bodies and list limits have application-level bounds, though resource controls are incomplete.
- Frontend dependency audit reported 0 vulnerabilities; frontend production build completed.
- Gitleaks reported no leaks in its scanned scope.

## Confirmed Risks

- RBAC NOT ENFORCED: role and ownership checks are absent, and global list/read access is possible to authenticated users.
- Several high-cost or mutating routes are unauthenticated, including SBOM upload, vulnerability ingest, proof generation, proof verification, and certificate-by-ID retrieval.
- Vulnerability ingestion accepts attacker-selected data and creates completed provisional snapshots without trusted-source authorization.
- Production Python/circuit/VK profile alignment is broken or unavailable: Python defaults to 1024/depth10, checked-in circuit is 8/depth3, and production VK is absent.
- Verification does not compare caller-supplied commitments to an authoritative registry.
- Internal subprocess errors can be persisted and returned through proof-job responses.

## Unverified Areas

UNVERIFIED — INSUFFICIENT EVIDENCE for live SQL Server permissions, production Nargo/Barretenberg behavior, proof authenticity and interoperability, TLS/reverse-proxy behavior, browser token storage, crash/backup retention, filesystem permissions, and remote CI/hosting controls.

## Unavailable Tools

`nargo`, `bb`, `pip-audit`, `safety`, `bandit`, `trivy`, `grype`, `syft`, `osv-scanner`, and `cyclonedx-py` were unavailable. Semgrep was installed but did not complete because repository ignore parsing failed.

## Unexecuted Production Paths

No production Docker Compose deployment, production database, production circuit compilation, production witness generation, Barretenberg proof, Barretenberg verification, reverse proxy, or browser-authenticated workflow was executed.

## Remaining Assumptions

This verdict assumes the inspected source is the deployed source, the verification certificate is relied upon as an authority statement, and services are reachable through the Compose/gateway topology. External compensating controls were not evidenced.

## Missing Tests

A full multi-user authorization matrix, authenticated-route contract test, authoritative snapshot approval test, real production proof/VK test, dev/prod cross-profile rejection test, concurrency/idempotency test, subprocess process-group/output test, artifact permission/cleanup test, malformed SBOM resource corpus, and working Compose deployment test are required.

## Required Next Action

Remediate and retest authorization/ownership and trusted-root binding first; then establish a reproducible production circuit/VK/toolchain build and execute real end-to-end proofs before making any production-readiness claim. This audit does not conclude that the platform is secure.

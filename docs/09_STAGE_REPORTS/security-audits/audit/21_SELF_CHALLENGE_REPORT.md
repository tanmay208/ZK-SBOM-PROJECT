# Separate Self-Challenge Report

This report intentionally attempts to disprove the initial audit conclusions and verified-control claims. It does not merge new conclusions into the register silently.

## Challenge to High Findings

- **RBAC-001:** Could an unseen gateway enforce authorization? The service routes themselves are directly exposed by Compose and no nginx file exists, so gateway enforcement is not evidenced. Could database row-level security compensate? Shared credentials and no DB policy evidence make that unproven. Finding remains confirmed at application layer.
- **API-001 / VI-001:** Could deployment network isolation make unauthenticated routes unreachable? The gateway is intended to expose them through port 80; no route allowlist or authentication proxy exists in the repository. Network controls outside scope are unverified, not a mitigation proven in code. Findings remain.
- **ZK-001:** Could generated target artifacts secretly represent a different circuit? Source and target metadata were inspected, but Nargo was unavailable. This limits the claim to checked-in source/artifact inconsistency and absence of production VK; it does not prove every possible external build fails. Classification remains confirmed deployment/control defect, with execution behavior unverified.
- **ZK-002:** Could the verifier's public inputs themselves be the intended authority? The API contract describes authoritative roots, but no registry comparison or signature check exists. A proof over caller-selected values would still verify. Finding remains a confirmed trust-model violation; the exact certificate abuse scenario requires live proof tooling.

## Challenge to Verified Controls

- **JWT:** HS256 restriction and required claims are real, but no issuer/audience, revocation, secret startup requirement, or multi-worker test exists. The verified-control statement is narrowed to algorithm/claim handling only.
- **Request limits:** Tests and code support the nominal 10 MB bound, but no live chunked/HTTP proxy test or memory profile proves deployment behavior. This is an application-level control, not a complete DoS defense.
- **ORM safety:** Parameterized ORM filters support the SQL-injection false positive. This does not cover future raw SQL, database compromise, or authorization.
- **Certificate gate:** Repository code gates creation on `verified`; a mocked verifier can return that value and production tooling was unavailable. The gate is verified as control flow, not as proof authenticity.
- **Gitleaks/npm audit:** Both tools produced clean results in their scopes, but neither covers runtime misconfiguration, unavailable Python scans, remote history, or semantic privacy.

## Challenge to Low-Risk Classifications

Parser limits may be more than low risk if 10 MB JSON nesting creates severe CPU/memory pressure; classification is therefore explicitly a hardening recommendation with residual DoS risk, not a claim of safety. Bash interpolation may become exploitable if a future non-UUID ID path is introduced; current evidence supports only hardening. The raceable verification fingerprint may duplicate certificates under concurrency, but live concurrent reproduction was not executed, so it remains probable rather than confirmed.

## Challenge to Production Readiness

A successful Next.js build and 480 backend tests could suggest readiness, but full collection fails, Compose references absent files, production VK is missing, and toolchain execution was unavailable. No production-readiness claim survives the challenge.

## Revised Residual Conclusion

The self-challenge did not disprove the high findings. It did narrow several claims from runtime exploit proof to confirmed code/control defects with unexecuted production behavior. The final verdict remains **CRITICAL/HIGH RISKS IDENTIFIED** and must not be read as a claim that the platform is secure.

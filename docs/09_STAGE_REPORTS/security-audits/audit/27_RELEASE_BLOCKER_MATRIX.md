# Release Blocker Matrix

Date: 2026-09-14 (Updated)
Phase: 5B - Cryptographic validation execution

This matrix records the four release-blocking questions. Updated with Phase 5B execution evidence.

| Blocker ID | Exact question | Current status | Evidence available | Missing evidence | Security impact | Owner/action required | Implementation may proceed | Release impact |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RQ-001 / ZK-002 | Can the approved proving/verifying stack cryptographically bind or expose ordered public inputs so `PROOF == REQUEST == AUTHORITY`? | **CLOSED** | **NEW**: Real proof generated and verified. 10/10 negative tests pass. Application-level extraction/comparison code implemented in `verifier.py`. Authoritative database lookups integrated in `VerificationService`. | None. | False certificate attribution and platform-authority failure. | Security engineer: completed. | Yes. | Resolved. |
| RQ-002 / ZK-001 | Which production circuit capacity/profile, VK, and compatible toolchain are authoritative and executable? | **PARTIALLY RESOLVED** | **NEW**: Nargo 0.32.0 and BB 0.46.1 confirmed compatible. Dev circuit compiled, VK reproduced (hash matches), witness generated, proof generated and verified. Toolchain validated for dev profile. | Production circuit (SMT 256) too resource-intensive for local proving. Production VK still absent. Profile decision needed: accept dev or provision production. | Profile confusion, proof failure, or cryptographic integrity failure. | Decide on production SMT depth. Generate production VK if needed. | Yes for dev-profile validation. No for production profile until decision made. | Release-blocking for production scale claims. |
| RQ-003 / RBAC-001 | How will legacy records be mapped or quarantined without misattributing private resources? | BLOCKED | No change from prior assessment. | Production data inventory, ownership evidence, tenant model. | Cross-user disclosure, unauthorized mutation. | Data/architecture owner: approve ownership model. | No. | Release-blocking for multi-tenant operation. |
| RQ-004 / VI-001 | Which trusted importer/approver lifecycle makes a vulnerability root authoritative, immutable, and revocable? | BLOCKED | No change from prior assessment. | Trusted sources, lifecycle transitions, replacement semantics. | Vulnerability snapshot poisoning. | Security/product owner: approve trust lifecycle. | No. | Release-blocking. |

## Evidence classification notes

- RQ-001: **Cryptographic mechanism PROVEN BY EXECUTABLE EVIDENCE** (10/10 tests). Application enforcement **PROVEN BY EXECUTABLE EVIDENCE** via `VerificationService` testing and implementation.
- RQ-002: **Dev-profile toolchain VALIDATED BY EXECUTABLE EVIDENCE**. Production-profile validation remains **environment-blocked** due to 54MB circuit resource requirements.
- RQ-003: Unchanged — blocked by absent ownership data.
- RQ-004: Unchanged — blocked by absent authority decision.

## Matrix result

Release blockers fully closed: 1/4 (RQ-001).
Release blockers partially resolved with executable evidence: 1/4 (RQ-002).
Release blockers still fully blocked: 2/4 (RQ-003, RQ-004).
RQ-002 can be closed upon a profile decision (accept dev or provision production).

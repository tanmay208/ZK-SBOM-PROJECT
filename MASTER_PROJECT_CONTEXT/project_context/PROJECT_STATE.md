# Authoritative Project State & Findings Register

**Document Version:** 4.0.0-final-release-ready
**Freshness Date:** 2026-10-30
**Workspace:** `E:\Main Project`
**Current Branch:** `integration/role-consolidation-on-main`
**Head Commit:** `cfefd07` (`Merge pull request #2 from tanmay208/integration/role-consolidation-on-main`)
**Active Milestone:** Master Prompt 6 — Authoritative Project Context Documentation Synchronization (Master Prompt 1 Security Audit, Master Prompt 2 Vulnerability Intelligence Remediation, Master Prompt 3 Policy Hardening, Master Prompt 3A/3B Verification Gateway Hardening, Master Prompt 4 E2E Acceptance, and Master Prompt 5 Final Release Readiness closed with `PASS — Expo-Ready Within Documented Scope` on 2026-10-30).
**Operating Mode:** LOCAL-ONLY. No remote operations, deployments, or external environment access without explicit authorization.

---

## 1. Verified Repository & Runtime Baseline

### 1.1 Service & Database Runtime Status
| Component | Runtime Identity | Verified Port | Status / Evidence |
| :--- | :--- | :--- | :--- |
| **API Gateway** | Docker Nginx Reverse Proxy (`mainproject-api-gateway-1`) | `127.0.0.1:8000` | **HEALTHY / OPERATIONAL**. Proxies incoming client requests to backend microservices; applies rate limiting and 10MB payload ceiling. |
| **Vulnerability Service** | Docker FastAPI (`mainproject-vulnerability-service-1`) | `8001/tcp` (internal) | **HEALTHY / OPERATIONAL**. OSV & NVD 2.0 adapters, SemVer & PEP 440 matcher, Two-Person Integrity, SMT Depth 256 commitment. |
| **Policy Service** | Docker FastAPI (`mainproject-policy-service-1`) | `8002/tcp` (internal) | **HEALTHY / OPERATIONAL**. Canonical policy contract, V1 Poseidon hash ($H_{\text{Policy}}$), V2 domain-separated SHA-256 digest, single active policy invariant. |
| **ZKP Prover Service** | Docker FastAPI (`mainproject-zkp-service-1`) | `8003/tcp` (internal) | **HEALTHY / OPERATIONAL**. Prover ecosystem and compliance preflight gates, advisory worker locks, UltraPlonk proof orchestration. |
| **Verification Service** | Docker FastAPI (`mainproject-verification-service-1`) | `8004/tcp` (internal) | **HEALTHY / OPERATIONAL**. Proof shares, native Barretenberg `bb.exe` UltraPlonk verifier, TOCTOU pre-signing re-validation, HS256 certificate authority. |
| **SBOM Service** | Docker FastAPI (`mainproject-sbom-service-1`) | `8000/tcp` (internal) | **HEALTHY / OPERATIONAL**. CycloneDX parser, canonical purl sorting, binary Merkle tree ($R_{\text{SBOM}}$, depth 10, capacity 1024). |
| **Local Dev Database** | Docker PostgreSQL 16.15 (`zkp_sbom_local_dev`) | `127.0.0.1:5433` | **AUTHORITATIVE LOCAL DEV DB / VERIFIED**. Database `ZKP_SBOM_LOCAL_DEV` at Alembic revision **`016`** (with untracked migration `017_add_proof_shares.py`). Historical certificates (including `312abe78-86e6-4727-9718-f2aa38280d9a`) 100% intact. Exactly zero mutations during MP5 testing. |
| **Frontend UI** | Next.js 15 / React 19 (`frontend/`) | `127.0.0.1:3000` | **SHUT DOWN / READY FOR BRING-UP**. Preserved offline throughout MP1–MP6. 116 tests passing, 19 routes compiled. Recommended for authorization prior to expo presentation. |
| **Automated Test Target** | Docker PostgreSQL 17 (`zkp_sbom_g0_pg17_restore`) | `127.0.0.1:5435` | **STANDBY TEST TARGET**. Preserved for isolated testing. |

### 1.2 Git Working Tree Inventory
- **Branch Status:** `integration/role-consolidation-on-main` (ahead of `newrepo/integration/role-consolidation-on-main` by 1 commit `cfefd07`).
- **Modified Tracked Files (43 files)**:
  - Backend services, models, repositories, and routes across policy, sbom, shared, verification, vulnerability, and zkp services.
  - Gateway configuration: `docker/nginx.conf`.
  - Frontend services, routes, and tests reflecting the consolidated 3-role model (`vendor`, `buyer`, `admin`).
- **Untracked Core Hardening & Test Files (20 files)**:
  - Migrations: `backend/alembic/versions/017_add_proof_shares.py`.
  - Policy contracts: `backend/policy_service/app/services/policy_contract.py`.
  - Adapters, normalization, and matcher: `backend/vulnerability_service/app/services/adapters/`, `normalization.py`, `matcher.py`, `snapshot_validator.py`.
  - Dedicated regression test suites:
    - `test_master_prompt_5_reconciliation.py` (19 tests)
    - `test_master_prompt_4_e2e_acceptance.py` (8 tests)
    - `test_gateway_hardening_mp3b.py` (22 tests)
    - `test_verification_ecosystem_and_policy_binding.py` (5 tests)
    - `test_policy_contract_and_binding.py` (10 tests)
    - `test_proof_shares.py` (16 tests)
    - `test_snapshot_coverage_and_soundness.py` (5 tests)
    - `test_ecosystem_matcher.py` (11 tests)
    - `test_two_person_integrity.py` (3 tests)
    - `test_prover_ecosystem_gate.py` (1 test)
    - `test_role_separation_and_security.py` (8 tests)
- **Circuit State:** All Noir 0.32.0 ACIR circuits (`segment_init_32`, `segment_mid_32`, `segment_final_32`) remain **FROZEN** and intact with 0 modifications.

---

## 2. Empirical Test Execution Accounting

| Test Suite / Inspection | Execution Scope | Passed | Skipped | Failed | Notes & Evidence |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **MP5 Reconciliation Suite** | 10 Adversarial conditions, Scenarios A & B, TOCTOU, HS256 JWT | **19** | **0** | 0 | `test_master_prompt_5_reconciliation.py`. 100% passed in 4.02s. Barretenberg native UltraPlonk verified. |
| **MP4 Acceptance Suite** | E2E Acceptance, Ecosystem Mismatch, Policy Boundaries | **8** | **0** | 0 | `test_master_prompt_4_e2e_acceptance.py`. 100% passed in 2.87s. |
| **MP3B Gateway Hardening** | Snapshot Identity, Provenance, TOCTOU, V2 Digest Binding | **22** | **0** | 0 | `test_gateway_hardening_mp3b.py`. 100% passed in 2.45s. |
| **Verification Binding Suite** | Ecosystem & Policy Binding, Tamper Rejection | **5** | **0** | 0 | `test_verification_ecosystem_and_policy_binding.py`. 100% passed in 1.29s. |
| **Native Crypto Suite** | Genuine Barretenberg Native UltraPlonk Verifier (`bb.exe`) | **24** | **0** | 0 | `test_b1_live_crypto.py`. 100% passed in 10.55s via native `bb.exe`. |
| **Certificate Rotation Suite** | Multi-Key Rotation, Key ID Resolution, Fallback Defenses | **15** | **0** | 0 | `test_certificate_rotation.py`. 100% passed in 0.82s. |
| **Certificate Signing Suite** | Certificate Secret Validation, Fingerprint Stability | **14** | **0** | 0 | `test_certificate_signing.py`. 100% passed in 0.44s. |
| **Proof Shares Suite** | Proof Share Lifecycle, Auto-Revocation, Role Isolation | **16** | **0** | 0 | `test_proof_shares.py`. 100% passed in 1.16s. |
| **Snapshot Soundness Suite** | SMT Root Integrity, Provenance & Expiration | **5** | **0** | 0 | `test_snapshot_coverage_and_soundness.py`. 100% passed in 1.12s. |
| **Ecosystem Matcher Suite** | SemVer, PEP 440, Scoped Packages, Clean Versions | **11** | **0** | 0 | `test_ecosystem_matcher.py`. 100% passed in 0.51s. |
| **Two-Person Integrity Suite** | Admin Separation, Approval & Freeze Rules | **3** | **0** | 0 | `test_two_person_integrity.py`. 100% passed in 0.40s. |
| **Policy Contract Suite** | V1 & V2 Policy Digests, Fail-Closed Evaluation | **10** | **0** | 0 | `test_policy_contract_and_binding.py`. 100% passed in 0.97s. |
| **Prover Ecosystem Gate** | Prover Ecosystem Preflight Gate | **1** | **0** | 0 | `test_prover_ecosystem_gate.py`. 100% passed in 0.28s. |
| **Role Separation Suite** | Separation of Duties (Admin, Vendor, Buyer) | **8** | **0** | 0 | `test_role_separation_and_security.py`. 100% passed in 7.98s. |
| **Dedicated Security Total** | **Consolidated MP1–MP5 Security Regressions** | **161** | **0** | **0** | **100% passing across 14 dedicated security suites.** |
| **Full Backend Regression** | All 7 microservices + baseline migrations | **1,345** | **0** | **0** | Baseline verified in Stage D/G (0 skips). |
| **Frontend Unit Tests** | tsx test runner (`src/**/*.test.ts`) | **116** | **0** | **0** | Verified in Stage G / MP4 (0 skips). |
| **Frontend Quality Gates** | `tsc --noEmit`, `eslint`, `next build` | **PASS** | 0 | 0 | 0 errors, 0 warnings, 19 compiled routes. |

---

## 3. Findings Register: Master Prompt 1–5 Remediations

| Finding ID | Title & Issue Description | Remediation & Implementation Status | Authoritative Boundary & Verdict |
| :--- | :--- | :--- | :--- |
| **AUD-3A-001** | **Vacuous Non-Membership in Disjoint SMT Trees** | Circuit verifies $P_i=0, L_i=0$ against empty or disjoint SMT roots, allowing vacuous proofs for unindexed components (e.g. npm component in PyPI-only tree). | **CLOSED / MITIGATED**: Implemented `SnapshotValidator.validate_snapshot_suitability_for_sbom` and prover-side ecosystem preflight gates. Blocks proof generation and verification fail-closed with `BLOCKED_INSUFFICIENT_COVERAGE`. | **BACKEND-ENFORCED**<br>(Circuit cannot parse ecosystem strings) |
| **AUD-3A-002** | **V2 Policy Commitment Enforcement** | V2 domain-separated policy contract attributes (excluded versions, severity bounds) were not enforced in the frozen circuit. | **CLOSED / MITIGATED**: V1 Poseidon hash ($H_{\text{Policy}}$) is enforced in-circuit. V2 contract digest (`policy_digest_v2`) and revision are dynamically computed and bound into the certificate JWT payload. | **CIRCUIT-ENFORCED ($H_{\text{Policy}}$)**<br>**BACKEND-ENFORCED ($V_2$)** |
| **AUD-3A-003** | **Unindexed Component Vacuous Proof Risk** | A vendor could reference an arbitrary snapshot that did not index their SBOM's ecosystems. | **CLOSED / VERIFIED**: Provenance validation requires explicit `ecosystems_covered`. Incomplete coverage rejects verification immediately. | **BACKEND-ENFORCED** & **CERTIFICATE-RECORDED** |
| **AUD-3A-004** | **Lack of Real Upstream Vulnerability Intelligence** | Vulnerability database relied on mock fixtures without real CVE feeds. | **CLOSED / VERIFIED**: Built live adapters for Google OSV API and NIST NVD 2.0 API; added advisory normalization, SemVer, and PEP 440 matching. | **BACKEND-ENFORCED** |
| **AUD-3A-005** | **Ambiguous Snapshot Resolution by Root** | Lookups by SMT root alone could resolve ambiguous snapshots if multiple snapshots shared the same empty root. | **CLOSED / VERIFIED**: Gateway binds exact `ProofJob.snapshot_id` and verifies that the snapshot's authoritative SMT root strictly matches public input $R_{\text{VulnDB}}$. | **BACKEND-ENFORCED** |
| **AUD-3A-006** | **Null Provenance Bypass** | Snapshots with null or malformed provenance bypassed ecosystem coverage validation. | **CLOSED / VERIFIED**: Added strict fail-closed provenance validation. Null, empty, or malformed JSON provenance is rejected with 422 Unprocessable Entity. | **BACKEND-ENFORCED** |
| **AUD-3A-007** | **TOCTOU Pre-Signing Race Condition** | Snapshot revocation or policy deactivation during proof verification could result in an invalid certificate being minted. | **CLOSED / VERIFIED**: Implemented atomic pre-signing re-validation check in `VerificationRepository.create_verification_record` and `update_verification_record`. Mutations abort certificate issuance fail-closed (`result = "record_mismatch"`). | **BACKEND-ENFORCED** |

---

## 4. Historical Database Integrity Verification

The local development PostgreSQL 16 database (`zkp_sbom_local_dev` on port 5433) was audited on 2026-10-30:

- **Historical Certificate ID:** `312abe78-86e6-4727-9718-f2aa38280d9a`
- **Associated Verification Request:** `8c54dec7-d5a6-48f2-b9ea-bede11dc7dfa`
- **Associated Proof Job:** `69ba5b3d-10fe-4f7b-9a23-4bfb4acd9987`
- **Associated SBOM Upload:** `e8ff7be2-dd32-474d-aa64-1e0f06b47c47` (`bom.1.4.json`, 837 components)
- **Associated Snapshot:** `ca829add-bfe1-4c12-a720-33758b29c9df` (`demo_cve_feed_2026_v1`)
- **Status:** **100% Present, Untouched, Unrevoked** (`is_revoked = false`, token length: 591 bytes).
- **PostgreSQL Table Counts:**
  - `verification.verification_certificates`: 6
  - `verification.verification_requests`: 22
  - `zkp.proof_jobs`: 6
  - `sbom.sbom_uploads`: 5
  - `vulnerability.vulnerability_snapshots`: 1
  - `policy.security_policies`: 1
  - `public.users`: 5
- **Net DB Mutations in PostgreSQL during MP5:** **0 rows added, 0 rows deleted, 0 rows modified**. All automated regression test suites executed against isolated in-memory SQLite instances (`sqlite:///:memory:`).

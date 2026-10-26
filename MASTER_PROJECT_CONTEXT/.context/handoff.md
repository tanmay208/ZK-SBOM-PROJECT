# Session Handoff & Continuity

**Freshness Date:** 2026-10-24  
**Workspace Root:** `E:\Main Project`  
**Active Milestone:** **Stage G: Final Viva Presentation Readiness & Acceptance (G3 ACCEPTED / G4 AUTHORIZED)**  
**Operating Mode:** LOCAL-ONLY (Gate 5R Strictly Blocked; No Remote Operations)  

---

## 1. Immediate Next Task: Stage G4 Presentation & Viva Defense Execution

Stage G3 is formally accepted and verified across all 6 approved presentation workflows.
The project is currently executing the authorized **Project Context Consolidation & Deep Repository Cleanup** operation to consolidate all documentation under `MASTER_PROJECT_CONTEXT/` and permanently remove redundant standalone context directories.

Upon sign-off of repository cleanup, resume **Stage G4** (Viva Defense Presentation Execution & Video Demonstration Recording).

---

## 2. Verified Runtime & Service Coordinates

- **Authoritative Presentation Database**: Supabase PostgreSQL 17 on `127.0.0.1:5432` (`aws-0-ap-southeast-2.pooler.supabase.com`, Alembic rev `016`). Baseline accounts and seeded presentation fixtures active.
- **Isolated Regression Test Database**: Docker PostgreSQL 17 on `127.0.0.1:5435` (`zkp_sbom_g2_integration`, Alembic rev `016`). Dedicated to automated regression testing.
- **API Gateway**: Running on `http://127.0.0.1:8080` (verified healthy at `GET /api/v1/health`).
- **Frontend UI**: `cd frontend; npm run dev` at `http://localhost:3000`.

---

## 3. Presentation Workflows Verified (Stage G3)

1. **Vendor & Application Registration**: Vendor authenticated, application registered, buyer account created.
2. **Compliant SBOM & Commitment**: Clean CycloneDX SBOM committed, Poseidon Merkle root calculated.
3. **Log4Shell Circuit Rejection**: Vulnerable Log4j SBOM rejected by authentic circuit constraint (`assert(scores[i] <= policy_max_cvss)` rejecting CVSS 100 > 70 with exit code 1 / `Chunk 0 failed`). Zero certificates issued.
4. **Valid UltraPlonk Proof & Verification**: Valid 1-segment UltraPlonk proof verified, compliance certificate issued.
5. **Buyer Independent Verification**: Buyer independently validates public commitments and certificate without access to raw SBOM.
6. **Certificate Revocation & Audit Integrity**: Admin revocation executed; database revocation takes precedence over signed JWT tokens.

---

## 4. Critical Boundaries & Safety Rules

- **NEVER** run `git reset --hard` or `git clean -fd`.
- **NEVER** expose `.env` contents, bearer tokens, or database passwords in documentation or reports.
- **PostgreSQL 16**: Excluded from Stage G and presentation workflows.
- **HONEST EVIDENCE**:
  - Full 256-segment UltraPlonk proving remains **DEFERRED / UNVERIFIED** under Stage D5 due to host RAM safety floor.
  - Presentations and demonstrations rely on bounded 1-segment ACIR UltraPlonk proofs (2,144 bytes).
  - Canonical context root is strictly `MASTER_PROJECT_CONTEXT/`.


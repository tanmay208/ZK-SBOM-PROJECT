# ZKP Proof Workflow Architecture

Date: 2026-10-01
Stage: 9 — ZKP Proof Generation & Proof Job Workflow

## 1. Core Workflow
- Users generate Zero-Knowledge Proofs at `/proofs/generate`.
- They select an SBOM, a Vulnerability Snapshot (Approved/Pending), and an active Security Policy.
- The request is delegated exclusively to the backend. The frontend performs NO cryptographic compilation or witness construction.
- Status is tracked via React Query polling on the list (`/proofs`) and detail (`/proofs/[id]`) routes.

## 2. Polling Strategy
- The lists and detail views poll their respective `proofService` methods at short intervals (3-5 seconds) ONLY when a job is detected to be in an active state (`pending` or `assembling_witness`).
- When all jobs reach terminal states (`completed`, `failed`, `execution_blocked`), the interval disables itself, preventing infinite queries.

## 3. Cryptographic Boundary
- The UI surfaces hashes (e.g. `sbom_root`, `policy_hash`) for verification referencing.
- **Strictly Prohibited**: The UI will NOT attempt to display `proof_artifact` binaries, `.gz` witnesses, or internal execution stderr strings.
- Proof generation is correctly labeled as a *generation* step, explicitly warning users that it does not imply *verification*.

## 4. Ownership and Role Access
- Vendor and Admin roles are granted access through `RouteGuard`.
- Auditor receives an immediate 403.
- The frontend assumes no tenant or owner identifiers in URL structures. The Backend token ensures strict isolation of `proofService` queries.

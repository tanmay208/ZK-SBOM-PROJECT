# Stage 9 Acceptance Criteria

Date: 2026-10-01
Stage: 9 — ZKP Proof Generation & Proof Job Workflow

## Criteria

1. **Proof Job List**: The `/proofs` route displays an active list of generation tasks, polling dynamically.
2. **Proof Generation Form**: The `/proofs/generate` route integrates with `sbomService`, `vulnerabilityService`, and `policyService` to construct valid requests.
3. **Detail Tracking**: The `/proofs/[id]` route tracks and displays the specific job, recognizing terminal states like `execution_blocked` or `failed`.
4. **No Cryptography Leakage**: The frontend does not expose witness binaries or parse proof artifacts.
5. **No Verification Misrepresentation**: Success states clearly indicate that a proof is generated but NOT verified.
6. **Role Isolation**: Only `vendor` and `admin` can access the Proof pages.
7. **Error Masking**: API Errors from failed generations are sanitized rather than emitting raw Node/Python exceptions to the DOM.

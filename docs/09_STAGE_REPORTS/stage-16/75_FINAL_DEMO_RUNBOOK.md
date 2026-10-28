# Final Demo Runbook

Date: 2026-10-01
Stage: 15 — Final Release & Evidence Validation

## Demo Setup
- Active Node.js and Python 3.12 environments.
- Backend running on `:8000`.
- Frontend running on `:3000`.
- Cryptographic execution requires Docker backend container if native tools are missing.

## Demo Sequence

### 1. Login
- **Action**: Authenticate with Demo Vendor credentials.
- **Expected Result**: Success, redirected to Dashboard.
- **Security Property**: Token loaded strictly to memory transport.

### 2. Dashboard
- **Action**: View loaded metrics.
- **Expected Result**: Accurate API response reflecting vendor scopes.
- **Security Property**: Zero fabricated claims/risk scores.

### 3. Upload SBOM
- **Action**: Submit 100kb valid CycloneDX JSON.
- **Expected Result**: 201 Created.
- **Security Property**: Payload size bounded (10MB), structure validated.

### 4. Generate Proof
- **Action**: Select SBOM and target Policy Hash.
- **Expected Result**: Job queued (MOCKED if local tools missing, REAL if containerized).
- **Security Property**: Zero client-side cryptographic exposure.

### 5. Wait for Completion
- **Action**: Poll job status.
- **Expected Result**: Transition from `pending` to `completed`.
- **Security Property**: Status driven by backend DB mutations only.

### 6. Verify Proof
- **Action**: Request verification on completed proof.
- **Expected Result**: Backend validation pass (MOCKED if local, REAL if containerized).
- **Security Property**: Backend authoritative result entirely untamperable by UI.

### 7. Show Verification Result
- **Action**: Observe UI update.
- **Expected Result**: Transition to `verified`.
- **Security Property**: State matching.

### 8. Show Certificate
- **Action**: Redirect from verification to certificate issue.
- **Expected Result**: New Certificate rendered.
- **Security Property**: Certificate generated purely by backend on `verified` status.

### 9. Open Public Certificate
- **Action**: Open `/certificates/[id]` in Incognito.
- **Expected Result**: Certificate loads.
- **Security Property**: Explicitly exposed public metadata only. No SBOM structures leaked.

### 10. Demonstrate Role Restriction
- **Action**: Login as Auditor, attempt SBOM upload.
- **Expected Result**: Denied (403).
- **Security Property**: RBAC boundary enforced.

### 11. Demonstrate Invalid Verification
- **Action**: Verify with modified Policy Hash.
- **Expected Result**: Failed validation.
- **Security Property**: Public input mismatch blocks certificate generation.

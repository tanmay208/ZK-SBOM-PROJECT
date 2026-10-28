# User Journeys

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## Core Journeys

### J1 — Login
- **Preconditions:** User has account. No active token in memory.
- **Actor:** Unauthenticated Visitor.
- **Entry Point:** `/login`
- **Steps:** 
  1. User enters username and password.
  2. Submits form.
  3. API responds with JWT bearer token.
  4. Frontend stores token in memory, fetches `/api/v1/auth/me`.
  5. Frontend redirects to `/dashboard`.
- **Backend Interactions:** `POST /api/v1/auth/login`, `GET /api/v1/auth/me`.
- **Security Boundary:** Password hashed on server; token in memory only.
- **Failure Result:** UI shows "Invalid credentials" (401).

### J2 — Logout
- **Preconditions:** User is logged in.
- **Actor:** Authenticated User (Any role).
- **Entry Point:** Main navigation "Logout" button.
- **Steps:** User clicks "Logout".
- **Backend Interactions:** None (logout is client-side).
- **Security Boundary:** Token and profile are immediately erased from JS memory.
- **Success Result:** Redirect to `/login`.

### J3 — Vendor uploads SBOM
- **Preconditions:** Logged in as vendor/admin.
- **Actor:** Vendor.
- **Entry Point:** `/sboms/upload`
- **Steps:** 
  1. Fill application name, vendor name. Select CycloneDX JSON file.
  2. Click Upload.
  3. Wait for submission to complete.
- **Backend Interactions:** `POST /api/v1/sbom/upload`.
- **Success Result:** Redirect to `/sboms`. UI shows success toast.
- **Failure Result:** Form displays validation errors (422) or file size error (413).

### J4 — Vendor views own SBOM
- **Preconditions:** Logged in as vendor/admin. Uploaded at least one SBOM.
- **Actor:** Vendor.
- **Entry Point:** `/sboms`
- **Steps:** View table of SBOMs.
- **Backend Interactions:** `GET /api/v1/sbom`.
- **Security Boundary:** The API only returns the vendor's own SBOMs. Raw content is NEVER returned.
- **Success Result:** Table populates with status, root hash, component count.

### J5 — Vendor initiates proof generation
- **Preconditions:** Vendor has 1+ SBOMs. An approved vulnerability snapshot exists. An active policy exists.
- **Actor:** Vendor.
- **Entry Point:** `/proofs/generate`
- **Steps:**
  1. Select SBOM from dropdown.
  2. Select Snapshot from dropdown.
  3. Select Policy from dropdown.
  4. Click Generate.
- **Backend Interactions:** `GET /api/v1/sbom`, `GET /api/v1/vulnerability/snapshots`, `GET /api/v1/policy`, `POST /api/v1/zkp/generate`.
- **Success Result:** Redirect to `/proofs/[id]` for the new job.
- **Failure Result:** API 400 if snapshot is revoked or not approved. UI displays error.

### J6 — Vendor observes proof lifecycle
- **Preconditions:** Proof job initiated.
- **Actor:** Vendor.
- **Entry Point:** `/proofs/[id]`
- **Steps:** Page polls for status updates until terminal state.
- **Backend Interactions:** Polling `GET /api/v1/zkp/jobs/{id}` (e.g. every 5 seconds).
- **Success Result:** State transitions: `pending` -> `assembling_witness` -> `completed`. Proof artifact appears.
- **Failure Result:** State transitions to `failed` or `execution_blocked`. Generic error displayed.

### J7 — User requests verification
- **Preconditions:** User has a proof artifact (base64) and knows the three roots/hashes.
- **Actor:** Authenticated User (Any role).
- **Entry Point:** `/verify`
- **Steps:**
  1. Paste SBOM Root, Vulnerability DB Root, Policy Hash, and Proof Artifact.
  2. Click Verify.
- **Backend Interactions:** `POST /api/v1/verification/verify`.
- **Success Result:** Result is `verified`. Certificate is issued and displayed with UUID.
- **Failure Result:** Result is `invalid`, `public_input_mismatch`, `authoritative_record_mismatch`, etc.

### J8 — User views verification result
- **Preconditions:** User completed J7.
- **Actor:** Authenticated User.
- **Entry Point:** Same page as J7.
- **Steps:** Observe the result enum returned by the API.

### J9 — User accesses certificate
- **Preconditions:** Certificate exists.
- **Actor:** Any (even unauthenticated).
- **Entry Point:** `/certificates/[id]`
- **Steps:** Load page via URL.
- **Backend Interactions:** `GET /api/v1/verification/certificates/{id}`.
- **Security Boundary:** No private data in response.

### J10 — Admin ingests vulnerability intelligence
- **Preconditions:** Logged in as Admin.
- **Actor:** Admin.
- **Entry Point:** `/admin/vulnerabilities`
- **Steps:** Paste JSON payload of CVEs/PURLs/CVSS. Click Ingest.
- **Backend Interactions:** `POST /api/v1/vulnerability/ingest`.
- **Success Result:** New snapshot appears in list as `pending`.

### J11 & J12 — Admin approves/revokes vulnerability snapshot
- **Preconditions:** Snapshot exists in list.
- **Actor:** Admin.
- **Entry Point:** `/admin/vulnerabilities`
- **Steps:** Click "Approve" or "Revoke" on a snapshot row.
- **Backend Interactions:** `POST /api/v1/vulnerability/snapshots/{id}/approve` or `/revoke`.
- **Success Result:** Status badge updates immediately.

### J13 — Admin manages security policy
- **Preconditions:** Logged in as Admin.
- **Actor:** Admin.
- **Entry Point:** `/admin/policies`
- **Steps:** Enter Name, Description, Max CVSS. Submit.
- **Backend Interactions:** `POST /api/v1/policy`.
- **Success Result:** Old policies show inactive; new policy shows active.

### J16 — Expired/invalid session
- **Preconditions:** Token expired on server.
- **Actor:** Authenticated User.
- **Steps:** Any API call returns 401.
- **Frontend Action:** Intercept 401 globally, wipe memory token, redirect to `/login`.

### J18, J19, J20 — Verification Failures
- **Preconditions:** Invalid proof, mismatched inputs, or revoked/inactive authoritative records.
- **Actor:** Authenticated User.
- **Entry Point:** `/verify`
- **Backend Interactions:** `POST /api/v1/verification/verify`
- **Frontend Action:** Display the specific failure reason returned by the server (e.g. `public_input_mismatch`). Do NOT claim success.

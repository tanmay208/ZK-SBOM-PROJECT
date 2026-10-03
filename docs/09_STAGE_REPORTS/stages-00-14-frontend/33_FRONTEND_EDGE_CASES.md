# Frontend Edge Cases and Failure Inventory

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Authentication Edge Cases
- **Invalid Credentials:** Backend returns 401. UI shows "Invalid username or password."
- **Expired Token:** In-flight API call returns 401. UI intercepts, clears memory token, redirects to `/login` with an optional `?redirect` parameter.
- **Malformed Token:** Same as expired.
- **Refresh/Deep-Link:** User hard-refreshes `/dashboard`. Memory token is lost. User is redirected to `/login`.

## 2. Authorization Edge Cases
- **Wrong Role:** Auditor tries to fetch `/sboms`. API returns 403. UI shows 403 Forbidden boundary page.
- **Non-Owner Resource:** Vendor A tries to fetch `/proofs/{vendor_b_job_id}`. API returns 404 (due to user_id filter). UI shows standard 404 Not Found.
- **Direct URL Access:** User types `/admin/policies` directly. If auth checks pass, page loads. If unauthorized, 403 boundary shown.

## 3. SBOM Management
- **Invalid File / Unsupported Format:** User uploads a non-CycloneDX file. API returns 422. UI displays schema validation errors.
- **Oversized Upload:** File > 10MB. Middleware returns 413. UI displays "File too large (Max 10MB)".
- **Failed Upload:** Database constraint or pipeline failure. API returns 400 or 500. UI shows generic failure toast.

## 4. Vulnerability Management
- **Unauthorized Approval/Revocation:** Vendor sends POST to approve. API returns 403.
- **Approve Revoked Snapshot:** Admin tries to approve a snapshot that is already revoked. API returns 400 (only `pending` can be approved). UI should disable the Approve button if status is not `pending`.

## 5. Policy Management
- **Inactive Policy:** User views policy list. Older policies are shown as inactive. The UI dropdown for Proof Generation must FILTER OUT inactive policies (they cannot be selected).

## 6. Proof Generation
- **Execution Blocked:** `nargo`/`bb` missing on backend. API returns job with `status="execution_blocked"`. UI stops polling and shows environment error.
- **Failed Proof:** Circuit constraints fail. API returns `failed`. UI shows "Proof generation failed."
- **Polling Timeout:** Frontend polling should have an upper bound (e.g., 10 minutes) to avoid infinite polling if the backend hangs without updating the status.

## 7. Verification
- **Malformed Proof:** Base64 is invalid. API returns 422 Validation Error. UI shows input error.
- **Authoritative Record Mismatch:** User pastes roots that don't match any approved snapshot or active policy in the DB. API returns `authoritative_record_mismatch`. UI explicitly states "The submitted roots do not match active system records."
- **Public Input Mismatch:** The proof is valid math, but was generated for different roots than the ones provided. API returns `public_input_mismatch`. UI explicitly states "Proof does not match the provided roots."
- **Unavailable Verifier:** Backend NoirVerifier class fails to init. API returns `unavailable`. UI shows system error.

## 8. Certificates
- **Invalid/Nonexistent ID:** User navigates to `/certificates/123-invalid`. API returns 404. UI shows "Certificate Not Found."

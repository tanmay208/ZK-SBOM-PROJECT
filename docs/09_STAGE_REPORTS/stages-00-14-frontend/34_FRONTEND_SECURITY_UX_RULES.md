# Frontend Security UX Rules

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## Core Rules

1. **Server Authorization is Authoritative:** The frontend must never make ultimate access decisions. The JWT role is used strictly for rendering navigation and UX hints, never for securing data.
2. **UI Hiding is Not Security:** Hiding a button for an auditor does not secure the endpoint. The backend 403 mechanism is the actual security.
3. **Access Tokens are Memory-Only:** `localStorage`, `sessionStorage`, and `IndexedDB` must never contain the JWT access token.
4. **Sensitive Data is Never Persisted:** No domain data (SBOMs, Proofs, Certificates) may be stored in browser persistent storage.
5. **Private Witness Information is Never Rendered:** The frontend must never try to obtain or display PURLs, component hashes, or raw vulnerability mappings.
6. **Sensitive Prover Errors are Never Rendered:** If a proof fails, display the sanitized `error_message` provided by the API. Never expose stderr or file paths.
7. **Proof Validity is Shown Only After Backend Verification:** A proof artifact existing does not mean it is valid. Only a `verified` result from the `/verify` endpoint authorizes a "Valid" UI state.
8. **Certificate Existence is Shown Only After Successful Verification:** Do not mock or preview a certificate.
9. **Pending/Revoked Vulnerability Snapshots Cannot be Treated as Trusted:** The proof generation dropdown must only list `approved` snapshots.
10. **Inactive Policies Cannot be Treated as Valid:** The proof generation dropdown must only list the currently `active` policy.
11. **Owner Boundaries Must be Reflected in UI:** Vendors only see their own data.
12. **Unauthorized and Forbidden States Must be Distinguishable:** 401 (redirect to login) and 403 (show access denied boundary) are separate UX flows.
13. **No Fake Security Results:** No hardcoded "success" paths for cryptographic operations.
14. **No Client-Side Cryptographic Trust Decisions:** The browser does not run Noir/nargo.
15. **No Client-Side Authorization Bypass:** Do not modify React router logic to bypass role checks.
16. **No Exposure of Secrets or Credentials:** Passwords must be cleared from component state immediately upon API submission.

# Page Design Specification

Date: 2026-10-01
Stage: 4 — Design System, Visual Language & UI Semantics Freeze

## 1. Authentication Pages (`/login`, `/register`)
- **Purpose:** Secure entry to the platform.
- **Layout:** Centered card layout on a subtle background.
- **Primary Content:** Standard `<form>` with username and password inputs.
- **Component Usage:** Input, Button (Primary), Alert (for errors).
- **Security:** Password field must use `type="password"`. 

## 2. Dashboard (`/dashboard`)
- **Purpose:** High-level operational metrics.
- **Layout:** Standard App Shell. 
- **Primary Content:** Grid of Metric Cards (SBOMs, Proofs, Verifications, Certificates).
- **State Presentation:** Skeleton loaders while fetching `/metrics`.

## 3. SBOM Management (`/sboms`)
- **Purpose:** List vendor's uploaded SBOMs.
- **Layout:** App Shell with a primary Data Table.
- **Primary Action:** "Upload SBOM" button (top right).
- **Component Usage:** Data Table, Badge (status), Hash Display (sbom_root).
- **Empty State:** Illustration/Text: "No SBOMs uploaded." -> Action: "Upload SBOM".

## 4. SBOM Upload (`/sboms/upload`)
- **Purpose:** Submit a new SBOM JSON.
- **Layout:** App Shell -> Card containing a form.
- **Primary Content:** Form (Application Name, Vendor Name, File Upload).
- **State Presentation:** Uploading spinner during POST. Disabled inputs during submission.
- **Error State:** Field-level validation errors (422) beneath inputs. File size error banner.

## 5. Proof Jobs Directory (`/proofs`)
- **Purpose:** List vendor's ZKP generation jobs.
- **Layout:** App Shell with a primary Data Table.
- **Primary Action:** "Generate Proof" button (top right).
- **Component Usage:** Data Table, Badge (job status), Hash Display (proof ID, roots).

## 6. Generate Proof (`/proofs/generate`)
- **Purpose:** Request a new proof.
- **Layout:** App Shell -> Card containing a form.
- **Primary Content:** Dropdowns for SBOM, Snapshot (only `approved`), and Policy (only `active`).
- **Primary Action:** "Generate Proof" submit button.
- **Security UX:** Do not list revoked/inactive entities in the dropdowns.

## 7. Proof Job Detail (`/proofs/[id]`)
- **Purpose:** View job status, roots, and download artifact.
- **Layout:** App Shell -> Header with Status Badge -> Grid of metadata -> Proof Artifact Viewer.
- **Component Usage:** Hash Display (for all 3 roots), Badge (status), Proof Artifact Viewer (`<pre>` block with copy button).
- **State Presentation:** 
  - If `pending`/`assembling_witness`: Show loading spinner in the artifact area.
  - If `failed`: Show Error Alert with sanitized message. Hide artifact area.

## 8. Verification Interface (`/verify`)
- **Purpose:** Submit proof for cryptographic verification.
- **Layout:** App Shell -> Split layout (Input Form | Result Panel).
- **Primary Content:** Inputs for SBOM Root, Vuln Root, Policy Hash, and a Textarea for the Proof Artifact.
- **Component Usage:** Form, Textarea, Button (Primary).
- **State Presentation:** 
  - **VERIFIED:** Show Success Panel covering the right side with a link to the issued Certificate.
  - **INVALID / MISMATCH:** Show Danger Panel covering the right side explaining the precise failure enum.

## 9. Certificate Directory (`/certificates`)
- **Purpose:** List issued certificates.
- **Layout:** App Shell -> Data Table.
- **Primary Content:** Table of certificate UUIDs and issuance timestamps.

## 10. Public Certificate View (`/certificates/[id]`)
- **Purpose:** Public display of an immutable certificate.
- **Layout:** Minimal Shell (no authenticated side nav, just a header).
- **Primary Content:** Centered Certificate Summary Card.
- **Component Usage:** Hash Display (for the 3 roots), Timestamp, Copy buttons.
- **Security UX:** Must not display vendor names or private data. Only UUIDs and hashes.

## 11. Admin: Policies (`/admin/policies`)
- **Purpose:** Manage global security policies.
- **Layout:** App Shell -> Split (List Table | Create Form for admins).
- **Component Usage:** Data Table, Badge (Active/Inactive), Form.
- **Security UX:** If user is `auditor` or `vendor`, hide the Create Form entirely.

## 12. Admin: Vulnerability Intelligence (`/admin/vulnerabilities`)
- **Purpose:** Ingest and manage snapshots.
- **Layout:** App Shell -> Split (Snapshot Table | Ingest Form for admins).
- **Primary Actions (Admin):** Ingest JSON, Approve button (on pending rows), Revoke button (on any row).
- **Component Usage:** Data Table, Badge (Status), Modal (for Approve/Revoke confirmation).
- **Security UX:** Read-only for `vendor` and `auditor`.

## 13. System Pages (403 / 404)
- **Layout:** App Shell (if authenticated) -> Centered Error Card.
- **Primary Content:** "Access Denied" (403) or "Page Not Found" (404).
- **Action:** "Return to Dashboard" button.

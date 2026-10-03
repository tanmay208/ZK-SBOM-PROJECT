# Frontend Data Visibility Contract

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Scope
Categorizes every piece of domain data into visibility tiers to ensure the frontend never leaks or requests inappropriate data.

## 2. Visibility Tiers

### PRIVATE / NEVER DISPLAYED
This data exists on the backend but is strictly prohibited from entering the frontend environment in any form.
- Raw SBOM CycloneDX content
- Component names, versions, PURLs, component hashes
- Vulnerability CVSS scores for specific PURLs (mappings)
- User password hashes
- Cryptographic private witness data (Prover.toml contents)
- ZKP circuit `.json` and verification keys

### OWNER-ONLY
This data is visible only to the authenticated user who created it.
- **SBOM Metadata:** `application_name`, `vendor_name`, `filename`, `sbom_root`, `component_count`, `status`
- **Proof Job Data:** `sbom_upload_id`, `snapshot_id`, `policy_id`, `status`, `proof_artifact`, `error_message`
- **Dashboard Metrics:** `sbom_count`, `proof_count` (these are scoped to the user)

### ROLE-RESTRICTED (Admin Modification, Public View)
This data is viewable by any authenticated user, but only modifiable by admins.
- **Security Policies:** `name`, `description`, `max_allowed_cvss`, `policy_hash`, `active`
- **Vulnerability Snapshots:** `snapshot_label`, `record_count`, `status` (`provisional_smt_root` is EXCLUDED per Stage 1.5)

### AUTHENTICATED SHARED
This data is viewable by any authenticated user.
- **Verification Request Results:** The `result` enum.
- **Certificate List:** The paginated list of all system certificates.

### PUBLIC
This data is viewable by anyone, even unauthenticated visitors (by direct UUID).
- **Certificate Detail:** `sbom_root`, `vulnerability_db_root`, `policy_hash`, `issued_at`, `certificate_data`

## 3. Frontend Enforcement Rules

1. **API Schema Strictness:** The frontend must use strict typing (e.g., TypeScript interfaces) that perfectly matches the `BaseModel` response schemas from Stage 1.5. It must not type a field (like `raw_content`) that the API does not return.
2. **No Data Derivation:** The frontend must not attempt to derive or calculate private data (e.g., trying to guess a CVSS score from a policy hash).
3. **Error Data:** The frontend must treat all `error_message` strings as safe-to-display, because the backend explicitly sanitizes them (e.g., Proof jobs return "Proof generation failed").
4. **Auth Data:** The `/api/v1/auth/me` response contains only `id`, `username`, and `role`. The frontend relies on this for navigation rendering but NOT for data visibility, which is enforced by the server.

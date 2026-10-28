# Auditor Workflow Specification

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Scope
Defines the specialized workflows available to the `auditor` role. This role represents the software buyer or compliance officer.

## 2. Auditor Capabilities

### 2.1 View Global Configurations
- **What they can view:** The list of global security policies (`/admin/policies`) and vulnerability snapshots (`/admin/vulnerabilities`).
- **What they cannot do:** They cannot create policies, ingest vulnerabilities, or approve/revoke snapshots. The UI must hide or disable these mutation controls.

### 2.2 Verify Compliance Claims
- **What they can verify:** They can use the `/verify` page to input public roots and a proof artifact provided to them (out-of-band) by a vendor.
- **Result inspection:** They can view the exact cryptographic verification result.

### 2.3 Inspect Certificates
- **What they can inspect:** They can browse the public directory of issued verification certificates (`/certificates`) and view individual certificate metadata (`/certificates/[id]`).
- **What they cannot modify:** Certificates are immutable.

## 3. Strict Prohibitions

### 3.1 No Vendor Data Access
- **SBOM Access:** Auditors CANNOT access `/sboms` or call `GET /api/v1/sbom`. If they try, the UI must block them and the API will return 403.
- **Proof Job Access:** Auditors CANNOT access `/proofs` or call `GET /api/v1/zkp`. If they try, the API will return 403.
- **Data restriction:** Auditors never see raw SBOM content, component names, versions, PURLs, or vendor application structures.

### 3.2 No Cross-Tenant Visibility
- **Metrics:** On `/dashboard`, an auditor's metrics will reflect only verifications and certificates they have interacted with. They do not see global proof generation counts.

## 4. UI Implementation Rules
1. The main navigation for an auditor must omit the "SBOMs" and "Proofs" links.
2. The Policy and Vulnerability pages must render in read-only mode (no "Create", "Ingest", "Approve", or "Revoke" buttons).
3. Attempting to force-navigate to `/sboms` must trigger a 403 Forbidden UI state.

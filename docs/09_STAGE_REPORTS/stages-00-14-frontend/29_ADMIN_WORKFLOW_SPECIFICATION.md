# Admin Workflow Specification

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Scope
Defines the specialized workflows available exclusively to the `admin` role.

## 2. Admin Operations

### 2.1 Vulnerability Ingestion
- **Authorization:** `admin` role required.
- **Page:** `/admin/vulnerabilities`
- **Action:** Paste JSON payload of CVE mappings. Click "Ingest".
- **API Interaction:** `POST /api/v1/vulnerability/ingest`
- **Confirmation Requirement:** None (immediate POST).
- **Success Behavior:** Table refreshes, new snapshot appears as `pending`.
- **Failure Behavior:** Validation errors from API displayed if JSON is malformed.
- **Forbidden Behavior:** Endpoint returns 403 if user is not an admin.
- **Auditability:** UNSUPPORTED (No backend audit log).

### 2.2 Vulnerability Snapshot Approval
- **Authorization:** `admin` role required.
- **Page:** `/admin/vulnerabilities`
- **Action:** Click "Approve" button on a `pending` snapshot row.
- **API Interaction:** `POST /api/v1/vulnerability/snapshots/{id}/approve`
- **Confirmation Requirement:** Modal prompt: "Are you sure? This authorizes proofs to be generated against this snapshot."
- **Success Behavior:** Snapshot status badge changes to green "Approved".
- **Failure Behavior:** Error toast if API fails.

### 2.3 Vulnerability Snapshot Revocation
- **Authorization:** `admin` role required.
- **Page:** `/admin/vulnerabilities`
- **Action:** Click "Revoke" button on any snapshot row.
- **API Interaction:** `POST /api/v1/vulnerability/snapshots/{id}/revoke`
- **Confirmation Requirement:** Modal prompt: "Are you sure? This prevents new proofs from using this snapshot. Existing proofs are not affected."
- **Success Behavior:** Snapshot status badge changes to red "Revoked".

### 2.4 Security Policy Management
- **Authorization:** `admin` role required.
- **Page:** `/admin/policies`
- **Action:** Fill form (Name, Description, Max CVSS). Click "Create Policy".
- **API Interaction:** `POST /api/v1/policy`
- **Confirmation Requirement:** Modal prompt: "Creating a new policy will deactivate the current active policy. Proceed?"
- **Success Behavior:** Table refreshes. Old policy goes "Inactive", new one is "Active".

### 2.5 Administrative Visibility
- **Operational Metrics:** Admins see their own scoped metrics on `/dashboard`, same as vendors. There is NO global metrics API for admins.
- **SBOM/Proof Visibility:** Admins only see their OWN SBOMs and Proofs on `/sboms` and `/proofs`. They cannot browse other vendors' data.

## 3. Unsupported Workflows
- **Audit Logs:** There is no backend `/audit` endpoint or DB table. The frontend MUST NOT implement an audit log page.
- **User Management:** There is no endpoint to list, delete, or change roles of users. The frontend MUST NOT implement a user management page.
- **Tenant Configuration:** There are no tenants.

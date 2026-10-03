# Stage 12 Acceptance Criteria

Date: 2026-10-01
Stage: 12 — ADMIN & SECURITY INTELLIGENCE

## Criteria

1. **Policy List**: `/admin/policies` accurately queries and lists Active/Inactive state of backend policies.
2. **Policy Creation**: The frontend creates policies without attempting client-side policy hashing.
3. **Vulnerability List**: `/admin/vulnerabilities` queries snapshot records securely without exposing vulnerability DB internals.
4. **Vulnerability Ingestion**: Admin can submit valid JSON arrays to map to `VulnerabilityIngestionItem`.
5. **Snapshot Lifecyle**: Approvals and revocations hit endpoints with strict visual reflection of state (`pending`, `approved`, `revoked`).
6. **Revocation Security**: Explicit confirmation guards revocation actions.
7. **RBAC Guarding**: Non-admins can view the lists, but all input actions are gracefully disabled with an explicit "Read Only" alert.
8. **Client Security**: No CVSS calculation or hashing computation exists in the browser.

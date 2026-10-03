# RBAC and Ownership Contract

Date: 2026-09-25
Stage: 1.5

## Scope

Freeze server-side role and resource rules for the frontend contract. The frontend is never the security boundary.

## Roles

Only the existing role vocabulary is retained: `admin`, `auditor`, and `vendor`. Registration creates `auditor`. No role-assignment endpoint exists; administrative role provisioning is UNKNOWN and not implemented here.

## Route Matrix

| Method/path | Auth | Role | Ownership/tenant | 401 | 403 |
|---|---|---|---|---|---|
| POST `/api/v1/auth/login` | No | Public | None | N/A | N/A |
| POST `/api/v1/auth/register` | No | Public; creates auditor | None | N/A | N/A |
| GET `/api/v1/auth/me` | Yes | Any existing role | Current identity | Missing/invalid bearer | Not applicable |
| GET `/api/v1/metrics` | Yes | Any role | Counts filtered to current user | Yes | No role denial |
| GET `/api/v1/sbom` | Yes | vendor/admin operational access | Current-user uploads | Yes | Role denial for auditor |
| POST `/api/v1/sbom/upload` | Yes | vendor/admin | New upload bound to current user | Yes | Auditor denied |
| GET `/api/v1/vulnerability/snapshots` | Yes | Any role | Shared snapshot metadata | Yes | No role denial |
| POST `/api/v1/vulnerability/ingest` | Yes | admin | Admin-controlled shared resource | Yes | Non-admin denied |
| POST snapshot approve/revoke | Yes | admin | Admin-controlled shared resource | Yes | Non-admin denied |
| GET `/api/v1/policy` | Yes | Any role | Shared policy metadata | Yes | No role denial |
| POST `/api/v1/policy` | Yes | admin | Admin-controlled shared resource | Yes | Non-admin denied |
| GET `/api/v1/zkp` | Yes | vendor/admin | Current-user jobs | Yes | Auditor denied |
| POST `/api/v1/zkp/generate` | Yes | vendor/admin | SBOM must belong to current user; snapshot approved | Yes | Auditor or non-owner denied |
| GET `/api/v1/zkp/jobs/{job_id}` | Yes | vendor/admin | Current-user job; direct owner check | Yes | Non-owner denied |
| POST `/api/v1/verification/verify` | Yes | Any role | Request recorded under current user; public inputs only | Yes | No role denial |
| GET `/api/v1/verification/certificates` | Yes | Any role | Authenticated list of public metadata | Yes | No role denial |
| GET certificate by ID | No | Public metadata | UUID lookup; no private fields | N/A | N/A |
| GET `/api/v1/health` | No | Public | Service status only | N/A | N/A |

## Resource Classification

- Application/SBOMUpload: vendor-private, owner-bound through `user_id`; admin may operate as an administrative role, but no cross-user detail endpoint exists.
- ProofJob: owner-bound through `user_id`; list and detail are current-user scoped, and generation verifies SBOM ownership.
- Policy: globally shared and admin-controlled; no user ownership field is added.
- VulnerabilitySnapshot: globally shared intelligence and admin-controlled lifecycle; no user ownership field is added.
- VerificationRequest: recorded with current `user_id`, but verification input is public and no detail/history endpoint is currently implemented.
- Certificate: public metadata by UUID; list requires authentication, detail is public and contains only public fields.
- Tenant model: no separate tenant entity or tenant boundary is present; tenant isolation is therefore UNKNOWN/NOT IMPLEMENTED beyond user ownership.

## Changes

Added reusable `require_roles` dependencies, applied them to SBOM upload, policy creation, and proof generation, and scoped metrics to the authenticated principal. Existing snapshot admin checks and ZKP repository ownership checks were retained.

## Tests

Focused suites cover role denial, owner access/isolation, admin snapshot controls, missing/invalid auth, public certificate direct access, and metrics privacy. New Stage 1.5 tests directly assert auditor denial for SBOM upload, policy creation, and proof generation.

## Unresolved Items

User administration, role assignment, disabled/deleted users, tenant isolation, policy audit ownership, verification history access, and admin cross-user operational views have no executable endpoints. No frontend may infer these capabilities.

## Residual Risks

Admin access to private resources is not represented by a universal cross-user detail API. Service-to-service authorization and database-level row security are not implemented. Direct service exposure outside the unified app/gateway remains a deployment concern.

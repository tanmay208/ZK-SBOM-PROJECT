# Frontend Route Architecture

Date: 2026-09-25
Scope: proposed route inventory only. No routes are implemented by this document.

## Route Rules

- Current implemented route: `/` only.
- A sidebar label is not evidence of a route or permission.
- Backend endpoint, request, response, ownership, and permission cells below use `UNKNOWN` when executable evidence is absent.
- Every protected route needs initial/loading/success/empty/error/unauthorized/forbidden/not-found states. Domain-specific states are in [05_FRONTEND_STATE_MATRIX.md](./05_FRONTEND_STATE_MATRIX.md).
- Public verification must never require raw SBOM data.

## Proposed Inventory

| Route | Purpose | Role/permission | Backend endpoint | Request/response | Sensitive fields | Relationship |
|---|---|---|---|---|---|---|
| `/login` | Acquire session | Public | `POST /api/v1/auth/login` | OAuth2 form `username`, `password`; response `access_token`, `token_type` | password/token | Entry to protected shell; session contract UNKNOWN. |
| `/register` | Create account if retained | Public | `POST /api/v1/auth/register` | OAuth2 form; response `message`, `username`, `role` | password | Registration policy and production availability UNKNOWN; backend assigns `auditor`. |
| `/unauthorized` | Explain absent authentication/permission | Public | None | None | None | Destination for 401/403 presentation. |
| `/` | Security overview, metrics, activity, health | Authenticated | `GET /api/v1/metrics`, plus other endpoints UNKNOWN | response has four scalar counts: `total_sboms`, `total_jobs`, `total_certificates`, `total_verifications` | aggregate data | Current implemented static dashboard; data ownership is currently global in backend. |
| `/sboms` | Upload/history/component summary | Authenticated; ownership rules backend-defined | `GET /api/v1/sbom?skip=&limit=`, `POST /api/v1/sbom/upload` | request fields and response in API map | upload `content` is private and must never render after submission | Links to `/sboms/[upload_id]`; processing endpoint UNKNOWN. |
| `/sboms/[upload_id]` | SBOM metadata/status/commitment | Authenticated owner | No detail endpoint confirmed | UNKNOWN | raw content/components private | From SBOM list/upload; detail contract UNKNOWN. |
| `/vulnerabilities` | Snapshot list/status | Authenticated; admin actions only where confirmed | `GET /api/v1/vulnerability/snapshots?skip=&limit=` | snapshot response | `provisional_smt_root` exposure is a documented discrepancy | Links to detail/admin actions. |
| `/vulnerabilities/[snapshot_id]` | Snapshot detail/status | Authenticated; ownership/public visibility UNKNOWN | approve/revoke actions confirmed; detail GET UNKNOWN | path UUID; response snapshot | root/status public classification requires contract review | Links to policies/proof. |
| `/policies` | Policy list and active status | Authenticated; role restriction UNKNOWN | `GET /api/v1/policy?skip=&limit=` | response policy fields | policy values/hash public by docs | Links to create/detail. |
| `/policies/new` | Create policy | Authenticated; permission UNKNOWN | `POST /api/v1/policy` | `name`, `description`, `max_cvss_score`; response policy | none beyond policy metadata | Returns to list/detail. |
| `/policies/[policy_id]` | Policy detail/state | Authenticated; ownership UNKNOWN | GET detail UNKNOWN | UNKNOWN | policy public | Used by proof setup. |
| `/zkp` | Proof job history | Authenticated owner | `GET /api/v1/zkp?skip=&limit=` | response proof job | proof artifact/error may be sensitive; error must be redacted | Links to create/job detail. |
| `/zkp/new` | Request proof generation | Authenticated vendor/owner permission UNKNOWN | `POST /api/v1/zkp/generate` | `sbom_upload_id`, `snapshot_id`, `policy_id`; proof job response | private witness is backend-side; IDs/public roots visible | Requires existing SBOM/snapshot/policy. |
| `/zkp/jobs/[job_id]` | Poll/view proof job | Authenticated owner | `GET /api/v1/zkp/jobs/{job_id}` | UUID; proof job response | `error_message` must not be shown raw | Processing/completed/failed lifecycle. |
| `/verification` | Submit verification/history | Buyer/auditor capability UNKNOWN; auth currently required in source | `POST /api/v1/verification/verify` | public roots/hashes, optional proof artifact; verification response | no raw SBOM; proof artifact public but validate size/content | Links to result/certificate. |
| `/verification/[verification_id]` | Verification result | Ownership/visibility UNKNOWN | detail endpoint UNKNOWN | response fields known from POST | public roots/result/certificate | Links to certificate. |
| `/certificates` | Certificate list | Authenticated; ownership missing in source | `GET /api/v1/verification/certificates?skip=&limit=` | certificate response | public metadata | Links to detail. |
| `/certificates/[certificate_id]` | Public certificate validation | Source route has no auth dependency; security decision UNKNOWN | `GET /api/v1/verification/certificates/{certificate_id}` | UUID; certificate response | public fields only | Share/verification entry point subject to policy. |
| `/audit` | Audit/security history | Endpoint UNKNOWN | UNKNOWN | UNKNOWN | likely security-sensitive | Do not implement until contract exists. |
| `/admin/users` | User/role administration | Admin only if feature is approved | Endpoint UNKNOWN | UNKNOWN | identities/roles sensitive | No current route or endpoint evidence. |
| `/admin/vulnerabilities` | Ingest/approve/revoke snapshots | `admin` confirmed for actions | ingest, approve, revoke endpoints | request/response in API map | source records/PURLs private/public boundary requires review | Links from vulnerability area. |
| `/health` | Service health | Visibility and auth UNKNOWN | `/api/v1/health` exists per service app | response `service`, `status`, `version` | deployment information | Dashboard/system area. |
| `/settings/profile` | Profile/session settings | Authenticated | `/api/v1/auth/me` read; writes UNKNOWN | identity response | token/session data must not render | Header user menu. |
| `/settings/system` | Configuration/status | Admin/system permission UNKNOWN | endpoint UNKNOWN | UNKNOWN | configuration is sensitive | Do not infer from frontend label. |

## Shared Route State Contract

Every route must define loading, empty, validation, unauthorized, forbidden, not-found, conflict, rate-limited, server-error, network-failure, timeout, retry, stale, and partial-failure behavior as applicable. Upload/proof/verification routes additionally require processing, completed, failed, and revoked/unavailable states.

## Navigation Relationships

The shell should eventually separate overview, vendor-private workflows, public verification, administration, and system settings. Actual visibility must derive from verified `/me` and server responses; role labels alone are not sufficient. Dead sidebar links remain an explicit current gap.

## Open Decisions

Gateway vs direct service base URL, route groups, registration availability, audit/settings API, and live deployment routing remain UNKNOWN. Stage 1.5 closes the current development contract as follows:

- Current frontend-facing development boundary: the unified `verification_service` application, with routes under `/api/v1`.
- Compose declares an Nginx gateway, but its referenced `docker/nginx.conf` is absent. `GATEWAY STATUS: NOT IMPLEMENTED` for executable use; no gateway endpoint is invented.
- Certificate detail is public metadata lookup by UUID; certificate list remains authenticated.
- `/audit` and `/settings` remain future frontend areas because no backend endpoints exist.
- Role and ownership behavior is frozen in [10_RBAC_AND_OWNERSHIP_CONTRACT.md](./10_RBAC_AND_OWNERSHIP_CONTRACT.md).

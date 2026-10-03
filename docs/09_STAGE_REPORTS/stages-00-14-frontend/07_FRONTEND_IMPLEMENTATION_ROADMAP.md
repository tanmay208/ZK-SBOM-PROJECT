# Frontend Implementation Roadmap

Date: 2026-09-25
This sequence is evidence-based and does not authorize implementation. Stage 2 must be separately authorized.

## Gates Before Stage 2

1. Resolve live Docker/database configuration and obtain safe local runtime access.
2. Publish/verify gateway composition and live OpenAPI for all confirmed routes.
3. Close or explicitly accept backend RBAC-001/API-001/VI-001/ZK-002/API-002 findings before exposing workflows.
4. Freeze session transport, token/cookie/CSRF, refresh/logout, role assignment, ownership, tenant, and 401/403 contracts.
5. Confirm development versus production cryptographic profile and VK/proof readiness independently of UI work.

## Staged Sequence

| Stage | Scope | Exit evidence |
|---|---|---|
| A | API/client foundation: base URL, typed confirmed contracts, safe error normalization, pagination, timeout/retry policy | Contract tests against approved OpenAPI; no invented endpoints/fields. |
| B | Authentication/session: login, optional registration, `/me`, expiry/logout, protected boundaries | Auth/session tests and approved browser storage/CSRF decision. |
| C | Application shell: responsive nav, header, breadcrumbs, user menu, route states | Keyboard/mobile/accessibility checks; no dead links presented as working. |
| D | Dashboard: verified metrics, recent activity/health only where contracts exist | Tenant-safe aggregates and partial-failure handling. |
| E | SBOM management: upload/history/detail/status | Private-content handling, ownership tests, upload size/error states. |
| F | Vulnerability snapshots: list/detail/ingest/governance | Admin authorization, public root exposure decision, lifecycle states. |
| G | Policies: list/create/detail/state | Policy ownership/role contract and validation tests. |
| H | ZKP lifecycle: request/jobs/polling/detail | Tool readiness, generic failure handling, owner isolation, rate limits. |
| I | Verification: public-input submission/history/result | Exact public-input and proof contract; no raw SBOM requirement. |
| J | Certificates: list/detail/validation | Public versus owner access decision; revoked/unavailable behavior. |
| K | Audit: history/security events | Endpoint, retention, filtering, and role visibility contract. |
| L | Administration: users/roles/admin actions | Explicit admin-only endpoints and audit confirmation. |
| M | Health/settings: service health/profile/config status | Health semantics reflect DB/tool readiness; sensitive config excluded. |
| N | Security hardening: privacy review, redaction, CSP/headers/deployment review, threat-model checks | Security review and negative tests. |
| O | Unit/component/API/auth/RBAC/accessibility/responsive tests | Required state and permission coverage; no reliance on visual hiding. |
| P | E2E validation: configured Docker/API/browser workflows | Full safe environment validation, documented blockers, production-profile separation. |

## Required Test Layers

- Unit: contract parsing, error normalization, permission presentation, field validation.
- Component: forms, tables, status/lifecycle states, dialogs, keyboard/focus behavior.
- API/client: request encoding, auth failure, pagination, malformed/private response rejection.
- RBAC: role matrix, owner isolation, direct forbidden actions, session expiry.
- Integration/E2E: upload-to-status, proof polling, verification-to-certificate, admin snapshot lifecycle, health degradation.
- Accessibility/responsive: labels, announcements, focus, contrast, reduced motion, keyboard/mobile layouts.

## Explicit Non-Goals Until Contracts Exist

Do not add audit/settings consumers, infer buyer permissions, persist credentials/private witness data, display raw proof errors, treat static metrics as tenant-safe, or expose production cryptographic readiness from development fixtures.

# Frontend Permission Matrix

Date: 2026-09-25
Authority: executable backend role fields and route checks. UI labels are not used as permission evidence.

## Roles Verified in Source

`User.role` is a string with documented examples `admin`, `auditor`, and `vendor`. Registration hardcodes new accounts to `auditor`. Role assignment beyond registration is UNKNOWN. JWT includes a role claim, but `get_current_user` reloads the user and route enforcement remains incomplete.

## Matrix

Legend: `Y` confirmed by source; `N` confirmed denied/absent only where explicit; `U` unknown or not safely enforceable; `P` presentation-only until backend enforcement exists.

| Feature/action | Auditor | Vendor | Admin | Ownership/authorization evidence |
|---|---:|---:|---:|---|
| Login/register | Y | Y | Y | Public endpoints; production registration policy UNKNOWN. |
| Read `/me` | Y | Y | Y | Bearer required. |
| Dashboard metrics | P | P | P | Bearer required, but counts are global and not role-scoped. |
| List own SBOMs | Y | Y | Y | Query filters by current user ID. Exact role policy UNKNOWN. |
| Upload SBOM | U | U | U | Bearer dependency exists; role restriction absent. Backend audit flags route authorization gap. |
| Read SBOM detail/components | U | U | U | No detail endpoint confirmed; private components must remain owner/private. |
| List snapshots | U | U | U | Bearer dependency exists; no user filter. Visibility policy UNKNOWN. |
| Ingest vulnerability data | N | N | Y | Explicit `admin` check, plus bearer. |
| Approve snapshot | N | N | Y | Explicit `admin` check. |
| Revoke snapshot | N | N | Y | Explicit `admin` check. |
| List/create policies | U | U | U | Bearer dependency exists; no role/owner check visible. |
| Generate proof | U | U | U | Bearer dependency and SBOM ownership check in repository; role policy UNKNOWN. |
| List proof jobs | P | P | P | Current-user filter. Role policy UNKNOWN. |
| Read proof job | P | P | P | Current-user ownership check; 403 explicit. |
| Submit verification | U | U | U | Bearer dependency; public buyer workflow conflicts with docs and role policy is UNKNOWN. |
| List certificates | P | P | P | Bearer dependency; no user filter visible. |
| Read certificate by ID | U | U | U | Route lacks visible auth dependency; public/owner policy UNKNOWN and requires backend review. |
| Audit logs | U | U | U | No endpoint/source contract confirmed. |
| User/role administration | U | U | U | No endpoint/source contract confirmed. |
| Health | U | U | U | Health route exists per service app; access/meaning are UNKNOWN. |
| Settings/profile | U | U | U | `/me` read exists; writes/settings endpoints UNKNOWN. |

## UI Enforcement Rules

- Unauthenticated users should not receive protected content; exact redirect/cookie strategy is UNKNOWN.
- Forbidden controls may be hidden only as a usability optimization after server permission is known. The backend must still reject the action.
- Actions with confirmed admin enforcement may be hidden or disabled for non-admins, but a direct request must still receive 403.
- Owner-only routes must use server-derived ownership, never IDs or role labels supplied by the browser.
- Do not expose private fields to buyers, auditors, or any role based solely on a frontend gate.
- Treat `UNKNOWN` as unavailable for implementation, not as allowed.

## Required Backend Decisions Before Stage 2

## Stage 1.5 Frozen Matrix

| Feature/action | Auditor | Vendor | Admin | Ownership/scope |
|---|---:|---:|---:|---|
| `/me`, authenticated shared reads | Y | Y | Y | Current authenticated principal. |
| SBOM upload | N | Y | Y | Upload is vendor-private; server binds current user. |
| SBOM list | N | Y | Y | Current-user owned uploads only. |
| Vulnerability snapshot list | Y | Y | Y | Shared authenticated metadata; no private component records. |
| Vulnerability ingest/approve/revoke | N | N | Y | Admin-controlled shared intelligence. |
| Policy list | Y | Y | Y | Shared public policy metadata. |
| Policy creation | N | N | Y | Admin-controlled shared resource. |
| Proof generation | N | Y | Y | Current user must own the SBOM; snapshot must be approved. |
| Proof list/detail | N | Y | Y | Current-user owned jobs only. |
| Verification submission | Y | Y | Y | Authenticated submission of public inputs; cryptographic binding remains server-side. |
| Certificate list | Y | Y | Y | Authenticated list of public certificate metadata. |
| Certificate detail | Public | Public | Public | UUID lookup returns public fields only. |
| Metrics | Y | Y | Y | Counts are scoped to current-user resources. |
| Health | Public | Public | Public | Service health only; no credentials/configuration. |

Role checks are server-side dependencies. Frontend gates remain presentation only. Audit/settings/user administration endpoints are NOT IMPLEMENTED and have no permission contract.

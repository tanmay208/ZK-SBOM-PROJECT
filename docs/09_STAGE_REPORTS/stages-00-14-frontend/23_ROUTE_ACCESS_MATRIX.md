# Route Access Matrix

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Role-Based Route Access

| Frontend Route | Unauthenticated | Vendor | Admin | Auditor | Enforcement |
|---|---|---|---|---|---|
| `/login` | ALLOW | REDIRECT (to `/dashboard`) | REDIRECT | REDIRECT | Client logic |
| `/register` | ALLOW | REDIRECT (to `/dashboard`) | REDIRECT | REDIRECT | Client logic |
| `/certificates/[id]` | ALLOW | ALLOW | ALLOW | ALLOW | Server `GET /certificates/{id}` has no auth |
| `/dashboard` | REDIRECT (to `/login`) | ALLOW | ALLOW | ALLOW | Server `GET /auth/me` requires token |
| `/verify` | REDIRECT | ALLOW | ALLOW | ALLOW | Server `POST /verify` requires token |
| `/certificates` | REDIRECT | ALLOW | ALLOW | ALLOW | Server `GET /certificates` requires token |
| `/sboms` | REDIRECT | OWNER-SCOPED | OWNER-SCOPED | DENY | Server role check + User scope |
| `/sboms/upload` | REDIRECT | ALLOW | ALLOW | DENY | Server role check |
| `/proofs` | REDIRECT | OWNER-SCOPED | OWNER-SCOPED | DENY | Server role check + User scope |
| `/proofs/generate` | REDIRECT | ALLOW | ALLOW | DENY | Server role check + SBOM ownership |
| `/proofs/[id]` | REDIRECT | OWNER-SCOPED | OWNER-SCOPED | DENY | Server role check + User scope |
| `/admin/policies` | REDIRECT | VIEW ONLY | FULL ACCESS | VIEW ONLY | Server `POST` requires admin |
| `/admin/vulnerabilities`| REDIRECT | VIEW ONLY | FULL ACCESS | VIEW ONLY | Server `POST` endpoints require admin |

## 2. Unauthenticated Access Behavior
If an unauthenticated user attempts to visit an authenticated route (e.g., `/dashboard`), the frontend must clear any stale token state and redirect the user to `/login`.
The requested URL may be stored to redirect back after successful login, but this is an optional UX enhancement.

## 3. Invalid/Expired Token Behavior
When an API request returns `401 Unauthorized`:
1. The frontend must immediately discard the token from memory.
2. The user profile state must be cleared.
3. The application must redirect to `/login`.
*Note: The backend has no refresh token mechanism, so silent token refresh is impossible.*

## 4. Forbidden Role Behavior
If an authenticated user attempts to visit a page they lack privileges for (e.g., an auditor visiting `/sboms/upload`), or if an API call returns `403 Forbidden`:
1. The frontend should render a generic "403 Forbidden" or "Access Denied" view.
2. The user's session remains active.
3. They are provided a link back to `/dashboard`.

## 5. Direct URL Navigation
Users can bookmark and navigate directly to any URL. The frontend application mounts, checks for the presence of the in-memory token (which will be absent on a hard refresh), and either allows access or redirects to `/login`. Because tokens are memory-only, a hard browser refresh WILL log the user out. This is the intended strict session behavior.

## 6. Post-Login / Post-Logout Redirects
- **Post-Login:** Redirect to `/dashboard`.
- **Post-Logout:** Clear token, redirect to `/login`.

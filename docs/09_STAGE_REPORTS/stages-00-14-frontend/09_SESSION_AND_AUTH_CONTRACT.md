# Session and Authentication Contract

Date: 2026-09-25
Stage: 1.5

## Scope

Freeze the existing OAuth2 password-form and JWT authentication boundary for later frontend work. No frontend session implementation was added.

## Verified Behavior

- `POST /api/v1/auth/login` accepts OAuth2 form `username` and `password` and returns `access_token` and `token_type=bearer`.
- `GET /api/v1/auth/me` requires a bearer token and returns only `id`, `username`, and `role`.
- JWT algorithm is HS256; decode requires `exp` and `sub`; the user is reloaded by username, so a caller-supplied role claim does not grant role authority.
- Access-token lifetime is one day (`ACCESS_TOKEN_EXPIRE_MINUTES = 1440`).
- Missing, malformed, expired, invalid-signature, and unknown-user tokens return 401.
- Registration remains public and assigns `auditor`; role fields in submitted form data are ignored.
- Missing `JWT_SECRET_KEY` now raises configuration failure. Production startup validation already fails closed; no ephemeral signing secret remains.

## Frozen Browser Contract

- Transport: `Authorization: Bearer <access_token>` request header.
- Browser storage: no localStorage, sessionStorage, IndexedDB, or client cookie storage. A future frontend may retain the token only in process/in-memory session state until the tab/process ends.
- Refresh: no refresh-token endpoint exists; do not invent one.
- Logout: client-side discard only; no server revocation endpoint exists.
- Expiry: API returns 401; frontend clears in-memory session and returns to authentication UI.
- 401: structured `{ "error": string, "code": "UNAUTHORIZED" }`, with `WWW-Authenticate: Bearer` where applicable.
- 403: structured `{ "error": string, "code": "FORBIDDEN" }`; do not retry as authentication.
- CSRF: not applicable to the bearer-header transport because credentials are not sent automatically by the browser as cookies. Reassess if transport changes.
- CORS: explicit configured origins only, methods limited to API methods, credentials disabled. Deployment origin values remain environment-controlled.

## Changes

`shared/auth.py` removed the ephemeral fallback and import-time secret snapshot. `shared/app_factory.py` disabled unnecessary credentialed CORS. The error handler now gives HTTP exceptions stable codes.

## Tests

Authentication tests cover missing, malformed, expired, valid, invalid-signature, unknown-user, `/me`, login enumeration consistency, role-claim non-escalation, and missing-secret fail-closed behavior. CORS tests verify the configured origin and absence of credentialed CORS. Stage 1.5 closure tests verify stable 401 output.

## Unresolved Items

There is no refresh, revocation, disabled-user, password-reset, or server-side logout contract. TLS termination, browser deployment policy, secret rotation, issuer/audience claims, and production identity provisioning remain UNKNOWN.

## Residual Risks

Bearer tokens held in memory remain usable until expiry if copied from a running browser context. A one-day lifetime is existing behavior, not a claim of production readiness. A future cookie-based session would require a new explicit CSRF/CORS review and must not be introduced implicitly.

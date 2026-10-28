# Frontend Storage Policy

Date: 2026-10-01
Stage: 2 — Frontend Data Storage & Persistence Architecture

## Scope

Define exactly what the browser is permitted to store, based on the Stage 1.5 frozen session/auth contract and the platform's security boundary. This is a policy document, not an implementation.

## Authoritative Session Contract (Stage 1.5)

- **Transport:** `Authorization: Bearer <access_token>` request header.
- **Browser storage:** No localStorage, sessionStorage, IndexedDB, or client cookie for the access token.
- **Token lifetime:** In-memory only, discarded when the tab/process ends.
- **Refresh:** No refresh-token endpoint exists; do not invent one.
- **Logout:** Client-side discard only; no server revocation.
- **CSRF:** Not applicable (bearer header, not cookies).
- **CORS:** Explicit origins only, credentials disabled.

## Storage Medium Classification

| Medium | Permitted Content | Forbidden Content |
|---|---|---|
| **JavaScript memory (in-process)** | Access token, user profile, API response caches, UI state, form drafts | Password plaintext (must not be retained after login call) |
| **React/query cache (in-memory)** | Server state responses (SBOM list, policies, snapshots, metrics, certificates), pagination state, loading/error state | Raw SBOM content (never received), private components, private witness data |
| **URL query parameters** | Pagination (`skip`, `limit`), filter state, sort state, resource IDs for navigation | Tokens, passwords, sensitive data of any kind |
| **sessionStorage** | CONDITIONALLY SAFE — UI preferences (theme, sidebar collapse) only | Access tokens, passwords, SBOM data, proof data, any sensitive data |
| **localStorage** | CONDITIONALLY SAFE — Non-sensitive UI preferences only (theme selection) | Access tokens, refresh tokens, passwords, password hashes, SBOM content, component data, PURLs, vulnerability details, private witness data, proof artifacts, certificate data, user profile data |
| **IndexedDB** | FORBIDDEN for this application | All data |
| **Cookies** | FORBIDDEN — session uses bearer header, not cookies | All data; reintroducing cookies requires new CSRF/CORS review |

## Data Category Classification

| Data Category | Browser Storage | Classification |
|---|---|---|
| JWT/access token | In-memory only | CONDITIONALLY SAFE (memory only) |
| Refresh token | N/A — does not exist | N/A |
| Password | FORBIDDEN — never retained after login API call | FORBIDDEN |
| Password hash | FORBIDDEN — never received from backend | FORBIDDEN |
| SBOM raw content | FORBIDDEN — never received from backend | FORBIDDEN |
| SBOM metadata (id, status, filename, root, count, timestamp) | In-memory cache | SAFE |
| Component list (names, versions, PURLs) | FORBIDDEN — never received from backend | FORBIDDEN |
| Vulnerability details | FORBIDDEN — not exposed in any response | FORBIDDEN |
| Private witness data | FORBIDDEN — never received | FORBIDDEN |
| Proof artifact (base64 encoded) | In-memory cache | CONDITIONALLY SAFE |
| Certificate metadata | In-memory cache | SAFE |
| Public roots (SBOM_ROOT, VULNERABILITY_DB_ROOT, POLICY_HASH) | In-memory cache | SAFE |
| Policy metadata (name, description, max_cvss, hash, active) | In-memory cache | SAFE |
| User profile (id, username, role) | In-memory only | CONDITIONALLY SAFE |
| Dashboard metrics (4 scalar counts) | In-memory cache | SAFE |
| UI preferences (theme, sidebar state) | sessionStorage or localStorage | SAFE |
| Search/filter state | URL query params or in-memory | SAFE |
| Pagination state | URL query params or in-memory | SAFE |
| Temporary upload state (form fields before submission) | In-memory only | CONDITIONALLY SAFE |
| Snapshot metadata (id, label, count, status) | In-memory cache | SAFE |

## Cache Strategy Policy

### Cacheable (in-memory query cache)

| Resource | Cache Duration | Invalidation Trigger | Stale Behavior |
|---|---|---|---|
| SBOM list | Short (30s–2min) | Upload, refresh | Show stale with indicator |
| Policy list | Medium (2–5min) | Policy creation, refresh | Show stale with indicator |
| Snapshot list | Medium (2–5min) | Ingest/approve/revoke, refresh | Show stale with indicator |
| Certificate list | Medium (2–5min) | Verification, refresh | Show stale with indicator |
| Metrics | Short (30s–2min) | Any mutation, refresh | Show stale with indicator |
| User profile (`/me`) | Long (session lifetime) | Login/logout | Re-fetch on 401 |
| Health | Short (30s) | Periodic refresh | Show stale |

### Non-Cacheable

| Resource | Reason |
|---|---|
| Login/register responses | One-time auth flow; token goes to memory |
| Proof generation response | Side-effecting mutation; always fetch fresh |
| Verification submission response | Side-effecting mutation; always fetch fresh |
| Snapshot approve/revoke response | Side-effecting mutation; always fetch fresh |

### Polling

| Resource | Polling Need | Interval |
|---|---|---|
| Proof job status | Yes — job lifecycle | UNKNOWN — backend does not define; suggest 5–10s |
| All other resources | No — user-initiated refresh | N/A |

## Security Rules

1. **Never persist the access token outside JavaScript runtime memory.** If the user closes the tab, the token is gone. This is the intended behavior per the Stage 1.5 contract.
2. **Never store sensitive server data in localStorage, sessionStorage, IndexedDB, or cookies.**
3. **Never cache raw SBOM content, component data, PURLs, or private witness data.** The backend does not send these, but the frontend must not attempt to derive or reconstruct them.
4. **Clear all in-memory state on logout or 401.** This includes query caches, user profile, and token.
5. **Cache HTTP responses must use `no-store` for authenticated endpoints** unless deployment reverse proxy explicitly defines otherwise.
6. **URL parameters must not contain tokens, passwords, or sensitive identifiers.** Resource UUIDs are acceptable in URL paths for navigation.

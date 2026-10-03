# Authentication and Session Architecture

Date: 2026-10-01
Stage: 6 — Authentication, Session & RBAC UI

## 1. Authentication Flow
- Users register via `/register`.
- Login occurs at `/login`.
- Upon successful login, the `authService` returns an `access_token`.

## 2. Token Lifecycle (Security Invariant)
- **Token Storage**: The access token is stored **STRICTLY IN MEMORY** via `authTransport.ts`.
- **Prohibited**: Tokens are never written to `localStorage`, `sessionStorage`, cookies, or URL params.
- **Hard Refresh**: Because memory is volatile, a hard browser refresh deliberately loses the token and forces re-authentication. This ensures maximum security.

## 3. Session State (`AuthProvider`)
- A React Context provides the session status (`initializing`, `unauthenticated`, `authenticated`).
- On initialization, it checks the memory token. If present, it executes `/me`.
- If `/me` returns `401 Unauthorized`, the token is cleared, and status falls back to `unauthenticated`.

## 4. Route Protection (`RouteGuard`)
- The `<RouteGuard>` component is wrapped around protected pages.
- **Unauthenticated Redirect**: Unauthenticated users trying to access protected paths are immediately pushed to `/login`.
- **403 Forbidden**: Authenticated users lacking the required `role` see a "403 Access Denied" UI shield. They are **not** redirected to login, as they are legitimately authenticated.

## 5. Role-Based Access Control (RBAC)
- **Vendor**: Full access to SBOM/ZKP workflows.
- **Admin**: All vendor access + audit capabilities.
- **Auditor**: Read-only verification access.
- **Sidebar**: The App Shell uses `allowedRoles` arrays to conditionally filter navigation links so users do not see forbidden areas.

## 6. Logout and Query Cache Purge
- Logout triggers `authTransport.clearToken()`.
- It explicitly calls `queryClient.clear()` to purge all cached API responses, ensuring no sensitive data bleeds into the next session.
- Finally, it redirects to `/login`.

## 7. Known Limitations
- Next.js Edge Middleware cannot be used for robust Route Protection because the `access_token` lives in JS memory, inaccessible to the edge runtime. Protection is enforced on the Client Component level alongside the Backend Contract boundary.

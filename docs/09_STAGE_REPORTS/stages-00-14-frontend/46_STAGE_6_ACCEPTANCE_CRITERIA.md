# Stage 6 Acceptance Criteria

Date: 2026-10-01
Stage: 6 — Authentication, Session & RBAC UI

## Criteria

1. **Memory-Only Tokens:** Verified that `localStorage`, `sessionStorage`, and `document.cookie` are never accessed for tokens.
2. **Session Bootstrap:** The session relies on the backend `/me` endpoint to confirm identity.
3. **Login/Register UIs:** Built using the design system specifications. Safe error handling implemented.
4. **Logout Lifecycle:** Logout clears the memory token AND calls `queryClient.clear()` to purge sensitive cached responses.
5. **RouteGuard Implementation:** Reusable guard enforces route access and redirects unauthenticated users to `/login`.
6. **403 Handling:** Users with insufficient roles see a 403 Forbidden state, not a redirect loop.
7. **Role-Aware Shell:** The Header shows the user's username and role badge. The Sidebar filters links dynamically based on the current user's role.
8. **No Test Leaks:** Hard refresh correctly forces re-authentication. No fake persistence mechanisms were invented.

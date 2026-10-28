# Stage 7 Acceptance Criteria

Date: 2026-10-01
Stage: 7 — Application Shell & Navigation

## Criteria

1. **Centralized Config:** `navigation.ts` must dictate the nav links; no hardcoded paths in `Sidebar` or `Header`.
2. **Role filtering:** The navigation must respect `vendor`, `admin`, and `auditor` visibility profiles.
3. **Public Route Shell:** The public `/certificates/[id]` page (and login/register) must not show the sidebar or user badge.
4. **Header Logout:** The header must include a logout button tied to the centralized `authTransport` purge flow from Stage 6.
5. **Mobile Navigation:** Screen sizes `< 768px` must rely on a hamburger menu expanding into a drawer (Sheet component).
6. **Active Nested State:** `/sboms/upload` must keep the `SBOM Management` parent section active.
7. **Breadcrumbs:** Breadcrumbs must reflect the current nested context.
8. **Test Coverage:** The `navigation.ts` config must be unit tested for role constraints and route prefix matching.

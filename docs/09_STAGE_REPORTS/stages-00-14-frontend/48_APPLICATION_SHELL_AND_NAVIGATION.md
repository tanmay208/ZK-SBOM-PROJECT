# Application Shell and Navigation Architecture

Date: 2026-10-01
Stage: 7 — Application Shell & Navigation

## 1. Shell Architecture
The ZK-SBOM Verify frontend splits its container layouts across:
1. **Authenticated Shell**: Contains a persistent Sidebar (on desktop) and Header. Used for all protected routes (e.g. `/dashboard`, `/sboms`, `/verify`).
2. **Public Shell**: Barebones main container. Applied to `/login`, `/register`, and `/certificates/[id]` to prevent leakage of the application interior.

## 2. Navigation Configuration
The navigation items are completely extracted out of React components into `src/config/navigation.ts`.
This single source of truth specifies:
- Path and label
- Associated Icon
- Array of `allowedRoles`
- Boolean `exactMatch` property

## 3. Role-Aware Navigation
Using the centralized config, the `Sidebar` and `Header` (Mobile Drawer) components filter the navigation list dynamically using the `useAuth()` session state.
- **Vendors** see standard pipelines.
- **Admins** see administrative features (`/audit`).
- **Auditors** are locked out of upload/proof sections.
**Crucially, this is UX only.** `RouteGuard` and the backend still enforce the ultimate boundary.

## 4. Active Route Semantics
To prevent "lost context", the active route is calculated using `pathname.startsWith()`. 
When a user is on `/sboms/upload`, the `/sboms` link remains highlighted and marked with `aria-current="page"`. Only the dashboard (`/`) uses strict equality to prevent every route from triggering it.

## 5. Breadcrumbs
A new `AppBreadcrumbs` component leverages the URL path fragments. It attempts to map the current fragment back to the readable `NAVIGATION_CONFIG` names. If none is found, it falls back to title-casing the path block. It intelligently remaps `/sboms/upload` to "Upload".

## 6. Mobile Responsiveness
The shell is responsive down to 390px.
- The Sidebar disappears on small screens (`md:hidden`).
- A hamburger icon appears in the Header.
- Triggering the hamburger opens a `Sheet` (Drawer) holding the identically-filtered navigation links, which auto-close upon navigation click.

## 7. Accessibility Considerations
- Focus traps inside the Sheet (provided inherently by shadcn's Radix UI integration).
- Aria labels for Icon-only buttons.
- `aria-current="page"` explicitly set for active sidebar elements.

# Navigation Architecture

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Top-Level Navigation Strategy

The application uses a persistent top/side navigation bar for authenticated users, and a minimal header for public routes.

## 2. Public Navigation (Unauthenticated)

| Label | Destination | Visibility Condition | Purpose |
|---|---|---|---|
| Login | `/login` | Always visible when logged out | Authenticate |
| Register | `/register` | Always visible when logged out | Create account |

## 3. Main Navigation (Authenticated)

This menu is visible to all logged-in users, but items are conditionally rendered based on the user's role in the JWT profile (`/api/v1/auth/me`).

| Label | Destination | Allowed Roles | Visibility Condition | Purpose |
|---|---|---|---|---|
| Dashboard | `/dashboard` | `vendor`, `admin`, `auditor` | Always visible | Operational metrics |
| SBOMs | `/sboms` | `vendor`, `admin` | Role `vendor` or `admin` | Manage uploaded SBOMs |
| Proofs | `/proofs` | `vendor`, `admin` | Role `vendor` or `admin` | Manage ZKP jobs |
| Verify | `/verify` | `vendor`, `admin`, `auditor` | Always visible | Submit verification request |
| Certificates | `/certificates` | `vendor`, `admin`, `auditor` | Always visible | View immutable certificates |
| Policies | `/admin/policies` | `vendor`, `admin`, `auditor` | Always visible | View global policies (admin can edit) |
| Intelligence | `/admin/vulnerabilities`| `vendor`, `admin`, `auditor` | Always visible | View snapshot DB (admin can ingest/approve) |

*Note: While `vendor` and `auditor` can see the Policies and Intelligence links, they will only see read-only views on those pages. Hiding the links entirely for non-admins is optional, but showing them as read-only is preferred for transparency.*

## 4. Account/Session Controls

| Label | Destination | Allowed Roles | Visibility | Purpose |
|---|---|---|---|---|
| `{username}` | N/A | Any | Logged in | Display current user |
| Role badge | N/A | Any | Logged in | Display active role |
| Logout | Action (Client) | Any | Logged in | Destroy token, redirect `/login` |

## 5. Breadcrumbs & Deep Linking

- **Breadcrumbs:** Required for detail pages:
  - `Proofs` > `Job ID`
  - `SBOMs` > `Upload`
- **Deep Linking:** UUID-based resources (Certificates, Proof Jobs) must be directly linkable. If an unauthenticated user hits an authenticated deep link, they are redirected to login.

## 6. Fallback Behavior

- **404 Not Found:** A standard "Page Not Found" layout keeping the main navigation intact (if authenticated).
- **403 Forbidden:** A standard "Access Denied" layout keeping the main navigation intact.

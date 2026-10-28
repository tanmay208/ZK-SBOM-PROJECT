# Frontend Component Architecture

Date: 2026-09-25
Design only; no components are implemented by this document.

## Foundation

Retain and extend the existing shadcn/Tailwind-style primitives: Button, Input, Label, Card, Badge, Separator, and Table. Required future foundation inventory: field/error message, select/combobox, textarea, file/dropzone surface, dialog/drawer, alert, toast/notice, skeleton, spinner/progress, pagination, tabs, breadcrumb, empty state, retry state, status badge, and accessible confirmation dialog.

Each primitive must preserve keyboard behavior, visible focus, semantic labels, disabled/pending behavior, reduced-motion compatibility, and responsive sizing. Foundation components must not encode domain permissions.

## Application Shell

```text
RootLayout
  SessionProvider (future; contract pending)
    AppShell
      Sidebar / MobileNavigation
      Header
        Breadcrumbs
        EnvironmentStatus
        UserMenu
        Notifications (future contract)
      MainContent
        RouteErrorBoundary
        RouteLoadingBoundary
        PageContent
```

Current `AppLayout`, `Sidebar`, and `Header` are reusable starting points but incomplete. Sidebar must become responsive and session/permission-aware only after backend rules are verified. Header's inert user button needs an actual menu contract before use.

## Domain Components

- **Dashboard:** metric cards, recent activity list, verification state panel, system-health summary. Metric ownership/global semantics are unresolved.
- **SBOM:** upload form, upload progress, safe metadata table, status timeline, commitment display, component summary that respects private/buyer boundary.
- **Vulnerability:** snapshot table, status/approval controls, snapshot metadata, ingestion form, revoked/unavailable state. Never expose private component mappings without an approved role contract.
- **Policy:** policy form, policy table, active-state badge, hash/public-input display, validation summary.
- **Proof:** proof request form, job table, status timeline, polling controller, public artifact display, generic failure state. Never display raw backend error text.
- **Verification:** public-input form, proof input control, result panel, certificate link, invalid/failed distinction.
- **Certificate:** certificate summary, commitment comparison, validation state, issued/revoked/unavailable presentation.
- **Audit:** event table, filters, severity/status indicators only after API exists.
- **Administration:** user/role table, admin action confirmations, snapshot governance controls only after explicit endpoints/permissions exist.
- **Health:** per-service status list, version/build metadata, degraded/unavailable states.

## Security Components

- `RequireSession`: presentation boundary driven by verified session state; never security enforcement.
- `PermissionGate`: hides/ disables UI affordances from server-derived permissions; never replaces backend authorization.
- `SecurityAlert`: safe generic messaging with no sensitive server details.
- `TrustState`: distinguishes public cryptographic commitments from private inputs.
- `VerificationResult`: valid/invalid/error/revoked states with exact assurance wording from project scope.
- `CertificateStatus`: public certificate lifecycle display.

## Reuse Boundaries

Keep transport, domain state, and presentation separate. API functions should return typed, sanitized contracts; feature containers should own query/mutation state; presentational tables/forms should receive data and callbacks. Do not put token handling, authorization decisions, raw upload content, or cryptographic assumptions in generic UI primitives.

## Missing Infrastructure

Providers, API client, error normalization, schema validation, query/cache, session store, permission types, route guards, feature hooks, test utilities, and accessibility test harness are all missing. Exact library choices are intentionally deferred; Stage 1 does not install dependencies.

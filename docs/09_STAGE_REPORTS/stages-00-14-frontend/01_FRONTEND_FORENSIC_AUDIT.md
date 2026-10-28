# Frontend Forensic Audit

Date: 2026-09-25
Scope: Stage 1 read-only frontend audit. Documentation only; no frontend, backend, API, database, RBAC, cryptographic, dependency, or cleanup changes were made.

## Status

- Stage 1: COMPLETE.
- Frontend audit: COMPLETE for repository-visible code; live browser/API behavior remains UNKNOWN.
- Feature implementation authorization: NOT AUTHORIZED.

Evidence labels: VERIFIED means directly observed in source or command output; DOCUMENTED means stated by repository documentation; DISCREPANCY means source and documentation differ; UNKNOWN means not established; BLOCKED means the check could not safely run.

## Executive Findings

1. The frontend is a Next.js 16 App Router shell with one implemented route, `/`, and seven declared sidebar links without corresponding pages.
2. The dashboard is static. Its four values are `---`; no API call, server state, authentication, or session exists.
3. Reusable foundation exists: layout shell, sidebar, header, shadcn/Tailwind-style primitives, `cn` utility, and Lucide icons.
4. Missing product infrastructure includes API client, contract types, validation boundary, query/cache layer, auth/session provider, route protection, permission model, domain state, tests, and feature workflows.
5. Backend contracts are only partially safe for frontend consumption. Confirmed backend audits report missing route/service authorization, unauthenticated expensive/mutating operations, global list access, proof error leakage, and caller-supplied commitment trust defects.
6. The frontend must treat backend authorization as authoritative. UI hiding or disabling is not security enforcement.
7. Live API/OpenAPI, database, Docker, production cryptographic readiness, deployment headers, and browser token behavior remain unverified.

## Source Inventory

| Area | Classification | Evidence |
|---|---|---|
| `src/app/layout.tsx` | EXISTING, REUSABLE, INCOMPLETE | Root layout, Google Geist fonts, metadata, global CSS, `AppLayout`; starter metadata remains. |
| `src/app/page.tsx` | EXISTING, INCOMPLETE, REQUIRES REFACTOR | Static dashboard cards; unused `CardDescription` warning; no remote data. |
| `src/app/globals.css` | EXISTING, REUSABLE, REQUIRES REVIEW | Tailwind 4, shadcn variables, light/dark tokens, base styles. Feature contrast/accessibility is UNKNOWN. |
| `src/components/layout/app-layout.tsx` | EXISTING, REUSABLE, INCOMPLETE | Desktop grid shell; no mobile navigation or auth-aware layout. |
| `src/components/layout/sidebar.tsx` | EXISTING, INCOMPLETE, SECURITY-SENSITIVE | Client pathname navigation; links to unimplemented routes; no role filtering, mobile drawer, focus management, or disabled/unauthorized semantics. |
| `src/components/layout/header.tsx` | EXISTING, INCOMPLETE, SECURITY-SENSITIVE | Development badge and inert user button; no menu/session/logout behavior. |
| `src/components/ui/{badge,button,card,input,label,separator,table}.tsx` | EXISTING, REUSABLE | Foundation primitives; no evidence of use in domain workflows. |
| `src/lib/utils.ts` | EXISTING, REUSABLE | `cn` helper only. |
| `src/hooks`, API modules, domain types, stores, providers, middleware | MISSING | No inspected files found. |
| Route-level `loading.tsx`, `error.tsx`, `not-found.tsx` | MISSING | Only Next-generated not-found output was observed. |
| `public/*.svg` | POTENTIALLY OBSOLETE | Default starter assets are unreferenced in inspected source; retained by Stage 0 cleanup rule. |
| `package.json` / lockfile | EXISTING, SECURITY-SENSITIVE | npm scripts are dev/build/start/lint only; no test script. Dependency classification is in the dependency section. |

## Application Architecture

Current server/client boundaries: root layout and page are server components by default; sidebar is a client component because it uses `usePathname`; no provider or middleware boundary exists. There is no auth gate, server action, route handler, API proxy, or environment URL use in frontend source. The only implemented route is `/`; build output also contains `/_not-found`.

Declared but unimplemented navigation: `/sboms`, `/vulnerabilities`, `/policies`, `/zkp`, `/certificates`, `/audit`, `/settings`. They should be treated as unavailable, not as proof that a product workflow exists.

## Backend Evidence Relevant to Frontend

Confirmed route families are listed in [03_FRONTEND_API_CONTRACT_MAP.md](./03_FRONTEND_API_CONTRACT_MAP.md). The executable code confirms OAuth2 password-form login, bearer JWT authentication, and `/api/v1/auth/me`. The model contains `auditor`, `vendor`, and `admin` role values, but role checks are visible only for vulnerability ingestion, approval, and revocation. SBOM and ZKP list/detail flows have some owner predicates; policy, snapshot, metrics, certificate list, and certificate detail ownership behavior is incomplete or absent in source.

Architecture documentation describes a future API Gateway and endpoint concepts such as `/api/v1/verify`, while executable code exposes separate service apps and `/api/v1/verification/verify`. This is a DISCREPANCY and must be resolved by backend/runtime evidence before client implementation. Audit and settings endpoints are UNKNOWN; no endpoint may be invented from sidebar labels.

## Security Forensics

### Current frontend exposure

- VERIFIED: no `localStorage`, `sessionStorage`, cookie, IndexedDB, fetch client, Authorization header, or browser log handling was found in frontend source.
- VERIFIED: no raw SBOM, private witness, proof input, database credential, subprocess stderr, stack trace, or internal path currently reaches the browser because there is no integration.
- VERIFIED: current static page contains no user-controlled HTML or URL navigation.

### Required future boundary

- Raw SBOM, component names/versions/PURLs, dependency graphs, private witness data, Merkle/SMT paths, and internal processing data MUST NOT cross a buyer verification boundary.
- `SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`, proof artifacts, verification results, and certificate metadata are documented public data, subject to backend response validation.
- Tokens and session identifiers MUST NOT be exposed to client code or persistent browser storage until the backend deployment/session contract is explicitly chosen. Exact cookie/CSRF strategy is UNKNOWN.
- Error rendering must avoid displaying `error_message` from proof jobs without a backend-approved redaction contract. Existing backend audit confirms subprocess stderr/path leakage risk.
- Frontend permission gates are presentation only. Every protected read/write must be server-enforced.

### Confirmed backend risks to carry forward

RBAC-001, API-001, VI-001, ZK-002, API-002, AUTH-001, and CFG-002 are documented open findings in the security audit/register. The frontend must not mask these with navigation logic. Certificate-by-ID currently has no visible auth dependency; vulnerability snapshot responses expose `provisional_smt_root` despite documentation saying it should not; proof responses expose `error_message`.

## UX and Accessibility Baseline

Existing semantic elements include `header`, `main`, `nav`, links, heading, labels, and screen-reader text for the user icon. Unknown or missing evidence includes keyboard traversal, focus return, mobile navigation, screen-reader announcements, error association, color contrast under both themes, reduced-motion handling, touch target validation, table semantics in workflows, and responsive behavior beyond basic Tailwind classes. These must be acceptance criteria for implementation, not inferred from the primitives.

## State and Data Storage Conclusions

- Server state: SBOM metadata, snapshots, policies, proof jobs, verification records, certificates, metrics, and `/me` identity.
- Session state: authenticated/unauthenticated/loading, verified user, role, expiry, logout, and unauthorized/forbidden transitions.
- UI state: navigation, filters, pagination, selected resource, dialogs, upload progress, polling, retry, and notices.
- Persistent client state: no requirement is verified. Do not persist raw SBOM, private witness, proof-generation inputs, credentials, JWTs, database details, or sensitive error content in localStorage, sessionStorage, IndexedDB, client cookies, or URL parameters. Exact permitted persistence policy is UNKNOWN.

## Dependency Audit

| Dependency/category | Classification | Evidence/action |
|---|---|---|
| Next, React, React DOM | FRAMEWORK-REQUIRED, CURRENTLY USED | Runtime foundation. |
| TypeScript, ESLint, eslint-config-next, Tailwind/PostCSS tooling | FRAMEWORK-REQUIRED, CURRENTLY USED | Build and lint foundation. |
| `@base-ui/react`, `shadcn`, `tw-animate-css`, `class-variance-authority`, `cn`, `lucide-react` | CURRENTLY USED or FOUNDATION CANDIDATE | Existing primitives/config/icons; actual usage varies. |
| API/query/auth/state/validation/test packages | MISSING | No client, cache, schema validation, state, or test dependency is currently configured. Do not install in Stage 1. |
| Duplicate/unnecessary/risky packages | UNKNOWN | Lockfile/package inspection alone does not establish runtime necessity; no removal authorized. |

## Product-Grade Gap Priorities

- **P0 Critical:** backend authorization and ownership contract is not verified/enforced consistently; live API boundary and session model are unknown; private/public data contract must be frozen before feature work; production cryptographic readiness is unresolved and must not be represented as ready.
- **P1 High:** API/client contract types and error taxonomy; auth/session boundary; protected route behavior; server-state/cache strategy; SBOM/proof privacy handling; testing foundation; responsive/accessibility acceptance criteria.
- **P2 Medium:** complete product routes/workflows; observability and retry/polling behavior; dashboard aggregation semantics; performance and pagination; design-system completion; deployment configuration.
- **P3 Low:** starter metadata/assets, visual refinement, nonessential preferences, and cleanup candidates.

## Evidence Limits and Unknowns

Live OpenAPI and gateway composition, actual response bodies in a running deployment, audit API, settings API, registration policy for production, tenant model, ownership for policies/snapshots/certificates, refresh/logout/revocation behavior, cookie/CSRF policy, rate limits, retention, browser security headers, TLS/reverse proxy, production VK/proof readiness, and final route permission semantics are UNKNOWN or BLOCKED as described in Stage 0.

## Validation Record

Stage 1 rerun after documentation completed successfully:

| Command | Result | Exact result |
|---|---|---|
| `Set-Location frontend; npm run lint` | PASS with warning | Exit 0; one existing warning: unused `CardDescription` in `src/app/page.tsx`. |
| `Set-Location frontend; npx tsc --noEmit` | PASS | Exit 0; no output. |
| `Set-Location frontend; npm run build` | PASS | Exit 0; Next 16.3.5 generated only `/` and `/_not-found`. |
| `Set-Location; .\\.venv\\Scripts\\python.exe -m pytest -q` | PASS with warnings | Exit 0; 493 passed, 26 warnings, 66.04 seconds. |

No source behavior was changed to obtain these results.

## Recommendation

Do not begin Stage 2 feature implementation. First resolve the backend authorization/session/API contract blockers, establish a safe configured runtime, and approve the route/permission documents. The next authorized stage should be API/client foundation only after those contracts are executable and reviewed.

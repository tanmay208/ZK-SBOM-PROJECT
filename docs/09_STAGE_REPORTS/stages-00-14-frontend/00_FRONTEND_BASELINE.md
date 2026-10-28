# Frontend Stage 0 Baseline

Date: 2026-09-25
Scope: inspection and documentation only. No frontend, backend, API, database, circuit, crypto, or cleanup changes were made.

Evidence labels used below: VERIFIED means directly checked by a command or source read; OBSERVED means visible in repository state; INFERRED means a bounded conclusion from verified evidence; UNKNOWN means not established; BLOCKED means an attempted check could not run.

## 1. Executive Summary

- VERIFIED: The frontend is a small Next.js App Router application with one rendered route, `/`, and a static dashboard shell.
- VERIFIED: `npm run lint` succeeds with one warning for an unused `CardDescription` import in `frontend/src/app/page.tsx`.
- VERIFIED: `npx tsc --noEmit` succeeds.
- VERIFIED: `npm run build` succeeds and produces only `/` and `/_not-found` routes.
- VERIFIED: The backend test suite passes: 493 passed, 26 warnings.
- BLOCKED: Live Docker/database startup could not be checked. Docker Desktop's Linux engine is unavailable and Compose requires missing `DB_PASSWORD`.
- BLOCKED: Nargo and Barretenberg are not available on PATH.
- INFERRED: Stage 1 frontend authorization should not begin until backend runtime configuration, live API routing, and the frontend/API contract boundary are made executable and confirmed.

## 2. Repository State

- VERIFIED: Current branch is `main`, at tag `day-01-architecture`.
- VERIFIED: HEAD is `733fd63 docs: finalize project architecture and specifications`.
- VERIFIED: Previous commit is `59a4e6b docs: finalize project architecture and specifications`.
- VERIFIED: Git reports 156 status lines: 4 tracked files modified (`A` in the current Git baseline output) and a large set of untracked files, including `frontend/`, `circuits/`, `circuits_dev/`, additional backend routes/migration files, scripts, and security documentation. This report does not normalize that state.
- OBSERVED: The working tree contains 40,016 files and approximately 703.84 MiB when `.git` is excluded. This includes installed dependencies, virtual-environment files, caches, and generated output.
- OBSERVED: Tracked file count reported by the initial command was 156; the working tree is substantially larger because many files are untracked or generated.
- OBSERVED: Top-level configuration includes `docker-compose.yml`, `.env.example`, `.gitignore`, `pyproject.toml`, backend requirements, frontend `package.json`/lockfile, circuit manifests, and Dockerfiles.
- VERIFIED: Migrations present are `backend/alembic/versions/001_initial_schema.py` and untracked `002_add_rbac_ownership_columns.py`.

## 3. Frontend Technology Stack

- VERIFIED: Next.js `16.3.5`, React `19.2.8`, React DOM `19.2.8`, TypeScript `^5`, ESLint 9.
- VERIFIED: Package manager is npm. `frontend/package-lock.json` exists and `frontend/node_modules/` exists.
- VERIFIED: Styling uses Tailwind CSS 4, `tw-animate-css`, `shadcn/tailwind.css`, CSS variables, and shadcn-style primitives.
- VERIFIED: UI dependencies include `lucide-react`, `@base-ui/react`, `class-variance-authority`, `cn`, and `shadcn`.
- VERIFIED: `next.config.ts` has no custom options.
- VERIFIED: TypeScript is strict, noEmit, bundler module resolution, React JSX transform, `@/*` mapped to `src/*`, and Next TypeScript plugin enabled.
- OBSERVED: `next/font/google` loads Geist and Geist Mono in the root layout, so the app has a network/build dependency unless fonts are cached or otherwise available.

## 4. Existing Frontend Structure

- `frontend/src/app/layout.tsx`: root layout, metadata, fonts, global CSS, `AppLayout`.
- `frontend/src/app/page.tsx`: only implemented page; static Security Dashboard metrics.
- `frontend/src/app/globals.css`: Tailwind/shadcn imports, light/dark CSS variables, base styles.
- `frontend/src/components/layout/app-layout.tsx`: sidebar/header/main shell.
- `frontend/src/components/layout/header.tsx`: development profile badge and user icon button.
- `frontend/src/components/layout/sidebar.tsx`: client component, pathname-aware navigation.
- `frontend/src/components/ui/`: badge, button, card, input, label, separator, and table primitives.
- `frontend/src/lib/utils.ts`: utility module.
- `frontend/public/`: default Next/Vercel starter SVG assets.
- UNKNOWN: No frontend `hooks/`, API client, domain `types/`, state store, test directory, or route-level error/loading files were found in the inspected source tree.

## 5. Existing Routes and Pages

- VERIFIED rendered route: `/`.
- VERIFIED Next build routes: `/` and `/_not-found` only.
- OBSERVED declared sidebar links: `/`, `/sboms`, `/vulnerabilities`, `/policies`, `/zkp`, `/certificates`, `/audit`, `/settings`.
- INFERRED: The seven non-root links currently resolve to Next not-found behavior because no corresponding App Router page was found.
- VERIFIED: No forms, tables, dashboards backed by remote data, or route-specific error/loading/empty states are implemented. The root dashboard has four static cards with `---` values and “Requires API Integration”.

## 6. Existing Components and UX Inventory

- Existing/reusable: layout shell, header, sidebar navigation, card, badge, button, input, label, separator, table primitives, `cn` helper.
- Missing: feature pages, upload form, policy form, vulnerability table, proof-job workflow, verification form, certificate views, audit log view, settings view, auth screens, API response types, fetch client, query/cache layer, mutations, and domain-specific errors.
- Incomplete: user icon has accessible screen-reader text but no menu behavior; navigation declares pages that do not exist; dashboard cards are placeholders; metadata still says “Create Next App”.
- Potentially obsolete: default public SVG starter assets are not referenced by the inspected source. They are retained because no deletion was authorized and framework/public conventions were not fully disproved.
- Responsive behavior: OBSERVED Tailwind responsive grid/sidebar classes exist, but UNKNOWN for feature pages because they do not exist. No mobile navigation behavior was found.
- Accessibility: OBSERVED semantic `header`, `main`, `nav`, links, heading, icon `sr-only` text, and form primitives. UNKNOWN for keyboard/mobile navigation, focus management, announcements, and feature workflows.
- Testing: no frontend test script or test files found. `package.json` scripts are `dev`, `build`, `start`, and `lint`.

## 7. Existing API Integration

- VERIFIED: No frontend `fetch`, Axios client, API module, API types, environment URL, or backend call was found in the source inspected.
- VERIFIED backend base prefix: `/api/v1`.
- VERIFIED shared application factory exposes health, OpenAPI, ReDoc, CORS, security middleware, and optional domain router.
- Confirmed contract map:

| Feature | Frontend route/page | API endpoint | Request schema | Response schema | Permission | Loading/empty/error |
|---|---|---|---|---|---|---|
| Dashboard metrics | `/` static page | `GET /api/v1/metrics` | none | object: `total_sboms`, `total_jobs`, `total_certificates`, `total_verifications` | authenticated bearer | UNKNOWN; no client integration |
| Authentication | UNKNOWN | `POST /api/v1/auth/login` | OAuth2 form: username/password | `access_token`, `token_type` | public endpoint; bearer returned | UNKNOWN |
| Registration | UNKNOWN | `POST /api/v1/auth/register` | OAuth2 form: username/password | message, username, role | public endpoint; new users forced to `auditor` | UNKNOWN |
| Current user | UNKNOWN | `GET /api/v1/auth/me` | none | id, username, role | authenticated bearer | UNKNOWN |
| SBOM list | `/sboms` declared only | `GET /api/v1/sbom?skip=&limit=` | query pagination | list of upload_id, application_id, status, format, filename, sbom_root, component_count, created_at | authenticated; query filters by current user | UNKNOWN |
| SBOM upload | `/sboms` declared only | `POST /api/v1/sbom/upload` | JSON `application_name`, `vendor`, optional `filename`, `format=CycloneDX`, raw `content` | safe upload metadata; raw content excluded | authenticated; max request body 10 MB | UNKNOWN |
| Vulnerability snapshots | `/vulnerabilities` declared only | `GET /api/v1/vulnerability/snapshots?skip=&limit=` | query pagination | `VulnerabilitySnapshotResponse` | authenticated; current implementation does not visibly filter list by user | UNKNOWN |
| Vulnerability ingest | `/vulnerabilities` declared only | `POST /api/v1/vulnerability/ingest` | `VulnerabilityIngestionRequest` | `VulnerabilityDatabaseResponse` | admin role required | UNKNOWN |
| Snapshot approval/revocation | `/vulnerabilities` declared only | `POST /api/v1/vulnerability/snapshots/{snapshot_id}/approve|revoke` | UUID path | snapshot response | admin role required | UNKNOWN |
| Policies | `/policies` declared only | `GET/POST /api/v1/policy` | POST `name`, `description`, bounded `max_cvss_score` | id, name, description, max_cvss_score, policy_hash, created_at, active | authenticated; role restriction not visible in route | UNKNOWN |
| ZKP jobs | `/zkp` declared only | `GET /api/v1/zkp`, `POST /api/v1/zkp/generate`, `GET /api/v1/zkp/jobs/{job_id}` | list pagination; generate request; UUID path | proof job response | authenticated; job ownership checked on detail | UNKNOWN |
| Verification | no implemented page | `POST /api/v1/verification/verify` | `VerifyProofRequest` | roots, policy hash, result, timestamps, optional certificate | authenticated | UNKNOWN |
| Certificates | `/certificates` declared only | `GET /api/v1/verification/certificates`, `GET /api/v1/verification/certificates/{certificate_id}` | pagination/UUID | certificate response | list authenticated; detail route dependency not visible | UNKNOWN |
| Audit logs | `/audit` declared only | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| Settings | `/settings` declared only | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |

The frontend must not infer additional fields or endpoints from navigation labels. The actual schemas above are the confirmed source contract; unknowns remain unknown.

## 8. Authentication and Session State

- VERIFIED backend authentication uses OAuth2 password form login and bearer JWTs with `sub`, `role`, and expiration claims.
- VERIFIED backend `/me` returns only id, username, and role; password hashes are excluded.
- VERIFIED frontend contains no login/register page, token acquisition, token storage, bearer injection, refresh, logout, session context, route guard, or role-aware rendering.
- VERIFIED browser storage search found no `localStorage`, `sessionStorage`, cookie, or client persistence use in frontend source.
- Security-sensitive frontend boundary: current frontend renders only static labels and scalar placeholders; it does not receive or persist backend private data, passwords, JWT secrets, witnesses, Prover.toml, server paths, subprocess stderr, stack traces, database credentials, or private cryptographic material.

## 9. Frontend Validation Results

| Command | Result | Evidence |
|---|---|---|
| `npm run lint` from `frontend` | PASS with warning | exit 0; one unused `CardDescription` warning in `src/app/page.tsx` |
| `npx tsc --noEmit` from `frontend` | PASS | exit 0; no output |
| `npm run build` from `frontend` | PASS | exit 0; Next 16.3.5 build generated `/` and `/_not-found` |
| frontend tests | NOT CONFIGURED | no test script/files found |
| initial `Set-Location frontend` type/build attempt | BLOCKED by command context | terminal was already in `frontend`, so path became `frontend/frontend`; rerun corrected this and passed |

## 10. Backend Validation Results

- VERIFIED: `.venv\Scripts\python.exe -m pytest -q`: exit 0, 493 passed, 26 warnings, 69.48 seconds.
- Warnings include Starlette anyio deprecation, websockets deprecations, and `datetime.utcnow()` deprecations in source/tests.
- BLOCKED: direct import check using `.venv\Scripts\python.exe` and module names `policy_service.app.main`, `sbom_service.app.main`, `vulnerability_service.app.main`, `zkp_service.app.main`, `verification_service.app.main` failed immediately with `ModuleNotFoundError: No module named 'policy_service'` because service package roots are not on the direct process path. The repository pytest configuration does use `backend` as a Python path.
- BLOCKED: `docker ps` could not connect to Docker Desktop Linux engine.
- BLOCKED: `docker compose config --quiet` could not interpolate required `DB_PASSWORD`, which is absent from the environment.
- UNKNOWN/BLOCKED: live SQL Server connectivity, live authentication, live API routing, and live endpoint behavior were not safely executable without configuration and a running database.

## 11. Environment Status

- VERIFIED: Python 3.12.10; selected interpreter `C:\Program Files\Python312\python.exe`.
- VERIFIED: repository virtual environment exists at `.venv`; it contains pytest and backend dependencies.
- VERIFIED: Node v24.19.0; npm 11.17.0.
- VERIFIED: WSL2 configured with default distribution `kali-linux`.
- VERIFIED: Docker CLI 29.8.0, but daemon unavailable.
- BLOCKED: `nargo --version` not found; `bb --version` not found.
- UNKNOWN: SQL Server version/connectivity in this current run; architecture documentation specifies SQL Server 2022 but no live connection was possible.
- BLOCKED/missing: `DB_PASSWORD` is required by Compose and absent. Other sensitive configuration values were not printed.
- OBSERVED: no relevant environment variables were present in the safe presence-only environment query.

## 12. Data Persistence Observations

- VERIFIED schema/model groups: `users`; `sbom.applications`, `sbom.sbom_uploads`, `sbom.components`; vulnerability snapshot/database models; `policy.security_policies`; `zkp.proof_jobs`; `verification.verification_requests` and `verification.verification_certificates`.
- VERIFIED ownership fields include `user_id` on users/application/SBOM upload/proof job and RBAC role on users. Retention/expiry fields were not found in the inspected model fields.
- VERIFIED SBOM raw content is persisted in `sbom.sbom_uploads.raw_content`; component name/version/PURL/hash fields are persisted in `sbom.components` and classified private by backend security code.
- VERIFIED proof job stores public roots/hashes plus `proof_artifact` and `error_message`; the frontend currently cannot see any of it because no client exists. Whether retention/cleanup is enforced is UNKNOWN.
- VERIFIED artifacts are represented by repository/database fields and circuit files; a separate browser/client artifact store was not found.
- UNKNOWN: audit-record persistence endpoint/model was not confirmed from the inspected source.

## 13. Security Observations

- VERIFIED frontend does not currently expose or persist the prohibited sensitive categories because it has no API/session/storage integration.
- VERIFIED backend response schemas and security utilities explicitly exclude raw SBOM/private witness fields from buyer-facing responses and redact configured patterns in logs.
- VERIFIED backend auth rejects missing/invalid bearer credentials and registration assigns `auditor` rather than accepting a requested role.
- UNKNOWN: live deployment headers, browser CORS behavior, token lifetime in operation, and reverse-proxy behavior.
- SECURITY-SENSITIVE: certificate detail route does not visibly declare a current-user dependency in the route source; this requires a later backend authorization review and must not be assumed safe from frontend navigation.

## 14. Crypto Status

- VERIFIED development profile: `CRYPTO_PROFILE=dev` or manifest fallback; circuit directory `circuits_dev`; max components 8; Merkle depth 3; SMT depth 256; expected Nargo 0.32.0; VK hash is present.
- VERIFIED production profile: circuit directory `circuits`; max components 8; Merkle depth 3; SMT depth 256; expected Nargo 0.32.0; `vk_hash` is null.
- VERIFIED production VK availability is not established as ready: the production manifest explicitly has a null VK hash and the executable toolchain is absent.
- VERIFIED production proof availability/readiness is not established. The ZKP service comments that the current environment fails fast and synchronous production task-queue execution is deferred.
- OBSERVED: application-level verification endpoints and tests exist, and public roots/hashes are modeled. This does not prove production cryptographic proving/verification readiness.
- UNKNOWN: full public-input binding assurance for a live production profile; no claim is made here beyond repository tests/docs.
- INFERRED: development profile functionality and passing test doubles must remain separate from frontend authorization and from a production-ready cryptographic claim.

## 15. Known Issues

- Static dashboard and placeholder metrics only.
- Declared sidebar routes without implemented pages.
- No frontend authentication/session boundary.
- No API client or contract types.
- Lint warning for unused import.
- Default Create Next App metadata remains.
- Live runtime cannot be verified due missing Docker/database configuration.
- Nargo and Barretenberg are unavailable.
- Backend direct service imports require an explicit package-path setup.
- Backend deprecation warnings are present.

## 16. Unknowns

Live API response payloads, OpenAPI output from running services, actual SQL Server connectivity/version, deployed gateway routing, frontend-to-gateway URL policy, final auth UX, audit API, retention enforcement, production VK/proof artifacts, and production public-input binding remain unconfirmed.

## 17. Deferred Items

Do not implement these in Stage 0: frontend redesign, route implementation, auth/session implementation, API client, state management, forms/tables, backend changes, schema/migration changes, crypto changes, cleanup deletion, or contract changes.

## 18. Stage 1 Prerequisites

1. Establish a documented, non-secret local environment with `DB_PASSWORD`, database reachability, and Docker service startup.
2. Confirm gateway route composition and obtain live OpenAPI/contracts for each intended frontend feature.
3. Resolve authentication/session ownership and role/permission rules before rendering protected navigation.
4. Confirm production/development crypto profile policy and artifact readiness independently of UI authorization.
5. Decide whether the current untracked repository state is intentional before implementation work is merged or committed.
6. Add a frontend test strategy and define loading, empty, unauthorized, validation, network, and server-error states.

## 19. GO / NO-GO for Stage 1

**NO-GO for feature implementation.** The frontend source can build, but live backend/API/database/crypto readiness and authorization boundaries are not sufficiently verified. Documentation and environment-contract work may continue; feature implementation should wait for the prerequisites above.

## Final Status

STAGE 0 STATUS: COMPLETE

FRONTEND BASELINE: NOT READY

BACKEND BASELINE: NOT READY

STAGE 1 AUTHORIZATION: NOT AUTHORIZED

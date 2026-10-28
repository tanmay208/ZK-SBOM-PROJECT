# Frontend Architecture

## Technology and structure

The frontend is a Next.js App Router application under frontend/src/app. API clients, transport, errors, domain services, and response types are under frontend/src/api; authentication is under src/auth; shared UI and layout components are under src/components; theme and React Query providers are under src/providers.

The package manifest declares Next.js 16.3.5, React 19.2.8, and TanStack React Query 5.x. The package lock is the dependency-resolution source. The package does not declare a Node.js engine version.

## Routes

Current route pages include /, /dashboard, /login, /register, /sboms, /sboms/upload, /proofs, /proofs/generate, /proofs/[id], /verify, /certificates, /certificates/[id], /admin/policies, and /admin/vulnerabilities.

## Auth and API boundary

The bearer token is held in module memory and attached by the API client to authenticated calls. The public certificate-validation method explicitly skips auth. Route guards and role-specific navigation are user-interface controls only; backend authorization must protect private resources.

## Workflow and async state

The UI links returned SBOM and proof identifiers through upload, proof generation, proof detail/progress, verification, and certificate display. React Query manages shared request state and invalidation. Proof polling stops at terminal states or query failure. Verification invalidates both verification and certificate caches.

## Evidence and limitations

The Stage22 final audit statically traced routes/contracts and reports automated tests, typecheck, lint, build, and limited local browser rendering/routing. It does not report a live authenticated backend workflow, comprehensive viewport tests, or assistive-technology certification. See [Stage22 final audit](../09_STAGE_REPORTS/STAGE_22_FINAL.md).

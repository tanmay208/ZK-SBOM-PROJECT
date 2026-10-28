# Frontend API Integration Foundation

Date: 2026-10-01
Stage: 5 — API Client, Types & Frontend Integration Foundation

## 1. API Architecture
The frontend uses a strict 3-tier API architecture:
1. **HTTP Client (`client.ts`)**: Base fetch wrapper handling headers, URLs, and JSON transformation.
2. **Domain Services (`services/*.ts`)**: Type-safe functions matching specific backend routes.
3. **Query/Mutation Hook Layer (`@tanstack/react-query`)**: Handles caching, polling, and UI state without knowing about HTTP mechanics.

## 2. Base URL Configuration
Configured in `config.ts` via `process.env.NEXT_PUBLIC_API_URL` with a fallback to `http://localhost:8000`. No secrets are exposed to the frontend environment variables.

## 3. Authentication Transport
- Managed strictly via `authTransport.ts`.
- **Mechanism:** In-memory variable only.
- **Persistence:** None. Tokens do not survive a page refresh. `localStorage` and cookies are strictly forbidden for tokens.
- **Injection:** `client.ts` automatically attaches `Authorization: Bearer <token>`.

## 4. Error Model & Status Semantics
- Errors are caught and re-thrown as `ApiError`.
- **401**: Interpreted as `UNAUTHORIZED`. Clears the in-memory token automatically.
- **403**: Interpreted as `FORBIDDEN`.
- **422**: Normalizes Pydantic validation failures.
- **Sanitization**: Internal stack traces or raw fetch errors are swallowed. Only structured API errors or generic network error strings are raised to the UI.

## 5. Domain Service Modules
- `authService`: `login`, `register`, `me` (uses `URLSearchParams` to meet OAuth2 requirements).
- `metricsService`: `getMetrics`.
- `sbomService`: `upload` (JSON payload matching intake ambiguity decision), `list`.
- `vulnerabilityService`: `listSnapshots`, `ingest`, `approve`, `revoke`.
- `policyService`: `list`, `create`.
- `proofService`: `list`, `generate`, `getJob`.
- `verificationService`: `verify`.
- `certificateService`: `list`, `getCertificate`.

## 6. Type Organization
All domain types reside in `types/index.ts` and strictly mirror the backend Pydantic models.
- **Enums**: `ProofJobStatus`, `VerificationResult`, and `VulnerabilitySnapshotStatus` use strict string unions. No fabricated states exist.

## 7. Storage Restrictions & Security Logging
- **Storage**: No `localStorage` or `IndexedDB` usage for API responses or tokens.
- **Logging**: The `apiClient` intentionally omits `console.log` interceptors. Request bodies (especially SBOMs) and passwords are never dumped to the console.

## 8. Dependencies
`@tanstack/react-query` was added to handle complex polling logic (specifically required for `proofService` polling).

## 9. Known Discrepancies
- **SBOM Upload Endpoint Protocol**: As documented in Stage 3.1, the backend uses a JSON envelope for the SBOM payload instead of `multipart/form-data` to easily leverage the 10 MB limit middleware. The frontend `sbomService` matches this executable backend behavior exactly by sending a JSON payload.

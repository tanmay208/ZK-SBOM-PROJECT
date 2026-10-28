# Backend Contract Closure

Date: 2026-09-25
Stage: 1.5

## Scope

This stage closed backend/frontend contract uncertainties from Stage 1 without implementing frontend features, changing the ZKP protocol, changing circuits, changing database schema/migrations, or deleting files.

## Evidence

Executable evidence came from FastAPI routes, Pydantic schemas, repositories, service code, application factory/middleware, existing security audits, existing tests, and the configured backend regression suite. The architecture still describes a future API Gateway, but Compose references a missing `docker/nginx.conf` and no executable gateway route was available.

## Decisions and Changes

- JWT secret lookup now fails closed when `JWT_SECRET_KEY` is absent; the previous ephemeral runtime fallback and import-time secret snapshot were removed.
- Server-side role dependencies now enforce vendor/admin SBOM upload, admin policy creation, and vendor/admin proof generation.
- Proof jobs remain owner-scoped, and repository checks retain SBOM ownership and approved snapshot requirements.
- Metrics are scoped to current-user SBOMs, proof jobs, verification requests, and certificates.
- Provisional SMT roots were removed from vulnerability snapshot responses because the existing schema documentation and tests classify them as provisional/non-response data.
- Proof-job error responses are sanitized to `Proof generation failed`; internal tool output is not a frontend contract.
- HTTP exceptions use the existing safe envelope style: `{ "error": string, "code": string }`; validation keeps safe locations/messages and request-size responses use `REQUEST_TOO_LARGE`.
- CORS remains explicit-origin only and no longer enables credentials because the session uses an Authorization header, not cookies.
- Certificate detail is public metadata lookup by UUID; the response model contains certificate metadata and public commitments only. Certificate listing remains authenticated.

## Current API Boundary

`verification_service` is the current unified development application and frontend-facing `/api/v1` boundary. Direct service apps remain executable service boundaries. Compose's Nginx gateway is declared but not executable because `docker/nginx.conf` is absent: `GATEWAY STATUS: NOT IMPLEMENTED`.

## Tests

- Pre-change configured backend baseline: 493 passed, 26 warnings using `.venv\\Scripts\\python.exe -m pytest -q`.
- Literal `pytest -q` was attempted and failed because `pytest` is not on the shell PATH; the configured virtual-environment command passed.
- Focused authorization/privacy slice: 89 passed, 24 warnings.
- Focused response-contract slice: 71 passed, 4 warnings.
- New closure tests: 4 passed, 1 warning.
- Session/auth/error slice: 19 passed, 16 warnings.
- Final configured backend regression: 497 passed, 27 warnings in 85.01 seconds.
- Frontend lint, TypeScript, and build were also rerun before backend changes and passed; frontend source was not modified.

## Unresolved Items

Live Docker/SQL Server/API gateway behavior remains blocked by unavailable Docker daemon, missing `DB_PASSWORD`, and missing gateway configuration. Live OpenAPI, rate limiting, reverse proxy/TLS, token revocation, audit/settings APIs, production cryptographic tooling, and deployment browser behavior remain UNKNOWN.

## Residual Risks

The one-day bearer token has no refresh or server-side revocation endpoint. Database retention/encryption, production secret management, service-to-service authentication, rate limiting, and production proof/VK readiness remain outside this closure. These are explicit Stage 2/deployment gates, not frontend assumptions.

# Certificate Management & Public Workflow Architecture

Date: 2026-10-01
Stage: 11 — Certificate Management & Public Certificate Workflow

## 1. Core Workflow
- Users view their verified certificates at `/certificates`.
- Success paths in `/verify` present users with a backend-minted `certificate.id`.
- The public route `/certificates/[id]` displays the public immutable metadata (hashes, status) proving verification took place.

## 2. Public Route Constraints
- The detail page is deliberately unprotected. `RouteGuard` is omitted. 
- API transport `apiClient` transparently omits the `Authorization` header if unauthenticated, allowing the backend to serve public objects while enforcing 404s/403s on unauthorized or missing items.
- No private data (raw SBOMs, witnesses, policy variables) is ever rendered.

## 3. Immutable Security Posture
- Certificates are treated as immutable backend-owned records. The UI presents no mutation actions (Edit, Revoke, Delete).
- The frontend performs no cryptographic hashing to independently "validate" the certificate content against the user's local state.

## 4. Query & Transport
- The list uses `certificateService.list()`.
- The detail page uses `certificateService.getCertificate()`.
- Error mapping uniformly catches 404s, returning safe "Not Found or Revoked" messages without leaking backend internal architecture.

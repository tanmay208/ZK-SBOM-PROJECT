# Stage 14 Acceptance Criteria

Date: 2026-10-01
Stage: 14 — Integration & Hardening

## Criteria

1. **Authentication Gate**: 401 routes correctly resolve and eject to unauthenticated views. Local token state is not leaked.
2. **RBAC Gate**: Route guards cleanly bounce mismatched roles to restricted states.
3. **Ownership / IDOR Gate**: Users attempting to load invalid/other-tenant objects hit strict isolated 404s/403s.
4. **Sensitive Data Gate**: SMT roots, raw vulnerabilities, and witness files are strictly isolated from client-side views.
5. **SBOM Validation Gate**: Strictly bound to 10MB limits matching API contracts.
6. **Vulnerability Trust Gate**: Admin mutations required for `pending` -> `approved` transition. 
7. **Proof Generation Boundary Gate**: ZK computations strictly enforced inside server-side wrappers.
8. **Verification Gate**: 100% backend authoritative verification with exact public-input binding.
9. **Certificate Integrity Gate**: Completely immutable presentation layer.
10. **Query Cache Gate**: `queryClient.clear()` ensures local state scrubbing on logout.
11. **Regression Gate**: Both frontend (30) and backend (497) test suites pass fully clean.

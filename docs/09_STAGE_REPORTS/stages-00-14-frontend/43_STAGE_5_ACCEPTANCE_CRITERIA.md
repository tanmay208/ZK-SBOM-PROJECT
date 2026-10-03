# Stage 5 Acceptance Criteria

Date: 2026-10-01
Stage: 5 — API Client, Types & Frontend Integration Foundation

## Acceptance Criteria

Stage 5 is complete ONLY if all of the following are true:

1. **API Client Exists:** A centralized HTTP client wraps `fetch`, removing repetitive fetch logic from components.
2. **Authentication Transport is Volatile:** The token is kept in memory. No code writes to `localStorage` or `document.cookie`.
3. **Error Normalization:** A consistent `ApiError` class is used. 401 interceptors correctly clear the memory token.
4. **Domain Types:** TypeScript interfaces strictly match the executable backend Pydantic schemas. No `any`.
5. **Service Modules:** Every backend domain (Auth, SBOM, Vuln, Policy, Proof, Verify, Certificate) has a dedicated service module.
6. **Query Layer Foundation:** A query abstraction (React Query) is configured with security-first defaults (no infinite retries for auth errors, short gcTime).
7. **Storage Policy Respected:** Sensitive fields (like `raw_content` or `provisional_smt_root`) are omitted from TS types because the backend omits them.
8. **No Secrets Exposed:** Environment config only exposes the API URL.
9. **Type Safety:** The new files pass TypeScript validation without `@ts-ignore`.
10. **Backend Preservation:** No backend Python code was modified to "make the frontend easier." The frontend conforms to the backend.

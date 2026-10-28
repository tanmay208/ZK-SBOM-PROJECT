# Stage 11 Acceptance Criteria

Date: 2026-10-01
Stage: 11 — Certificate Management & Public Certificate Workflow

## Criteria

1. **Authenticated Certificate List**: `/certificates` uses `certificateService.list()` and `RouteGuard` to list user certificates.
2. **Public Certificate Detail**: `/certificates/[id]` uses `certificateService.getCertificate()` and purposefully omits `RouteGuard` for unauthenticated access.
3. **Immutability**: No edit, delete, or revoke buttons exist on any certificate interface. 
4. **Certificate Transport**: `apiClient` transparently omits tokens for public queries when unauthenticated.
5. **No Cryptographic Forgery**: The frontend never mints its own UUIDs or certificates in JS, heavily trusting the backend ID.
6. **No Scope Creep**: The UI ignores any raw proof parsing or re-validation workflows for certificates. 
7. **Verification Handoff**: Successful verifications in `/verify` present an explicit, accessible navigation link passing the backend-generated certificate UUID to the public detail page.
8. **Responsive UI**: Pages follow Shadcn and accessible contrast guidelines.

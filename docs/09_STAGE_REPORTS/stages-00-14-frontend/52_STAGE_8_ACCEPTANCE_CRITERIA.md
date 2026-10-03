# Stage 8 Acceptance Criteria

Date: 2026-10-01
Stage: 8 — SBOM Management & Upload

## Criteria

1. **SBOM List View**: Implemented at `/sboms`, surfacing only `upload_id`, `application_id`, `status`, `filename`, `sbom_root`, and `created_at`.
2. **Empty/Loading/Error States**: The list dynamically handles React Query statuses and provides an "Upload SBOM" empty state.
3. **Upload Workflow**: Implemented at `/sboms/upload` with robust file parsing and validation (JSON only, 10MB limit).
4. **Transport Format**: Validated that `sbomService.upload()` correctly transmits the JSON payload per the known backend contract, relying on the central token handling.
5. **Success Routing**: Successful uploads display a success state and invalidate the `["sboms"]` cache without attempting local root computation or mock redirects.
6. **Error Sanitization**: Server payload validation errors do not expose internal Python/Database tracebacks.
7. **Role Visibility**: Tested that the routes are completely locked for `auditor`.
8. **Security Boundary**: Confirmed the UI does not process or expose component graphs, CVSS mappings, or vulnerabilities.

# SBOM Workflow Architecture

Date: 2026-10-01
Stage: 8 — SBOM Management & Upload

## 1. Routes and Access
- `/sboms` (List view)
- `/sboms/upload` (Upload form)
- Protected by `RouteGuard` allowing only `vendor` and `admin`. `auditor` receives a 403 Forbidden.

## 2. API / Service Integration
The application uses the `sbomService.ts` constructed in Stage 5. 
The upload transport utilizes a strict JSON payload format as currently accepted by the backend, rather than `multipart/form-data`, ensuring alignment with the currently executable contract (Discrepancy Documented in Stage 5). The backend maps JSON fields like `application_name`, `vendor`, `format`, `content`, and `filename`.

## 3. Upload Lifecycle and Validation
1. **Idle**: The user selects a `.json` file and enters the Application Name.
2. **Validation**: The frontend checks:
   - File exists.
   - Size <= 10 MB.
   - Extension is `.json`.
   - Content is parseable JSON (to prevent sending malformed text to the backend).
3. **Uploading**: React Query mutation starts, UI elements disable, and spinner activates.
4. **Success**: Returns the `upload_id` and surfaces a success card, immediately invalidating the `["sboms"]` React Query cache to sync the updated list.
5. **Error Mapping**: `ApiError` mapping automatically converts 401s, 403s, 413s, and 422s to sanitized human-readable alert boxes.

## 4. Security Visibility Boundary
No component lists, PURLs, private keys, or raw JSON structures are surfaced to the DOM. The SBOM table explicitly restricts its rendering surface to the deterministic properties defined in `SBOMUploadResponse`.

## 5. Owner Scoping
There is NO ownership selector drop-down on the client. The authenticated token dictates ownership isolation purely through backend enforcement. The frontend simply consumes `sbomService.list()` relative to the active session token.

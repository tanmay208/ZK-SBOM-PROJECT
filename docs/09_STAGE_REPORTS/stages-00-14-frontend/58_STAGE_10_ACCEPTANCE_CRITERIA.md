# Stage 10 Acceptance Criteria

Date: 2026-10-01
Stage: 10 — Verification & Verification Result Workflow

## Criteria

1. **Verify Page Implementation**: `/verify` exists and functions according to design language.
2. **Proof Selection**: Only `completed` Proof Jobs are presented as options in the dropdown.
3. **Verification Transport**: Verification payload maps strictly to `verificationService.verify()` omitting disallowed local artifacts.
4. **Lifecycle Mapping**: `verified`, `invalid`, `authoritative_record_mismatch`, `public_input_mismatch`, and `unavailable` are visually and semantically distinct.
5. **Certificate Handling**: Certificates are surfaced purely reactively if present in the success response payload. No client-side creation.
6. **No Client-side Crypto**: No roots or hashes are recomputed in JS/TS.
7. **Role Access**: `vendor`, `admin`, and `auditor` can all access the page.
8. **Error Masking**: API Errors (401, 403, 404, 422, etc) are uniformly handled through `ApiError` mapping without exposing tracebacks.

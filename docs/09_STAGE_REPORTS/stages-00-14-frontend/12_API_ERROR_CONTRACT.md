# API Error Contract

Date: 2026-09-25
Stage: 1.5

## Scope

Freeze the safe, frontend-consumable HTTP error behavior currently implemented by the shared FastAPI infrastructure. This does not add a rate limiter or invent unavailable gateway statuses.

## Envelope

Application HTTP errors use:

```json
{
  "error": "safe human-readable message",
  "code": "STABLE_ERROR_CODE"
}
```

Request validation errors additionally include a safe `details` array containing locations, generic messages, and Pydantic error types. Submitted values are not echoed.

## Status Map

| Status | Code | Meaning |
|---:|---|---|
| 400 | `BAD_REQUEST` | Invalid state or malformed request accepted by the route layer. |
| 401 | `UNAUTHORIZED` | Missing, malformed, expired, invalid-signature, or unknown-user bearer token. |
| 403 | `FORBIDDEN` | Authenticated role or ownership policy denies the operation. |
| 404 | `NOT_FOUND` | Resource or route target does not exist. |
| 409 | `CONFLICT` | Reserved by the shared contract for conflicting state; no confirmed frontend endpoint currently emits it. |
| 413 | `REQUEST_TOO_LARGE` | Request exceeds the 10 MB middleware limit. |
| 422 | `VALIDATION_ERROR` | Request schema or domain input validation failed. |
| 429 | `RATE_LIMITED` | Reserved; no rate limiter is implemented or verified. |
| 500 | `INTERNAL_ERROR` | Unhandled server failure; no exception detail is returned. |
| 502 | `BAD_GATEWAY` | Reserved for a future gateway/deployment boundary; no executable gateway exists. |
| 503 | `SERVICE_UNAVAILABLE` | Reserved for unavailable dependencies; no confirmed route currently emits it. |

## Changes

The shared exception registry now handles FastAPI `HTTPException` with stable codes while preserving safe authentication headers. Request-size middleware responses now include `REQUEST_TOO_LARGE`. Existing custom `ServiceError`, validation, and 500-safe responses remain intact.

## Frontend Rules

The frontend should branch on status/code, not arbitrary exception strings. It must show generic messages for 500, tool failures, network failures, and timeouts. It must never render raw proof-job diagnostics, stack traces, commands, paths, credentials, or submitted private values.

Network failure and timeout are transport conditions, not backend JSON errors. Retry policy, rate-limit headers, correlation IDs, and gateway 502/503 behavior remain UNKNOWN.

## Tests

Existing shared security tests cover 400/403/404/422/500-safe responses and request-size limits. New closure tests cover stable 401 output; focused suites cover 403 role denial and proof-error sanitization.

## Unresolved Items

No rate limiting, timeout header, retry-after contract, gateway response, or service-unavailable behavior is implemented. These must be resolved before production frontend retry logic is finalized.

## Residual Risks

Some domain code still raises FastAPI exceptions with human-readable details. The shared handler now preserves those details when they are already safe; future routes must not put sensitive values into exception details. Live reverse-proxy behavior is unverified.

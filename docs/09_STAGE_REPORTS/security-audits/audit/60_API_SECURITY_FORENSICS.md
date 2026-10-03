# Phase 8: API Security and Input Validation Audit

## Scope
Audit of API boundary enforcement, Pydantic schema validation, and request limits across all FastApi routes to prevent Denial of Service (DoS), payload injection, and parameter tampering.

## Findings

### 1. Unbounded Path Parameters (DoS Vector)
- **Status:** **FAIL / HIGH DEFECT**
- **Location:** `vulnerability_service/app/api/routes/vulnerability_routes.py`
- **Details:** The `approve_snapshot` and `revoke_snapshot` endpoints type their path parameters as `snapshot_id: str`. This completely bypasses FastAPI's built-in UUID length and format validation. The unbounded string is passed directly into a SQLAlchemy filter (`VulnerabilitySnapshot.id == snapshot_id`). An attacker supplying an abnormally large string (e.g., several megabytes) in the URL path forces the database driver or Python's UUID parser into expensive type-casting operations, causing memory exhaustion and triggering HTTP 500 Application Crashes rather than safe HTTP 422 Validation Errors.
- **Context:** The `shared/security.py` module actually provides a `validate_uuid` helper specifically to prevent this, but it is orphaned and never used by any route.

### 2. Request Size Limits (10 MB Cap)
- **Status:** **PASS**
- **Location:** `shared/security.py` (`RequestSizeLimitMiddleware`) and `sbom_schemas.py`
- **Details:** The `SBOMUploadRequest` schema intentionally leaves the `content` string (the raw SBOM payload) unbounded at the Pydantic level. However, the custom `RequestSizeLimitMiddleware` correctly wraps the ASGI `receive` stream, enforcing a strict 10 MB payload limit by tracking the stream's `body_size`. This successfully mitigates memory exhaustion attacks that attempt to bypass `Content-Length` header checks.

### 3. Pydantic String Bounding
- **Status:** **PASS**
- **Location:** `policy_schemas.py`, `verification_schemas.py`
- **Details:** With the exception of the SBOM `content` (protected by middleware), all user-controlled strings are strictly bounded using `max_length`. For example, `VerifyProofRequest.proof_artifact` is bounded to 64KB (`max_length=65536`), and identifiers are restricted to `max_length=255` or `max_length=128`. This prevents malicious payload injection in subsequent processing tiers.

### 4. PURL Validation Regular Expression (ReDoS Resistance)
- **Status:** **PASS**
- **Location:** `shared/utils/purl.py`
- **Details:** The `_PURL_PATTERN` regular expression evaluates the package URL scheme. The regex uses linear captures (`(?P<remainder>.+)`) and avoids nested quantifiers (e.g., `(a+)+`). This ensures that malformed PURLs cannot trigger catastrophic backtracking (ReDoS) during the vulnerability ingestion normalization phase.

## Required Fixes
- **Path Parameter Coercion:** Refactor `vulnerability_routes.py` to type `snapshot_id` as `UUID` (e.g., `snapshot_id: UUID = Path(...)`) to guarantee strict format and length validation at the FastAPI boundary before interacting with SQLAlchemy.

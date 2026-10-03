# Phase 2: Authentication Forensic Review

## Scope
Audit of `backend/shared/auth.py` and `backend/shared/security.py` with a focus on JWT validation, password handling, and authentication flows.

## Findings

### 1. JWT Signature and Expiration Validation
- **Status:** **PASS**
- **Details:** 
  - `get_current_user` correctly uses `jwt.decode` with `algorithms=["HS256"]`, mitigating `none` algorithm attacks.
  - `options={"require": ["exp", "sub"]}` ensures the expiration claim is required. PyJWT automatically validates the `exp` claim if present, so expired tokens will be correctly rejected.

### 2. Universal Application of Authentication
- **Status:** **PASS**
- **Details:** `get_current_user` is injected as a dependency across all tested endpoints (zkp, sbom, verification, policy, vulnerability, metrics), ensuring unauthenticated access is blocked.

### 3. JWT Secret Configuration in Production
- **Status:** **FAIL / CRITICAL DEFECT**
- **Details:** `get_jwt_secret()` generates an ephemeral secret via `secrets.token_urlsafe(32)` if `JWT_SECRET_KEY` is missing. While this avoids a hardcoded default (like "secret"), it introduces a critical production failure: in a multi-worker or multi-container environment (e.g., Gunicorn/Uvicorn with multiple workers or Kubernetes deployments), each worker will generate a different ephemeral secret. A token issued by Worker A will be rejected by Worker B. It masks a missing configuration and replaces it with unpredictable `401 Unauthorized` errors.

### 4. Timing Attack Mitigation
- **Status:** **PASS**
- **Details:** `verify_dummy_password()` is correctly implemented to hash a predefined string when a user is not found, mitigating username enumeration timing attacks.

## Required Fixes
- **Authentication Stability:** The fallback to `secrets.token_urlsafe(32)` must be modified. If `JWT_SECRET_KEY` is absent in a production environment (or entirely), the application must crash on startup (fail-fast) rather than generating an ephemeral secret, to ensure stateless JWT architecture remains stable across multiple workers.

# Phase 10: Configuration, Secrets, and Dependency Audit

## Scope
Audit of application configuration management, secret handling, cryptographic material initialization, and third-party dependencies (`requirements.txt`).

## Findings

### 1. Silent Ephemeral JWT Secret Fallback in Production
- **Status:** **FAIL / HIGH DEFECT**
- **Location:** `backend/shared/auth.py` and `backend/shared/config.py`
- **Details:** The `auth.py` module defines `get_jwt_secret()`, which attempts to read `JWT_SECRET_KEY` from the environment. If unset, it silently generates an ephemeral cryptographic key using `secrets.token_urlsafe(32)`. While convenient for single-node local development, this is highly dangerous for production.
- **Root Cause:** The `validate_config()` function in `shared/config.py` explicitly enforces the presence of `DB_PASSWORD`, `DB_HOST`, and `DB_NAME`, successfully failing closed if they are missing. However, it completely omits any validation for `JWT_SECRET_KEY`.
- **Impact:** If operators deploy the application without supplying `JWT_SECRET_KEY`, the application will silently start up with an ephemeral key. Any pod restart, deployment, or auto-scaling event will generate a *new* ephemeral key, immediately invalidating all active JWT sessions.

### 2. Dependency Audit
- **Status:** **PASS**
- **Location:** `backend/shared/requirements.txt`
- **Details:** All backend dependencies are strictly pinned to exact versions. Cryptographic and security boundaries rely on standard, well-maintained libraries (e.g., `bcrypt==5.0.0`, `PyJWT==2.12.1`). No outdated or known-compromised packages are present.

### 3. Safe Configuration Logging and Defaults
- **Status:** **PASS**
- **Location:** `backend/shared/config.py`
- **Details:** The `DatabaseSettings` dataclass properly overrides `__repr__` and implements a `safe_url` property to ensure that the `DB_PASSWORD` is masked. The `validate_config` function strictly adheres to logging the masked URL (`safe_url`), preventing credential leakage into application telemetry or cloud logging providers. Additionally, the CORS defaults are appropriately scoped to development origins (`localhost`, `127.0.0.1`) and can be safely overridden via `CORS_ORIGINS`.

## Required Fixes
- **Configuration Validation:** Update `validate_config` in `shared/config.py` (or a dedicated auth config module) to mandate the presence of `JWT_SECRET_KEY` when `DEBUG=false` or `ENV=prod`. If running in production, the application must refuse to start (fail closed) rather than silently falling back to an ephemeral key.

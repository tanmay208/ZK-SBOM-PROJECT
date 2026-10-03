# Phase 6: Crypto Profile and Production/Dev Separation Audit

## Scope
Audit of `backend/shared/crypto/config.py`, `profile.json`, and the environment configuration logic separating development circuits from production circuits.

## Findings

### 1. Insecure Default and Unusable Production Profile
- **Status:** **FAIL / CRITICAL DEFECT**
- **Location:** `backend/shared/crypto/profile.json` and `config.py`
- **Details:** The system's active cryptographic profile defaults to `"dev"`. The `"prod"` profile is shipped with `vk_hash: null`. The config validation in `config.py` raises a fatal `CryptoProfileConfigError` if the verification key hash is null. Therefore, if an operator attempts to deploy with `CRYPTO_PROFILE=prod`, the application crashes on startup. This effectively forces all environments (including production) to silently fallback to the `"dev"` profile as a workaround.

### 2. SMT Depth Configuration Disconnect
- **Status:** **FAIL / HIGH DEFECT**
- **Location:** `backend/shared/crypto/smt.py`
- **Details:** The `profile.json` correctly defines `smt_depth` (e.g., 256) for each profile. However, `smt.py` completely ignores the active profile's configuration. Instead, it relies on a hidden environment variable: `SMT_DEPTH = 3 if os.environ.get("DEV_MODE") == "1" else 256`. 
If `CRYPTO_PROFILE=dev` is active (using `circuits_dev` which requires depth 3) but `DEV_MODE=1` is not set in the environment, Python generates an SMT path of 256 elements, causing `nargo execute` to crash due to a witness array length mismatch. 

### 3. Production Circuit is a Mock (Not Production-Ready)
- **Status:** **FAIL / CRITICAL DEFECT**
- **Location:** `circuits/src/main.nr`
- **Details:** Even if the `prod` profile were fixed (by populating `vk_hash`), the underlying production circuit (`circuits/src/main.nr`) is explicitly marked as a mock. It hardcodes `global MAX_COMPONENTS: u32 = 8;`. Real-world SBOMs contain hundreds or thousands of components. The `ProverService` checks `active_count > self._profile.max_components` and will instantly reject nearly all production workloads with a "Component count exceeds profile scale" error.

## Required Fixes
- **Profile Initialization:** Populate the correct `vk_hash` for the `prod` profile. Remove the `active_profile: "dev"` fallback, and instead require `CRYPTO_PROFILE` to be explicitly set in the environment, failing securely if it is missing.
- **Circuit Scaling:** The `circuits` directory must be updated to a production-ready scale (e.g., `MAX_COMPONENTS = 1024`).
- **Configuration Unification:** Refactor `smt.py` to read `smt_depth` dynamically from `get_crypto_profile().smt_depth` rather than relying on the `DEV_MODE` environment variable.

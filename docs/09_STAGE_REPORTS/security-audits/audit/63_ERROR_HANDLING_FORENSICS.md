# Phase 11: Error Handling and Information Disclosure Audit

## Scope
Audit of global exception handlers, log sanitization filters, and API response structures to ensure no internal stack traces, database metadata, or Private Data is leaked to the client.

## Findings

### 1. Global Exception Handlers (Safe Wrappers)
- **Status:** **PASS**
- **Location:** `backend/shared/exceptions.py`
- **Details:** The global exception handler explicitly intercepts `Exception` and `RequestValidationError`. It logs the true exception type server-side while guaranteeing that the HTTP response is a generic `Internal server error` (500) or safe `Validation error` (422) payload. This successfully prevents database connection strings, ORM traces, or internal logic branches from leaking to end users.

### 2. Log Redaction (SecurityAwareFilter)
- **Status:** **PASS**
- **Location:** `backend/shared/security.py`
- **Details:** The `SecurityAwareFilter` applies structural regex matching (e.g., `pkg:[a-z]+/.+`, `component_hash`, `merkle_path`) to redact sensitive private data from Python log records. Since this filter intercepts all logs traversing the root logger, even accidental logging of private data by developers will be scrubbed before hitting stdout or telemetry pipelines.

### 3. Cryptographic Subprocess Stderr Leakage (Private Witness Exfiltration)
- **Status:** **FAIL / HIGH DEFECT**
- **Location:** `backend/zkp_service/app/services/prover_service.py`
- **Details:** The prover service captures `stderr` from the `nargo execute` and `bb prove` shell commands and writes it verbatim to the `error_message` column of the `ProofJob` record. This column is then exposed to the client via `ProofJobResponse`.
- **Impact:** If the Noir circuit or Barretenberg prover crashes (e.g., due to a failed constraint, assertion, or Out-Of-Memory panic), the `stderr` output often includes Rust backtraces, execution context, and dumps of the failing witness variables. Because the witness explicitly contains the Private Data (raw SBOM `components` array and `vulnerability_scores`), an attacker could intentionally craft an oversized or misaligned request to trigger a prover panic, causing the backend to hand over the private vulnerability data of a target snapshot via the API's `error_message` field.

## Required Fixes
- **Prover Error Masking:** Refactor `prover_service.py` so that `execute_result.stderr` and `prove_result.stderr` are strictly logged server-side (where `SecurityAwareFilter` can redact them). The `error_message` persisted to the database and returned to the user must be a safe, static string (e.g., "Prover execution failed due to a constraint violation or internal error").

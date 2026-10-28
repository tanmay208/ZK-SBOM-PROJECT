# Phase 7: Prover and Subprocess Security Audit

## Scope
Audit of subprocess invocation, command injection vectors, and temporary file lifecycle management within the ZKP generation and verification boundaries (`prover_service.py` and `verifier.py`).

## Findings

### 1. Command Injection Resistance
- **Status:** **PASS**
- **Location:** `zkp_service/app/services/prover_service.py` and `verification_service/app/core/verifier.py`
- **Details:** Both services orchestrate the Noir and Barretenberg cryptographic toolchains via `subprocess.run` into a WSL environment. The arguments passed into the shell (`bash -c`) or directly to the WSL executable are interpolated with `job_id` and `verify_id`. Since these identifiers are strictly validated as `UUID.hex` strings (alphanumeric and hyphens only), it is mathematically impossible for a malicious actor to supply shell metacharacters (e.g., `; rm -rf /`) to achieve arbitrary command execution.

### 2. Ephemeral Artifact Lifecycle (File Cleanup)
- **Status:** **PASS**
- **Location:** `prover_service.py` (`finally` block) and `verifier.py` (`finally` block)
- **Details:** The services correctly use `try...finally` blocks to guarantee the deletion of sensitive and intermediate cryptographic artifacts (`Prover.toml`, `.gz` witness files, and `.proof` payloads). Regardless of whether the subprocess succeeds, times out, or crashes with a non-zero exit code, the filesystem is wiped of the ephemeral files, preventing disk exhaustion and cross-job data leakage.

### 3. Subprocess Timeout Enforcement
- **Status:** **PASS**
- **Location:** Both services.
- **Details:** The services enforce strict timeouts (`timeout=300` for proving, `timeout=60` for verifying). This protects the backend from Denial of Service (DoS) attacks where a maliciously crafted circuit or proof could cause the prover/verifier to enter an infinite loop or hang the WSL container.

## Required Fixes
- None required for Phase 7. Subprocess invocation and file lifecycle are highly secure.

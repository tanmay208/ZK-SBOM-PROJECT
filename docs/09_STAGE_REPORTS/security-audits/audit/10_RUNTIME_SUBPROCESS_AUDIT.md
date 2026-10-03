# Runtime and Subprocess Audit

## Observed Invocations

`ProverService` invokes WSL/Nargo with an argument list and invokes Barretenberg through `bash -c`; `NoirVerifier` writes a UUID-named proof and invokes Barretenberg through `bash -c`. Both set timeouts and capture stdout/stderr.

## Findings

- No `shell=True` was found. The Nargo command's attacker-influenced job ID is a UUID from the database/request schema and is not an arbitrary shell string. This suspected injection path is a FALSE POSITIVE for the current code.
- Barretenberg command strings interpolate UUIDs generated internally or parsed as UUIDs. Direct shell injection is not demonstrated, but using `bash -c` expands the attack surface and should be removed. Classification: HARDENING RECOMMENDATION.
- Timeouts are 300 seconds for execute/prove and 60 seconds for verify. The code does not evidence process-group termination or cleanup of descendants after timeout. Classification: SECURITY WEAKNESS / resource risk.
- stdout/stderr are captured without explicit output-size limits. Error stderr is persisted in `error_message` and returned in job responses. Classification: CONFIRMED SECURITY WEAKNESS.
- WSL distribution, executable locations, and working directories are hardcoded; `nargo`/`bb` are unavailable on the audited Windows PATH. Production execution is UNVERIFIED.
- Per-job filenames use UUIDs and cleanup runs in `finally`; verification proof cleanup is also in `finally`. No symlink or permission-hardening evidence was found for circuit directories.

## Required Tests

Timeout with a child process, oversized stderr, concurrent jobs, stale artifact collision, symlink replacement, failed cleanup, and production/dev executable-profile selection.

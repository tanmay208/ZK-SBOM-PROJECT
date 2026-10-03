# Filesystem and Artifact Audit

## Observations

- Prover writes `Prover_<job UUID>.toml` under the selected circuit directory, creates target witness/proof artifacts, base64-reads the proof, and removes temporary files in a `finally` block.
- Verifier writes a random UUID proof file under the selected circuit `proofs/` directory and removes it in `finally`.
- Production and development circuit directories are repository-local and writable by the application process in the observed implementation.
- Large generated artifacts and proof-like files are present: production target JSON about 55 MB, development target JSON about 1 MB, a 10-byte production proof placeholder, fake and mutated development proofs, and an untracked `.bin/nargo` executable/archive.

## Findings

- Cleanup is best-effort. If deletion fails, stale private/proof artifacts remain; no startup scavenger or permission policy was found. Classification: SECURITY WEAKNESS.
- Prover TOML contains roots, policy values, component hashes, scores, and SMT paths. It is temporary private witness material. The code does not apply restrictive file permissions and the application runs with unspecified container privileges. Classification: HARDENING RECOMMENDATION; exposure impact is unverified.
- Artifact selection depends only on `DEV_MODE`; there is no embedded circuit/VK digest or artifact provenance check. Classification: SECURITY WEAKNESS.
- UUID names provide collision resistance but not authorization or filesystem isolation. No TOCTOU exploit is confirmed because names are generated internally and opened directly.

## Required Evidence

UNVERIFIED — INSUFFICIENT EVIDENCE for host filesystem permissions, container user, mounted-volume permissions, backup retention, crash leftovers, and whether committed proof artifacts are used by any runtime path.

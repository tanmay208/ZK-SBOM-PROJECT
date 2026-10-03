# STAGE 18 BASELINE

**Date:** 2026-10-01

## 1. Toolchain Versions
- **Nargo:** 0.32.0 (noirc version 0.32.0+c679f01a)
- **Barretenberg:** 0.46.1
- **Python:** 3.13.12 (WSL/Kali Linux)

## 2. Git State
- **Staged Changes:** Interrupted PostgreSQL configuration changes (`backend/shared/config.py`, `backend/shared/requirements.txt`). Docs moved to `docs/Main Docs/`.
- **Untracked Files:** Stage 17 benchmarking and feasibility artifacts (`test_feasibility.py`, `test_smt_scaling.py`, `smt_scaling_results.json`). `circuits_dev/` and `circuits/`.
- **Cleanliness:** The repository is currently inconsistent due to the partial PostgreSQL migration from Stage 17, but the cryptographic sub-system remains intact. 

## 3. Current Crypto Profile
- **Hash Function:** Poseidon BN254.
- **SMT Logical Depth:** 256.
- **Component Identity:** PURL-authoritative, full 256-bit hash as SMT key (LSB-first).
- **Vulnerability Semantics:** CVSS 0 is valid. `presence=1` leaf = `Poseidon(hash, score)`, `presence=0` leaf = `0`. Empty leaf = `0`.
- **Policy Hash:** `Poseidon(policy_max_cvss)`.

## 4. Current Circuit State
- `circuits_dev/`: Known-good 8-component monolithic circuit (SMT depth 3 fallback).
- `circuits/`: Known-broken 1024-component monolithic circuit (SMT depth 256, experimental arithmetic predication logic, causes OOM).

## 5. Implementation Target
To implement the 8-segment SMT path decomposition protocol (Stage 17-C).
The target starts at `C=1` component (Phase 1) and scales to `C=32` components per chunk (Phase 7).
No toolchain updates or PostgreSQL fixes will be made during this cryptographic implementation.

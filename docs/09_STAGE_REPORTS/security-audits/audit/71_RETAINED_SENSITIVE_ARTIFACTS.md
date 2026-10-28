# 71 — Retained Sensitive Cryptographic Artifacts and Audit Evidence

## Executive Summary
This document details the forensic justification for preserving security-sensitive cryptographic assets, compiled circuits, verification keys, toolchain binaries, and audit proof evidence. None of these files were deleted during the cleanup. Each artifact was evaluated against seven rigorous criteria to prove its necessity.

---

## 1. Cryptographic Evaluation Matrix

| Artifact Path | Size | SHA-256 Digest | Profile Required | Test Ref | Audit Report Ref | Status & Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `.bin/nargo` | 44,603,960 B | `4dc7fef39e6e8e8982cf0b67540209e99a89669dcbb7c4091e70498e72ba7eeb` | Toolchain | Runtime Toolchain | Baseline 00, 11 | **RETAINED** (Nargo v0.32.0 Linux ELF; verified in WSL) |
| `circuits_dev/target/sbom_zkp.json` | 1,086,829 B | `c6293324ee020f32a1fffd7303c52f88e1297c5e56a52d98dfeb6a25d171cd5d` | **YES (`dev`)** | `test_crypto_profile.py` | 00, 09, 11, 53 | **RETAINED** (Active dev circuit; validated by `shared.crypto.config`) |
| `circuits_dev/target/vk` | 1,719 B | `a8733e6ca6434360fac2c91a7e94d9b4ff70a74ed4a0d392d6517032afc29e75` | **YES (`dev`)** | `test_crypto_profile.py` | 00, 09, 11, 53 | **RETAINED** (Active dev VK; validated by `shared.crypto.config`) |
| `circuits/target/sbom_zkp.json` | 54,913,292 B | `2e493e08116bfa26cb9ead989f65d901de9bec122cdea04e797b46a0e2dac747` | **YES (`prod`)** | Hashed in `profile.json` | 00, 09, 11, 53 | **RETAINED** (Full production ACIR circuit target) |
| `circuits/proofs/sbom_zkp.proof` | 10 B | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | No | Negative / Format tests | 01, 11, 17, 19 | **RETAINED** (Audit evidence: placeholder proof artifact) |
| `circuits_dev/test_fake.proof` | 2,000 B | `112814bb66c888d227926b479ca404bc5db825709cf7e85c13b28ee52c2fb8b2` | No | Negative / Format tests | 11, 17, 19, 22 | **RETAINED** (Audit evidence: synthetic fake proof artifact) |
| `circuits_dev/proofs/sbom_zkp.proof.mutated` | 2,240 B | `b68074d2cb6d95da5b1b4bcbb2081d6f54c2598380cf05c6d99723ec017d8400` | No | Adversarial proof tests | 11, 17, 19, 22 | **RETAINED** (Audit evidence: tampered proof rejection test) |
| `circuits_dev/proofs/sbom_zkp.proof.mutated2` | 2,240 B | `61f8515c0e27188177df83ba2d0a07106607e467d58aa488cb3bfef4396b27d1` | No | Adversarial proof tests | 11, 17, 19, 22 | **RETAINED** (Audit evidence: secondary mutated proof artifact) |
| `circuits/Prover.toml` | 144,258 B | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (non-empty) | Witness Input | `scripts/test_main_circuit.py` | 11 | **RETAINED** (Pre-computed witness vector with depth-256 SMT path) |
| `backend/shared/crypto/profile.json` | 683 B | Validated | **Active Manifest** | All crypto tests | 00, 53 | **RETAINED** (Defines active profile, hashes, and constraint bounds) |
| `backend/shared/tests/vectors/crypto_vectors.json` | 24,892 B | Validated | Test Fixture | All vector tests | 00, 09, 11 | **RETAINED** (Authoritative frozen cryptographic vectors) |

---

## 2. Seven-Question Forensic Assessment

### 1. Is it required by the active profile?
- **YES**: `circuits_dev/target/sbom_zkp.json` and `circuits_dev/target/vk` are explicitly required by the active `dev` profile. At application startup, `shared.crypto.config.CryptoProfile._validate_artifacts()` computes the SHA-256 digest of both files and fails fast if they are absent or if their hashes diverge.
- **YES**: `circuits/target/sbom_zkp.json` is required by the `prod` profile configuration.

### 2. Is it referenced by tests?
- **YES**: `backend/shared/tests/test_crypto_profile.py` verifies hash integrity against `profile.json`.
- **YES**: `backend/shared/tests/test_authoritative_vectors.py` and `test_crypto_vectors.py` assert deterministic mathematical behavior against `crypto_vectors.json`.

### 3. Is it referenced by reports?
- **YES**: `circuits/proofs/sbom_zkp.proof`, `circuits_dev/test_fake.proof`, `sbom_zkp.proof.mutated`, and `sbom_zkp.proof.mutated2` are documented across Security Audit Reports 01, 09, 11, 17, 19, and 22. Deleting them would invalidate the audit evidence chain.

### 4. Is it required for reproducibility?
- **YES**: `circuits/Prover.toml` and `.bin/nargo` allow developers to reproduce circuit compilation and constraint checking on demand without network access.

### 5. Is it a placeholder or invalid artifact?
- `circuits/proofs/sbom_zkp.proof` (10 bytes) is indeed a placeholder proof. Per Phase 6 guidelines: *"If a checked-in artifact is invalid/placeholder, do not silently delete it. Document it as a release blocker or replacement candidate."* It is retained as audit evidence.

### 6. Is it a valid production artifact?
- `circuits/target/sbom_zkp.json` is the compiled production Noir circuit. However, production Verification Key generation (`vk_hash: null` in `profile.json`) remains pending Barretenberg toolchain setup.

### 7. Is it only temporary experiment residue?
- **NO**: None of the retained cryptographic assets are temporary residue. True temporary residue (such as `scripts/noir_src/` and stale `__pycache__`) has been removed.

---

## 3. Toolchain Binary Governance: `.bin/nargo`

The binary `.bin/nargo` (44.6 MB) was retained after confirming:
1. Executable file format: Linux x86_64 ELF 64-bit LSB pie executable.
2. Invocation via WSL: `wsl /mnt/e/Main\ Project/.bin/nargo --version` returns `nargo version = 0.32.0`.
3. Circuit validation: Compiles `circuits_dev` successfully (`[sbom_zkp] Constraint system successfully built!`).
4. Hygiene: `.bin/` was added to `.gitignore` so this binary does not pollute Git commits while remaining available for local development and CI under Linux/WSL.

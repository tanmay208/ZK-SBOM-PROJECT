# STAGE 19: C=32 CRYPTOGRAPHIC RESULTS

**Date:** 2026-10-01
**Component Count (C):** 32 (One full chunk)
**SMT Logical Depth:** 256 (Decomposed into 8 segments of 32 levels)
**Toolchain:** Nargo 0.32.0, Barretenberg 0.46.1

## 1. Segment Init (Levels 0–31)
- **Compile Time:** 991.63s
- **Compile RSS:** 5.40 GB
- **Compile VM:** 6.56 GB
- **Circuit Artifact Size:** 36.76 MB
- **Witness Generation Time:** 15.10s (RSS: 1.07 GB)
- **Proof Generation Time (Write VK + Prove):** 79.15s (Prove RSS: 7.91 GB)
- **Proof Size:** 2.25 KB
- **Verification Time:** 0.04s
- **Result:** SUCCESS

## 2. Segment Mid (Levels 32–63) *Average across 6 segments*
- **Compile Time:** 577.49s
- **Compile RSS:** 4.23 GB
- **Compile VM:** 5.22 GB
- **Circuit Artifact Size:** 28.78 MB
- **Witness Generation Time:** ~12.0s (RSS: 0.91 GB)
- **Proof Generation Time (Write VK + Prove):** ~41.0s (Prove RSS: 4.50 GB)
- **Proof Size:** 2.22 KB
- **Verification Time:** 0.05s
- **Result:** SUCCESS

## 3. Segment Final (Levels 224–255)
- **Compile Time:** 556.58s
- **Compile RSS:** 4.27 GB
- **Compile VM:** 5.30 GB
- **Circuit Artifact Size:** 27.78 MB
- **Witness Generation Time:** 11.47s (RSS: 0.88 GB)
- **Proof Generation Time (Write VK + Prove):** 43.43s (Prove RSS: 4.33 GB)
- **Proof Size:** 2.19 KB
- **Verification Time:** 0.05s
- **Result:** SUCCESS

## 4. Chunk Verification Validation
- [x] All 8 segment proofs generated and verified successfully.
- [x] `components_commit` is strictly identical across all 8 segment proofs.
- [x] `hash_out_commit` strictly matches `hash_in_commit` across segment boundaries.
- [x] `global_sbom_root`, `policy_hash`, and `vulnerability_db_root` correctly bound.
- [x] Negative security tests for C=32 confirm verification failure on tampered segment linkage.

## Conclusion
The full C=32 component chunk scaling architecture performs exactly within expectations, establishing a rock-solid, resource-bounded proving paradigm that scales to the 1024-component deployment target.

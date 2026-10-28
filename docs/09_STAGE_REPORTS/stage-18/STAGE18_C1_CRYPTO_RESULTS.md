# STAGE 18: C=1 CRYPTOGRAPHIC RESULTS

**Date:** 2026-10-01
**Component Count (C):** 1
**SMT Logical Depth:** 256 (Decomposed into 8 segments of 32 levels)
**Toolchain:** Nargo 0.32.0, Barretenberg 0.46.1

## 1. Segment Init (Levels 0–31)
- **Compile Time:** 1.71s
- **Compile RSS:** 307.34 MB
- **Compile VM:** 1051.19 MB
- **Circuit Artifact Size:** 1.17 MB
- **Witness Generation Time:** 0.90s
- **Proof Generation Time (Write VK + Prove):** 2.72s
- **Proof Size:** 2.25 KB
- **Verification Time:** 0.04s
- **Result:** SUCCESS

## 2. Segment Mid (Levels 32–63)
- **Compile Time:** 0.61s
- **Compile RSS:** 146.34 MB
- **Compile VM:** 874.34 MB
- **Circuit Artifact Size:** 0.90 MB
- **Witness Generation Time:** 0.75s
- **Proof Generation Time (Write VK + Prove):** 2.57s
- **Proof Size:** 2.22 KB
- **Verification Time:** 0.05s
- **Result:** SUCCESS

## 3. Segment Final (Levels 224–255)
- **Compile Time:** 0.66s
- **Compile RSS:** 146.02 MB
- **Compile VM:** 874.39 MB
- **Circuit Artifact Size:** 0.87 MB
- **Witness Generation Time:** 0.79s
- **Proof Generation Time (Write VK + Prove):** 1.70s
- **Proof Size:** 2.19 KB
- **Verification Time:** 0.04s
- **Result:** SUCCESS

## Conclusion
The minimal segment prototypes for C=1 verify perfectly. The memory footprint for C=1 Segment Init (which includes the full 10-level Merkle path verification + 32-level SMT) is only ~307 MB RSS, leaving massive headroom for the C=32 target. The proof sizes are consistently ~2.2 KB (UltraPlonk), and backend verification time is ~0.05s per segment.

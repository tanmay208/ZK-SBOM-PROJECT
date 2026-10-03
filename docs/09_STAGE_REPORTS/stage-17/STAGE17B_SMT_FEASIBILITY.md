# STAGE 17-B — SMT PATH DECOMPOSITION FEASIBILITY STUDY

**Date:** 2026-10-01
**Nargo Version:** 0.32.0

## 1. Executive Summary

This read-only feasibility study investigated the memory scaling characteristics of the Nargo compiler when processing the 256-level Sparse Merkle Tree (SMT) path verification logic. By isolating the SMT path logic into a minimal circuit and varying both the logical depth and the number of components, we identified the fundamental bottleneck that caused the OOM failures in Stage 17.

**Conclusion:** The compiler memory overhead scales strictly with the total number of Poseidon hashes (and corresponding loops) in the circuit, regardless of whether those hashes come from one deep SMT path or multiple shallow ones. A single 256-level SMT path consumes ~1.1 GB of RAM to compile. 

## 2. Benchmark Results

| Components | SMT Depth | Total Hashes | Compile Time | Peak RSS (MB) | Peak VM (MB) | Artifact (MB) | Status |
|------------|-----------|--------------|--------------|---------------|--------------|---------------|--------|
| 1          | 16        | 16           | 0.9s         | 199.1         | 928.5        | 0.45          | SUCCESS|
| 1          | 32        | 32           | 1.3s         | 258.3         | 987.2        | 0.86          | SUCCESS|
| 1          | 64        | 64           | 2.5s         | 385.0         | 1116.9       | 1.67          | SUCCESS|
| 1          | 128       | 128          | 7.5s         | 638.5         | 1376.9       | 3.29          | SUCCESS|
| 1          | 256       | 256          | 24.1s        | 1106.6        | 1859.0       | 6.53          | SUCCESS|
| 2          | 32        | 64           | 2.6s         | 385.1         | 1116.2       | 1.70          | SUCCESS|
| 4          | 32        | 128          | 8.0s         | 631.3         | 1362.2       | 3.37          | SUCCESS|
| 8          | 32        | 256          | 27.5s        | 1139.4        | 1887.2       | 6.71          | SUCCESS|

## 3. Interpretation of Scaling Behavior

**The scaling is perfectly consistent with total hash iterations:**
- 1 component × 64 depth (64 hashes) uses **385.0 MB RSS**.
- 2 components × 32 depth (64 hashes) uses **385.1 MB RSS**.
- 1 component × 256 depth (256 hashes) uses **1106.6 MB RSS**.
- 8 components × 32 depth (256 hashes) uses **1139.4 MB RSS**.

The evidence indicates that memory usage scales almost perfectly linearly with the total number of constraint-heavy operations (Poseidon hashing and bitwise key splitting), rather than being dominated exclusively by either component count or SMT depth. 

**Extrapolation to Stage 17 failures:**
A 64-component chunk at SMT depth 256 requires `64 × 256 = 16,384` hashes.
Linearly scaling the 1.1 GB cost of 256 hashes by a factor of 64 gives a theoretical compiler memory requirement of **~70 GB**. This perfectly explains why the 64-component chunk timed out and OOM-killed (peaking at ~15.4 GB on a 16 GB WSL instance). The monolithic 1024-component circuit would require an estimated **~1.1 TB** of compiler RAM.

## 4. Feasibility of SMT Decomposition

SMT path decomposition appears highly feasible. A 32-level circuit requires only ~258 MB of RAM to compile, which easily fits within the target 8-16 GB environment constraint, even if combined into chunks of 8 or 16 components (which would require ~1.1 GB to 2.2 GB).

## 5. Potential Protocol Architecture

Since the logical statement must remain *"the complete 256-level SMT path verifies against the authoritative vulnerability DB root"*, the 256-level path can be horizontally decomposed into 8 sequential segments of 32 levels each.

**Design:**
Each segment circuit verifies 32 levels of the path. The segments are linked algebraically via public inputs (intermediate node commitments):

- **Segment 0:** `hash_in` (the leaf), `path[0..31]`, `key[0..31]`, outputs `hash_out_0`
- **Segment 1:** `hash_in = hash_out_0`, `path[32..63]`, `key[32..63]`, outputs `hash_out_1`
- ...
- **Segment 7:** `hash_in = hash_out_6`, `path[224..255]`, `key[224..255]`, asserts `hash_out_7 == vulnerability_db_root`.

A higher-level component-chunking protocol can then process $N$ components per chunk. For example, a chunk could verify 8 components across a 32-level SMT segment, requiring 8 such chunks to complete the 256-level path for those 8 components.

## 6. Security Invariants

This decomposition preserves all exact cryptographic semantics:
- Poseidon BN254 remains the hash function.
- SMT logical depth remains 256.
- Field encoding, PURL identity, CVSS zero semantics, and existing leaf construction are strictly preserved.
- The LSB-first SMT direction semantics are preserved (merely partitioned).

No security equivalence is claimed yet until a formal verifier protocol is designed to securely assert the equivalence of intermediate inputs/outputs across the decomposed proofs.

## 7. Toolchain Observations

Nargo 0.32.0 is the limiting factor. The compiler unrolls arrays and loops in a way that consumes ~4.3 MB of RSS per Poseidon hash invocation during SSA generation/optimization. 

Newer stable Noir toolchains (e.g., 0.33+) provide compiler optimizations, data bus optimization, and better support for `fold` and recursive verification. These features could potentially mitigate this memory explosion natively or allow for built-in recursive aggregation of the decomposed proofs. However, as toolchain migration is not authorized, explicit decomposition at the protocol level is the required workaround for 0.32.0.

## 8. Risks

- **Verification Complexity:** The off-chain verifier (Verification Service) must ensure that the public inputs of Segment $(k)$ exactly match the outputs of Segment $(k-1)$. Any gap in this linkage completely compromises soundness.
- **Key Binding:** The verifier must re-assemble the 256-bit SMT key from the 8 `key_segment` inputs and ensure it corresponds to the correct component hash.
- **Proof Volume:** 1024 components × 8 segments = 8,192 proofs if done individually, or 128 chunked proofs if chunked by 8 components per proof. This will increase verification latency.

## 9. Recommended Next Stage

If the 8-component chunking over 32-level segments fits comfortably in ~1.1 GB (proven), recommend proceeding to a **formal SMT path decomposition protocol design**. The design must formally define the linkage of intermediate commitments and the verifier's exact responsibilities in establishing the full 256-level statement.

# STAGE 17-C — SMT DECOMPOSITION PROTOCOL DESIGN

## 1. Motivation
Stage 17-B established that Nargo 0.32.0 compiler memory scales linearly with the total number of Poseidon hash iterations (~4.3 MB RSS per hash). The monolithic 256-level SMT verification for 1024 components requires ~262,144 hashes, consuming ~1.1 TB of RAM. Even a 64-component chunk requires ~16,384 hashes, peaking at 15.4 GB before OOM/timeout. 

To satisfy the 8–16 GB deployment constraint without altering cryptographic semantics, we must horizontally decompose the 256-level logical SMT path into 8 sequential segments of 32 levels, algebraically linked by intermediate node commitments.

## 2. Existing SMT Semantics
The protocol must strictly preserve these existing definitions:
- **Leaf Construction**: `presence * Poseidon(component_hash, score)`. If `presence=0`, the leaf is `0`.
- **CVSS 0**: Handled correctly as `1 * Poseidon(component_hash, 0)`.
- **SMT Key Construction**: The full 256-bit `component_hash`.
- **Key Bit Extraction**: `key.to_le_bits(256)`, where bit 0 is the LSB and defines the direction at level 0 (the leaf).
- **Left/Right Selection**: For bit `i`, if `0`, `left = current_hash, right = sibling`. If `1`, `left = sibling, right = current_hash`.
- **Poseidon Invocation**: `current_hash = Poseidon([left, right])`.
- **Empty Leaf**: `0`.
- **Root Comparison**: The hash after 256 iterations must exactly match the global `vulnerability_db_root`.
- **Path Ordering**: `path[0]` is the sibling of the leaf. `path[255]` is the sibling of the root's child.

## 3. Segment Definition
The 256-level path is divided into 8 segments:
- **Segment 0**: Levels 0–31. Input state: computed `leaf`. Output state: `hash_out_0`.
- **Segment 1**: Levels 32–63. Input state: `hash_in_1`. Output state: `hash_out_1`.
- ...
- **Segment 7**: Levels 224–255. Input state: `hash_in_7`. Output state: `vulnerability_db_root`.

For each component in segment `k`, the circuit uses `path[k*32 .. k*32+31]` as the sibling path and extracts bits `k*32 .. k*32+31` from the component's 256-bit hash.

## 4. Public/Private Inputs
To process $C$ components per chunk proof safely, we use commitment arrays. 
We define 3 circuit variants for the decomposition pipeline:

**Init Circuit (Segment 0)**
- **Public Inputs:** `global_sbom_root`, `policy_hash`, `chunk_index`, `components_commit`, `hash_out_commit`
- **Private Witness:** `components[C]`, `scores[C]`, `presence[C]`, `paths[C][32]`, `all_1024_components[1024]`, `policy_max_cvss`

**Mid Circuit (Segments 1–6)**
- **Public Inputs:** `segment_index`, `components_commit`, `hash_in_commit`, `hash_out_commit`
- **Private Witness:** `components[C]`, `hash_in[C]`, `paths[C][32]`

**Final Circuit (Segment 7)**
- **Public Inputs:** `vulnerability_db_root`, `components_commit`, `hash_in_commit`
- **Private Witness:** `components[C]`, `hash_in[C]`, `paths[C][32]`

## 5. Intermediate Linkage
Equality between segments is enforced via **deterministic verifier-side comparison** (Option D combined with Option A).

The backend verifier receives all 8 proofs for a chunk. It independently computes and asserts:
1. `Proof[0].hash_out_commit == Proof[1].hash_in_commit`
2. `Proof[1].hash_out_commit == Proof[2].hash_in_commit`
...
7. `Proof[6].hash_out_commit == Proof[7].hash_in_commit`

By using `hash_out_commit = Poseidon(hash_out_array)`, we compress $C$ intermediate hashes into a single $O(1)$ public input per segment boundary.

## 6. Key Binding
The composed protocol guarantees that all 8 segments use the exact same logical 256-bit key.
This is achieved by making the full 256-bit `components` array a private witness in *every* segment circuit, and forcing each circuit to publicly expose `components_commit = Poseidon(components)`. 
The verifier enforces:
`Proof[0].components_commit == Proof[1].components_commit == ... == Proof[7].components_commit`.

Because every segment is forced to commit to the exact same 256-bit hash, the prover cannot independently choose different key bits for different segments. The $k$-th segment circuit extracts the full 256 bits of the private component hash and strictly applies bits `k*32` through `k*32+31`.

## 7. Root Binding
The chain of soundness:
1. **Init Circuit** generates `hash_out_0` dynamically from the cryptographically verified leaf.
2. The **Verifier** ensures `hash_out_0` flows unchanged into Segment 1, and so on until Segment 7.
3. The **Final Circuit** strictly binds its `hash_out` to the public `vulnerability_db_root`.
4. Therefore, there is an unbroken, cryptographically verified algebraic chain from the component leaf to the authoritative root.

## 8. Component Binding
Segment 0 is exclusively responsible for the lowest 32 levels (starting at level 0) and the leaf construction.
It takes `scores`, `presence`, and `policy_max_cvss`. 
It enforces:
1. `assert(scores[i] <= policy_max_cvss)`
2. `assert(presence[i] == 0 | 1)`
3. `leaf = presence * Poseidon(component_hash, scores[i])`

This preserves exact CVSS 0 semantics while ensuring inactive components strictly resolve to the empty leaf `0`.

## 9. Multi-Component Composition
Based on the Stage 17-B scaling data (1 hash = ~4.3 MB RAM), we evaluate:
**F. Hybrid Chunking (Component-level chunking grouped into Segment-level proofs)**

Using a chunk size of $C=32$ components is the mathematically safest optimum:
- **Segment 0**: 1023 hashes (Global Merkle Root) + 32 × 32 hashes (SMT) = 2,047 hashes. Estimated peak RSS: **~8.8 GB**.
- **Segments 1-7**: 32 × 32 hashes = 1,024 hashes. Estimated peak RSS: **~4.4 GB**.

Both fit comfortably within a 16 GB environment without risking the OOM threshold seen at ~15.4 GB. 
1024 components divided by 32 components per chunk = 32 chunks. 
32 chunks × 8 segment proofs = 256 total proofs.

## 10. Adversarial Analysis

The verifier strictly evaluates the proof array for a chunk. It rejects:
1. **Missing segment:** Array length != 8.
2. **Duplicate/Swapped segment:** The verifier matches `segment_index` public input against the array index `[0..7]`.
3. **Forged intermediate commitment:** The verifier asserts `hash_out_commit(k) == hash_in_commit(k+1)`. A forgery breaks this chain.
4. **Wrong component hash / Wrong SMT key:** The verifier asserts `components_commit` is identical across all 8 proofs. 
5. **Wrong vulnerability_db_root:** Checked explicitly on Proof 7.
6. **Segment from another SBOM:** Checked explicitly on Proof 0 via `global_sbom_root`.

## 11. Protocol Statement
*Logical equivalence argument:* 
The sequence of mathematical operations $H_{k+1} = Poseidon(L, R)$ performed over 256 iterations can be grouped associatively into 8 blocks of 32 iterations. Because the hash function is collision-resistant and deterministic, proving that intermediate states link correctly across the blocks is mathematically equivalent to computing the entire loop in a single context.

*Final composed statement:*
"I possess a set of 1024 components whose Merkle root is `global_sbom_root`. For chunk $j$, I have computed a 256-level SMT verification against `vulnerability_db_root` using identical 256-bit keys, partitioned into 8 verified algebraic segments."

## 12. Resource Model
- **Prover CPU**: Proving 256 small circuits is highly parallelizable across multiple cores.
- **Prover Memory**: Peak memory is bounded to ~8.8 GB during Segment 0 compilation.
- **Verifier Load**: 256 Barretenberg backend verifications. At ~0.5s each, total backend verification takes ~2 minutes sequentially, or seconds if parallelized.

## 13. Implementation Plan
1. Scaffold 3 Noir projects (`segment_init`, `segment_mid`, `segment_final`).
2. Update `ProverService` to generate the 8 witness sets per chunk (total 256 jobs).
3. Update `NoirVerifier` to receive an array of 8 proofs, verify each, and assert intermediate linkage public inputs.

## 14. Test Plan
- Unit tests: Verify Python `smt.py` outputs identical intermediate hashes at levels 32, 64, etc.
- Integration tests: Complete verification with valid and invalid intermediate commitments.

## 15. Remaining Unknowns
- How to store the 256 proofs efficiently in the database (e.g., grouped by chunk in a JSON column or separate rows).

## 16. Explicit Stage 17-D Gate Conditions
- [ ] Protocol design approved.
- [ ] Implementation authorized for Stage 18.
- [ ] No toolchain updates requested.

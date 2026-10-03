# STAGE 18: BACKEND CRYPTOGRAPHIC BOUNDARY

## Overview
The ZKP pipeline is decomposed into 256 backend proofs (32 component chunks × 8 segment segments) that collectively establish a 256-level SMT inclusion proof for 1024 components. The backend must orchestrate the generation and verification of these proofs securely.

## Exact Backend Interface

The orchestration must define two strict security boundaries:

### 1. `GenerateChunkProofs(chunk_index, components, scores, presence_flags) -> ProofSet`
The ProverService must extract exactly $C=32$ components corresponding to `chunk_index` (0 to 31).
It must dynamically derive the 8 sets of witnesses.
- `Segment 0` (Init): Uses global `merkle_paths` and executes levels 0–31 to produce `hash_out_0`.
- `Segment 1–6` (Mid): Uses the intermediate states sequentially.
- `Segment 7` (Final): Produces `hash_out_7` matching the `vulnerability_db_root`.
The ProverService executes Noir, creates 8 `.gz` proofs, and bundles them into a `ProofSet`.

### 2. `VerifyChunkProofSet(ProofSet, global_sbom_root, vulnerability_db_root, policy_hash) -> bool`
The VerificationService must receive the array of 8 proofs for a chunk and independently assert the following cryptographically linked public inputs:

**Linkage Assertions:**
1. `Proof[0].components_commit == Proof[1].components_commit == ... == Proof[7].components_commit` (Key Binding)
2. `Proof[0].hash_out_commit == Proof[1].hash_in_commit` (Segment Linkage)
3. `Proof[1].hash_out_commit == Proof[2].hash_in_commit`
4. `Proof[2].hash_out_commit == Proof[3].hash_in_commit`
5. `Proof[3].hash_out_commit == Proof[4].hash_in_commit`
6. `Proof[4].hash_out_commit == Proof[5].hash_in_commit`
7. `Proof[5].hash_out_commit == Proof[6].hash_in_commit`
8. `Proof[6].hash_out_commit == Proof[7].hash_in_commit`

**Authoritative Binding Assertions:**
- `Proof[0].global_sbom_root == authoritative_global_sbom_root`
- `Proof[0].policy_hash == authoritative_policy_hash`
- `Proof[7].vulnerability_db_root == authoritative_vulnerability_db_root`
- `Proof[k].segment_index == k` (For k=1..6)
- `Proof[k].chunk_index == chunk_index`

## Authoritative Derivation Requirements
The backend must **never trust** the public inputs supplied in the proof artifact. It must independently inject the known `global_sbom_root`, `vulnerability_db_root`, and `policy_hash` into the UltraPlonk SNARK verifier function call as the *expected* public inputs. If the proof requires different public inputs to pass, the verifier will correctly reject the proof.

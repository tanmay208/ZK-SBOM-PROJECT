---
trigger: model_decision
description: Apply when touching circuits, proofs, VKs, profiles, manifests, proof parsing, public inputs, cryptographic runtime, or verification tests.
---

# Cryptographic Invariants & Verification Standards

**Authoritative Specification**: [`project_context/CRYPTOGRAPHY_RULES.md`](file:///E:/Main%20Project/project_context/CRYPTOGRAPHY_RULES.md)

1. **Follow the Locked Six-Stage Roadmap**: `Stage A → Stage B → Stage C → Stage D → Stage E → Stage F`. All cryptographic verification tasks map to Stages D and E.
2. **Pinned Toolchain**: Noir `0.32.0` (ACIR), Barretenberg `0.46.1` / `@noir-lang/backend_barretenberg@0.32.0`. Do not modify ACIR artifacts, circuits, or crypto versions without authorization.
3. **BN254 & Poseidon**: Preserve canonical 32-byte big-endian BN254 scalar field encoding. Poseidon sponge permutation is pinned to $t=3$ for Merkle tree binary nodes and $t=2$ for leaf commitments.
4. **Tree Topologies**: Depth 10 binary Merkle tree (1024 leaves) for SBOMs; Depth 256 Sparse Merkle Tree (SMT) with dynamic depth precomputation (`AUD-A-010`) for vulnerability databases.
5. **Legacy ACIR Body**: The UltraPlonk proof body is strictly 2144 bytes for Noir 0.32.0 backend representation.
6. **Fail-Closed Verification**: Only an explicit Boolean `true` from the official `BarretenbergVerifier.verifyProof()` constitutes cryptographic acceptance. CLI `bb verify` exit codes are not authority.
7. **Distinct Error Categories**: `STRUCTURAL_REJECTION`, `RUNTIME_FAILURE`, and `ENVIRONMENT_FAILURE` must remain distinct from `CRYPTOGRAPHIC_FALSE`.
8. **Anti-Mocking & Transparent Accounting**: Never present mocked proofs as live verification. Report skipped native tests explicitly (`F2-C-001`).

For complete cryptographic schemas, public input vectors, and mathematical invariants, consult [`project_context/CRYPTOGRAPHY_RULES.md`](file:///E:/Main%20Project/project_context/CRYPTOGRAPHY_RULES.md).

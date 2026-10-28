# Cryptographic Validation Methodology

## Evidence layers

1. **Source/profile inspection:** circuit sources, compiler metadata, artifact hashes, profile limits, and backend verifier topology.
2. **Known-answer/vector checks:** Python and Noir-compatible vectors retained in the repository, including backend/shared/tests/vectors/crypto_vectors.json and Stage21 reference-vector evidence.
3. **Proof-system execution:** Nargo witness/proof generation and Barretenberg verification, when a specific execution is documented with runtime evidence.
4. **Application/archive verification:** archive schema/topology checks, public-input binding, and persisted segment-proof correspondence.
5. **Application lifecycle tests:** persistence, authorization, idempotency, verification state, and certificate/revocation tests.

These layers answer different questions. Unit tests and archive hashes alone do not show that a new proof was generated or cryptographically verified.

## Historical large-workload evidence

The Stage21L report records a 1,024-component workload, 32 chunks, eight SMT segments per chunk, 256 Nargo/Barretenberg proof executions, and archive digest 362be7463b3af52fb499a9bf95d64a69d1dac44e64d48f52cb197a5b48bb7e3d. A later audit records the historical manifest status as pending. The workload was not rerun during this documentation consolidation. See the [Stage21L report](../09_STAGE_REPORTS/stage-21/STAGE21L_CRYPTOGRAPHIC_RUNTIME_VALIDATION_REPORT.md) as historical evidence, not a new run.

## Reproduction caveats

Proof execution requires the matching toolchain, profile-selected artifacts, resources, and configured database. The historical Stage21L report says peak memory, archive size, and disk usage were not captured. No new benchmark or general performance claim is made.

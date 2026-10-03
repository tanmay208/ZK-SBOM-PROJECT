# Public-Input Binding Experiment

Date: 2026-09-13
Finding: ZK-002
Experiment status: NOT EXECUTED TO COMPLETION

## 1. Objective

Demonstrate, using real compatible artifacts and a supported interface, that:

```text
PROOF PUBLIC INPUTS == EXPECTED PUBLIC INPUTS
```

and then that the expected values can be constructed from authoritative application records. The experiment must reject altered inputs, mismatched VK/profile, malformed proof, tampered proof, and witness-as-proof input.

## 2. Isolated workspace and safety

The experiment used only temporary WSL paths:

```text
/tmp/nargo-0.32.0-recovery
/tmp/sbom-zkp-phase5
```

The repository circuit source was copied into the temporary workspace. No repository `circuits/`, `circuits_dev/`, proof, VK, source, or Prover.toml file was modified. The development VK was not used as a production VK. No fake proof, certificate, or bypass was created.

## 3. Planned experiment

### Stage A - Compiler and circuit check

```text
official Nargo 0.32.0 --version
copy intended circuit/profile to temporary workspace
nargo check
```

Observed result:

```text
nargo version = 0.32.0
noirc version = 0.32.0+c679f01a19b02ad2ac2287c8e699b46887f7872c
[sbom_zkp] Constraint system successfully built!
```

This stage passed. It proves compiler availability and source checkability only; it does not generate a VK or proof.

### Stage B - Witness/proof generation

Command:

```text
cp circuits/Prover.toml /tmp/sbom-zkp-phase5/Prover.toml
nargo execute phase5_witness
```

Observed result: the bounded 120-second run did not complete and was stopped. Temporary inspection showed only the copied `Nargo.toml`, `Prover.toml`, and `src/` files; no completed witness/proof was recorded. No Nargo or BB process remained afterward.

Interpretation: environment/workload execution is incomplete. This is not a proof of circuit incompatibility and not a successful witness result.

### Stage C - VK/proof/verification

Not reached because Stage B did not produce a witness. No `bb prove`, valid proof verification, or production VK generation was executed.

### Stage D - Public-input extraction and negative tests

Not reached. The official vendored NoirJS source documents the supported `ProofData.publicInputs` model, but the package was not built or run and no real proof was available.

## 4. Required positive and negative cases

These remain mandatory before ZK-002 can be validated:

| Case | Expected result | Executed |
| --- | --- | --- |
| Valid proof, matching ordered inputs `[SBOM_ROOT, VULNERABILITY_DB_ROOT, POLICY_HASH]` | Accept | No |
| Altered expected SBOM root | Reject | No |
| Altered expected vulnerability root | Reject | No |
| Altered expected policy hash | Reject | No |
| Swapped public-input order | Reject | No |
| Wrong VK/profile | Reject | No |
| One-byte proof tamper | Reject | No |
| Truncated/malformed proof | Reject | No |
| Witness/gzip supplied as proof | Reject | No |
| Revoked/stale authoritative record | Reject before certificate | No |

## 5. Evidence classification

- Nargo `0.32.0` compiler availability: **PROVEN BY EXECUTABLE EVIDENCE**.
- Circuit source check under Nargo `0.32.0`: **PROVEN BY EXECUTABLE EVIDENCE** in a temporary copy.
- BB `0.46.1` presence and version: **PROVEN BY EXECUTABLE EVIDENCE**.
- Nargo/BB compatibility for this circuit proof: **UNKNOWN**; witness generation did not complete and no proof/VK exists.
- Production VK availability: **DISPROVEN for the repository path**; `circuits/target/vk` is absent. Development VK presence does not satisfy the requirement.
- Supported structured public-input model: **PROVEN BY OFFICIAL LOCAL SOURCE** through NoirJS `ProofData.publicInputs` and reconstruction code.
- Current Python/CLI expected-input enforcement: **DISPROVEN**; current verifier passes only VK/proof paths and caller roots are persisted without authoritative comparison.
- Altered expected public-input rejection: **UNKNOWN / NOT EXECUTED**.

## 6. Exact blocker

The final cryptographic experiment is blocked by incomplete proof generation on the intended circuit/profile. The bounded `nargo execute` attempt exceeded 120 seconds without producing a witness. Docker cannot provide an alternate environment because the Docker Linux daemon is unavailable. No production VK is available for the repository profile.

The correct next action is to obtain an approved, bounded isolated proving environment and profile/artifact decision. Do not increase limits indefinitely, use the development VK, or infer public-input binding from source alone.

PUBLIC-INPUT BINDING VALIDATED: UNKNOWN
ISOLATED EXPERIMENT EXECUTED: NO (compiler-check stage only; proof stages not executed)
ZK-002 REMEDIATED: NO

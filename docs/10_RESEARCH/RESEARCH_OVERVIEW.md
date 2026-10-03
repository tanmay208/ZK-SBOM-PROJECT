# Research Overview

## Research problem

Can a software supplier show that an SBOM satisfies a stated vulnerability policy against an identified vulnerability snapshot without disclosing the full component inventory to the verifier?

## Implementation contribution

The repository implements an application and cryptographic prototype connecting committed SBOM/vulnerability data and policy context to a decomposed Noir proof workflow, backend verification, persisted results, and certificate status validation. This is a project description, not a priority or novelty claim.

## Evaluation material

Historical documents record circuit feasibility experiments, toolchain compatibility, vectors, application tests, database integration, and the Stage21L large proof workload. The workload report records execution time, but says peak memory, disk usage, and archive size were not captured. Comparative baseline results are not asserted. See the [documentation index](../README.md) and [validation register](../08_VALIDATION/VALIDATION_AND_EVIDENCE.md).

## Research limitations

This repository does not establish peer-reviewed validation, formal security proof of the complete implementation, comparative superiority, or novelty against prior art. The proof statement is limited by its circuit, public inputs, policy, and committed data. Snapshot completeness/freshness is not proved by the ZKP itself.

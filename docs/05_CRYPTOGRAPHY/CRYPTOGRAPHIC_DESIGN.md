# Cryptographic Design

## Design intent

The system represents SBOM and vulnerability information using commitments and checks a policy statement with Noir circuits. The application associates verification with an SBOM root, vulnerability database root, and policy hash. A proof is meaningful only for the statement, public inputs, circuit artifacts, and verification key to which it is bound.

## Data and hash path

The backend includes component canonicalization and identity resolution, field encoding, Poseidon BN254 hashing, Merkle-root construction, and sparse Merkle tree code under the SBOM service and backend/shared/crypto. Noir sources live in circuits/, with a development profile in circuits_dev/. Exact encoding and circuit semantics are defined by source, authoritative vectors, and preserved Stage17–21 cryptographic documents; this summary does not substitute for them.

## Decomposed SMT profile

The checked-in crypto profile declares a production maximum of 1,024 components, Merkle depth 10, and SMT depth 256. Stage17–19 design and the Stage21L report describe 32-component chunks and eight 32-level SMT segments per chunk. The profile selects and hash-checks configured circuit and verification-key artifacts. These parameters describe checked-in configuration and historical evidence; they do not imply this consolidation reran proof generation.

## Public and private data

The intended witness includes SBOM-side information needed by the circuit. Public commitments/context bind verification to identified roots and policy state. Public inputs and returned certificate/status metadata remain observable. For exact public/private signal lists, consult current Noir sources and the historical [ZKP specification](../09_STAGE_REPORTS/original-project-documents/ZKP_SPECIFICATION.md); no extra privacy guarantee is inferred here.

## Claim boundary

A successful proof supports the exact encoded predicate over supplied committed inputs. It does not attest vulnerability snapshot completeness or freshness, correctness of the original SBOM, absence of all vulnerabilities, or software runtime behavior. Hashes provide binding/integrity only according to their construction; archive SHA-256 is not a substitute for semantic proof verification.

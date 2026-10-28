# Zero-Knowledge Proof Specification

This document is the authoritative Zero-Knowledge Proof (ZKP) specification for the project.

## Cryptographic Primitives
Use:
- zk-SNARK
- Noir
- Nargo
- Barretenberg
- Poseidon
- BN254 scalar field

SBOM: Standard binary Merkle tree
Vulnerability database: Poseidon Sparse Merkle Tree

## Public Inputs
Exactly:
- SBOM_ROOT
- VULNERABILITY_DB_ROOT
- POLICY_HASH

Do NOT add unnecessary public inputs.
Do NOT remove any of these three.

## Private Witness
Define:
- component_count
- canonical component hashes
- vulnerability scores
- vulnerability SMT proofs
- policy_max_cvss
- required Merkle witness/path information

The exact low-level witness representation can be refined during implementation, but the privacy boundary cannot change.

## ZKP Statement
"I know a private SBOM corresponding to SBOM_ROOT, and the complete committed SBOM satisfies the security policy represented by POLICY_HASH with respect to the vulnerability dataset represented by VULNERABILITY_DB_ROOT."

Conceptually:
∃ private SBOM such that:
Commit(SBOM) = SBOM_ROOT
and
the committed vulnerability information is consistent with:
VULNERABILITY_DB_ROOT
and
all components satisfy:
vulnerability_score <= policy_max_cvss
where:
Poseidon(policy_max_cvss) = POLICY_HASH

## SBOM Representation & Commitment
- ordered list of components
- canonical component identity
- PURL canonicalization
- deterministic UTF-8 encoding
- component hashing
- standard binary Merkle tree
- deterministic EMPTY_HASH padding
- fixed maximum circuit capacity

SBOM_ROOT must represent the complete fixed-size committed SBOM tree. The architecture must prevent a malicious vendor from proving compliance for only a subset of the SBOM by enforcing `component_count` + deterministic padding + complete tree reconstruction.

## Vulnerability Database Commitment
The vulnerability database canonical record is: `(component_hash, cvss_score)`
Represent CVSS numerically as an integer (e.g., 7.5 → 75). If no vulnerability exists: 0.

For every canonical component identity, the committed vulnerability value must represent the maximum applicable CVSS score among all vulnerabilities associated with that component in the selected vulnerability snapshot. If no applicable vulnerability exists: 0.

Leaf payload:
`Poseidon(component_hash, max_cvss_for_component)`

Use: Poseidon Sparse Merkle Tree with `component_hash` as the index/path.
The complete root is: `VULNERABILITY_DB_ROOT`.
The SMT must conceptually support inclusion and non-inclusion.

## Policy Design
The authoritative policy for the current ZKP implementation is `max_allowed_cvss`.
Policy canonicalization must be deterministic.
Policy hash: `Poseidon(max_allowed_cvss)`
Public commitment: `POLICY_HASH`
Policy extensions are possible in future versions but are outside the current authoritative circuit unless explicitly enforced.

## ZKP Circuit Logic (Constraints)
1. Verify: `Poseidon(policy_max_cvss) == POLICY_HASH`
2. Verify: `component_count <= MAX_COMPONENTS`
3. Real components occur before `component_count`.
4. `EMPTY_HASH` padding occurs after `component_count`.
5. Recompute the complete fixed-size SBOM Merkle root.
6. Assert: `computed_root == SBOM_ROOT`
7. For every real component, verify its vulnerability score against the vulnerability SMT represented by: `VULNERABILITY_DB_ROOT`
8. Enforce: `vulnerability_score <= policy_max_cvss`
9. Ensure the proof applies to the complete committed SBOM.

## Cryptographic Interoperability (IMPLEMENTATION PREREQUISITE — MUST BE FROZEN BEFORE ZKP CODING)
Identify every value that must be computed identically between Python and Noir. Exact implementation requirements must be documented for:
- PURL canonicalization
- UTF-8 encoding
- byte-to-field conversion
- byte order
- chunking
- padding
- empty input
- length handling
- component hashing
- Poseidon input ordering
- Merkle leaf encoding
- Merkle node hashing
- SMT leaf encoding
- SMT index/path encoding
- domain separation if used

Do NOT invent values for parameters that have not been finalized.

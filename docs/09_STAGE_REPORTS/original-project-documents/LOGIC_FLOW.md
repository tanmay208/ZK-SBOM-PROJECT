# Logic Flow

This document details the distinct logical flows for the Minor baseline system and the Major Zero-Knowledge Proof (ZKP) system.

## 1. Minor Flow (Disclosure-Based Baseline)

Vendor uploads/generates SBOM
        ↓
CycloneDX parsing
        ↓
Component normalization
        ↓
Grype + vulnerability data
        ↓
CVE matching
        ↓
CVSS
        ↓
Security Policy
        ↓
PASS / FAIL
        ↓
Security Report

## 2. Major ZKP Flow (Privacy-Preserving)

PRIVATE SBOM
    ↓
Parse
    ↓
Normalize
    ↓
Canonicalize
    ↓
Cryptographic Commitment
    ↓
SBOM_ROOT

In parallel:

NVD/CVE SNAPSHOT
    ↓
Canonical Vulnerability Records
    ↓
Hash Records
    ↓
Poseidon Sparse Merkle Tree
    ↓
VULNERABILITY_DB_ROOT

Security Policy
    ↓
Canonicalize
    ↓
Hash
    ↓
POLICY_HASH

Then:

Private Witness
+
SBOM_ROOT
+
VULNERABILITY_DB_ROOT
+
POLICY_HASH
    ↓
Noir Circuit
    ↓
zk-SNARK
    ↓
Proof
    ↓
Buyer Verification
    ↓
VALID / INVALID

## 3. Vulnerability Analysis vs Database Commitment

**VULNERABILITY ANALYSIS (Minor Flow)**
SBOM
 ↓
Component Matching
 ↓
CVE Findings
 ↓
CVSS Scores

**VULNERABILITY DATABASE COMMITMENT (Major Flow)**
NVD/CVE Snapshot
 ↓
Canonical Vulnerability Records
 ↓
Component Identity Mapping
 ↓
Maximum Applicable CVSS Per Component
 ↓
Poseidon SMT
 ↓
VULNERABILITY_DB_ROOT

These are NOT the same process. VULNERABILITY_DB_ROOT is NOT the result of a Grype vulnerability scan.

## 4. SBOM Processing and Commitment Flow
- Private SBOM is parsed.
- Components are normalized and canonicalized into a deterministic UTF-8 encoding.
- Canonical components are hashed and inserted into a standard binary Merkle tree.
- Deterministic EMPTY_HASH padding is applied up to a fixed maximum circuit capacity.
- The `SBOM_ROOT` is produced, representing the complete fixed-size committed SBOM tree.

## 5. Policy Canonicalization Flow
- Security policy (`max_allowed_cvss`) is retrieved.
- Policy is canonicalized deterministically.
- Policy is hashed using Poseidon.
- The `POLICY_HASH` is produced.

## 6. Proof-Generation Flow
- ZKP Service gathers the Private Witness (component count, canonical hashes, vulnerability scores, SMT proofs, Merkle paths, `policy_max_cvss`).
- ZKP Service gathers the Public Inputs (`SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`).
- Noir circuit is executed via Nargo/Barretenberg.
- A zk-SNARK Proof is generated.

## 7. Buyer Verification Flow
- Buyer receives the zk-SNARK Proof and the exact Public Inputs (`SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`).
- Buyer runs the verifier algorithm.
- The verification algorithm outputs VALID or INVALID.

## 8. Privacy Boundary and Data Flow
- **Private Data Flow:** Raw SBOM, component identities, and internal processing data never leave the vendor environment.
- **Public Data Flow:** Only the cryptographic roots, proof, and verification results cross the buyer boundary. Diagrams of this process do not imply that raw SBOM data reaches the buyer.

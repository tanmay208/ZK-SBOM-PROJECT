# Project Scope

## Project Title
A Zero-Knowledge Proof Framework for Privacy-Preserving SBOM Vulnerability Verification in Software Supply Chains

## Problem Statement
Organizations/software buyers need independently verifiable assurance that vendor applications satisfy defined software-security requirements.

Vendors, however, may not want to disclose their raw SBOM because dependency information can reveal:
- proprietary software composition
- third-party technology relationships
- dependency relationships
- software architecture information
- security-sensitive dependency information

Conventional SBOM verification requires disclosure of the SBOM to the verifier.

This project proposes a zero-knowledge approach where the vendor keeps the underlying SBOM private while proving that the committed SBOM satisfies a predefined known-vulnerability security policy with respect to a specific cryptographically committed vulnerability-database snapshot.

## Core Objective
The system must enable:
PRIVATE SBOM → CRYPTOGRAPHIC COMMITMENT → ZK COMPLIANCE PROOF → INDEPENDENT BUYER VERIFICATION
without revealing the underlying dependency information.

## Security Assurance Statement
The system MUST NOT claim:
- software is universally secure
- software contains no vulnerabilities of any kind
- complete software security
- universal vulnerability detection
- first-ever ZKP/SBOM system
- that using a ZKP alone is the novelty

The valid assurance statement is:
"The vendor possesses a committed SBOM that satisfies a specified known-vulnerability security policy with respect to a specified vulnerability-database snapshot, while the underlying dependency information remains private."

## Core Principle
ASSURANCE WITHOUT DISCLOSURE
The system replaces direct SBOM disclosure with cryptographically verifiable security assurance.

## Minor Scope (Disclosure-Based Baseline)
The conventional baseline system functionality includes:
- application registration
- SBOM upload
- SBOM generation using Syft
- CycloneDX JSON parsing/validation
- component/PURL normalization
- NVD/CVE import
- Grype scanning
- vulnerability matching
- CVSS analysis
- configurable security policy
- PASS/FAIL compliance
- security report
- vendor dashboard
- buyer baseline dashboard
- scan history

## Major Scope (ZKP Privacy-Preserving Flow)
- Private SBOM parsing, normalization, canonicalization, and hashing
- Standard binary Merkle tree commitment resulting in `SBOM_ROOT`
- NVD/CVE snapshot canonicalization and Poseidon SMT commitment resulting in `VULNERABILITY_DB_ROOT`
- Policy canonicalization and Poseidon hashing resulting in `POLICY_HASH`
- Noir circuit constraint verification
- zk-SNARK proof generation using Nargo/Barretenberg
- Independent buyer-side proof verification based entirely on public inputs

## Out-of-Scope Items
- Kubernetes orchestration
- Redis caching layers
- Blockchain integration
- PostgreSQL databases
- Unnecessary distributed or complex cloud infrastructure
- Mobile applications
- Multiple ZKP frameworks
- Unnecessary microservice or authentication infrastructure beyond the core protocol requirements

## 45-Day Scope Boundary
The scope defined in this document and the Implementation Plan represents the absolute boundary for the 45-day implementation window. No additional features will be introduced unless explicitly reviewed and approved.

## Final Novelty Framing
The novelty consists of:
1. PRIVATE SBOM COMPLIANCE PROOF: Prove compliance without disclosing dependency identities.
2. TRIPLE CRYPTOGRAPHIC BINDING: Proof bound to exact SBOM_ROOT, VULNERABILITY_DB_ROOT, POLICY_HASH.
3. PRACTICAL INDEPENDENT VERIFICATION: Buyer verification without raw SBOM.
4. EMPIRICAL EVALUATION: Compare conventional vs privacy-preserving verification on metrics like proof size, generation/verification time, and scalability.

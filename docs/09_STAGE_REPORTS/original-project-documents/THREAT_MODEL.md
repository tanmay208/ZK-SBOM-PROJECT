# Threat Model

This document outlines the realistic threat model for the Zero-Knowledge Proof SBOM Verification system. It focuses on the specific threats addressed by the protocol and explicitly acknowledges its limitations.

## 1. Malicious Vendor Claims False Compliance
- **Threat:** A vendor attempts to prove compliance for an SBOM that actually contains vulnerabilities exceeding the policy threshold.
- **Attack Idea:** Tamper with the ZKP generation process to return a valid proof for invalid witness data.
- **Affected Component:** ZKP Service / Noir Circuit.
- **Mitigation:** The cryptographic soundness of the zk-SNARK prevents a computationally bounded prover from generating a valid proof for a false statement. The buyer verification algorithm will reject it.
- **Residual Limitation:** Relies on the security of the underlying elliptic curve (BN254) and the Groth16/Plonk proving system.

## 2. Vendor Omits Components
- **Threat:** A vendor attempts to omit vulnerable components from the committed SBOM to achieve a passing compliance result.
- **Attack Idea:** Submit a partial SBOM to the commitment process.
- **Affected Component:** SBOM Commitment / Merkle Tree.
- **Mitigation:** The Noir circuit enforces a complete, fixed-size tree constraint (`MAX_COMPONENTS`) with deterministic padding. The vendor is forced to commit to a specific fixed-size structure.
- **Residual Limitation:** If a vendor completely excludes a component from their internal raw SBOM *before* the commitment process begins (and the system cannot independently discover it), the proof only validates what was committed.

## 3. Vendor Modifies SBOM After Commitment
- **Threat:** A vendor alters the SBOM content after generating the `SBOM_ROOT`.
- **Attack Idea:** Serve a different raw SBOM internally while presenting the original proof.
- **Affected Component:** Vendor SBOM Storage.
- **Mitigation:** The zk-SNARK proof is cryptographically bound to the exact `SBOM_ROOT`. Any modification changes the root, rendering the old proof mathematically invalid against the new root.
- **Residual Limitation:** None within the context of the mathematical proof.

## 4. Vendor Uses a Different Vulnerability Database
- **Threat:** Vendor tries to prove compliance against an older, less strict, or manipulated vulnerability database.
- **Attack Idea:** Provide a manipulated SMT witness to the circuit.
- **Affected Component:** Vulnerability DB Commitment / ZKP Service.
- **Mitigation:** The proof is cryptographically bound to a specific `VULNERABILITY_DB_ROOT`. The buyer verifies the proof using the `VULNERABILITY_DB_ROOT` they expect (or a known trusted snapshot root).
- **Residual Limitation:** The buyer must have an independent way to trust that the provided `VULNERABILITY_DB_ROOT` actually represents an accurate NVD/CVE snapshot.

## 5. Vendor Uses a Different Policy
- **Threat:** Vendor tries to prove compliance against a looser policy (e.g., `max_allowed_cvss = 10.0`).
- **Attack Idea:** Pass a higher `policy_max_cvss` to the circuit.
- **Affected Component:** ZKP Circuit / Policy Service.
- **Mitigation:** The circuit enforces `Poseidon(policy_max_cvss) == POLICY_HASH`. The buyer checks the proof against their expected `POLICY_HASH` (e.g., hash of `7.0`).
- **Residual Limitation:** None.

## 6. Tampering with SBOM_ROOT
- **Threat:** An attacker alters the `SBOM_ROOT` in transit to the buyer.
- **Attack Idea:** Man-in-the-middle attack.
- **Affected Component:** Network / Verification Service API.
- **Mitigation:** TLS for API endpoints; digital signatures on the metadata payload containing the roots.
- **Residual Limitation:** Standard PKI reliance.

## 7. Tampering with VULNERABILITY_DB_ROOT
- **Threat:** An attacker alters the DB root in transit.
- **Attack Idea:** Man-in-the-middle attack.
- **Affected Component:** Network / Verification Service API.
- **Mitigation:** TLS; buyer cross-referencing roots from a trusted registry.
- **Residual Limitation:** Standard PKI reliance.

## 8. Tampering with POLICY_HASH
- **Threat:** An attacker alters the policy hash in transit.
- **Attack Idea:** Man-in-the-middle attack.
- **Affected Component:** Network / Verification Service API.
- **Mitigation:** TLS; buyer independently hashing the expected policy.
- **Residual Limitation:** Standard PKI reliance.

## 9. Tampering with the Proof
- **Threat:** An attacker alters the SNARK proof bytes in transit.
- **Attack Idea:** Fuzz or modify proof artifact.
- **Affected Component:** Verification Service.
- **Mitigation:** The verifier algorithm inherently detects any tampering with the proof structure and will reject it (output INVALID).
- **Residual Limitation:** None.

## 10. Replay of an Old Proof
- **Threat:** Vendor submits an old, valid proof for an outdated SBOM version.
- **Attack Idea:** Replay attack.
- **Affected Component:** Verification Service.
- **Mitigation:** The proof is inextricably bound to the specific `SBOM_ROOT` and `VULNERABILITY_DB_ROOT`. A buyer requesting verification for the *latest* SBOM and *latest* vulnerability DB snapshot will require a new proof over the new roots.
- **Residual Limitation:** The buyer must enforce checks on the freshness of the roots.

## 11. Buyer Attempts to Recover Private SBOM
- **Threat:** A malicious buyer tries to reverse-engineer the raw SBOM from the provided verification data.
- **Attack Idea:** Analyze the zk-SNARK proof and public inputs.
- **Affected Component:** ZKP Protocol.
- **Mitigation:** The Zero-Knowledge property of the SNARK guarantees that no information about the private witness (the raw SBOM data) is leaked by the proof.
- **Residual Limitation:** The computational assumption underlying the SNARK (e.g., discrete logarithm problem).

## 12. Unauthorized Access to Stored Proof Artifacts
- **Threat:** Attacker breaches the `zkp` or `verification` schemas.
- **Attack Idea:** Database exfiltration.
- **Affected Component:** SQL Server.
- **Mitigation:** Proof artifacts only contain public data (`SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`, and the proof). No private data is exposed even if breached.
- **Residual Limitation:** Loss of availability or integrity of the history, but no loss of confidentiality.

## 13. Leakage Through Logs
- **Threat:** Private SBOM data is inadvertently written to application logs.
- **Attack Idea:** Log analysis.
- **Affected Component:** All Services.
- **Mitigation:** Strict development rules prohibiting logging of component names, PURLs, private hashes, or Merkle paths.
- **Residual Limitation:** Depends on developer adherence and code review processes.

## 14. Leakage Through API Responses
- **Threat:** The Verification Service accidentally returns raw SBOM data.
- **Attack Idea:** API scraping.
- **Affected Component:** Verification Service.
- **Mitigation:** The Verification Service must be physically/logically isolated from the `sbom` database schema and operate strictly on the public proof artifacts.
- **Residual Limitation:** Architectural enforcement required.

## 15. Vulnerability Database Snapshot Inconsistency
- **Threat:** The snapshot process misses recent CVEs or creates an inconsistent view.
- **Attack Idea:** Exploit timing windows during database updates.
- **Affected Component:** Vulnerability Service.
- **Mitigation:** Snapshots are strictly versioned and locked during canonicalization. The `VULNERABILITY_DB_ROOT` represents a frozen-in-time state.
- **Residual Limitation:** The proof only guarantees compliance against that specific frozen snapshot, not against zero-day or post-snapshot vulnerabilities.

## 16. Canonicalization Inconsistencies
- **Threat:** An identical component is canonicalized differently during SBOM commitment vs. Vulnerability DB commitment, resulting in a missed match.
- **Attack Idea:** Exploit parsing edge cases.
- **Affected Component:** SBOM Service / Vulnerability Service.
- **Mitigation:** A single, shared PURL canonicalization library must be used across both services.
- **Residual Limitation:** Inherent complexity of software naming conventions.

## 17. Python/Noir Cryptographic Encoding Mismatch
- **Threat:** The Python backend computes a Hash(X) differently than the Noir circuit computes Hash(X) due to byte-ordering or field encoding differences.
- **Attack Idea:** Causes valid ZK proofs to fail generation, or creates soundness bugs.
- **Affected Component:** ZKP Service / Noir Circuit.
- **Mitigation:** Explicit requirement to finalize and test a byte-to-field encoding specification before implementation begins.
- **Residual Limitation:** Requires rigorous cross-language test vectors.

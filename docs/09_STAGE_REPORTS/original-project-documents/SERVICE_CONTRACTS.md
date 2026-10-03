# Service Contracts

This document defines the initial responsibilities and future API boundaries for the five core services in the system.

## 1. SBOM Service

### Purpose
Handles the generation, parsing, validation, and commitment of Software Bill of Materials (SBOMs) while preserving confidentiality.

### Service Owner
sbom_service

### Input/Output Concept
- **Input:** Source code repositories, raw SBOM files, vendor inputs.
- **Output:** Canonicalized SBOM components, standard binary Merkle tree, `SBOM_ROOT`.

### Privacy Classification
- **Classification:** Strictly Confidential / Private.
- Raw SBOM data, PURLs, component names, versions, and dependency relationships are private and must not leave the vendor boundary.

### Dependencies
- None. (Independent initialization).

### Future Implementation Boundary
- Provides API `/api/v1/sbom` for upload and generation orchestration.
- Integrates with Syft for SBOM generation.
- Handles CycloneDX processing and validation.

---

## 2. Vulnerability Service

### Purpose
Ingests, processes, and commits vulnerability databases to provide a cryptographic snapshot of known vulnerabilities. Also handles Grype scanning for the Minor flow.

### Service Owner
vulnerability_service

### Input/Output Concept
- **Input:** NVD/CVE data feeds, Syft output (Minor flow).
- **Output:** Canonical vulnerability records, Poseidon Sparse Merkle Tree (SMT), `VULNERABILITY_DB_ROOT`.

### Privacy Classification
- **Classification:** Public / Transparent.
- Vulnerability database snapshots, canonical records, and the resulting `VULNERABILITY_DB_ROOT` are public commitments.

### Dependencies
- NVD/CVE feeds.

### Future Implementation Boundary
- Provides API `/api/v1/vulnerability`.
- Responsible for NVD/CVE ingestion and vulnerability feed processing.
- Handles Grype vulnerability analysis and CVE/CVSS matching for Minor flow.
- Produces the maximum applicable CVSS score per component.

---

## 3. Policy Service

### Purpose
Manages, canonicalizes, and commits security policies against which the SBOMs will be evaluated.

### Service Owner
policy_service

### Input/Output Concept
- **Input:** Policy configurations (e.g., maximum allowed CVSS).
- **Output:** `POLICY_HASH`.

### Privacy Classification
- **Classification:** Public / Transparent.
- The security policy and its resulting hash are public inputs.

### Dependencies
- None.

### Future Implementation Boundary
- Provides API `/api/v1/policy`.
- Authoritative ZKP policy: `max_allowed_cvss`.
- Handles policy canonicalization and generation of `POLICY_HASH` via Poseidon.

---

## 4. ZKP Service

### Purpose
Executes Noir circuits to generate zero-knowledge proofs demonstrating that the private SBOM satisfies the public policy against the public vulnerability database snapshot.

### Service Owner
zkp_service

### Input/Output Concept
- **Input:** 
  - Private Witness (component count, canonical component hashes, vulnerability scores, SMT proofs, Merkle paths).
  - Public Inputs (`SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`).
- **Output:** zk-SNARK Proof.

### Privacy Classification
- **Classification:** Mixed (Processes Private Data to produce Public Proof).
- Must have access to private witness data but must never expose it. Proof and public inputs are public.

### Dependencies
- sbom_service (for SBOM witness data).
- vulnerability_service (for vulnerability SMT witness data).
- policy_service (for policy witness data).

### Future Implementation Boundary
- Provides API `/api/v1/zkp`.
- Integrates with Noir, Nargo, and Barretenberg.
- Manages proof artifact generation and storage.

---

## 5. Verification Service

### Purpose
Allows buyers to independently verify the zero-knowledge proofs without requiring access to the raw SBOM.

### Service Owner
verification_service

### Input/Output Concept
- **Input:** zk-SNARK Proof, `SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`.
- **Output:** Verification result (VALID / INVALID), Verification Certificate.

### Privacy Classification
- **Classification:** Public.
- Operates entirely on public data. Must NEVER require or process private SBOM data.

### Dependencies
- ZKP verification keys.

### Future Implementation Boundary
- Provides API `/api/v1/verify`.
- Validates public inputs and proof.
- Maintains verification history and certificates.

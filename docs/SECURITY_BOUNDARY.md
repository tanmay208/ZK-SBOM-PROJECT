# Security Boundary

This document outlines the strict security and privacy boundaries enforced within the architecture.

## 1. Data Classifications

### Private Data (Must Never Cross Buyer Boundary)
- Raw SBOM files (CycloneDX JSON, etc.)
- Component names, versions, and identities
- Package URLs (PURLs)
- Dependency relationships and graphs
- Vulnerability witness information (specific CVEs matched to vendor components during ZKP generation)
- Merkle and SMT paths for the private components
- The complete ZKP private witness
- Internal processing data

### Public Data (Safe for Buyer Boundary)
- `SBOM_ROOT`
- `VULNERABILITY_DB_ROOT`
- `POLICY_HASH`
- zk-SNARK Proof artifacts
- Verification results (VALID / INVALID)
- Verification certificate metadata
- Canonical vulnerability database snapshots (publicly available data)
- Public policy configurations

## 2. Vendor vs. Buyer Boundaries

### Vendor-Side Data
The vendor infrastructure processes and stores both Private Data and Public Data. It is responsible for parsing the SBOM, analyzing vulnerabilities (in the Minor flow), canonicalizing data, constructing Merkle/SMT trees, and generating the zk-SNARK proof. The vendor infrastructure has access to the full private context.

### Buyer-Side Data
The buyer infrastructure (and the Verification Service API exposed to buyers) must ONLY receive, process, and store Public Data. 

**CRITICAL:** The raw SBOM MUST NOT cross the buyer verification boundary. Buyer-side verification must NOT require raw SBOM access.

## 3. Service Boundaries

- **sbom_service:** Operates entirely within the Private vendor boundary.
- **vulnerability_service:** Operates on public threat intelligence to build public commitments, but also processes private SBOM data during Grype scanning (Minor flow). The DB commitment output (`VULNERABILITY_DB_ROOT`) is public.
- **policy_service:** Manages public policy configurations. Output (`POLICY_HASH`) is public.
- **zkp_service:** Operates at the edge of the private boundary. It ingests private witness data and outputs the public zk-SNARK proof.
- **verification_service:** Operates strictly on the public side of the boundary. It must not have endpoints that accept or return private SBOM components.

## 4. Database Boundaries

- **sbom schema:** Contains Private Data. Restricted access.
- **vulnerability schema:** Contains public NVD/CVE data and canonicalized vulnerability records.
- **policy schema:** Contains public policy data.
- **zkp schema:** Stores proof artifacts and intermediate generation state. Private witness data must not be permanently stored if not strictly necessary, and must be secured if it is.
- **verification schema:** Stores verification histories, certificates, and results (Public Data).

## 5. Proof Boundary

The zero-knowledge proof itself acts as the primary cryptographic privacy boundary. It leaks zero information about the private witness beyond the fact that the statement holds true for the given public inputs.

## 6. Logging and Artifact Restrictions

- **Logging Restrictions:** Application logs, error logs, and access logs must NEVER contain Private Data (e.g., component names, PURLs, private hashes, Merkle paths). Logs from the Verification Service must especially be sanitized to prevent leakage.
- **Artifact Restrictions:** Proof artifacts stored and distributed must only contain the cryptographic proof and the three required public inputs. No raw or encoded representation of the SBOM may be embedded in the proof artifact metadata unless cryptographically blinded.
- **API Responses:** API responses to unauthorized or buyer-role users must immediately strip all private fields.

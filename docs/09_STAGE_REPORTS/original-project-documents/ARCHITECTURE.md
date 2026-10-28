# Architecture

This document defines the complete system architecture for the Zero-Knowledge Proof Framework for Privacy-Preserving SBOM Vulnerability Verification.

## 1. System Overview
The system allows a software vendor to generate a zero-knowledge proof demonstrating that a committed, private Software Bill of Materials (SBOM) complies with a specific security policy against a specific vulnerability database snapshot. Buyers can independently verify this proof without ever seeing the raw SBOM.

## 2. Technology Stack

### Frontend
- React
- TypeScript
- Vite
- Tailwind CSS
- Node.js 20 LTS
- Nginx

### Backend
- Python 3.11
- FastAPI
- Pydantic
- SQLAlchemy
- Uvicorn

### Database
- Microsoft SQL Server 2022
- SQL Server Management Studio
- Microsoft ODBC Driver for SQL Server

### SBOM
- CycloneDX JSON
- Syft

### Vulnerability Analysis
- Grype
- NVD/CVE data
- CVSS

### Zero Knowledge
- Noir
- Nargo
- Barretenberg
- zk-SNARK
- Poseidon
- Binary Merkle Tree
- Poseidon Sparse Merkle Tree (SMT)

### Testing
- Pytest
- Vitest
- Noir circuit tests
- API/integration tests
- Security/negative tests
- Performance benchmarks

### Deployment & Tools
- Docker
- Docker Compose
- Git
- GitHub
- AI Development: Antigravity, Cursor

## 3. Rejected Technologies (Out of Scope)
Explicitly outside the 45-day scope. Do not introduce these technologies later unless the project scope is explicitly changed:
- Kubernetes
- Redis
- Blockchain
- PostgreSQL
- Unnecessary cloud infrastructure
- Unnecessary distributed infrastructure
- Mobile application
- Multiple ZKP frameworks
- Unnecessary authentication infrastructure
- Unnecessary microservice infrastructure

## 4. Component & Service Architecture

The system consists of a React Frontend communicating via an API Gateway to five core FastAPI services. 

*IMPORTANT: Do NOT describe the entire system as a strictly linear business pipeline. The services are independently responsible for their domains and communicate through defined contracts.*

```text
                         React Frontend
                              |
                              v
                         API Gateway
                            FastAPI
                              |
        +---------------------+---------------------+
        |                     |                     |
        v                     v                     v
   SBOM Service       Vulnerability Service    Policy Service
        |                     |                     |
        +---------------------+---------------------+
                              |
                              v
                         ZKP Service
                              |
                              v
                    Verification Service
```

### Service Responsibilities

**SBOM SERVICE**
Responsibilities:
- SBOM upload
- SBOM generation orchestration
- CycloneDX processing
- SBOM validation
- component normalization
- SBOM canonicalization
- SBOM commitment
- SBOM_ROOT generation

Does NOT own:
- vulnerability database construction
- policy ownership
- proof verification

**VULNERABILITY SERVICE**
Responsibilities:
- NVD/CVE ingestion
- vulnerability feed processing
- vulnerability record canonicalization
- vulnerability database snapshots
- vulnerability database commitment
- Merkle/SMT construction
- VULNERABILITY_DB_ROOT
- Grype scanning
- vulnerability matching
- CVSS information

CRITICAL: VULNERABILITY_DB_ROOT is NOT the result of a Grype vulnerability scan. The vulnerability database commitment is a separate process.

**POLICY SERVICE**
Responsibilities:
- policy management
- policy canonicalization
- policy hashing
- POLICY_HASH
- policy configuration

Current authoritative ZKP policy: `max_allowed_cvss`. Do NOT make `allowed_licenses` part of the authoritative ZKP policy unless it is also enforced inside the ZKP circuit.

**ZKP SERVICE**
Responsibilities:
- witness preparation
- circuit input preparation
- Noir circuit execution
- Barretenberg integration
- proof generation
- proof artifact management

**VERIFICATION SERVICE**
Responsibilities:
- zk-SNARK proof verification
- public-input validation
- verification result
- verification certificate
- verification history

Buyer-side verification MUST NOT require the raw SBOM.

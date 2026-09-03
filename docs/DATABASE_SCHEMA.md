# Database Schema Architecture

This document defines the logical database architecture for the project.

## Logical Architecture

Use exactly ONE SQL Server 2022 instance.
Do NOT create separate database servers for each microservice.

Use one application database with logical schemas:
- `sbom`
- `vulnerability`
- `policy`
- `zkp`
- `verification`

Service names:
- `sbom_service`
- `vulnerability_service`
- `policy_service`
- `zkp_service`
- `verification_service`

**IMPORTANT:**
Service names and SQL schema names are different concepts. This separation is fundamental to the logical design of the system.

## Schema Ownership and Expected Entities

At Day 1, this defines the logical database ownership and future entity boundaries. Do NOT implement the full database tables yet. The complete application database schema begins on Day 3.

### 1. `sbom` Schema
- **Owner:** `sbom_service`
- **Purpose:** Stores private SBOM data, vendor metadata, and intermediate component representations required for generating the SBOM commitment.

### 2. `vulnerability` Schema
- **Owner:** `vulnerability_service`
- **Purpose:** Stores raw NVD/CVE feed data, Grype scan results (for Minor flow), canonical vulnerability records, and SMT structures.

### 3. `policy` Schema
- **Owner:** `policy_service`
- **Purpose:** Stores configurable security policies.

### 4. `zkp` Schema
- **Owner:** `zkp_service`
- **Purpose:** Stores intermediate proof generation state, witness preparation artifacts, and generated zk-SNARK proof references.

### 5. `verification` Schema
- **Owner:** `verification_service`
- **Purpose:** Stores the history of proof verifications, public inputs, and issued certificates for the buyer.

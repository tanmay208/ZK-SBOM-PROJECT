# STAGE 21 REFERENCE VECTORS

## 1. Summary
This report details the cryptographic reference vectors generated and validated during the Stage 21 1024-component E2E execution.

## 2. Dataset Constraints
- **Components**: Exactly 1024 deterministically ordered components (via `stage21_payload.json`).
- **Policy**: `max_cvss_score = 5.0`
- **Topology**: C=32 chunks, 8 segments per chunk. 256 segment proofs.
- **Circuit Version**: Nargo 0.32.0, Barretenberg (Honk) 0.46.1.

## 3. Measured Cryptographic Root Bounding
The following roots were measured dynamically during the real production-code execution via the `execute_stage21.py` test harness:

- **Authoritative SBOM Root**: `0x0488e797c03f731404f902e1dcc34f8d4c7729072d7d1c492b96d88b53de8c9d`
  - *Source*: Real production `SBOMIntakeService` computation using recursive depth-10 Merkle tree.
- **Authoritative Vulnerability/SMT Root**: `0x202388f194c40573b71fcf996b2e572ab507f682174c69ec94c527c46aeab70b`
  - *Source*: Real production `VulnerabilitySnapshot` computation via depth-256 SMT tree updates.
- **Authoritative Policy Hash**: `0x2134767d1a7374bad1868ce448a03bb65c63cefa0fa5a4c40dc274acbf2f0cea`
  - *Source*: Real production `PolicyService` evaluating a single `poseidon_hash([5.0])` constraint mapping.

## 4. Evidence Classification
- **Measured Evidence**: `SBOM Root`, `Provisional SMT Root`, `Policy Hash` dynamically mapped during Stage 21 execution run on SQLite mapping.
- **Inherited Evidence**: Deterministic component generation from Stage 20 payloads.
- **Real Production-Code**: Vectors computed dynamically by the production REST-service contracts (`SBOMIntakeService`, `ingest_vulnerabilities`, `add_policy`).
- **Test-Harness Behavior**: Memory-mapped SQLite attachment across schemas. No database alteration shortcuts taken.

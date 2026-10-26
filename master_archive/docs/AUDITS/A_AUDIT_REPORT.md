# Phase A — Backend In-Depth Integration Audit Report

**Status:** COMPLETE (EVIDENCE-DRIVEN AUDIT)
**Objective:** Map architecture, verify integration points, and identify what actually breaks without remediating.

## 1. Application Architecture & Configuration (Steps 0–2)

**Implementation:**
The backend consists of five distinct logical services (SBOM, Vulnerability, Policy, ZKP, Verification) that share a common domain model and utility base (`backend/shared/`).
All services are instantiated via a centralized factory (`shared.app_factory.create_app`). 
The `lifespan` context manager invokes `validate_config()` at startup.

**Finding: Fast-Fail Configuration Defect**
The `validate_config()` method strictly requires environment secrets (e.g., `DB_PASSWORD`) to be set. Because defaults are only supplied in `conftest.py` (which only applies during testing), attempting to run any service in the local environment fails immediately on startup if these variables are not exported.

## 2. Database Integration & Migrations (Step 3)

**Implementation:**
The platform uses a shared database strategy with logical schemas separating service domains.

**Finding: SQL Server vs. PostgreSQL Divergence**
The database initialization script (`backend/scripts/init_db.py`) is hardcoded to connect to a Microsoft SQL Server (`mssql+pyodbc`) instance. However:
1. `DatabaseSettings` (in `shared/config.py`) lacks the `driver` attribute entirely, causing `init_db.py` to crash with an `AttributeError`.
2. The current environment leverages a Supabase (PostgreSQL) connection string (`postgresql+psycopg2://...`). 
3. Alembic attempts to run against the Supabase backend but fails due to authentication/connectivity issues (`OperationalError`).

**Impact:** Database provisioning and migration are currently completely broken in the local environment due to this driver/dialect impedance mismatch.

## 3. Authorization & Tenant Isolation (Steps 4–6)

**Implementation:**
- **Authorization:** Handled effectively via `shared.auth.require_roles` injected as FastAPI dependencies. Endpoints correctly enforce `vendor` vs `admin` roles.
- **Tenant Isolation:** Implemented securely via manual IDOR checks in the data access layer (e.g., `.filter(ProofJob.user_id == current_user.id)`). 
- **Vulnerability Snapshots:** Intentionally lack tenant isolation as they represent the platform's global, authoritative vulnerability database managed exclusively by admins.

## 4. SBOM Lifecycle & Canonicalization (Steps 7–9)

**Implementation:**
The SBOM intake pipeline (`sbom_intake_service.py` → `commitment_service.py` → `canonicalization.py`) successfully parses CycloneDX, handles Poseidon hashing, and constructs the Merkle tree up to 1024 components.

**Finding A: PURL Canonicalization Data Loss**
When a CycloneDX component specifies a `purl`, the canonicalizer (`extract_component_fields_from_purl`) extracts the `name` and `version` directly from the PURL, completely discarding the raw `name` and `version` declared in the CycloneDX node. This creates a disconnect where the cryptographic commitment reflects the PURL's metadata rather than the vendor's declared SBOM metadata.

**Finding B: Duplicate Component Tree Exhaustion**
`ComponentIdentityResolver` identifies duplicates (e.g. `DuplicateClass.EXACT`) but the commitment pipeline persists and hashes *all* of them into the Merkle tree. A vendor could submit an SBOM with 1024 identical components, consuming the entire tree capacity without violating the validation layer.

## 5. Noir / Barretenberg Environment Isolation (Step 10)

**Implementation:**
Proof generation (`prover_service.py`) and verification (`verifier.py`) invoke the Noir compiler and Barretenberg backend via subprocesses.

**Finding: Hardcoded Windows WSL Dependency**
The backend explicitly executes `subprocess.run(["wsl", "-d", "kali-linux", "--", "bash", "-c", ...])`. This inextricably binds the application to a specific Windows local development machine running a WSL distribution named `kali-linux`. The backend will catastrophically fail in any native Linux deployment (Docker, Cloud VMs, CI/CD).

## 6. Concurrency & Idempotency Architecture (Steps 11, 16)

**Implementation:**
The A0 audit identified six redundant `segment_mid_32_*` directories intended for concurrent segment generation.

**Finding A: Concurrency Architecture is Disabled**
The runtime implementation in `prover_service.py` dynamically overrides the circuit directory for all mid segments back to the base `"segment_mid_32"`. It then iterates through segments sequentially (`for seg_idx in range(self.SEGMENTS_PER_CHUNK):`). The 6 subdirectories on disk are dead, historical artifacts.

**Finding B: Global Process-Level Deadlock**
`_global_prover_lock` (a `threading.Lock`) is acquired at the start of `process_job`. If a second user requests a proof while one is running, the service immediately returns a 429 "Server is at capacity" failure. Concurrency is limited to 1 globally per process.

## 7. Verification Lifecycle & Public Input Extraction (Steps 12, 17)

**Implementation:**
`VerificationService` accurately protects against IDOR and ties the verification result to authoritative backend state via the archive manifest. 

**Finding: Structurally Flawed Public Input Extraction**
`NoirVerifier` manually attempts to extract public inputs from the generated proof by slicing the first bytes of the proof artifact (`proof_bytes[index*32:(index+1)*32]`). In Barretenberg UltraPlonk proofs, the first bytes are cryptographic commitments (e.g., $W_1$), not public inputs. This guarantees that `extract_pi` will always return garbage data, resulting in an unconditional `public_input_mismatch` and preventing any proof from ever verifying successfully.

---
## Conclusion

Phase A has successfully mapped the backend integration points and identified the precise architectural defects blocking execution. The environment is non-portable (WSL), the database initialization is fractured (MSSQL vs Postgres), the concurrency architecture is disabled, and cryptographic verification is structurally flawed. 

**The repository is ready to proceed to Phase B (Database & Configuration Remediation).**

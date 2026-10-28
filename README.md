# Privacy-Preserving Zero-Knowledge SBOM Vulnerability Verification Platform

> [!IMPORTANT]
> **Authoritative Documentation & Governance Root:**
> All project specifications, security rules, cryptographic parameters, the Official Locked Roadmap V3, and audit registers are consolidated in:
> [`MASTER_PROJECT_CONTEXT/`](MASTER_PROJECT_CONTEXT/) (see [`MASTER_PROJECT_CONTEXT/README.md`](MASTER_PROJECT_CONTEXT/README.md)).
> For the complete runtime and technology specification, see [`TECH_STACK_AND_ENVIRONMENT.md`](TECH_STACK_AND_ENVIRONMENT.md).
> For agent instructions and operating rules, see [`AGENTS.md`](AGENTS.md).


---

## 1. Executive Summary

This research and engineering platform enables a software vendor to cryptographically prove that a Software Bill of Materials (SBOM) complies with a specific security policy against an authoritative vulnerability database snapshot, using zero-knowledge proofs (UltraPlonk / ACIR).

A buyer independently verifies the proof and public commitments ($R_{\text{SBOM}}$, $R_{\text{VulnDB}}$, $H_{\text{Policy}}$) and consults an authorized verification certificate **without receiving or disclosing the private SBOM component inventory**.

A valid proof establishes compliance strictly against the identified policy and committed snapshot—it does not claim the software is universally free of all vulnerabilities.

---

## 2. Core Architecture & Consolidated 3-Role Model

Under **Stage G (G0–G6)** of the Official Locked Roadmap V3, user workflows are consolidated into three distinct roles:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Next.js 15 App Router                           │
│     (RouteGuard Protected | In-Memory Bearer Auth | Slate Design System)    │
└──────────────┬──────────────────────────────┬───────────────────────────────┘
               │                              │
        ┌──────▼──────┐                ┌──────▼──────┐
        │   Vendor    │                │    Buyer    │
        │  Workspace  │                │  Workspace  │
        └──────┬──────┘                └──────┬──────┘
               │                              │
               └──────────────┬───────────────┘
                              │
                       ┌──────▼──────┐
                       │    Admin    │
                       │  Workspace  │
                       └──────┬──────┘
                              │
               ┌──────────────▼──────────────┐
               │    Internal Nginx Gateway   │
               │         (Port 8000)         │
               └──────────────┬──────────────┘
                              │
     ┌────────────────────────┼────────────────────────┐
     │                        │                        │
┌────▼───────────┐   ┌────────▼──────────┐   ┌─────────▼─────────┐
│  SBOM Service  │   │ Vulnerability Svc │   │  Policy Service   │
│  (Port 8001)   │   │   (Port 8002)     │   │   (Port 8003)     │
└────┬───────────┘   └────────┬──────────┘   └─────────┬─────────┘
     │                        │                        │
     └────────────────────────┼────────────────────────┘
                              │
     ┌────────────────────────┴────────────────────────┐
     │                                                 │
┌────▼───────────┐                            ┌────────▼──────────┐
│  ZKP Service   │                            │ Verification Svc  │
│  (Port 8004)   │                            │   (Port 8005)     │
└────┬───────────┘                            └────────┬──────────┘
     │                                                 │
     ▼                                                 ▼
Noir 0.32.0 / Native bb.exe                     PostgreSQL 17
(256 Segment SMT Prover)                        (Alembic 001-016)
```

1. **Vendor:** Manages applications and private SBOMs; initiates segmented UltraPlonk proof jobs; exports verifiable evidence bundles.
2. **Buyer:** Receives evidence bundles; independently verifies proofs and public cryptographic commitments; validates authentic verification certificates.
3. **Admin:** Manages user accounts, security policies, and vulnerability intelligence snapshots with TTL lifecycle management.

---

## 3. Cryptographic Foundation

- **Proving System:** UltraPlonk via Barretenberg 0.46.1 native runtime (`bb.exe` / `bb_launcher.c`).
- **Circuit Architecture:** Decomposed 32-attribute Sparse Merkle Tree (SMT) circuits in Noir 0.32.0:
  - [`segment_init_32/`](segment_init_32/): Initial segment circuit.
  - [`segment_mid_32/`](segment_mid_32/): Intermediate accumulator segment circuit.
  - [`segment_final_32/`](segment_final_32/): Terminal segment circuit binding public inputs.
- **Poseidon Sponge Parameters:** $t=2$ and $t=3$ over BN254 / Alt-bn128 curve.
- **Empirical Scale:** Verified across 256 segments (1,024 components, 32 chunks) in 531.8 seconds with zero proof regeneration.

---

## 4. Technology Stack & Verification State

| Domain | Technology / Specification | Verification Status |
| :--- | :--- | :--- |
| **Frontend** | Next.js 15, React 19, TypeScript, Tailwind CSS / Vanilla CSS | 116 automated unit/integration tests passing (0 skips) |
| **Backend Services** | FastAPI 0.115, Python 3.11, Pydantic v2, SQLAlchemy 2.0 | 1,345 backend unit/integration tests passing (0 skips) |
| **Cross-Role Suite** | Automated regression across Vendor, Buyer, Admin | 348 automated tests passing (0 failures, 0 skips) |
| **Database** | PostgreSQL 17, Alembic linear migrations 001 through 016 | Rev 016 applied (Snapshot TTL, tenant isolation, token revocation) |
| **Crypto Runtime** | Noir 0.32.0, Barretenberg 0.46.1, Native `bb_launcher.c` | 24/24 cryptographic tests passing (0 skips) |

---

## 5. Security & Privacy Invariants

1. **In-Memory Privacy:** Bearer tokens are held strictly in memory (`authTransport.ts`) and cleared on logout or refresh. Re-authentication is the deliberate design trade-off for zero persistent browser storage leaks.
2. **Multi-Tenant Isolation:** Application tenant isolation enforced across SBOMs and components (Alembic rev 014).
3. **Token Revocation:** Database-backed token blacklisting for revoked authentication tokens (Alembic rev 015).
4. **Vulnerability Snapshot TTL:** Time-to-live expiration enforced on vulnerability snapshots (Alembic rev 016).
5. **Redaction & Logging:** Credentials, tokens, and raw SBOM component records are scrubbed by logging filters.
6. **Operating Boundary:** Gate 5R is strictly enforced: **LOCAL-ONLY** operation. No remote production databases, deployments, or credentials exist in this repository.

---

## 6. Repository Layout

```
.
├── MASTER_PROJECT_CONTEXT/   # Consolidated authoritative documentation root
│   ├── project_context/      # Locked Roadmap V3, decisions, security rules, student runbook
│   └── README.md             # Documentation directory index
├── backend/                  # 5 FastAPI microservices & shared libraries
│   ├── alembic/              # Linear database migrations (001 through 016)
│   ├── verification_service/ # Independent proof & certificate verification
│   ├── zkp_service/          # Noir proving pipeline & ACVM integration
│   ├── sbom_service/         # SBOM parsing, normalization & tenant isolation
│   ├── policy_service/       # Policy creation & version enforcement
│   └── vulnerability_service/# CVE/NVD snapshot management & TTL lifecycle
├── frontend/                 # Next.js 15 application
│   ├── src/app/              # App Router pages (Vendor, Buyer, Admin workspaces)
│   ├── src/auth/             # RouteGuard & in-memory auth transport
│   └── src/components/       # UI design system components
├── segment_init_32/          # Noir SMT initial segment circuit
├── segment_mid_32/           # Noir SMT accumulator segment circuit
├── segment_final_32/         # Noir SMT terminal segment circuit
├── archive/                  # 256-segment proof archive & verification keys
├── master_archive/           # Preserved historical circuits and audit reports
├── scripts/                  # Native bb_launcher.c, crypto setup & test runners
├── docker/                   # Internal Nginx reverse proxy configuration
├── bootstrap.ps1             # Automated local development bootstrap script
├── .env.local_dev.example    # Local development configuration template
└── README.md                 # Public onboarding documentation
```

---

## 7. Local Development & Verification

### 7.0 Prerequisites & Environment Requirements
Before initializing the environment from a newly extracted source ZIP:
- **Node.js & npm:** Node.js >= 18.0.0 and npm (required to install the pinned cryptographic runtime `@noir-lang/backend_barretenberg@0.32.0`, which provides the Barretenberg `@aztec/bb.js@0.46.1` engine).
- **Python:** Python 3.11+ with `venv` (required for backend microservices and test suites).
- **C Compiler (Optional):** GCC (e.g. MinGW-w64 on Windows) to compile the native `.bin/bb.exe` launcher from `scripts/bb_launcher.c`. If GCC is absent, the setup script automatically configures `.bin/bb.cmd` as the fallback execution wrapper.
- **Noir Compiler (Optional):** Noir 0.32.0 (`nargo`) via `noirup -v 0.32.0`. *Note: Circuit compilation is only required if modifying `.nr` circuit source files. Independent proof verification (`bb verify`) and live testing of existing proofs do not require `nargo`.*

### 7.1 Native Cryptographic Runtime Setup (First Step)
Because platform-specific binaries (`.bin/`) and `node_modules` are properly excluded from the source distribution, initialize the cryptographic runtime first:
```powershell
.\scripts\setup_crypto_runtime.ps1
```
This script validates Node.js, restores pinned `@noir-lang/backend_barretenberg@0.32.0` (providing `@aztec/bb.js@0.46.1`) via `npm ci`, creates the `.bin/` directory, generates the Windows `bb.cmd` and POSIX `bb` wrappers, compiles `bb.exe` if GCC is available, and executes `bb --help` verification.

### 7.2 Project Context Bootstrap
Inspect the project context, roadmap status, and safety boundaries:
```powershell
.\bootstrap.ps1
```

### 7.3 Backend Verification & Cryptographic Tests
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # On POSIX: source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest backend/verification_service/tests/test_b1_live_crypto.py -q
pytest -q
```

### 7.4 Frontend Verification
```powershell
cd frontend
npm ci
npm test
npx tsc --noEmit
npx eslint .
npm run build
npm run dev
```

---

## 8. Deployment Boundaries & Limitations

- **Production Deployment Status:** **NOT READY / NOT VERIFIED**.
- **TLS Termination:** The internal Nginx gateway operates over plain HTTP inside Docker. External HTTPS/TLS termination, origin isolation, and WAF are unconfigured and deferred.
- **Production Infrastructure:** No cloud hosting infrastructure is provisioned. The repository is configured exclusively for local development, academic inspection, and candidate viva demonstrations.
- **Proof Guarantee:** A zero-knowledge proof verifies compliance strictly against the identified policy and committed vulnerability snapshot—it does not certify an application is free from all vulnerabilities.

---

## 9. Governance & Academic Reference

- **Authoritative Context:** [`MASTER_PROJECT_CONTEXT/`](MASTER_PROJECT_CONTEXT/)
- **Locked Roadmap:** [`MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md`](MASTER_PROJECT_CONTEXT/project_context/PROJECT_ROADMAP.md)
- **Candidate Viva Slides:** [`MASTER_PROJECT_CONTEXT/project_context/VIVA_PRESENTATION_SLIDES.md`](MASTER_PROJECT_CONTEXT/project_context/VIVA_PRESENTATION_SLIDES.md)
- **Operational Runbook:** [`MASTER_PROJECT_CONTEXT/project_context/STUDENT_RUNBOOK.md`](MASTER_PROJECT_CONTEXT/project_context/STUDENT_RUNBOOK.md)
- **Security Validation Report:** [`MASTER_PROJECT_CONTEXT/project_context/SECURITY_VALIDATION_REPORT.md`](MASTER_PROJECT_CONTEXT/project_context/SECURITY_VALIDATION_REPORT.md)

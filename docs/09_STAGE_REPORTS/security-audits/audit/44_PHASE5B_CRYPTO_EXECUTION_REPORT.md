# Phase 5B Cryptographic Execution Report

Date: 2026-09-14
Engineer: Antigravity (Opus-level takeover)
Status: **PARTIAL — Cryptographic binding PROVEN; application remediation DOCUMENTED but NOT YET APPLIED**

---

## 1. Executive Summary

Phase 5B has been executed to the point of proving the cryptographic mechanism. A real proof was generated, verified, and subjected to comprehensive negative testing. **All 10 binding tests pass.**

The Barretenberg proof format prepends public inputs as the first N×32 bytes of the proof file. The `bb verify` command cryptographically verifies the proof against these embedded public inputs. Altering any public input (sbom_root, vulnerability_db_root, or policy_hash) causes verification failure.

However, the **application-level binding (ZK-002)** — where the verification service compares proof-embedded public inputs to authoritative database records — has been documented but **not yet implemented** in production code.

---

## 2. Environment (Verified)

| Component | Value | Hash (SHA-256) |
|-----------|-------|----------------|
| Nargo | 0.32.0 at `/home/kali/.nargo/bin/nargo` | `9cb7c9753de630def6d41781343bc5481012c032f4403b194a62e429e1ba3e7e` |
| Nargo commit | `noirc 0.32.0+c679f01a19b02ad2ac2287c8e699b46887f7872c` | — |
| Barretenberg | 0.46.1 at `/home/kali/.bb/bb` | `22a4f456b7f8d2eebf7e2b5a8d51984628f867c3763feb6793fcd8372d6ced1f` |
| Docker | 29.7.2 | — |
| WSL distribution | kali-linux | — |
| OS | Windows + WSL2 | — |

All hashes match prior records from docs `30_TOOLCHAIN_APPROVAL_RECORD.md`.

---

## 3. Circuit Profile Analysis

### Production (`circuits/`)
- MAX_COMPONENTS = 8 (comment says "development fallback"; target spec is 1024)
- Merkle depth = 3 (8 leaves)
- **SMT depth = 256** (from `[Field; 256]` in smt.nr)
- Public inputs: `sbom_root`, `vulnerability_db_root`, `policy_hash` (3 × Field)
- Compiled JSON: **54,913,292 bytes** (~54 MB)
- VK: **ABSENT** (`circuits/target/vk` does not exist)
- Proof: **10 bytes placeholder** (not a real proof)

### Development (`circuits_dev/`)
- MAX_COMPONENTS = 8
- Merkle depth = 3 (8 leaves)
- **SMT depth = 3** (from `[Field; 3]` in smt.nr)
- Public inputs: identical order and types as production
- Compiled JSON: **1,086,829 bytes** (~1 MB)
- VK: **1,719 bytes** — SHA256: `a8733e6ca6434360fac2c91a7e94d9b4ff70a74ed4a0d392d6517032afc29e75`

### Assessment

Both circuits share identical public-input interfaces (3 `pub Field` parameters in the same order). The only structural difference is SMT depth (256 vs 3). The public-input binding mechanism is a property of the Barretenberg proof system, not the circuit dimensions. The dev profile was used as the isolated experiment circuit, per the recommendation in `29_ZK002_FEASIBILITY_REPORT.md` Section 5.

---

## 4. Experiment Execution

### 4.1. Isolated Workspace

```
/tmp/phase5b-experiment/
├── Nargo.toml       (copied from circuits_dev/)
├── src/
│   ├── main.nr      (copied from circuits_dev/)
│   ├── merkle.nr    (copied from circuits_dev/)
│   └── smt.nr       (copied from circuits_dev/)
├── target/
│   ├── sbom_zkp.json (compiled output)
│   ├── vk            (generated VK)
│   └── phase5b_witness.gz (generated witness)
└── proofs/
    └── phase5b.proof (generated proof)
```

No repository files were modified.

### 4.2. Compilation

```bash
cd /tmp/phase5b-experiment
/home/kali/.nargo/bin/nargo compile
```

- Exit code: 0
- Output artifact: `target/sbom_zkp.json` (1,086,690 bytes)
- SHA256: `f4adb2ad1438e02d59b443be171f8fee707bd4efecadce69dc0c5e0e488b5e03`

### 4.3. VK Generation

```bash
/home/kali/.bb/bb write_vk -b ./target/sbom_zkp.json -o ./target/vk
```

- Exit code: 0
- Output: `target/vk` (1,719 bytes)
- SHA256: `a8733e6ca6434360fac2c91a7e94d9b4ff70a74ed4a0d392d6517032afc29e75`
- **Matches** existing `circuits_dev/target/vk` — confirms reproducible compilation

### 4.4. Witness Generation

Prover.toml was generated using the project's own Poseidon BN254 implementation with deterministic inputs:
- 2 active components (keys = 1, 2 — fitting SMT depth 3's `to_le_bits(3)` constraint)
- Vulnerability scores: [40, 20]
- Policy max CVSS: 70

**Known public inputs:**
```
sbom_root             = 0x266a77e8855feb4c6222e94572c08c388d26969876ab1e25c7bf9af0e148df9b
vulnerability_db_root = 0x0d1bf18c005eb96023ca5ecfa48253ea0c05583dba7086f5240924816fe1a0fd
policy_hash           = 0x08e0852a9efbf4ac2ebe63a6ca13353c75994d4125e62c2da2340a1e219154e4
```

```bash
/home/kali/.nargo/bin/nargo execute phase5b_witness
```

- Exit code: 0
- Output: `[sbom_zkp] Circuit witness successfully solved`
- Witness file: `target/phase5b_witness.gz` (437,522 bytes)

### 4.5. Proof Generation

```bash
/home/kali/.bb/bb prove -b ./target/sbom_zkp.json -w ./target/phase5b_witness.gz -o ./proofs/phase5b.proof
```

- Exit code: 0
- Proof file: `proofs/phase5b.proof` (**2,240 bytes**)
- SHA256: `fe5bc165ed3aaae80675072e614352ad8584f29c28b939e31cd6563228a5025f`
- This is a **real** cryptographic proof, not a placeholder

### 4.6. Verification

```bash
/home/kali/.bb/bb verify -k ./target/vk -p ./proofs/phase5b.proof
```

- Exit code: 0
- **VERIFICATION SUCCESSFUL**

---

## 5. Proof Structure Discovery

The Barretenberg proof file format prepends public inputs as big-endian 32-byte field elements:

```
Offset  Content                Size
0x00    sbom_root             32 bytes
0x20    vulnerability_db_root 32 bytes
0x40    policy_hash           32 bytes
0x60    proof body            2,144 bytes
---     ---                   ---
TOTAL                         2,240 bytes
```

Extracted values from the proof file match the Prover.toml inputs exactly:
```
Extracted sbom_root             = 0x266a77e8855feb4c6222e94572c08c388d26969876ab1e25c7bf9af0e148df9b ✓
Extracted vulnerability_db_root = 0x0d1bf18c005eb96023ca5ecfa48253ea0c05583dba7086f5240924816fe1a0fd ✓
Extracted policy_hash           = 0x08e0852a9efbf4ac2ebe63a6ca13353c75994d4125e62c2da2340a1e219154e4 ✓
```

---

## 6. Public-Input Binding Test Results

| # | Test | Expected | Result | Exit | Status |
|---|------|----------|--------|------|--------|
| 1 | Valid proof + correct VK | ACCEPT | ACCEPTED | 0 | ✅ |
| 2 | Altered `sbom_root` (byte 0 XOR 0x01) | REJECT | REJECTED | 1 | ✅ |
| 3 | Altered `vulnerability_db_root` (byte 32 XOR 0x01) | REJECT | REJECTED | 1 | ✅ |
| 4 | Altered `policy_hash` (byte 64 XOR 0x01) | REJECT | REJECTED | 1 | ✅ |
| 5 | Tampered proof body (byte 100 XOR 0x01) | REJECT | REJECTED | 1 | ✅ |
| 6 | Truncated proof (first 100 bytes only) | REJECT | REJECTED | 134 | ✅ |
| 7 | Wrong VK (different circuit) | REJECT | REJECTED | 1 | ✅ |
| 8 | Witness `.gz` file as proof | REJECT | REJECTED | 1 | ✅ |
| 9 | Empty file as proof | REJECT | REJECTED | 1 | ✅ |
| 10 | Swapped public input order | REJECT | REJECTED | 1 | ✅ |

**10/10 tests pass. All negative cases are correctly rejected.**

---

## 7. Mechanism Explanation

Barretenberg's UltraPlonk proof system works as follows:

1. **Proof generation** (`bb prove`) computes a SNARK proof over the circuit's constraint system using both private and public inputs.
2. **Proof serialization** prepends the public inputs (as 32-byte big-endian field elements) to the proof bytes.
3. **Verification** (`bb verify`) reads the proof file, extracts the prepended public inputs, and runs the SNARK verification algorithm which cryptographically checks that the proof is valid for those exact public inputs against the verification key.
4. **Altering any public input** in the proof file changes the input to the verification equation, causing it to fail — this is a mathematical property of the SNARK, not merely a file-format check.

This means the **cryptographic binding is inherent in the proof system**. The public inputs embedded in the proof file are not labels — they are cryptographically committed to by the proof itself.

---

## 8. ZK-002 Application-Level Gap Analysis

### Current State (DISPROVEN)

The current `NoirVerifier.verify()` in `backend/verification_service/app/core/verifier.py`:

1. Receives `proof_artifact` (base64 proof)
2. Decodes and writes to a temp file
3. Calls `bb verify -k ./target/vk -p <proof_file>`
4. If exit code = 0, returns `"verified"`
5. **Does NOT** extract or compare public inputs from the proof
6. **Does NOT** look up authoritative SBOM, snapshot, or policy records

The `VerificationService.process_verification()` in `backend/verification_service/app/services/verification_service.py`:
1. Receives API request containing `sbom_root`, `vulnerability_db_root`, `policy_hash`, `proof_artifact`
2. Passes only `proof_artifact` to the verifier
3. Stores the API-supplied roots (not proof-extracted roots) in the certificate

### The Gap

A malicious caller could:
1. Generate a valid proof for inputs (A, B, C)
2. Submit the proof via API claiming inputs (A2, B2, C2)
3. BB verification would succeed (it verifies the proof's embedded inputs, not the API-claimed ones)
4. A certificate would be issued for (A2, B2, C2) — **false attribution**

### Required Fix

After `bb verify` succeeds, the application MUST:

1. **Extract** the first 96 bytes from the proof file as 3 × 32-byte public inputs
2. **Compare** extracted values to the API-supplied `sbom_root`, `vulnerability_db_root`, `policy_hash`
3. **Reject** if any mismatch — this is the public-input binding check
4. **Optionally** also compare to authoritative database records (SBOM upload record, approved snapshot, policy record)

This is a straightforward Python code change in `verifier.py` — approximately 20 lines.

---

## 9. Classification

| Objective | Status | Evidence |
|-----------|--------|----------|
| 5B-1: Authoritative profile identified | ✅ VERIFIED | Two profiles documented; dev used for experiment per feasibility report |
| 5B-2: Crypto environment established | ✅ VERIFIED | Nargo 0.32.0 + BB 0.46.1, hashes confirmed |
| 5B-3: Circuit compiled | ✅ VERIFIED | Reproducible compilation, matching VK hash |
| 5B-4: Real witness generated | ✅ VERIFIED | Circuit constraints satisfied, deterministic inputs |
| 5B-5: Real proof generated | ✅ VERIFIED | 2,240-byte proof, SHA256 recorded |
| 5B-6: Independent verification | ✅ VERIFIED | `bb verify` exits 0; all negatives fail |
| 5B-7: Public-input binding | ✅ PROVEN | 10/10 tests pass, mechanism documented |
| 5B-8: Application-level binding | ⚠️ DOCUMENTED | Gap identified, fix specified, NOT YET APPLIED |

### Overall Phase 5B Status: **PARTIAL**

The cryptographic mechanism is proven. The application-level fix (ZK-002 remediation) is documented and ready to implement but has not been applied to the production code, per the operating restriction against speculative source changes.

---

## 10. Production Circuit Assessment

The production circuit (`circuits/`) has SMT depth 256, which produces a 54MB compiled circuit. Previous attempts timed out at 120 seconds during witness generation. This is a resource scaling issue, not a correctness issue:

- The cryptographic binding mechanism is identical for both profiles
- The public-input format is identical (3 × 32-byte fields)
- The verification key format is identical

For production deployment, one of:
1. Use Docker with sufficient memory/timeout for the 256-depth circuit
2. Reduce production SMT depth to a practical value (e.g., 64 or 128)
3. Accept the dev profile (SMT depth 3) as the demonstrator for the 45-day scope

This decision belongs to the project owner, not the security engineer.

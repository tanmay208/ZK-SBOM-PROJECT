# Public-Input Binding Validation Report

Date: 2026-09-14
Finding: ZK-002
Status: **CRYPTOGRAPHIC MECHANISM PROVEN; APPLICATION-LEVEL FIX SPECIFIED**

---

## 1. Validation Result

**PUBLIC-INPUT BINDING VALIDATED: YES (at cryptographic level)**

The Barretenberg proof format cryptographically binds public inputs. The `bb verify` command cannot accept a proof whose embedded public inputs have been altered. This was demonstrated with 10 controlled tests, all passing.

**APPLICATION-LEVEL BINDING IMPLEMENTED: NO**

The current `NoirVerifier.verify()` does not extract or compare public inputs from the proof file. A fix is specified below.

---

## 2. Proof Structure

Barretenberg proof file layout for this circuit (3 public inputs):

```
[0..31]   sbom_root              (32-byte big-endian BN254 field element)
[32..63]  vulnerability_db_root  (32-byte big-endian BN254 field element)
[64..95]  policy_hash            (32-byte big-endian BN254 field element)
[96..]    proof body             (UltraPlonk proof)
```

Number of public inputs = 3. Each is 32 bytes. Total public-input prefix = 96 bytes.
The proof body begins at byte offset 96.

---

## 3. Positive Test

| Input | Expected | Result |
|-------|----------|--------|
| Valid proof, matching VK, correct public inputs embedded | ACCEPT | ACCEPTED (exit=0) ✅ |

---

## 4. Negative Tests

| # | Alteration | Expected | Result | Exit | Status |
|---|------------|----------|--------|------|--------|
| 1 | Byte 0 of sbom_root XOR 0x01 | REJECT | REJECTED | 1 | ✅ |
| 2 | Byte 32 of vulnerability_db_root XOR 0x01 | REJECT | REJECTED | 1 | ✅ |
| 3 | Byte 64 of policy_hash XOR 0x01 | REJECT | REJECTED | 1 | ✅ |
| 4 | Byte 100 of proof body XOR 0x01 | REJECT | REJECTED | 1 | ✅ |
| 5 | Truncated to 100 bytes | REJECT | REJECTED | 134 | ✅ |
| 6 | Wrong VK (compiled from different circuit) | REJECT | REJECTED | 1 | ✅ |
| 7 | Witness .gz file supplied as proof | REJECT | REJECTED | 1 | ✅ |
| 8 | Empty file supplied as proof | REJECT | REJECTED | 1 | ✅ |
| 9 | Swapped sbom_root and vulnerability_db_root | REJECT | REJECTED | 1 | ✅ |

---

## 5. Why This Proves Binding

The SNARK verification equation is:

```
Verify(VK, public_inputs, proof) → {true, false}
```

The public inputs are not metadata — they are cryptographic inputs to the verification equation. If any public input differs from what the prover used, the equation yields `false`. This is a mathematical guarantee of the UltraPlonk proof system, not a software check.

The proof file prepends the public inputs, and `bb verify` reads them as part of the verification. Therefore:

1. The proof file is the **canonical source** of what public inputs were proven
2. Altering the embedded public inputs breaks the cryptographic verification
3. A valid proof can ONLY verify with the exact public inputs it was generated for

---

## 6. Application-Level Fix Specification

### Problem

The current verifier accepts the proof and calls `bb verify`, which succeeds based on the proof's embedded public inputs. But the application stores the API-supplied roots in the certificate, not the proof-extracted roots. A caller can submit a valid proof for (A, B, C) while claiming (A2, B2, C2) and get a certificate for the wrong inputs.

### Solution

After `bb verify` returns exit code 0, the verifier must:

```python
# Extract public inputs from proof file (first 96 bytes = 3 × 32-byte fields)
NUM_PUBLIC_INPUTS = 3
FIELD_SIZE = 32

with open(proof_path, "rb") as f:
    proof_bytes = f.read()

extracted_inputs = []
for i in range(NUM_PUBLIC_INPUTS):
    field_bytes = proof_bytes[i * FIELD_SIZE : (i + 1) * FIELD_SIZE]
    extracted_inputs.append("0x" + field_bytes.hex())

# Compare to expected values (from API request / authoritative records)
expected = [expected_sbom_root, expected_vuln_root, expected_policy_hash]
if extracted_inputs != expected:
    return "public_input_mismatch"
```

### Where to Apply

File: `backend/verification_service/app/core/verifier.py`

The `verify()` method signature must be extended to accept expected public inputs:
```python
def verify(self, proof_artifact: str | None, 
           expected_sbom_root: str | None = None,
           expected_vuln_root: str | None = None,
           expected_policy_hash: str | None = None) -> str:
```

The `VerificationService.process_verification()` must pass the API request's roots to the verifier.

### Test Coverage

- Matching inputs → `"verified"` ✅
- Mismatched sbom_root → `"public_input_mismatch"` 
- Mismatched vulnerability_db_root → `"public_input_mismatch"`
- Mismatched policy_hash → `"public_input_mismatch"`

---

## 7. Authoritative Record Binding (5B-8)

Beyond comparing proof inputs to API inputs, the full invariant requires:

```
PROOF PUBLIC INPUTS == API REQUEST INPUTS == AUTHORITATIVE DATABASE RECORDS
```

This requires the verification service to:
1. Look up the SBOM record by `sbom_root` and verify it exists and is the caller's
2. Look up the vulnerability snapshot by `vulnerability_db_root` and verify it is approved
3. Look up the policy by `policy_hash` and verify it is active

This is an application-level access control concern beyond the cryptographic binding. The database lookups already exist in the prover service; the verification service needs equivalent read-only checks.

---

## 8. Evidence Artifacts

| Artifact | Location | SHA-256 |
|----------|----------|---------|
| Compiled circuit | `/tmp/phase5b-experiment/target/sbom_zkp.json` | `f4adb2ad1438e02d59b443be171f8fee707bd4efecadce69dc0c5e0e488b5e03` |
| Verification key | `/tmp/phase5b-experiment/target/vk` | `a8733e6ca6434360fac2c91a7e94d9b4ff70a74ed4a0d392d6517032afc29e75` |
| Witness | `/tmp/phase5b-experiment/target/phase5b_witness.gz` | N/A (intermediate) |
| Proof | `/tmp/phase5b-experiment/proofs/phase5b.proof` | `fe5bc165ed3aaae80675072e614352ad8584f29c28b939e31cd6563228a5025f` |
| Nargo executable | `/home/kali/.nargo/bin/nargo` | `9cb7c9753de630def6d41781343bc5481012c032f4403b194a62e429e1ba3e7e` |
| BB executable | `/home/kali/.bb/bb` | `22a4f456b7f8d2eebf7e2b5a8d51984628f867c3763feb6793fcd8372d6ced1f` |

# Cryptographic and ZK Audit

## Verified Code Properties

- Python uses BN254 Fr constants, 31-byte big-endian chunks, `0x80` termination, and a Poseidon sponge with a fixed maximum of 216 fields.
- Python Merkle uses `hash_1(0)` empty leaves and fixed depth 3 in `DEV_MODE`, depth 10 otherwise.
- Circuit source uses Poseidon, little-endian key bits for SMT paths, and asserts policy hash, component count, SBOM root, score bound, SMT paths, and public root equality.
- Certificate creation occurs only when the verifier returns exactly `verified` in repository code.

## Finding ZK-001

**Title:** Production Python commitment profile does not match the checked-in production circuit profile

**Severity:** High

**Confidence:** Confirmed

**Classification:** CONFIRMED VULNERABILITY (integrity/availability deployment defect)

**Affected files:** `backend/shared/crypto/merkle.py`, `backend/zkp_service/app/services/prover_service.py`, `circuits/src/main.nr`, `circuits/src/merkle.nr`.

**Attacker role:** Any caller able to submit or trigger proof generation; also affects legitimate production users.

**Attacker-controlled input:** Component count and upstream IDs; profile selected by `DEV_MODE`.

**Expected invariant:** Production SBOM root, witness dimensions, circuit constraints, and verification key must be one mutually compatible profile.

**Actual behavior:** Python default Merkle profile is depth 10/1024, while checked-in production Noir source has arrays of 8 and depth 3. Prover rejects counts over 8 and always serializes eight entries. Production verification key file is absent; development key exists. Therefore production success is not demonstrated and is expected to fail or be incompatible.

**Exact data flow:** SBOM commit computes default Python root -> prover reads it and creates 8-entry witness -> production circuit computes depth-3 root -> verifier looks for `circuits/target/vk`.

**Attack prerequisites:** Production execution or a user attempting a production proof; no exploit account needed for availability impact.

**Impact:** Proof generation/verification denial and inability to rely on production certificates; profile confusion could invalidate integrity assumptions.

**Evidence:** Direct source/artifact inspection; `Test-Path circuits/target/vk` false, `Test-Path circuits_dev/target/vk` true. Nargo/Barretenberg were unavailable, so no live proof claim is made.

**Reproduction or validation method:** Compare source dimensions and Python constants; attempt production toolchain only after installing approved tools.

**Existing mitigations:** Explicit `DEV_MODE` branch and comments identify development scale.

**Why mitigations are insufficient:** Default deployment does not prove that profile and key artifacts align; comments do not enforce selection.

**Recommended remediation:** Freeze profile manifests, compile and verify production circuit/key pair in CI, refuse startup when selected artifacts are absent or mismatched, and remove dev fallback from production.

**Required regression test:** Generate and verify a real production proof for 0, 1, 8, 9, and maximum components with production VK; reject dev proof under production VK.

**Residual risk:** Cross-language Poseidon/encoding interoperability remains unverified without Nargo.

## Finding ZK-002

**Title:** Verification trusts caller-supplied commitments rather than an authoritative registry

**Severity:** High

**Confidence:** Confirmed for trust-model violation; live cryptographic exploit unexecuted

**Classification:** CONFIRMED VULNERABILITY

**Affected files:** `verification_routes.py`, `verification_service.py`, `verification_repository.py`, `verification_schemas.py`.

**Actual behavior:** Verifier checks the submitted artifact against the submitted roots/hash but never resolves those commitments against approved SBOM, vulnerability, or policy records. A genuine proof over attacker-selected public inputs can therefore yield a certificate that is cryptographically valid but not authoritative for the platform.

**Impact:** False assurance and certificate integrity failure.

**Existing mitigation:** Circuit binds roots internally and certificate issuance is gated on verifier exit code.

**Why insufficient:** Binding to caller-selected values is not binding to the platform's intended values.

**Required test:** Submit a real proof for an unapproved root and assert certificate issuance is denied.

## Unverified Areas

UNVERIFIED — INSUFFICIENT EVIDENCE for Noir Poseidon compatibility, proof artifact format authenticity, production VK correctness, stale-proof binding policy, and complete private witness non-retention. No cryptographic bypass is claimed solely from fake/mutated proof files.

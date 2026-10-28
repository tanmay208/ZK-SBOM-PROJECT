# ZK-002 Feasibility Report

Date: 2026-09-13
Finding: ZK-002 - Proof public inputs not bound to authoritative records
Scope: Feasibility and experiment design only. No verifier, circuit, or API code was changed.

## 1. Required invariant

The platform must establish before certificate issuance:

```text
verified proof public inputs
    == API request public inputs
    == authoritative database records
```

For the current circuit, `circuits/src/main.nr` declares the first three parameters public in this exact order:

1. `sbom_root: pub Field`
2. `vulnerability_db_root: pub Field`
3. `policy_hash: pub Field`

The remaining witness parameters are private. The order must be confirmed again from the generated ABI in the approved build, not inferred solely from source.

## 2. Current application result

The invariant is not enforced by the current application:

- `backend/verification_service/app/core/verifier.py:NoirVerifier.verify` accepts only a base64 proof artifact and invokes `bb verify -k ./target/vk -p <proof>`.
- `backend/verification_service/app/services/verification_service.py:process_verification` passes no expected public-input vector to the verifier.
- `backend/verification_service/app/repositories/verification_repository.py:create_verification_record` persists request-supplied roots and creates a certificate when the verifier returns `verified`.
- No authoritative SBOM, approved snapshot, or approved policy lookup occurs before certificate creation.

This is a current-implementation failure, not a claim that Barretenberg is incapable of public-input handling.

## 3. Supported mechanism evidence

The vendored official Noir source provides a supported mechanism in the NoirJS Barretenberg backend:

1. `@noir-lang/backend_barretenberg` version `0.32.0` depends on `@aztec/bb.js` `0.46.1`.
2. Its `ProofData` type contains `publicInputs: string[]` and `proof: Uint8Array`.
3. `BarretenbergBackend.generateProof` separates public-input bytes from the proof and returns `ProofData`.
4. `BarretenbergVerifier.verifyProof(proofData, verificationKey)` reconstructs the complete proof by flattening and prepending `proofData.publicInputs`, then calls the Barretenberg verification API.
5. `public_inputs.ts` defines 32-byte public-input encoding/decoding and ordered flattening.

This establishes **capability proven by official local source**: a NoirJS/Barretenberg integration can carry public inputs as structured data and include them in cryptographic verification. An application can compare `ProofData.publicInputs` to expected authoritative values before invoking `verifyProof`; altered public inputs should cause verification failure because the reconstructed proof bytes change.

It does not establish **capability proven by executable evidence** for this repository. The vendored TypeScript package was not built or run, Nargo is unavailable, no valid production VK exists, and the Python service does not use this API.

The installed WSL CLI reports BB `0.46.1`, but its `verify --help` and `verify -h` invocations attempted to read a missing `./target/vk` rather than exposing a documented expected-input interface. This leaves the CLI path's exact public-input handling unknown.

## 4. Feasibility determination

ZK-002 feasibility is **PROVEN IN PRINCIPLE, NOT EXECUTED IN THIS PROJECT**.

The supported NoirJS API evidence means a principled implementation path exists without inventing proof parsing: use a supported `ProofData` representation, compare its ordered public inputs with authoritative values, and call the supported verification API. However, ZK-002 is not fixed, the current verifier does not enforce it, and no certificate may be treated as authority-bound until the integration is executed and negative tests pass.

If the project must retain only the CLI subprocess path, feasibility remains **UNKNOWN** until an official BB CLI interface or supported serialization/API bridge is demonstrated. The CLI command currently used by the service does not itself prove expected-input equality.

## 5. Minimal isolated feasibility experiment

The experiment must live outside production source and production circuit directories, for example in a temporary workspace or separate disposable directory. It must use the approved Nargo/BB pair and a toy circuit whose public interface is deliberately small. It must not create fake proofs or modify `circuits/`, `circuits_dev/`, service code, or production VK files.

### Experiment circuit

Use an isolated Noir circuit with two private witness values and three public fields, or an equivalent minimal circuit approved by the cryptography owner. The circuit must constrain a statement and expose public values in a known order. Record the source hash and generated ABI. Do not reuse the production VK or proof.

### Positive path

1. Compile with Nargo `0.32.0`.
2. Generate a VK using the approved compatible backend.
3. Generate a proof with known public vector `[A, B, C]`.
4. Obtain structured public inputs through the supported NoirJS `ProofData` API, or through an officially documented CLI/API mechanism.
5. Assert the extracted order is exactly `[A, B, C]`.
6. Compare `[A, B, C]` to the expected vector before verification.
7. Verify using the matching VK and assert success.

### Negative paths

Each test must use the same isolated artifact and record the exact return/error:

1. Alter expected input `A` while retaining the proof; reject before certificate-equivalent success.
2. Alter expected input `B`; reject.
3. Alter expected input `C`; reject.
4. Swap public-input ordering; reject either at exact comparison or cryptographic verification.
5. Use a VK from another circuit/profile; reject.
6. Change one proof byte; reject.
7. Supply a truncated or malformed proof; reject without crash or acceptance.
8. Supply a witness/gzip artifact in place of a proof; reject.
9. Confirm the same proof cannot verify when its public inputs are reconstructed with a different vector.

### Evidence record

The experiment is successful only if it records:

- exact Nargo and BB/NoirJS versions and executable/package hashes;
- circuit, ABI, VK, and proof hashes;
- public-input order and encoding;
- exact commands/API calls;
- positive and every negative result;
- no application certificate issuance path was used;
- a reproducible clean rerun.

## 6. Execution result in this workspace

The experiment was **not executed**.

Exact blockers:

- Nargo is absent from Windows PATH and WSL Kali.
- Docker build of the repository-pinned Nargo image could not start because the Docker Linux daemon was unavailable.
- Production `circuits/target/vk` is absent.
- The checked-in production proof is a 10-byte placeholder and cannot serve as a valid proof.
- The WSL BB `0.46.1` binary is present but its CLI interface and provenance are not approved for this project.
- The vendored NoirJS package source is available, but its TypeScript backend was not built or executed.

No success, proof verification, public-input extraction, or negative-result claim is made.

## 7. Exact next action

1. Start an approved Docker Linux daemon or provision WSL with the official Nargo `v0.32.0` release asset referenced by `docker/Dockerfile.noir`.
2. Record `nargo --version` and executable hash.
3. Approve and record the BB `0.46.1` provenance or select a different explicitly compatible version; do not treat presence as approval.
4. Build/run the vendored `@noir-lang/backend_barretenberg 0.32.0` path, or obtain official CLI evidence for equivalent public-input handling.
5. Run the isolated experiment above using a disposable circuit and artifacts.
6. Only after the experiment passes should an implementation design be selected. Until then, certificate issuance remains release-blocked.

## 8. Final classification

- Current application enforcement: DISPROVEN.
- Supported public-input mechanism in official vendored NoirJS source: PROVEN BY DOCUMENTED SOURCE.
- Current project integration: UNKNOWN / NOT EXECUTED; compiler check passed, witness/proof stages did not complete.
- CLI expected-input interface: UNKNOWN.
- Production cryptographic validation: BLOCKED.
- ZK-002 remediation: NOT SOLVED.

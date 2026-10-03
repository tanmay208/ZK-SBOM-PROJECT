# Cryptographic Toolchain Compatibility

Date: 2026-09-13
Phase: 4 - Toolchain recovery and ZK-002 feasibility
Scope: Evidence and isolated-experiment design only. No production code or circuit artifact was modified.

## 1. Repository compatibility inventory

| Concern | Repository evidence | Current conclusion |
| --- | --- | --- |
| Noir/Nargo | `circuits/Nargo.toml`, `circuits_dev/Nargo.toml`, `docker/Dockerfile.noir`, target metadata | Required compiler is Noir/Nargo `0.32.0`; Docker pins `v0.32.0`. |
| Noir release | Official Noir GitHub release `v0.32.0`, dated 2024-07-18 | Release exists and is the declared compiler target. |
| NoirJS backend | Vendored `scripts/noir_src/tooling/noir_js_backend_barretenberg/package.json` | `@noir-lang/backend_barretenberg` is `0.32.0`. |
| Barretenberg library dependency | Same package metadata | `@aztec/bb.js` dependency is exactly `0.46.1`. |
| Barretenberg CLI | WSL `/home/kali/.bb/bb --version` | Reports `0.46.1`; binary is present but not approved or integrated into a validated project run. |
| Proof system | `docs/ZKP_SPECIFICATION.md`, circuit source, NoirJS backend | Noir circuit with Barretenberg backend; public inputs are fields. |
| Circuit compiler compatibility | Both project manifests use `compiler_version = "0.32.0"`; official vendored backend package is `0.32.0` | Candidate compatibility pair is evidenced by source metadata, not by a completed project proof. |
| Proof artifact | Prover writes a proof file under `circuits*/proofs`; current verifier base64-decodes it | File format and CLI serialization compatibility remain unvalidated. |
| Verification key | `circuits_dev/target/vk` exists; `circuits/target/vk` is absent | Development VK exists; production VK is unavailable. |
| Verification command | Python invokes `bb verify -k ./target/vk -p proofs/<id>.proof` | Command does not accept expected public inputs in the current wrapper. |
| Public-input order | `circuits/src/main.nr` marks the first three parameters `pub` in order | `SBOM_ROOT`, `VULNERABILITY_DB_ROOT`, `POLICY_HASH`. Must still be checked against generated ABI/proof data. |
| Profile selection | `ProverService` and `NoirVerifier` select `circuits` or `circuits_dev` from `DEV_MODE` | Not an immutable validated profile manifest; production separation remains unresolved. |

## 2. Official evidence available locally

The repository includes a vendored Noir source tree. The following official source/documentation facts were inspected:

1. `scripts/noir_src/tooling/noir_js_backend_barretenberg/package.json` declares:
   - `@noir-lang/backend_barretenberg` version `0.32.0`.
   - dependency `@aztec/bb.js` version `0.46.1`.
2. `src/backend.ts` in that package defines `ProofData` handling. `generateProof` splits the Barretenberg proof buffer into public-input bytes and proof bytes, then returns `{ proof, publicInputs }`.
3. `src/verifier.ts` defines `BarretenbergVerifier.verifyProof(proofData, verificationKey)`. It reconstructs the proof by concatenating flattened public inputs and proof bytes before calling `acirVerifyProof`.
4. `scripts/noir_src/tooling/noir_js_types/src/types.ts` defines `ProofData` as `publicInputs: string[]` plus `proof: Uint8Array`.
5. The vendored v0.32.0 project documentation explains that `pub` visibility determines verifier-visible inputs and that `Prover.toml` supplies inputs to execution/proving.
6. The vendored Barretenberg installation page describes `bb` as the CLI for generating and verifying Noir proofs and uses versioned installation through `bbup`; it does not establish this repository's CLI flags for expected public-input comparison.
7. Official Noir GitHub release `v0.32.0` exists. Official Aztec GitHub release `barretenberg-v0.46.1` exists. These release pages establish provenance/version names, not successful compatibility of this project artifacts.

This evidence proves a supported NoirJS integration data model for public inputs. It does not prove that the current Python subprocess wrapper can use it, that the installed CLI has the same interface, or that a production VK/proof is valid.

## 3. Local executable evidence

Commands executed:

```text
wsl.exe -d kali-linux -- /home/kali/.bb/bb --version
0.46.1
exit 0
```

```text
wsl.exe -d kali-linux -- /home/kali/.bb/bb verify --help
File is empty or there's an error reading it: ./target/vk
exit 1
```

The installed CLI attempted verification rather than exposing a help interface. This is not evidence that expected public-input flags do or do not exist.

The repository proof/VK attempt was also run:

```text
wsl.exe -d kali-linux -- bash -lc "cd /mnt/e/Main Project/circuits; /home/kali/.bb/bb verify -k ./target/vk -p ./proofs/sbom_zkp.proof"
File is empty or there's an error reading it: ./target/vk
exit 1
```

The production proof is only 10 bytes and `circuits/target/vk` is absent. No valid production verification was possible. Nargo was not found on Windows PATH or inside WSL. The repository Docker build was attempted using the pinned Dockerfile:

```text
docker build -f docker/Dockerfile.noir -t zkp-noir-0.32.0 .
ERROR: failed to connect to the docker API ... dockerDesktopLinuxEngine ... system cannot find the file specified
```

Therefore the pinned Docker provisioning route is documented but not executed because the Docker daemon was unavailable. No tool was installed.

## 4. Minimum compatibility matrix

The minimum matrix that must be approved and recorded before production validation is:

| Component | Candidate/required value | Evidence status | Required validation |
| --- | --- | --- | --- |
| Noir compiler/Nargo | `0.32.0` | Declared in manifests, Dockerfile, official release | Run `nargo --version`, `nargo check`, and `nargo execute` in the approved Linux environment. |
| NoirJS package, if used for binding | `@noir-lang/backend_barretenberg 0.32.0` | Vendored package metadata | Build/run the package against the selected circuit artifact. |
| Barretenberg library, if using NoirJS | `@aztec/bb.js 0.46.1` | Vendored package dependency | Execute backend proof/verification with the compiled circuit. |
| Barretenberg CLI, if retaining subprocess path | `bb 0.46.1` is a candidate only | WSL binary reports 0.46.1; CLI integration unvalidated | Verify exact CLI provenance, flags, proof/VK format, and expected-input behavior with valid artifacts. |
| Circuit compiler output | Target artifact compiled by Nargo `0.32.0` | Checked-in metadata exists; reproducible compile unavailable | Recompile in clean environment and hash source, artifact, ABI, and compiler output. |
| Proof artifact format | Noir/Barretenberg artifact compatible with selected backend | Current 10-byte production placeholder is invalid evidence | Generate a real proof and verify it with the matching VK. |
| VK format | Matching VK generated from the selected compiled circuit | Dev VK only; production VK absent | Generate or obtain VK, hash it, and reject wrong-profile VKs. |
| Verification API | NoirJS `verifyProof(ProofData, verificationKey)` is documented in vendored source; current CLI wrapper is `bb verify -k ... -p ...` | API model evidenced; project integration absent | Use supported API or document a supported CLI equivalent; no custom parser. |
| Public inputs | `ProofData.publicInputs` concatenated before verification; circuit first three `pub` fields are ordered roots | Official source evidence; project runtime unvalidated | Compare expected authoritative values to extracted/supplied public inputs, then verify. |
| Profile | Immutable project manifest, not `DEV_MODE` request behavior | Not present | Define profile ID, dimensions, hashes, tool versions, and startup fail-closed checks. |

The candidate `0.32.0`/`0.46.1` pair is a documented NoirJS dependency pairing, not a production approval. The project currently uses a Python subprocess wrapper and therefore still needs a deliberate interface decision.

## 5. Safe Nargo recovery plan

### Docker/Linux path

The repository already supplies `docker/Dockerfile.noir`, which pins:

```text
NOIR_VERSION=v0.32.0
NOIR_TAR=nargo-x86_64-unknown-linux-gnu.tar.gz
```

The next safe action is to start Docker Desktop's Linux daemon, build that exact Dockerfile, and verify `nargo --version` inside the resulting image. The image must be recorded by digest and must not be extended with an unapproved Barretenberg version. A separate approved BB artifact or the approved NoirJS backend must then be provisioned and hashed.

### WSL path

The next safe WSL action is to obtain the official Noir `v0.32.0` Linux release asset referenced by the pinned Dockerfile, verify its release/checksum provenance, and install it as `nargo` in the approved WSL distribution. Do not use the unrelated `.bin/nargo` file, a nightly, or a newer version. Then verify `nargo --version`, `nargo check`, and a temporary isolated circuit before touching production validation.

The existing WSL BB binary reports `0.46.1`, matching the vendored NoirJS backend dependency, but it must not be approved solely on version equality. Its source/provenance, CLI interface, and proof/VK behavior need validation in the same environment.

## 6. Compatibility conclusion

- Nargo `0.32.0`: required by repository artifacts; executable environment unavailable.
- Barretenberg `0.46.1`: candidate compatibility is supported by vendored package metadata and official release identity; the installed CLI is not yet approved.
- Proof/VK format: not validated against a real production artifact.
- Public-input data model: proven by official vendored NoirJS source, not executable in this workspace.
- Current Python/CLI verifier integration: does not enforce expected authoritative inputs.
- Production profile: unresolved because production VK is absent and dimensions conflict.

## 7. Status

TOOLCHAIN APPROVED: NO
NARGO ENVIRONMENT AVAILABLE: NO
BARRETENBERG CANDIDATE VERSION: 0.46.1
PRODUCTION VK AVAILABLE: NO
REAL PROOF EXECUTED: NO
PUBLIC-INPUT API EVIDENCE: OFFICIAL SOURCE, NOT EXECUTED

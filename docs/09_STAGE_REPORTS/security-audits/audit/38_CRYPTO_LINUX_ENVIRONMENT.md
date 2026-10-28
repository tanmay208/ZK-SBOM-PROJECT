# Cryptographic Linux Environment

Date: 2026-09-14

## Nargo

- Required: Noir/Nargo 0.32.0.
- WSL path: `/home/kali/.nargo/bin/nargo`.
- SHA-256: `9cb7c9753de630def6d41781343bc5481012c032f4403b194a62e429e1ba3e7e`.
- Output: `nargo version = 0.32.0`, `noirc version = 0.32.0+c679f01a19b02ad2ac2287c8e699b46887f7872c`.
- Temporary-copy production circuit `nargo check`: passed.

The repository Dockerfile was corrected to install the root-level binary from the official archive. The archive SHA-256 is `e9056171d3da6ac365b105eea14e0d6a4e64d5426e7b36fc66acf89ccf18a25e`. The resulting image built successfully and direct entrypoint execution passed.

- Image: `zkp-noir-0.32.0-local`.
- Image ID: `sha256:f051f358870cc650c225448f4d8845c6acd4220123491e56102c865c2bfb7d9e`.
- Platform: Linux amd64.
- Successful command: `docker run --rm --entrypoint /usr/local/bin/nargo zkp-noir-0.32.0-local --version`.

## Barretenberg

- WSL path: `/home/kali/.bb/bb`.
- Version: `0.46.1`.
- SHA-256: `22a4f456b7f8d2eebf7e2b5a8d51984628f867c3763feb6793fcd8372d6ced1f`.
- Updater hash: `d628f9b43f0a2e9080ab3f125e8685c3c34129f8f27720bdc6fa2ba57ddee6f1`.

Barretenberg is executable and its version matches the recorded NoirJS dependency candidate, but its provenance and project proof/VK integration are not approved. No development VK was used as production.

## Artifact separation

- Production VK: missing at `circuits/target/vk`.
- Development VK: retained at `circuits_dev/target/vk`; never promoted.
- Checked-in production proof: retained, 10 bytes; not treated as a proof.
- Production target JSON and development target JSON: retained.

## Cryptographic status

**CRYPTO TOOLCHAIN STATUS: VERIFIED for compiler/environment provisioning, BLOCKED for production proof validation.**

Nargo executable provisioning, versioning, architecture, hash, and circuit check are verified. Barretenberg executable presence/version/hash are verified. Matching production VK/proof generation, verification, public-input extraction, and negative binding tests remain unexecuted.

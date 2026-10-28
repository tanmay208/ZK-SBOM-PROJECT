# Artifact Storage Architecture

Date: 2026-10-01
Stage: 2 — Frontend Data Storage & Persistence Architecture

## Scope

Trace the storage location, lifecycle, access control, and cleanup behavior of every non-database artifact in the platform: raw SBOMs, ZKP artifacts (Prover.toml, witness, proof, VK, circuit JSON), and certificate evidence.

## Raw SBOM Artifact Storage

| Property | Value | Status |
|---|---|---|
| Storage medium | SQL Server `sbom.sbom_uploads.raw_content` column (Text type) | VERIFIED |
| Filesystem storage | NONE — raw SBOM is stored inline in the database, not on a filesystem | VERIFIED |
| Object storage | NONE | VERIFIED |
| Filename strategy | `filename` column stores the original filename as cosmetic metadata only | VERIFIED |
| Generated identifiers | UUID primary key (`sbom_uploads.id`) | VERIFIED |
| Access control | Owner-scoped via `user_id` filter in list; no raw content API | VERIFIED |
| Download mechanism | NONE — no download endpoint exists; raw content is never returned | VERIFIED |
| Maximum size | 10 MB enforced by `RequestSizeLimitMiddleware` | VERIFIED |
| Allowed formats | `CycloneDX` only (schema and service validation) | VERIFIED |
| Path traversal protection | N/A — no filesystem path construction for SBOM content | VERIFIED |
| Frontend access | NEVER — `SBOMUploadResponse` excludes `raw_content` | VERIFIED |
| Retention | Indefinite in DB; no cleanup | UNDEFINED |

## ZKP Artifact Storage

### Circuit Artifacts (Persistent)

| Property | Value | Status |
|---|---|---|
| Location | `circuits_dev/` (dev profile), `circuits/` (prod profile) | VERIFIED |
| Circuit JSON | `circuits_dev/target/sbom_zkp.json` (~1MB) | VERIFIED |
| Verification Key | `circuits_dev/target/vk` (~1.7KB) | VERIFIED |
| Integrity validation | SHA-256 hash verification at profile load time (`shared/crypto/config.py`) | VERIFIED |
| Profile config | `shared/crypto/profile.json` with `dev` and `prod` profiles | VERIFIED |
| VK hash (dev) | `a8733e6ca6434360fac2c91a7e94d9b4ff70a74ed4a0d392d6517032afc29e75` | VERIFIED |
| VK hash (prod) | `null` — production VK is NOT READY | VERIFIED |
| Frontend access | NEVER — circuit artifacts are server-side only | VERIFIED |
| Mutability | IMMUTABLE per frozen crypto profile; changes require new profile entry | VERIFIED |

### Per-Job Temporary Artifacts

The prover service (`zkp_service/app/services/prover_service.py`) creates the following temporary files during proof generation:

| Artifact | Location | Lifetime | Cleanup | Status |
|---|---|---|---|---|
| `Prover_{job_id}.toml` | `circuits_dev/Prover_{job_id}.toml` | Job duration only | `finally` block: `os.remove(prover_path)` | VERIFIED |
| Witness file (`.gz`) | `circuits_dev/target/sbom_zkp_{job_id}.gz` | Job duration only | `finally` block: `os.remove(target_gz)` | VERIFIED |
| Proof file (`.proof`) | `circuits_dev/proofs/sbom_zkp_{job_id}.proof` | Job duration only | `finally` block: `os.remove(proof_path)` | VERIFIED |

**CRITICAL PRIVACY GUARANTEE:** The `Prover.toml` contains the full private witness (component hashes, vulnerability scores, SMT paths). The `finally` block ensures cleanup even on failure. This is a key security invariant.

### Proof Artifact (Persistent)

| Property | Value | Status |
|---|---|---|
| Storage | `zkp.proof_jobs.proof_artifact` column (Text type, base64-encoded) | VERIFIED |
| Format | Base64-encoded binary proof | VERIFIED |
| Size | Variable; stored as Text column (unlimited in SQL Server) | VERIFIED |
| Access control | Owner-scoped via `user_id` filter; response schema sanitizes error_message | VERIFIED |
| Frontend access | Via `ProofJobResponse.proof_artifact` field for job owner | VERIFIED |
| Retention | Indefinite in DB | UNDEFINED |

### Existing Test/Mutated Proofs

| File | Location | Purpose | Status |
|---|---|---|---|
| `test_fake.proof` | `circuits_dev/test_fake.proof` | Test artifact | VERIFIED |
| `sbom_zkp.proof.mutated` | `circuits_dev/proofs/sbom_zkp.proof.mutated` | Test artifact (mutated proof) | VERIFIED |
| `sbom_zkp.proof.mutated2` | `circuits_dev/proofs/sbom_zkp.proof.mutated2` | Test artifact (mutated proof) | VERIFIED |

These are development/test artifacts, not production data.

## Certificate Storage

| Property | Value | Status |
|---|---|---|
| Storage | `verification.verification_certificates` table in SQL Server | VERIFIED |
| `certificate_data` | SHA-256 derived string: `CERT-{hash[:16].upper()}` | VERIFIED |
| Filesystem storage | NONE — certificates are DB records only | VERIFIED |
| Access control | Public by UUID; list requires authentication | VERIFIED |
| Frontend access | Full public certificate metadata via API | VERIFIED |
| Immutability | Created atomically with verification; never modified | VERIFIED |
| Retention | Indefinite | UNDEFINED |

## Orphan Conditions

| Condition | Prevention Mechanism | Detection | Status |
|---|---|---|---|
| DB record without temp artifact | `finally` block cleanup | N/A — temp files are short-lived | VERIFIED |
| Temp artifact without DB record | `finally` block runs on exception; job status set to failed | Manual filesystem check | INFERRED |
| ProofJob without SBOMUpload | FK CASCADE in migration 002 | DB constraint | VERIFIED |
| ProofJob without Snapshot | FK CASCADE in migration 002 | DB constraint | VERIFIED |
| ProofJob without Policy | FK CASCADE in migration 002 | DB constraint | VERIFIED |
| Certificate without VerificationRequest | FK CASCADE in migration 002 | DB constraint | VERIFIED |
| Proof referencing revoked snapshot | Application-level check: `snapshot.status != "approved"` → 400 | New proof generation rejected; existing proofs retain their data | VERIFIED |
| SBOM referencing deleted application | DB CASCADE would delete uploads | No delete API exists | INFERRED |
| Application without user | `user_id` is nullable; get_or_create doesn't require FK | Pre-migration data could have null user_id | VERIFIED |

## Storage Security Review

| Check | Finding | Status |
|---|---|---|
| Path traversal | Prover.toml path uses `os.path.join` with `job_id` (UUID). UUID format prevents traversal | VERIFIED |
| Unsafe filenames | `filename` column is cosmetic; not used for filesystem operations | VERIFIED |
| Predictable artifact names | Per-job files use `Prover_{job_id}` where `job_id` is UUID4 — unpredictable | VERIFIED |
| Unauthorized downloads | No file download endpoint exists | VERIFIED |
| IDOR | Owner-scoped queries and UUID PKs; no sequential IDs | VERIFIED |
| Stale artifact access | `finally` cleanup removes temp files; DB artifacts persist | VERIFIED |
| Temporary file leakage | Cleanup in `finally` block; failure case documented | VERIFIED |
| Browser cache leakage | Stage 1.5 CORS has `allow_credentials=False`; no cache headers defined | UNKNOWN |
| Sensitive error leakage | `ProofJobResponse.error_message` sanitized to generic message | VERIFIED |
| Oversized files | 10 MB middleware limit for request body | VERIFIED |
| MIME confusion | No file serving endpoint; proof is base64 in JSON | VERIFIED |
| Cross-user artifact access | Owner-scoped queries for SBOM and proof jobs | VERIFIED |

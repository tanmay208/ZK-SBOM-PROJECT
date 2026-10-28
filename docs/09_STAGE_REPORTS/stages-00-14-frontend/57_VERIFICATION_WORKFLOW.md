# Verification Workflow Architecture

Date: 2026-10-01
Stage: 10 — Verification & Verification Result Workflow

## 1. Core Workflow
- Users verify generated proofs at `/verify`.
- They select a completed proof job to verify.
- The request passes strictly defined public inputs (`sbom_root`, `vulnerability_db_root`, `policy_hash`, `proof_artifact`) to `verificationService.verify()`.
- The frontend acts strictly as a presentation layer; the backend verification service makes the authoritative decision.

## 2. Verification States
The UI translates explicit backend statuses:
- `verified`: Successful validation.
- `invalid`: The artifact is cryptographically invalid.
- `authoritative_record_mismatch`: Signatures/hashes do not map to the system of record.
- `public_input_mismatch`: The inputs claimed do not match the expected state.
- `unavailable`: The verification service could not process the request.

## 3. Cryptographic Boundary
- The browser performs no Zero-Knowledge compilation, tree hash recomputation, or witness decoding.
- The UI exposes public hashes strictly as visual references.

## 4. Certificate Boundary
- The frontend does NOT forge or initiate certificate objects.
- If a certificate payload is returned organically by the backend's `verified` response, the UI simply presents the metadata and UUID. 
- Revocation and lifecycle management of certificates are explicitly out of scope for this boundary.

## 5. Security & Access
- All roles (`vendor`, `admin`, `auditor`) may access `/verify`, but isolated queries inherently restrict proof selection to tenant-scoped assets via the backend API.

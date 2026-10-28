# Frontend API Contract Map

Date: 2026-09-25
Source priority: executable backend route/schema code, then security/architecture documentation. Live OpenAPI and gateway behavior were unavailable.

## Confirmed Endpoint Map

| Method/path | Auth | Role/ownership evidence | Request | Response | Errors/pagination/filtering | Frontend consumer |
|---|---|---|---|---|---|---|
| POST `/api/v1/auth/login` | Public | None | OAuth2 form `username`, `password` | `access_token`, `token_type` | 401 shared message; form validation UNKNOWN; no pagination | `/login` |
| POST `/api/v1/auth/register` | Public | New user forced to `auditor` | OAuth2 form | `message`, `username`, `role` | 400 duplicate, 422 empty fields | `/register` if approved |
| GET `/api/v1/auth/me` | Bearer | Identity loaded by username; role returned | None | `id`, `username`, `role` | 401 invalid/missing token | session/header |
| GET `/api/v1/metrics` | Bearer | No user filter; global counts in source | None | `total_sboms`, `total_jobs`, `total_certificates`, `total_verifications` | dashboard |
| GET `/api/v1/sbom?skip=&limit=` | Bearer | Filters `SBOMUpload.user_id == current_user.id` | query `skip>=0`, `1<=limit<=100` | list of `upload_id`, `application_id`, `status`, `format`, `filename`, `sbom_root`, `component_count`, `created_at` | SBOM history |
| POST `/api/v1/sbom/upload` | Bearer | Writes current user ID | JSON `application_name`, `vendor`, optional `filename`, `format=CycloneDX`, raw `content` | safe upload metadata above | 10 MB middleware; validation 422; exact service errors UNKNOWN | upload |
| GET `/api/v1/policy?skip=&limit=` | Bearer dependency present | No role or owner filter visible | query pagination | `id`, `name`, `description`, `max_cvss_score`, `policy_hash`, `created_at`, `active` | 422 query; global list behavior; no filters/sort beyond created desc | policies |
| POST `/api/v1/policy` | Bearer dependency present | No role check visible | `name?`, `description?`, `max_cvss_score` 0..10; extra fields forbidden | policy response above | 422 schema; other status UNKNOWN | policy creation |
| GET `/api/v1/vulnerability/snapshots?skip=&limit=` | Bearer | No user filter; global list | query pagination | `id`, `snapshot_label`, `record_count`, `provisional_smt_root`, `status` | 422 query; root exposure conflicts with schema doc | snapshots |
| POST `/api/v1/vulnerability/ingest` | Bearer | `current_user.role == admin` | `vulnerabilities[]`; each `purl`, `cvss_score` 0..10 | `snapshot_id`, `components_processed` | 403 non-admin; 422 schema; body limit; filters/sort none | admin snapshot ingest |
| POST `/api/v1/vulnerability/snapshots/{snapshot_id}/approve` | Bearer | `admin` required; status must be pending | UUID path | snapshot response | 403, 404, 400 invalid state | admin |
| POST `/api/v1/vulnerability/snapshots/{snapshot_id}/revoke` | Bearer | `admin` required; no owner filter | UUID path | snapshot response | 403, 404 | admin |
| GET `/api/v1/zkp?skip=&limit=` | Bearer | Filters `ProofJob.user_id == current_user.id` | query pagination | `ProofJobResponse` | 422 query; 500/prover behavior UNKNOWN | proof history |
| POST `/api/v1/zkp/generate` | Bearer | Creates job for current user; repository checks SBOM ownership; synchronous processing | `sbom_upload_id`, `snapshot_id`, `policy_id` UUIDs | job ID, refs, status, three roots, proof artifact, error message, timestamps | 403/404 repository behavior; tool failures may enter `error_message`; no async contract | proof creation |
| GET `/api/v1/zkp/jobs/{job_id}` | Bearer | 404 missing; 403 if job user differs | UUID path | proof job response | error field may leak subprocess stderr/path | job polling/detail |
| POST `/api/v1/verification/verify` | Bearer dependency present | Creates record with current user ID; service trust/authority checks require review | `sbom_root`, `vulnerability_db_root`, `policy_hash` strings; optional `proof_artifact` | verification ID, roots, result, times, optional certificate | 422 schema; `extra=forbid`; exact verification statuses in service; proof failure behavior UNKNOWN | verification |
| GET `/api/v1/verification/certificates?skip=&limit=` | Bearer | No user filter visible | query pagination | certificate ID, verification ID, data, roots, issued time | 422 query; global list risk | certificates |
| GET `/api/v1/verification/certificates/{certificate_id}` | No dependency visible | Public-by-ID behavior is undocumented; source lacks auth | UUID path | certificate response | 404 missing | certificate detail/public validation |
| GET `/api/v1/health` | Public in app factory | Per-service health route | None | `service`, `status`, `version` | DB/tool readiness may still be false while status is healthy | health |

## Contract Discrepancies and Security Constraints

- Architecture/service docs mention API Gateway and `/api/v1/verify`; executable verification is `/api/v1/verification/verify` in separate service apps. Gateway composition is UNKNOWN.
- Service docs say snapshot ingestion response does not expose `provisional_smt_root`; executable snapshot list response does expose it.
- `VerifyProofRequest` accepts identifier-like strings, not fixed-length hex; a cryptographic bypass is not established, but frontend must not claim canonical validation.
- `ProofJobResponse.error_message` can contain subprocess stderr/exception text. The frontend must display only an approved generic state until a redacted contract exists.
- Metrics are aggregate but global in source; tenant-safe semantics are not established.
- Audit and settings endpoints do not exist in the confirmed route inventory. Do not create client calls for them.

## Common HTTP and Transport Unknowns

Rate-limit policy, timeout behavior, gateway prefixes, live OpenAPI, and deployment reverse-proxy behavior remain UNKNOWN. The current backend error envelope and session contract are frozen in [09_SESSION_AND_AUTH_CONTRACT.md](./09_SESSION_AND_AUTH_CONTRACT.md) and [12_API_ERROR_CONTRACT.md](./12_API_ERROR_CONTRACT.md).

## Sensitive Fields

Never expose raw SBOM `content`, `raw_content`, component names/versions/PURLs, component hashes, private witness data, Merkle/SMT paths, internal paths, subprocess stderr, database credentials, or stack traces. Public roots, policy metadata, proof artifacts, verification results, and certificate metadata remain subject to backend response validation and ownership policy.

## Stage 1.5 Frozen Corrections

- `POST /api/v1/sbom/upload`: bearer plus `vendor` or `admin` role.
- `POST /api/v1/policy`: bearer plus `admin` role; policies are shared platform resources, not user-owned.
- `POST /api/v1/zkp/generate`: bearer plus `vendor` or `admin`; SBOM ownership is enforced by the repository.
- `GET /api/v1/metrics`: bearer; all four counts are scoped to the authenticated user's owned SBOMs, proof jobs, verification requests, and certificates.
- `GET /api/v1/vulnerability/snapshots`: authenticated shared snapshot metadata; `provisional_smt_root` is no longer returned.
- Snapshot ingest/approve/revoke: bearer plus `admin` role.
- `GET /api/v1/verification/certificates/{certificate_id}`: public certificate metadata only; list remains bearer-protected.
- Proof failure responses expose only `Proof generation failed`; subprocess stderr, paths, commands, and exception details remain outside the response contract.
- Standard application errors use `{ "error": string, "code": string }`; validation additionally has safe `details` locations/messages. Request-size errors use `REQUEST_TOO_LARGE`.

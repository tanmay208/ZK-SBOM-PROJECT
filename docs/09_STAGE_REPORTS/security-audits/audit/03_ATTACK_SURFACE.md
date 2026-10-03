# Attack Surface Inventory

All paths below are mounted by the service entrypoints; the verification service additionally mounts the platform routers.

| Method/path | Handler/source | Auth/RBAC | Inputs and operations | Outputs/cost | Tests/gaps |
|---|---|---|---|---|---|
| GET `/api/v1/health` | factory health handler | none / none | no DB; returns service/version | public health metadata; low cost | health tests; no deployment exposure test |
| POST `/api/v1/auth/login` | `shared/api/auth_routes.py:login` | none / none | form username/password; DB lookup + bcrypt + JWT | bearer token; bcrypt cost | auth tests; no rate limit |
| POST `/api/v1/auth/register` | `shared/api/auth_routes.py:register` | none / none | form username/password; inserts user | username/role metadata; bcrypt + DB write | registration tests; no email/approval/admin workflow |
| GET `/api/v1/auth/me` | `shared/api/auth_routes.py:get_me` | bearer / none | token decode + user lookup | identity and role | token tests; no disabled-user field exists |
| GET `/api/v1/metrics` | `shared/api/metrics_routes.py:get_dashboard_metrics` | bearer / none | four unfiltered count queries | aggregate counts; DB work | pagination/privacy tests; no per-tenant semantics |
| GET `/api/v1/sbom` | `sbom_routes.py:list_sboms` | bearer / none | skip/limit; unfiltered SBOM query | metadata including roots; DB query bounded 100 | tests cover pagination; no ownership test |
| POST `/api/v1/sbom/upload` | `sbom_routes.py:upload_sbom` | none / none | JSON envelope with raw CycloneDX; parse/hash/Merkle/DB writes | upload metadata/root; up to 10 MB CPU/DB cost | intake/parser tests; no auth or rate-limit test |
| GET `/api/v1/policy` | `policy_routes.py:list_policies` | bearer / none | skip/limit; unfiltered query | policy metadata/hash | policy tests; no role or tenant test |
| POST `/api/v1/policy` | `policy_routes.py:add_policy` | bearer / none | bounded policy fields; DB write/hash | policy metadata | validation tests; no admin-only test |
| GET `/api/v1/vulnerability/snapshots` | vulnerability routes | bearer / none | skip/limit; snapshot query | includes provisional SMT root | no owner/source authorization test |
| POST `/api/v1/vulnerability/ingest` | vulnerability routes | none / none | vulnerability list, PURLs, CVSS; DB write/SMT | snapshot ID/count; CPU/DB cost | ingestion tests; no auth/source authorization/rate test |
| GET `/api/v1/zkp` | `zkp_routes.py:list_jobs` | bearer / none | skip/limit; unfiltered proof jobs | commitments, proof artifact, error | API tests; no ownership test |
| POST `/api/v1/zkp/generate` | `zkp_routes.py:generate_proof` | none / none | three caller-selected UUIDs; DB reads/writes; WSL/Nargo/bb; filesystem | proof artifact/error; up to two 300s subprocesses | mocks service; no unauthorized/cross-user/resource test |
| GET `/api/v1/zkp/jobs/{job_id}` | `zkp_routes.py:get_proof_job` | none / none | UUID query | full public response including artifact/error | retrieval tests; no auth/ownership test |
| POST `/api/v1/verification/verify` | `verification_routes.py:verify_proof` | none / none | roots/hash and base64 proof; filesystem + WSL/bb + DB | verification status and certificate | verifier doubles; no live production proof test |
| GET `/api/v1/verification/certificates` | verification routes | bearer / none | skip/limit; unfiltered query | all certificates | list test; no ownership/tenant test |
| GET `/api/v1/verification/certificates/{id}` | verification routes | none / none | UUID query | certificate data and roots | API test; no auth or authorization test |

Global controls: request body middleware nominally caps bodies at 10 MB; verification proof field is separately capped at 65,536 characters; route query limits are 1-100 where present. No global rate limiter, concurrency budget, queue, or authenticated gateway dependency was found.

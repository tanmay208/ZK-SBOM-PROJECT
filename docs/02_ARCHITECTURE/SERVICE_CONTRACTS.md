# Service Contracts

The endpoint paths below are current frontend/API route families. Detailed request/response shapes remain in FastAPI schemas and frontend API types.

| API family | Responsibility | Route evidence |
| --- | --- | --- |
| Auth and metrics | Session creation/current user and dashboard metrics | /api/v1/auth/*, /api/v1/metrics |
| SBOM | Upload and retrieve SBOM/application records | /api/v1/sbom/* |
| Vulnerability | Ingest and manage snapshots, approval, and revocation | /api/v1/vulnerability/* |
| Policy | List and create policy records | /api/v1/policy/* |
| ZKP | Generate/list/retrieve proof jobs | /api/v1/zkp/* |
| Verification | Submit verification, retrieve permitted verification/certificate data, revoke certificates, and validate public status | /api/v1/verification/* |

The frontend API client centralizes base URL selection, bearer transport, and error handling. Public certificate validation uses /api/v1/verification/certificates/{id}/validate with authentication skipped. The endpoint families are a navigation aid, not a replacement for schema definitions.

Source: backend service API routes and schemas; frontend/src/api/services and frontend/src/api/types.

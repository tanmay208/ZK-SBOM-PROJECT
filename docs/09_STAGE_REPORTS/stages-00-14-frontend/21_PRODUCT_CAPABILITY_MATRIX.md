# Complete Product Capability Matrix

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Access & Identity

| Capability | Actor | User Objective | Auth | Role Authz | Input | Output | Backend Dependency | Security Constraint | Current Backend Support | Frontend Status |
|---|---|---|---|---|---|---|---|---|---|---|
| Login | Any | Authenticate | None | None | User, Pass | Token | `POST /api/v1/auth/login` | Token in memory only | IMPLEMENTED | PLANNED FRONTEND |
| Register | Any | Create account | None | None | User, Pass | Success msg | `POST /api/v1/auth/register` | Creates `auditor` role | IMPLEMENTED | PLANNED FRONTEND |
| Logout | Auth | End session | Yes | Any | None | Local clear | N/A | Local token flush | IMPLEMENTED (Client) | PLANNED FRONTEND |
| Get Profile | Auth | View identity | Yes | Any | None | Profile | `GET /api/v1/auth/me` | No password hash | IMPLEMENTED | PLANNED FRONTEND |

## 2. Dashboard

| Capability | Actor | User Objective | Auth | Role Authz | Input | Output | Backend Dependency | Security Constraint | Current Backend Support | Frontend Status |
|---|---|---|---|---|---|---|---|---|---|---|
| View Metrics | Auth | See summary counts | Yes | Any | None | 4 scalar counts | `GET /api/v1/metrics` | User-scoped queries | IMPLEMENTED | PLANNED FRONTEND |

## 3. SBOM Management

| Capability | Actor | User Objective | Auth | Role Authz | Input | Output | Backend Dependency | Security Constraint | Current Backend Support | Frontend Status |
|---|---|---|---|---|---|---|---|---|---|---|
| Upload SBOM | Vendor, Admin | Submit SBOM | Yes | `vendor`, `admin` | App name, Vendor, JSON | SBOM Metadata | `POST /api/v1/sbom/upload` | 10MB limit, no raw return | IMPLEMENTED | PLANNED FRONTEND |
| List SBOMs | Vendor, Admin | View own uploads | Yes | `vendor`, `admin` | Skip, Limit | SBOM List | `GET /api/v1/sbom` | User-scoped only | IMPLEMENTED | PLANNED FRONTEND |
| View SBOM Detail | Vendor, Admin | N/A | N/A | N/A | N/A | N/A | N/A | No endpoint exists | UNSUPPORTED | UNSUPPORTED |

## 4. Vulnerability Intelligence

| Capability | Actor | User Objective | Auth | Role Authz | Input | Output | Backend Dependency | Security Constraint | Current Backend Support | Frontend Status |
|---|---|---|---|---|---|---|---|---|---|---|
| Ingest Vulns | Admin | Batch load CVSS | Yes | `admin` | PURLs, CVSS | Snapshot ID | `POST /api/v1/vulnerability/ingest` | PURLs are private | IMPLEMENTED | PLANNED FRONTEND |
| List Snapshots | Auth | View snapshot history| Yes | Any | Skip, Limit | Snapshot List | `GET /api/v1/vulnerability/snapshots` | No provisional roots | IMPLEMENTED | PLANNED FRONTEND |
| Approve Snapshot | Admin | Authorize for ZKP | Yes | `admin` | Snapshot ID | Updated Snapshot| `POST /api/v1/vulnerability/snapshots/{id}/approve` | Only from 'pending' | IMPLEMENTED | PLANNED FRONTEND |
| Revoke Snapshot | Admin | Invalidate for ZKP | Yes | `admin` | Snapshot ID | Updated Snapshot| `POST /api/v1/vulnerability/snapshots/{id}/revoke` | From any state | IMPLEMENTED | PLANNED FRONTEND |

## 5. Security Policy Management

| Capability | Actor | User Objective | Auth | Role Authz | Input | Output | Backend Dependency | Security Constraint | Current Backend Support | Frontend Status |
|---|---|---|---|---|---|---|---|---|---|---|
| Create Policy | Admin | Set CVSS limit | Yes | `admin` | Name, Desc, MaxCVSS| New Policy | `POST /api/v1/policy` | Deactivates prior policies | IMPLEMENTED | PLANNED FRONTEND |
| List Policies | Auth | View global policies| Yes | Any | Skip, Limit | Policy List | `GET /api/v1/policy` | Shared public data | IMPLEMENTED | PLANNED FRONTEND |

## 6. Zero-Knowledge Proofs

| Capability | Actor | User Objective | Auth | Role Authz | Input | Output | Backend Dependency | Security Constraint | Current Backend Support | Frontend Status |
|---|---|---|---|---|---|---|---|---|---|---|
| Generate Proof | Vendor, Admin | Create compliance proof| Yes | `vendor`, `admin` | SBOM, Snap, Pol IDs| Proof Job Metadata| `POST /api/v1/zkp/generate` | SBOM ownership check | IMPLEMENTED | PLANNED FRONTEND |
| List Proof Jobs | Vendor, Admin | View job history | Yes | `vendor`, `admin` | Skip, Limit | Proof Job List | `GET /api/v1/zkp` | User-scoped only | IMPLEMENTED | PLANNED FRONTEND |
| View Proof Job | Vendor, Admin | See proof artifact | Yes | `vendor`, `admin` | Job ID | Proof Job Detail | `GET /api/v1/zkp/jobs/{id}` | User-scoped only | IMPLEMENTED | PLANNED FRONTEND |

## 7. Verification & Certificates

| Capability | Actor | User Objective | Auth | Role Authz | Input | Output | Backend Dependency | Security Constraint | Current Backend Support | Frontend Status |
|---|---|---|---|---|---|---|---|---|---|---|
| Verify Proof | Auth | Check compliance | Yes | Any | Roots, Hash, Proof| Verif. Result | `POST /api/v1/verification/verify` | No private witness input | IMPLEMENTED | PLANNED FRONTEND |
| List Certificates | Auth | View issued certs | Yes | Any | Skip, Limit | Certificate List | `GET /api/v1/verification/certificates` | Shared public data | IMPLEMENTED | PLANNED FRONTEND |
| View Certificate | Any | Inspect specific cert| No | None | Certificate ID | Certificate Detail| `GET /api/v1/verification/certificates/{id}`| No private fields | IMPLEMENTED | PLANNED FRONTEND |
| Verification Hist. | Auth | N/A | N/A | N/A | N/A | N/A | N/A | No history endpoint | UNSUPPORTED | UNSUPPORTED |

## 8. Administration

| Capability | Actor | User Objective | Auth | Role Authz | Input | Output | Backend Dependency | Security Constraint | Current Backend Support | Frontend Status |
|---|---|---|---|---|---|---|---|---|---|---|
| View Audit Logs | Admin | N/A | N/A | N/A | N/A | N/A | N/A | No DB table/API exists | UNSUPPORTED | UNSUPPORTED |
| Manage Users | Admin | N/A | N/A | N/A | N/A | N/A | N/A | No admin user API exists | UNSUPPORTED | UNSUPPORTED |
| Tenant Config | Admin | N/A | N/A | N/A | N/A | N/A | N/A | No tenant entity exists | UNSUPPORTED | UNSUPPORTED |

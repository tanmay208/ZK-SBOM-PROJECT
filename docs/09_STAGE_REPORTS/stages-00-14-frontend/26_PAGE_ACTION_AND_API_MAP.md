# Page Action and API Map

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Authentication
| Page | Action | Actor | Precondition | API Endpoint | Method | Req Payload | Res Payload | Security Req |
|---|---|---|---|---|---|---|---|---|
| `/login` | Submit login | Unauth | None | `/api/v1/auth/login` | POST | `username`, `password` (Form) | `{access_token, token_type}` | Memory only |
| `/register`| Submit reg | Unauth | None | `/api/v1/auth/register` | POST | `username`, `password` (Form) | `{message, username, role}` | Creates auditor |
| (Any) | Fetch Profile| Auth | Token exists | `/api/v1/auth/me` | GET | None | `{id, username, role}` | Token required |

## 2. Dashboard
| Page | Action | Actor | Precondition | API Endpoint | Method | Req Payload | Res Payload | Security Req |
|---|---|---|---|---|---|---|---|---|
| `/dashboard` | Load metrics | Auth | None | `/api/v1/metrics` | GET | None | `{sbom_count, proof_count, verification_count, certificate_count}` | User scoped |

## 3. SBOM Management
| Page | Action | Actor | Precondition | API Endpoint | Method | Req Payload | Res Payload | Security Req |
|---|---|---|---|---|---|---|---|---|
| `/sboms` | Load list | Ven/Adm | None | `/api/v1/sbom` | GET | `?skip,limit` | `[SBOMUploadResponse]` | User scoped |
| `/sboms/upload`| Submit file | Ven/Adm | Valid JSON | `/api/v1/sbom/upload`| POST | `app_name, vendor, file` | `SBOMUploadResponse` | No raw return |

## 4. Zero-Knowledge Proofs
| Page | Action | Actor | Precondition | API Endpoint | Method | Req Payload | Res Payload | Security Req |
|---|---|---|---|---|---|---|---|---|
| `/proofs` | Load list | Ven/Adm | None | `/api/v1/zkp` | GET | `?skip,limit` | `[ProofJobResponse]` | User scoped |
| `/proofs/[id]` | Load detail | Ven/Adm | None | `/api/v1/zkp/jobs/{id}`| GET | None | `ProofJobResponse` | User scoped |
| `/proofs/generate`| Submit form | Ven/Adm | Valid inputs | `/api/v1/zkp/generate` | POST | `{sbom_upload_id, snapshot_id, policy_id}` | `ProofJobResponse` | Owner verified |

## 5. Verification
| Page | Action | Actor | Precondition | API Endpoint | Method | Req Payload | Res Payload | Security Req |
|---|---|---|---|---|---|---|---|---|
| `/verify` | Submit verify| Auth | None | `/api/v1/verification/verify`| POST | `{sbom_root, vuln_root, policy_hash, proof_artifact}` | `VerificationResponse` | No private data |
| `/certificates`| Load list | Auth | None | `/api/v1/verification/certificates`| GET | `?skip,limit` | `[CertificateResponse]` | Public metadata |
| `/certificates/[id]`| Load detail | Any | None | `/api/v1/verification/certificates/{id}`| GET| None | `CertificateResponse` | Public metadata |

## 6. Admin: Vulnerability Intelligence
| Page | Action | Actor | Precondition | API Endpoint | Method | Req Payload | Res Payload | Security Req |
|---|---|---|---|---|---|---|---|---|
| `/admin/vulnerabilities`| Load list | Auth | None | `/api/v1/vulnerability/snapshots`| GET | `?skip,limit` | `[SnapshotResponse]` | No provisional root |
| `/admin/vulnerabilities`| Submit ingest| Admin | Valid JSON | `/api/v1/vulnerability/ingest`| POST | `[VulnerabilityInput]` | `SnapshotResponse` | Admin only |
| `/admin/vulnerabilities`| Click approve| Admin | Status=pending| `/api/v1/vulnerability/snapshots/{id}/approve`| POST| None | `SnapshotResponse` | Admin only |
| `/admin/vulnerabilities`| Click revoke | Admin | None | `/api/v1/vulnerability/snapshots/{id}/revoke`| POST| None | `SnapshotResponse` | Admin only |

## 7. Admin: Policy
| Page | Action | Actor | Precondition | API Endpoint | Method | Req Payload | Res Payload | Security Req |
|---|---|---|---|---|---|---|---|---|
| `/admin/policies` | Load list | Auth | None | `/api/v1/policy` | GET | `?skip,limit` | `[PolicyResponse]` | Shared public |
| `/admin/policies` | Create policy| Admin | Valid CVSS | `/api/v1/policy` | POST | `{name, desc, max_allowed_cvss}`| `PolicyResponse` | Admin only |

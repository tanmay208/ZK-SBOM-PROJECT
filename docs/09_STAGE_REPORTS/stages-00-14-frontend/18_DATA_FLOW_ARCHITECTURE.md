# Data Flow Architecture

Date: 2026-10-01
Stage: 2 — Frontend Data Storage & Persistence Architecture

## Scope

Conceptual data flows for every frontend feature, tracing Browser → API → Service → Database/Artifact for each operation. This document defines the data boundary, persistent state transitions, and sensitive data classification for each flow.

## Flow Diagrams

### 1. Login

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ POST /auth/login ─────►│                            │                  │
  │  (form: username, pwd)  ├─ verify_password ─────────►│                  │
  │                         │  verify_dummy_password      ├─ query User ───►│
  │                         │                            │  by username     │
  │                         │◄─ User or 401 ─────────────┤                  │
  │                         ├─ create_access_token       │                  │
  │◄─ {access_token, type} ─┤                            │                  │
  │                         │                            │                  │
  ├─ STORE token in memory  │                            │                  │
```

**Persistent state:** None created. Token is ephemeral.
**Sensitive boundary:** Password never logged or stored beyond bcrypt comparison. Token in memory only.
**Cache:** No.

### 2. Registration

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ POST /auth/register ──►│                            │                  │
  │  (form: username, pwd)  ├─ check existing ──────────►│                  │
  │                         │  hash password             ├─ query User ───►│
  │                         │  create User               ├─ insert User ──►│
  │                         │                            │  role=auditor    │
  │◄─ {msg, username, role}─┤                            │                  │
```

**Persistent state:** New User row created (dbo.users).
**Sensitive boundary:** Password hashed with bcrypt(12); hash never returned.
**Cache:** No.

### 3. Dashboard (Metrics)

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ GET /metrics ─────────►│                            │                  │
  │  (Bearer token)         ├─ get_current_user         │                  │
  │                         ├─ COUNT SBOMUpload ────────►│  WHERE user_id  │
  │                         ├─ COUNT ProofJob ──────────►│  WHERE user_id  │
  │                         ├─ COUNT VerificationReq ───►│  WHERE user_id  │
  │                         ├─ COUNT Certificate ───────►│  JOIN on user_id│
  │◄─ {4 scalar counts} ───┤                            │                  │
```

**Persistent state:** None modified.
**Sensitive boundary:** Counts are user-scoped aggregates only. No entity details.
**Cache:** In-memory query cache, 30s–2min TTL. Invalidate on mutations.

### 4. SBOM Upload

```
Browser                    API                         Service              DB/Artifacts
  │                         │                            │                  │
  ├─ POST /sbom/upload ────►│                            │                  │
  │  (JSON: app_name,       ├─ require_roles(vendor,admin)                  │
  │   vendor, content)      ├─ SBOMIntakeService.ingest ►│                  │
  │                         │                            ├─ get_or_create  │
  │                         │                            │  Application ──►│
  │                         │                            ├─ create_upload ►│
  │                         │                            │  (raw_content   │
  │                         │                            │   stored in DB) │
  │                         │                            ├─ commit()       │
  │                         │                            │  parse, validate│
  │                         │                            │  canonicalize   │
  │                         │                            │  hash, Merkle   │
  │                         │                            │  → SBOM_ROOT    │
  │                         │                            ├─ update upload ►│
  │                         │                            │  status=committed│
  │                         │                            │  sbom_root, count│
  │                         │                            ├─ persist Components►│
  │◄─ SBOMUploadResponse ──┤                            │                  │
  │  (NO raw_content)       │                            │                  │
```

**Persistent state:** Application (get-or-create), SBOMUpload (pending→committed), Component rows.
**Sensitive boundary:** `raw_content` stored in DB, NEVER returned. Component data is Private.
**Cache:** Invalidate SBOM list cache, metrics cache.

### 5. SBOM History

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ GET /sbom?skip=&limit=►│                            │                  │
  │  (Bearer token)         ├─ get_current_user         │                  │
  │                         ├─ query SBOMUpload ────────►│  WHERE user_id  │
  │                         │  ORDER BY created_at DESC  │  OFFSET/LIMIT   │
  │◄─ [SBOMUploadResponse]─┤                            │                  │
```

**Persistent state:** None modified.
**Sensitive boundary:** Response excludes `raw_content`. Only safe metadata fields.
**Cache:** In-memory query cache, keyed by (user, skip, limit).

### 6. Vulnerability Snapshot Browsing

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ GET /vulnerability/snapshots ►│                     │                  │
  │  (Bearer token)         ├─ get_current_user         │                  │
  │                         ├─ query VulnerabilitySnapshot ►│  ALL (shared) │
  │◄─ [SnapshotResponse] ──┤  (NO provisional_smt_root) │                  │
```

**Persistent state:** None modified.
**Sensitive boundary:** `provisional_smt_root` excluded from response schema.
**Cache:** In-memory query cache, 2–5min.

### 7. Vulnerability Ingestion (Admin)

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ POST /vulnerability/ingest ►│                       │                  │
  │  (Bearer token, admin)  ├─ role check (admin)       │                  │
  │  {vulnerabilities:[...]}├─ ingest_vulnerabilities ──►│                  │
  │                         │  canonicalize PURLs        ├─ create Snapshot►│
  │                         │  hash components           ├─ create Mappings►│
  │                         │  compute provisional SMT   │                  │
  │◄─ {snapshot_id, count} ─┤                            │                  │
```

**Persistent state:** VulnerabilitySnapshot (processing→pending), ComponentVulnerabilityMapping rows.
**Sensitive boundary:** PURLs never logged. Response contains only safe metadata.
**Cache:** Invalidate snapshot list cache.

### 8. Snapshot Approve/Revoke (Admin)

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ POST /snapshots/{id}/approve ►│                     │                  │
  │  (Bearer, admin)        ├─ role check (admin)       │                  │
  │                         ├─ query snapshot           ├─ WHERE id ──────►│
  │                         ├─ validate status=pending  │                  │
  │                         ├─ update status=approved ──►│                  │
  │◄─ SnapshotResponse ────┤                            │                  │
```

**Persistent state:** Snapshot status updated. Mutable field: `status` only.
**Cache:** Invalidate snapshot list cache.

### 9. Policy Management

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ GET /policy ──────────►│  (any auth role)           │                  │
  │◄─ [PolicyResponse] ────┤  (shared, all policies)    │                  │
  │                         │                            │                  │
  ├─ POST /policy ─────────►│  (admin only)              │                  │
  │  {max_cvss_score, ...}  ├─ deactivate all policies ─►│                  │
  │                         ├─ compute policy_hash       │                  │
  │                         ├─ create new active policy ─►│                  │
  │◄─ PolicyResponse ──────┤                            │                  │
```

**Persistent state:** All existing policies deactivated; new policy created.
**Sensitive boundary:** Policy data is public. `policy_hash` is a Poseidon hash of the CVSS threshold.
**Cache:** Invalidate policy list cache.

### 10. Proof Generation

```
Browser                    API                     Prover Service           DB/Filesystem
  │                         │                            │                  │
  ├─ POST /zkp/generate ───►│                            │                  │
  │  {sbom_upload_id,       ├─ require_roles(vendor,admin)                  │
  │   snapshot_id,          ├─ create_job (pending) ─────►│                  │
  │   policy_id}            │  verify SBOM ownership     │                  │
  │                         │  verify snapshot approved  │                  │
  │                         ├─ process_job ─────────────►│                  │
  │                         │                            ├─ fetch SBOM ────►│
  │                         │                            ├─ fetch snapshot ►│
  │                         │                            ├─ fetch policy ──►│
  │                         │                            ├─ fetch components►│
  │                         │                            ├─ build SMT       │
  │                         │                            ├─ write Prover.toml (TEMP)
  │                         │                            ├─ execute nargo   │
  │                         │                            ├─ execute bb prove│
  │                         │                            ├─ read proof file │
  │                         │                            ├─ base64 encode   │
  │                         │                            ├─ cleanup temp files
  │                         │                            ├─ update job ─────►│
  │                         │                            │  status=completed │
  │                         │                            │  proof_artifact   │
  │◄─ ProofJobResponse ────┤                            │                  │
  │  (sanitized error_msg)  │                            │                  │
```

**Persistent state:** ProofJob (pending→assembling_witness→completed/failed).
**Sensitive boundary:** Prover.toml contains private witness — deleted in `finally`. Error messages sanitized.
**Temp artifacts:** Created and destroyed within job execution.
**Cache:** Invalidate proof list cache, metrics cache.

### 11. Proof Job Monitoring

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ GET /zkp/jobs/{id} ──►│                            │                  │
  │  (Bearer token)         ├─ get_current_user         │                  │
  │                         ├─ query ProofJob ──────────►│  WHERE id        │
  │                         ├─ verify user_id ownership │                  │
  │◄─ ProofJobResponse ────┤  (sanitized)               │                  │
```

**Persistent state:** None modified.
**Cache:** Short TTL during polling; respect terminal states.

### 12. Verification Submission

```
Browser                    API                         Verifier             DB
  │                         │                            │                  │
  ├─ POST /verification/verify ►│                        │                  │
  │  {sbom_root, vuln_root, ├─ get_current_user         │                  │
  │   policy_hash, proof}   ├─ check idempotency ───────►│                  │
  │                         ├─ validate authoritative ──►│  check SBOM,     │
  │                         │  records                   │  snapshot, policy│
  │                         ├─ verify proof ─────────────►│  NoirVerifier   │
  │                         ├─ create verification ──────►│                  │
  │                         │  record + certificate      │                  │
  │◄─ VerificationResponse ┤  (with certificate if verified)               │
```

**Persistent state:** VerificationRequest created; VerificationCertificate created atomically if verified.
**Sensitive boundary:** Only public inputs accepted. No private data in request or response.
**Cache:** Invalidate verification/certificate caches, metrics.

### 13. Certificate Retrieval

```
Browser                    API                         Service              DB
  │                         │                            │                  │
  ├─ GET /certificates ────►│  (Bearer, any role)        │                  │
  │◄─ [CertificateResponse]┤  (all certs, paginated)    │                  │
  │                         │                            │                  │
  ├─ GET /certificates/{id}►│  (NO auth required)        │                  │
  │                         ├─ query by UUID ───────────►│                  │
  │◄─ CertificateResponse ─┤  (public metadata only)    │                  │
```

**Persistent state:** None modified.
**Sensitive boundary:** Certificate detail is public by design (public verification model).
**Cache:** Medium TTL for list; individual certificates are immutable and highly cacheable.

### 14. Health Check

```
Browser                    API
  │                         │
  ├─ GET /health ──────────►│
  │◄─ {service, status, version} ─┤
```

**Persistent state:** None.
**Cache:** Short TTL (30s).

## Resource Ownership Graph (Final)

```
User (dbo.users)
  ├──► Application (sbom.applications) — user_id
  │      └──► SBOMUpload (sbom.sbom_uploads) — application_id FK CASCADE
  │             ├──► Component (sbom.components) — sbom_upload_id FK CASCADE
  │             ├──► ScanResult (vulnerability.scan_results) — sbom_upload_id FK CASCADE
  │             └──► ProofJob (zkp.proof_jobs) — sbom_upload_id FK CASCADE
  │                    (also refs: snapshot_id FK CASCADE, policy_id FK CASCADE)
  ├──► ProofJob (zkp.proof_jobs) — user_id (direct ownership)
  ├──► VerificationRequest (verification.verification_requests) — user_id
  │      └──► VerificationCertificate (verification.verification_certificates) — FK CASCADE
  └──► (admin) VulnerabilitySnapshot (vulnerability.vulnerability_snapshots) — created_by

Shared / Admin-Controlled:
  SecurityPolicy (policy.security_policies) — globally shared, admin lifecycle
  VulnerabilitySnapshot — globally shared metadata, admin lifecycle
  VulnerabilityRecord — globally shared threat intelligence
```

## Final Stage 2 Entity Matrix

| Entity | Auth. Storage | Owner | Tenant | Sensitive Data | Frontend Access | API Access | Cacheable | Retention | Delete Model | Dependencies | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| User | dbo.users | Self | N/A | hashed_password | id, username, role via /me | Auth routes | Session lifetime | UNDEFINED | None | Application, SBOMUpload, ProofJob, VerificationRequest | VERIFIED |
| Application | sbom.applications | user_id | None | None | application_id in SBOM list | No direct API | Via SBOM list | UNDEFINED | ORM cascade to uploads | SBOMUpload | VERIFIED |
| SBOMUpload | sbom.sbom_uploads | user_id | None | raw_content | Safe metadata only | GET/POST /sbom | Short TTL | UNDEFINED | CASCADE to Components, ScanResults, ProofJobs | Component, ScanResult, ProofJob | VERIFIED |
| Component | sbom.components | Derived (SBOM) | None | ALL fields | NEVER | None | N/A | Cascaded | CASCADE from SBOMUpload | None | VERIFIED |
| VulnerabilityRecord | vulnerability.vulnerability_records | Shared | None | None | NEVER | None | N/A | UNDEFINED | None | None | VERIFIED |
| VulnerabilitySnapshot | vulnerability.vulnerability_snapshots | Admin (created_by) | None | provisional_smt_root | id, label, count, status | GET/POST /vulnerability | Medium TTL | UNDEFINED | None (status lifecycle) | ComponentVulnerabilityMapping, ProofJob | VERIFIED |
| ComponentVulnerabilityMapping | vulnerability.component_vulnerability_mappings | Derived (Snapshot) | None | component_hash | NEVER | None | N/A | Cascaded | CASCADE from Snapshot | None | VERIFIED |
| ScanResult | vulnerability.scan_results | Derived (SBOM) | None | component_name, purl | NEVER | None | N/A | Cascaded | CASCADE from SBOMUpload | None | VERIFIED |
| SecurityPolicy | policy.security_policies | Shared/Admin | None | None | All fields public | GET/POST /policy | Medium TTL | UNDEFINED | Deactivation, not deletion | ProofJob | VERIFIED |
| ProofJob | zkp.proof_jobs | user_id | None | error_message (sanitized) | Safe public fields | GET/POST /zkp | Short TTL (polling) | UNDEFINED | None | SBOMUpload, Snapshot, Policy (FK CASCADE) | VERIFIED |
| VerificationRequest | verification.verification_requests | user_id | None | proof_artifact (public) | Via verification response | POST /verification/verify | No (mutation) | UNDEFINED | None | VerificationCertificate (CASCADE) | VERIFIED |
| VerificationCertificate | verification.verification_certificates | Public | None | None | All fields public | GET /certificates | Immutable/long | UNDEFINED | CASCADE from Request | None | VERIFIED |
| Audit Data | NOT FOUND | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | NOT FOUND |
| Raw Artifacts | DB column (raw_content) | SBOM owner | None | Entire content | NEVER | NEVER | N/A | UNDEFINED | With SBOMUpload | N/A | VERIFIED |
| Proof Artifacts | DB column (proof_artifact) | Job owner | None | None (public proof) | Via ProofJobResponse | GET /zkp/jobs/{id} | With job | UNDEFINED | With ProofJob | N/A | VERIFIED |

# Application Security Rules & Invariants

**Document Version:** 2.0.0-consolidated  
**Workspace Root:** `E:\Main Project`  
**Authoritative Location:** `project_context/SECURITY_RULES.md`  
**Effective Date:** 14 October 2026  

---

## 1. Core Security Posture

1. **Untrusted Client Boundary**: Treat all incoming HTTP requests, headers, form payloads, and proof artifacts as untrusted. Never rely on client assertions or frontend state for authorization.
2. **Fail-Closed Verification**: Any parsing failure, unexpected exception, missing parameter, or unverified commitment must result in immediate request rejection. Cryptographic verification succeeds **only** when the pinned official verifier returns an explicit Boolean `true`.
3. **Defense in Depth**: Security boundaries must be enforced at multiple layers:
   - API layer (FastAPI dependency injection & middleware).
   - Service layer (explicit tenant and ownership checks).
   - Database layer (row-level `user_id` filtering, foreign keys, unique constraints).

---

## 2. Authentication & Session Security

1. **Password Hashing & Strength**:
   - Passwords must be hashed using strong one-way algorithms (Argon2id or bcrypt with salt).
   - Passwords must be at least 8 characters long and cannot exceed 72 UTF-8 bytes (bcrypt input truncation limit).
   - Password hashes must **never** be included in API responses or logs (`DEVELOPMENT_RULES.md §19`).
2. **Account Enumeration Protection**:
   - The `/api/v1/auth/login` endpoint must execute a constant-time dummy password hash verification when a non-existent username is requested. This prevents attackers from measuring timing discrepancies to identify valid user accounts.
3. **In-Memory JWT Transport**:
   - Access tokens issued by the backend must be stored **strictly in application memory** (`authTransport`) on the frontend.
   - Tokens must **never** be stored in `localStorage`, `sessionStorage`, or unencrypted cookies, preventing token theft via Cross-Site Scripting (XSS).
   - Token expiration is strictly bounded (`ACCESS_TOKEN_EXPIRE_MINUTES = 60`).
4. **Base Role Allocation**:
   - The self-registration route (`POST /api/v1/auth/register`) strictly assigns the base role `buyer` to all newly created users.
   - Roles cannot be selected, submitted, or escalated through registration request payloads.

---

## 3. Role-Based Access Control (RBAC) & Separation of Duties

The application enforces strict separation between three consolidated roles (`admin`, `vendor`, `buyer`):

| Role | Permitted Actions | Prohibited Actions | Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **`vendor`** | Register applications, upload private SBOMs, trigger ZKP proof generation jobs, download issued certificates. | Cannot ingest CVE vulnerability data, cannot approve/freeze vulnerability snapshots, cannot create policies. | `require_roles("vendor", "admin")` |
| **`buyer`** | Submit public roots and proof artifacts for independent verification, inspect issued certificates, validate tamper-evident records. | Cannot upload private SBOM manifests, cannot trigger ZKP proof jobs, cannot create policies or approve snapshots. | Default registration role; restricted routes reject with 403 Forbidden. |
| **`admin`** | Create security policies, ingest vulnerability feeds (under Two-Person Integrity), approve and freeze vulnerability snapshots, manage platform users, and revoke compromised certificates. | Cannot self-approve own vulnerability snapshots (`creator != approver`); cannot demote last active admin. | `require_roles("admin")` |

*Note: Legacy roles (`auditor` and `trusted_importer`) are retired from active assignment, registration, filters, and UI workflows. Historical database constraints and migrations 001–016 remain preserved.*

### Two-Person Integrity (Separation of Duties)
- Ingesting vulnerability data creates snapshots in `pending` status.
- Only an `admin` can transition a snapshot to `approved` and `frozen`.
- The user who ingested a snapshot cannot approve it, preventing a single compromised account from silently altering the authoritative vulnerability baseline (`AUD-A-009`).

---

## 4. Multi-Tenant Scoping & IDOR Prevention

1. **Application Namespace Isolation**:
   - Applications are scoped strictly by `(name, vendor, user_id)`.
   - The database model enforces a composite `UniqueConstraint("name", "vendor", "user_id")` (`AUD-A-001`, Migration 014).
   - A vendor uploading an SBOM can never link it to an application owned by a different user.
2. **Object Ownership Filtering**:
   - All database queries for applications, SBOM uploads, proof jobs, and verification certificates must filter by the authenticated user's `current_user.id`.
   - Any attempt by User A to retrieve, modify, or delete a resource owned by User B must fail closed with HTTP 404 Not Found (or HTTP 403 Forbidden) to prevent Insecure Direct Object References (IDOR).

---

## 5. Privacy & Data Confidentiality

1. **Private Data Classification**:
   - Raw CycloneDX SBOM JSON content, component names, package URLs (`purl`), versions, and dependency graphs are classified as **Private Vendor Data**.
2. **Buyer-Facing Sanitization**:
   - Route handlers and verification responses must **never** return raw content, PURLs, or component versions to buyers or public verifiers (`SECURITY_BOUNDARY.md §1, §4`).
   - The public verification endpoint consumes only the 32-byte public Merkle roots, the policy hash, and the proof artifact.
3. **Upload Request Body Limit**:
   - All upload endpoints enforce a strict **10 MB body size ceiling** via `RequestSizeLimitMiddleware` (`shared/app_factory.py`). Requests exceeding 10 MB are rejected immediately with HTTP 413 Payload Too Large.

---

## 6. Input Validation & Error Handling

1. **Strict Hex Validation**:
   - All commitment roots (`sbom_root`, `vulnerability_db_root`, `policy_hash`) must be strictly validated as `0x`-prefixed, 64-character hexadecimal strings matching `^0x[a-fA-F0-9]{64}$`.
2. **Normalized Error Bodies**:
   - All error responses must adhere to the standardized schema:
     ```json
     {
       "error": "Human-readable description of error",
       "code": "MACHINE_READABLE_ERROR_CODE"
     }
     ```
   - Raw exception tracebacks, database schema names, and SQL statements must never be returned to the client in production or local dev mode.

---

## 7. Structured Logging & Secret Redaction

1. **Zero Secret Logging**:
   - Structured JSON audit loggers must sanitize request payloads before logging.
   - Passwords, authorization headers, JWT tokens, private keys, and raw SBOM contents must be masked or completely omitted.
2. **Masked Connection Strings**:
   - When database connections are logged, the password must be masked using `safe_url` (`postgresql+psycopg2://postgres:****@127.0.0.1:5433/ZKP_SBOM_LOCAL_DEV`).

---

## 8. Mandatory Negative Testing Rules

Every security-sensitive pull request or code modification must include corresponding negative test cases:
1. **Unauthenticated access** $\rightarrow$ Assert `HTTP 401 Unauthorized`.
2. **Insufficient role permissions** $\rightarrow$ Assert `HTTP 403 Forbidden`.
3. **Cross-tenant resource access (IDOR)** $\rightarrow$ Assert `HTTP 404` or `403`.
4. **Oversized payload (> 10 MB)** $\rightarrow$ Assert `HTTP 413 Payload Too Large`.
5. **Malformed commitment strings** $\rightarrow$ Assert `HTTP 422 Unprocessable Entity`.
6. **Mismatched public inputs or tampered proofs** $\rightarrow$ Assert fail-closed verification rejection.

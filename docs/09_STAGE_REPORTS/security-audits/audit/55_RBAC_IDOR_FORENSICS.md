# Phase 3: RBAC, Ownership, and IDOR/BOLA Audit

## Scope
Audit of role-based access control, ownership verification, and Insecure Direct Object Reference (IDOR) vulnerabilities across all service endpoints.

## Findings

### 1. Global Policy Creation (RBAC Privilege Escalation)
- **Status:** **FAIL / CRITICAL DEFECT**
- **Location:** `backend/policy_service/app/api/routes/policy_routes.py` -> `add_policy`
- **Details:** The `/api/v1/policy` POST endpoint allows **any authenticated user** (including vendors) to create a global security policy. There is no role check (e.g., `current_user.role == "admin"`). A malicious vendor could create a lax policy (e.g., max CVSS = 10.0) to bypass ZKP verification constraints for their vulnerable software.

### 2. Application Namespace Hijacking (IDOR/BOLA)
- **Status:** **FAIL / HIGH DEFECT**
- **Location:** `backend/sbom_service/app/repositories/sbom_repository.py` -> `get_or_create_application`
- **Details:** When an SBOM is uploaded, the service looks up the application by `(name, vendor)`. If it exists, it returns the existing application **without verifying ownership** (`existing.user_id == user_id`). This allows User B to upload an SBOM and attach it to User A's application, polluting the application's history.

### 3. Certificate Listing Information Disclosure
- **Status:** **FAIL / MEDIUM DEFECT**
- **Location:** `backend/verification_service/app/api/routes/verification_routes.py` -> `list_certificates`
- **Details:** The endpoint requires authentication but queries all certificates globally without filtering by `current_user.id`. While individual certificates represent public attestations, allowing any authenticated user to enumerate the entire global history of certificates exposes competitor activity and usage patterns.

### 4. Admin Role Enforcement on Vulnerability Ingestion
- **Status:** **PASS**
- **Location:** `backend/vulnerability_service/app/api/routes/vulnerability_routes.py`
- **Details:** The `/ingest`, `/approve`, and `/revoke` endpoints correctly enforce `if current_user.role != "admin"`, preventing vendors from manipulating the vulnerability database.

### 5. Proof Job Ownership (IDOR Prevention)
- **Status:** **PASS**
- **Location:** `backend/zkp_service/app/api/routes/zkp_routes.py` -> `get_proof_job` and `list_jobs`
- **Details:** Safely filters by `user_id == current_user.id` or checks `job.user_id != current_user.id` explicitly, preventing unauthorized access to pending jobs and intermediate proof artifacts.

## Required Fixes
- **Policy RBAC:** Enforce `admin` role checks on all POST/PUT/DELETE operations in `policy_routes.py`.
- **Application BOLA:** Modify `get_or_create_application` to verify `existing.user_id == user_id` and raise a `403 Forbidden` or `409 Conflict` if a namespace collision occurs.
- **Certificate Listing:** Filter `list_certificates` by `current_user.id` so buyers/vendors only see their own verification history. If global enumeration is intended for an auditor role, restrict the unfiltered view to that role.

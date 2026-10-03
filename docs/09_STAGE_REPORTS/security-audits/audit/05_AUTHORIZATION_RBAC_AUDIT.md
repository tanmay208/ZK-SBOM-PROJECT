# Authorization and RBAC Audit

## Finding RBAC-001

**Title:** Authenticated identity is not authorization

**Severity:** High

**Confidence:** Confirmed

**Classification:** SECURITY WEAKNESS

**Affected files:** `backend/shared/auth.py`; all service route modules.

**Affected functions/routes:** `list_sboms`, `upload_sbom`, `list_policies`, `add_policy`, `list_snapshots`, `ingest_vulns`, `list_jobs`, `generate_proof`, `get_proof_job`, `verify_proof`, `list_certificates`, `get_certificate`.

**Attacker role:** Any registered auditor, vendor, or unauthenticated caller where noted.

**Attacker-controlled input:** IDs, raw SBOM, vulnerability data, policy values, roots, proof artifact, pagination.

**Expected security invariant:** Roles and object ownership must constrain every read/write; vendors must not access other vendors' SBOMs; only authorized intelligence operators may ingest; only authorized users may create/read jobs and certificates.

**Actual behavior:** No role-check dependency, `current_user.role` comparison, owner column, or `current_user` filter was found. Several sensitive or mutating routes omit `get_current_user` entirely. The user model's `role` field is persistence/identity metadata only.

**Exact data flow:** Bearer token, where required -> `get_current_user` -> user lookup by username -> handler; handler queries whole tables or writes records without user/tenant predicates. Unauthenticated handlers skip that dependency.

**Attack prerequisites:** Network access to the API; registration is open for an initial valid account, or unauthenticated route access.

**Concrete exploit scenario:** A valid auditor lists all SBOMs, proof jobs, snapshots, and certificates; a caller submits vulnerability snapshots, creates policies, selects another user's object IDs for proof generation, or retrieves another user's job by UUID. `POST /api/v1/sbom/upload`, vulnerability ingestion, proof generation, verification, and certificate-by-ID are directly reachable without authentication.

**Impact:** Cross-user confidentiality loss, unauthorized state mutation, poisoned intelligence, proof-job resource consumption, and vertical privilege escalation if administrative roles are later introduced.

**Evidence:** Route signatures in `backend/*/app/api/routes/*.py`; `User.role` in `backend/shared/models/user.py`; no role predicate in repositories/services.

**Reproduction or validation method:** Static route tracing; backend tests include a test explicitly documenting that endpoint-level RBAC is currently unforced, but do not exercise cross-user live authorization.

**Existing mitigations:** UUID path validation, Pydantic schemas, authenticated dependency on some routes, registration hardcodes `auditor`.

**Why mitigations are insufficient:** Authentication is not authorization; UUIDs are identifiers, not access control; hardcoding new users to auditor does not restrict existing auditor capabilities.

**Recommended remediation:** Define role and tenant policy, bind records to principals, enforce dependencies/service checks before retrieval and mutation, and deny by default.

**Required regression test:** Multi-user matrix covering auditor/vendor/admin against every route, including cross-user IDs and unauthenticated requests.

**Residual risk:** Database-wide shared credentials and missing deployment-level controls remain outside route code.

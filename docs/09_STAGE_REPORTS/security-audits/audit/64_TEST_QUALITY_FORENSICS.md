# Phase 12: Test Quality and Coverage Audit

## Scope
Audit of the Python test suite (`pytest`) to assess logic coverage, test environment parity, and the presence of false-positive confidence regarding previously discovered defects.

## Findings

### 1. False Confidence via Test/Production Database Discrepancy
- **Status:** **FAIL / HIGH DEFECT**
- **Location:** Global Test Suite Fixtures (`conftest.py` / `database.py`)
- **Details:** The test suite successfully collects and passes 493 robust tests, including tests for RBAC enforcement, IDOR prevention, and ownership boundaries. However, these tests pass exclusively because they use mocked repositories or an in-memory SQLite database (`create_engine("sqlite:///:memory:")`) via SQLAlchemy's `Base.metadata.create_all()`. They completely bypass the actual Alembic migration scripts (`alembic/versions/*.py`) and the strict SQL Server dialect.
- **Impact:** This structural flaw allowed the critical Phase 9 Database Schema Drift (unmigrated `user_id` columns) to remain entirely undetected. The test suite reported 100% success on RBAC logic, providing a false sense of security while the production application would instantly crash upon schema mismatch.

### 2. Missing Malicious Boundary Fuzzing
- **Status:** **FAIL / MEDIUM DEFECT**
- **Location:** API Route Tests
- **Details:** The API tests diligently verify happy paths and basic validation rejections (e.g., malformed PURLs, negative CVSS). However, they lack adversarial fuzzing for boundary constraints. There are no tests verifying the application's resilience against unbounded path parameters (such as supplying a 10MB `snapshot_id` to `vulnerability_routes.py`), which led to the Phase 8 DoS vulnerability going unnoticed.

### 3. Missing Cryptographic Interop Failure Assertions
- **Status:** **FAIL / MEDIUM DEFECT**
- **Location:** `zkp_service/tests/test_prover_service.py`
- **Details:** The test suite heavily mocks the subprocess execution of `nargo` and `bb`. There are no integration tests asserting the behavior of the `prover_service` when the cryptographic backend suffers an Out-Of-Memory panic or an assertion failure that dumps the witness into `stderr`. Consequently, the Phase 11 Information Disclosure vulnerability (leaking private SBOM data via `error_message`) had zero test coverage preventing regressions.

## Required Fixes
- **Test Infrastructure Parity:** Refactor the test suite's database fixtures to execute the actual Alembic migrations against a transient SQL Server instance (e.g., via Docker Testcontainers) instead of relying on SQLite and `create_all()`.
- **Adversarial Fuzzing:** Introduce a dedicated `test_adversarial_boundaries.py` suite to systematically test path parameter limits, payload limits, and ReDoS vectors across all API boundaries.
- **Subprocess Mocking Rigor:** Update the prover tests to explicitly mock `nargo execute` failure states that inject sensitive witness payloads into `stderr`, asserting that the API response masks this data.

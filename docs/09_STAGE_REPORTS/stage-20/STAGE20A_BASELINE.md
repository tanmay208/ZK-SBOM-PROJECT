# STAGE 20A — BASELINE

## Pre-Migration Status

A complete backend test suite run was executed against the Stage 20 backend codebase before test migration:

Total tests: 505
Passed: 479
Failed: 26
Skipped: 0
Warnings: 6

### Exactly Failing Tests
1. `backend/verification_service/tests/test_verification_api.py::test_verify_unavailable`
2. `backend/verification_service/tests/test_verification_api.py::test_verify_invalid`
3. `backend/verification_service/tests/test_verification_api.py::test_verify_success_and_fetch_certificate`
4. `backend/verification_service/tests/test_verification_api.py::test_schema_validation_missing_fields`
5. `backend/verification_service/tests/test_verification_api.py::test_schema_validation_invalid_hex`
6. `backend/verification_service/tests/test_verification_api.py::test_schema_validation_empty_root`
7. `backend/verification_service/tests/test_verification_api.py::test_schema_validation_oversized_payload`
8. `backend/verification_service/tests/test_verification_api.py::test_schema_validation_unexpected_private_fields`
9. `backend/verification_service/tests/test_verification_service.py::test_verification_unavailable`
10. `backend/verification_service/tests/test_verification_service.py::test_invalid_proof`
11. `backend/verification_service/tests/test_verification_service.py::test_verified_test_double`
12. `backend/verification_service/tests/test_verification_service.py::test_idempotent_submission`
13. `backend/verification_service/tests/test_verification_service.py::test_idempotent_re_evaluation`
14. `backend/verification_service/tests/test_verification_service.py::test_authoritative_record_mismatch`
15. `backend/verification_service/tests/test_verifier.py::test_verifier_fails_closed_on_missing_inputs`
16. `backend/verification_service/tests/test_verifier.py::test_verifier_verification_unavailable`
17. `backend/zkp_service/tests/test_prover_service.py::test_prover_service_execution_blocked`
18. `backend/zkp_service/tests/test_tenant_isolation.py::test_job_isolation_get_job`
19. `backend/zkp_service/tests/test_tenant_isolation.py::test_job_isolation_list_jobs`
20. `backend/zkp_service/tests/test_tenant_isolation.py::test_job_isolation_generate_job`
21. `backend/zkp_service/tests/test_zkp_api.py::test_generate_proof_api_success`
22. `backend/zkp_service/tests/test_zkp_api.py::test_get_proof_job_not_found`

All of these failures trace directly to the structural changes introduced in Stage 20:
- SQLAlchemy `ForeignKey` mapping initialization exceptions on `ProofJob.chunks` blocking dependent API initialization.
- Test assertions expecting the `proof_artifact` payload format (monolithic base64) which has been deprecated in favor of `proof_job_id`.
- Type changes for Pydantic input models rejecting mocked dummy strings instead of valid UUIDs for `proof_job_id`.
- Test environments bypassing the required `Session` argument required for orchestrating multi-entity `NoirVerifier` verification sets.
- `CryptoProfile` loader failing due to deprecated monolithic `.json` circuits in CI environments.

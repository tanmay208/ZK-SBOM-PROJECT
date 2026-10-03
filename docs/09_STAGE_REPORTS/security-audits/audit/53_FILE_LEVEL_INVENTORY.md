# Phase 1: Complete Repository Inventory

## File-to-Purpose Inventory

### `Root`
- `.dockerignore`: 
- `.env.example`: 
- `.gitignore`: 
- `README.md`: 
- `docker-compose.yml`: 
- `fix_tests.py`: 
- `pyproject.toml`: 
- `test_asgi.py`: 
- `test_f008_real.py`: 

### `backend`
- `alembic.ini`: 

### `backend\policy_service`
- `Dockerfile`: 
- `requirements.txt`: 

### `backend\policy_service\app`
- `__init__.py`: 
- `main.py`: 

### `backend\policy_service\app\api\routes`
- `__init__.py`: 
- `policy_routes.py`: 

### `backend\policy_service\app\core`
- `__init__.py`: 

### `backend\policy_service\app\models`
- `__init__.py`: 
- `policy_models.py`: 

### `backend\policy_service\app\repositories`
- `__init__.py`: 

### `backend\policy_service\app\schemas`
- `__init__.py`: 
- `policy_schemas.py`: 

### `backend\policy_service\app\security`
- `__init__.py`: 

### `backend\policy_service\app\services`
- `__init__.py`: 
- `policy_service.py`: 

### `backend\policy_service\tests`
- `test_policy_health.py`: 

### `backend\sbom_service`
- `Dockerfile`: 
- `requirements.txt`: 

### `backend\sbom_service\app`
- `__init__.py`: 
- `main.py`: 

### `backend\sbom_service\app\api\routes`
- `__init__.py`: 
- `sbom_routes.py`: 

### `backend\sbom_service\app\core`
- `__init__.py`: 

### `backend\sbom_service\app\models`
- `__init__.py`: 
- `sbom_models.py`: 

### `backend\sbom_service\app\repositories`
- `__init__.py`: 
- `sbom_repository.py`: 

### `backend\sbom_service\app\schemas`
- `__init__.py`: 
- `parsed_sbom.py`: 
- `sbom_schemas.py`: 

### `backend\sbom_service\app\security`
- `__init__.py`: 

### `backend\sbom_service\app\services`
- `__init__.py`: 
- `canonicalization.py`: 
- `commitment_service.py`: 
- `identity.py`: 
- `parser.py`: 
- `sbom_intake_service.py`: 
- `validator.py`: 

### `backend\sbom_service\tests`
- `test_adversarial_identity.py`: 
- `test_canonicalization.py`: 
- `test_f008_real.py`: 
- `test_failure_modes.py`: 
- `test_identity.py`: 
- `test_intake_api_privacy.py`: 
- `test_privacy_leakage.py`: 
- `test_sbom_health.py`: 
- `test_sbom_intake.py`: 
- `test_sbom_parser.py`: 
- `test_sbom_tenant_isolation.py`: 
- `test_sbom_validator.py`: 
- `test_security_adversarial.py`: 

### `backend\scripts`
- `init_db.py`: 

### `backend\shared`
- `__init__.py`: 
- `app_factory.py`: 
- `auth.py`: 
- `config.py`: 
- `database.py`: 
- `exceptions.py`: 
- `logging.py`: 
- `requirements.txt`: 
- `schemas.py`: 
- `security.py`: 

### `backend\shared\api`
- `auth_routes.py`: 
- `metrics_routes.py`: 

### `backend\shared\crypto`
- `component_hash.py`: 
- `config.py`: 
- `field_encoding.py`: 
- `merkle.py`: 
- `poseidon_bn254.py`: 
- `poseidon_constants.py`: 
- `profile.json`: 
- `smt.py`: 

### `backend\shared\models`
- `user.py`: 

### `backend\shared\tests`
- `test_adversarial_crypto.py`: 
- `test_authoritative_vectors.py`: 
- `test_component_hash.py`: 
- `test_component_hash_compatibility.py`: 
- `test_crypto_profile.py`: 
- `test_crypto_vectors.py`: 
- `test_field_encoding.py`: 
- `test_merkle.py`: 
- `test_poseidon_bn254.py`: 
- `test_purl.py`: 
- `test_security.py`: 
- `test_shared.py`: 
- `test_smt.py`: 
- `test_stage3_security.py`: 

### `backend\shared\tests\vectors`
- `crypto_vectors.json`: 

### `backend\shared\utils`
- `__init__.py`: 
- `purl.py`: 

### `backend\verification_service`
- `Dockerfile`: 
- `requirements.txt`: 

### `backend\verification_service\app`
- `__init__.py`: 
- `main.py`: 

### `backend\verification_service\app\api\routes`
- `__init__.py`: 
- `verification_routes.py`: 

### `backend\verification_service\app\core`
- `__init__.py`: 
- `verifier.py`: 

### `backend\verification_service\app\models`
- `__init__.py`: 
- `verification_models.py`: 

### `backend\verification_service\app\repositories`
- `__init__.py`: 
- `verification_repository.py`: 

### `backend\verification_service\app\schemas`
- `__init__.py`: 
- `verification_schemas.py`: 

### `backend\verification_service\app\security`
- `__init__.py`: 

### `backend\verification_service\app\services`
- `__init__.py`: 
- `verification_service.py`: 

### `backend\verification_service\tests`
- `test_verification_api.py`: 
- `test_verification_health.py`: 
- `test_verification_service.py`: 

### `backend\vulnerability_service`
- `Dockerfile`: 
- `requirements.txt`: 

### `backend\vulnerability_service\app`
- `__init__.py`: 
- `main.py`: 

### `backend\vulnerability_service\app\api\routes`
- `__init__.py`: 
- `vulnerability_routes.py`: 

### `backend\vulnerability_service\app\core`
- `__init__.py`: 

### `backend\vulnerability_service\app\models`
- `__init__.py`: 
- `vulnerability_models.py`: 

### `backend\vulnerability_service\app\repositories`
- `__init__.py`: 

### `backend\vulnerability_service\app\schemas`
- `__init__.py`: 
- `vulnerability_schemas.py`: 

### `backend\vulnerability_service\app\security`
- `__init__.py`: 

### `backend\vulnerability_service\app\services`
- `__init__.py`: 
- `vulnerability_service.py`: 

### `backend\vulnerability_service\tests`
- `test_cvss.py`: 
- `test_vulnerability_health.py`: 
- `test_vulnerability_ingestion.py`: 

### `backend\zkp_service`
- `Dockerfile`: 
- `requirements.txt`: 

### `backend\zkp_service\app`
- `__init__.py`: 
- `main.py`: 

### `backend\zkp_service\app\api\routes`
- `__init__.py`: 
- `zkp_routes.py`: 

### `backend\zkp_service\app\core`
- `__init__.py`: 

### `backend\zkp_service\app\models`
- `__init__.py`: 
- `zkp_models.py`: 

### `backend\zkp_service\app\repositories`
- `__init__.py`: 
- `zkp_repository.py`: 

### `backend\zkp_service\app\schemas`
- `__init__.py`: 
- `zkp_schemas.py`: 

### `backend\zkp_service\app\security`
- `__init__.py`: 

### `backend\zkp_service\app\services`
- `__init__.py`: 
- `prover_service.py`: 

### `backend\zkp_service\tests`
- `test_prover_service.py`: 
- `test_tenant_isolation.py`: 
- `test_zkp_api.py`: 
- `test_zkp_health.py`: 

### `circuits`
- `Nargo.toml`: 
- `Prover.toml`: 

### `circuits\src`
- `main.nr`: 
- `merkle.nr`: 
- `smt.nr`: 

### `circuits_dev`
- `Nargo.toml`: 

### `circuits_dev\src`
- `main.nr`: 
- `merkle.nr`: 
- `smt.nr`: 

### `docker`
- `Dockerfile.noir`: 

### `docs`
- `ARCHITECTURE.md`: 
- `CRYPTO_INTEROPERABILITY.md`: 
- `DATABASE_SCHEMA.md`: 
- `DEVELOPMENT_RULES.md`: 
- `IMPLEMENTATION_PLAN.md`: 
- `LOGIC_FLOW.md`: 
- `MILESTONE_FREEZE_DAY_9.md`: 
- `PROJECT_SCOPE.md`: 
- `SECURITY_BOUNDARY.md`: 
- `SERVICE_CONTRACTS.md`: 
- `THREAT_MODEL.md`: 
- `ZKP_SPECIFICATION.md`: 

### `docs\security\audit`
- `00_EXECUTION_LOG.md`: 
- `01_REPOSITORY_INVENTORY.md`: 
- `02_ARCHITECTURE_TRUST_BOUNDARIES.md`: 
- `03_ATTACK_SURFACE.md`: 
- `04_AUTHENTICATION_AUDIT.md`: 
- `05_AUTHORIZATION_RBAC_AUDIT.md`: 
- `06_API_SECURITY_AUDIT.md`: 
- `07_SBOM_PARSER_AUDIT.md`: 
- `08_VULNERABILITY_INTELLIGENCE_AUDIT.md`: 
- `09_CRYPTOGRAPHIC_ZK_AUDIT.md`: 
- `10_RUNTIME_SUBPROCESS_AUDIT.md`: 
- `11_FILESYSTEM_ARTIFACT_AUDIT.md`: 
- `12_DATABASE_AUDIT.md`: 
- `13_SECRETS_PRIVACY_LOGGING_AUDIT.md`: 
- `14_DEPENDENCY_AUDIT.md`: 
- `15_CONFIGURATION_DEPLOYMENT_AUDIT.md`: 
- `16_TEST_ASSURANCE_AUDIT.md`: 
- `17_GIT_HISTORY_AUDIT.md`: 
- `18_VULNERABILITY_REGISTER.md`: 
- `19_FALSE_POSITIVES.md`: 
- `20_FINAL_VERDICT.md`: 
- `21_SELF_CHALLENGE_REPORT.md`: 
- `22_MASTER_FINDING_RECONCILIATION.md`: 
- `23_REMEDIATION_ARCHITECTURE.md`: 
- `24_REMEDIATION_PLAN.md`: 
- `25_SECURITY_DECISIONS_REQUIRED.md`: 
- `26_DECISION_CLOSURE.md`: 
- `27_RELEASE_BLOCKER_MATRIX.md`: 
- `28_CRYPTO_TOOLCHAIN_COMPATIBILITY.md`: 
- `29_ZK002_FEASIBILITY_REPORT.md`: 
- `30_TOOLCHAIN_APPROVAL_RECORD.md`: 
- `31_PUBLIC_INPUT_BINDING_EXPERIMENT.md`: 
- `32_COMPLETE_ENVIRONMENT_INVENTORY.md`: 
- `33_INSTALLATION_AND_CONFIGURATION_REPORT.md`: 
- `34_RUNTIME_VALIDATION_MATRIX.md`: 
- `35_REMAINING_ENVIRONMENT_BLOCKERS.md`: 
- `36_WINDOWS_ENVIRONMENT_STANDARDIZATION.md`: 
- `37_NATIVE_WINDOWS_COMPONENTS.md`: 
- `38_CRYPTO_LINUX_ENVIRONMENT.md`: 
- `39_FINAL_INSTALLATION_STATUS.md`: 
- `40_REPOSITORY_CLEANUP_INVENTORY.md`: 
- `41_SAFE_CLEANUP_EXECUTION_REPORT.md`: 
- `42_ENVIRONMENT_REMEDIATION_REPORT.md`: 
- `43_ANTIGRAVITY_OPUS_TAKEOVER_ASSESSMENT.md`: 
- `44_PHASE5B_CRYPTO_EXECUTION_REPORT.md`: 
- `45_PUBLIC_INPUT_BINDING_VALIDATION.md`: 
- `46_ZK002_APPLICATION_REMEDIATION_REPORT.md`: 
- `47_REMAINING_BLOCKERS_EXECUTION_PLAN.md`: 
- `52_FINAL_AUDIT_BASELINE.md`: 
- `git_diff.txt`: 
- `git_diff_stat.txt`: 
- `git_log.txt`: 
- `git_status.txt`: 
- `inventory_list.txt`: 
- `inventory_list_clean.txt`: 

### `docs\security\remediation`
- `00_BASELINE.md`: 

### `frontend`
- `.gitignore`: 
- `AGENTS.md`: 
- `CLAUDE.md`: 
- `README.md`: 
- `components.json`: 
- `eslint.config.mjs`: 
- `next-env.d.ts`: 
- `next.config.ts`: 
- `package-lock.json`: 
- `package.json`: 
- `postcss.config.mjs`: 
- `tsconfig.json`: 

### `frontend\public`
- `file.svg`: 
- `globe.svg`: 
- `next.svg`: 
- `vercel.svg`: 
- `window.svg`: 

### `frontend\src\app`
- `favicon.ico`: 
- `globals.css`: 
- `layout.tsx`: 
- `page.tsx`: 

### `frontend\src\components\layout`
- `app-layout.tsx`: 
- `header.tsx`: 
- `sidebar.tsx`: 

### `frontend\src\components\ui`
- `badge.tsx`: 
- `button.tsx`: 
- `card.tsx`: 
- `input.tsx`: 
- `label.tsx`: 
- `separator.tsx`: 
- `table.tsx`: 

### `frontend\src\lib`
- `utils.ts`: 

### `scripts`
- `bn254.nr`: 
- `consts.nr`: 
- `extract_consts.py`: 
- `generate_crypto_vectors.py`: 
- `generate_inventory.py`: 
- `generate_noir_vector_tests.py`: 
- `generate_print_main.py`: 
- `get_all_vectors.py`: 
- `get_merkle_vectors.py`: 
- `get_python_hashes.py`: 
- `mod.nr`: 
- `perm.nr`: 
- `run_noir_compatibility_tests.py`: 
- `size_analysis.py`: 
- `temp_merkle.py`: 
- `test_main_circuit.py`: 
- `test_perm.py`: 
- `test_poseidon.py`: 
- `true_max_size.py`: 
- `true_valid_max_size.py`: 

### `scripts\noir_compatibility`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_compatibility\src`
- `main.nr`: 

### `scripts\noir_experiment`
- `Nargo.toml`: 

### `scripts\noir_experiment\src`
- `main.nr`: 

### `scripts\noir_src`
- `.aztec-sync-commit`: 
- `.eslintrc.js`: 
- `.gitattributes`: 
- `.gitignore`: 
- `.prettierrc`: 
- `.release-please-manifest.json`: 
- `.rustfmt.toml`: 
- `.tokeignore`: 
- `.yarnrc.yml`: 
- `CHANGELOG.md`: 
- `CONTRIBUTING.md`: 
- `Cargo.lock`: 
- `Cargo.toml`: 
- `LICENSE-APACHE`: 
- `LICENSE-MIT`: 
- `README.md`: 
- `SUPPORT.md`: 
- `cspell.json`: 
- `deny.toml`: 
- `noir-logo.png`: 
- `package.json`: 
- `release-please-config.json`: 
- `rust-toolchain.toml`: 
- `yarn.lock`: 

### `scripts\noir_src\.github`
- `ACVM_NOT_PUBLISHABLE.md`: 
- `ACVM_PUBLISH_FAILED.md`: 
- `CRATES_IO_PUBLISH_FAILED.md`: 
- `Cross.toml`: 
- `DEAD_LINKS_IN_DOCS.md`: 
- `JS_PUBLISH_FAILED.md`: 
- `pull_request_template.md`: 

### `scripts\noir_src\.github\ISSUE_TEMPLATE`
- `bug_report.yml`: 
- `feature_request.yml`: 

### `scripts\noir_src\.github\actions\docs\build-status`
- `action.yml`: 
- `script.sh`: 

### `scripts\noir_src\.github\actions\install-playwright`
- `action.yml`: 

### `scripts\noir_src\.github\actions\setup`
- `action.yml`: 

### `scripts\noir_src\.github\scripts`
- `acvm_js-build.sh`: 
- `acvm_js-test-browser.sh`: 
- `acvm_js-test.sh`: 
- `backend-barretenberg-build.sh`: 
- `backend-barretenberg-test.sh`: 
- `cargo-binstall-install.sh`: 
- `integration-test-browser.sh`: 
- `integration-test-node.sh`: 
- `nargo-build.sh`: 
- `nargo-test.sh`: 
- `noir-codegen-build.sh`: 
- `noir-codegen-test.sh`: 
- `noir-js-build.sh`: 
- `noir-js-test.sh`: 
- `noir-js-types-build.sh`: 
- `noir-wasm-build.sh`: 
- `noir-wasm-test-browser.sh`: 
- `noir-wasm-test.sh`: 
- `noirc-abi-build.sh`: 
- `noirc-abi-test-browser.sh`: 
- `noirc-abi-test.sh`: 
- `playwright-install.sh`: 
- `wasm-bindgen-install.sh`: 
- `wasm-opt-install.sh`: 
- `wasm-pack-install.sh`: 

### `scripts\noir_src\.github\workflows`
- `cache-cleanup.yml`: 
- `deny.yml`: 
- `docs-dead-links.yml`: 
- `docs-pr.yml`: 
- `formatting.yml`: 
- `gates_report.yml`: 
- `lockfile.yml`: 
- `mirror-external_libs.yml`: 
- `publish-acvm.yml`: 
- `publish-docs.yml`: 
- `publish-es-packages.yml`: 
- `publish-nargo.yml`: 
- `publish-nightly.yml`: 
- `pull-request-title.yml`: 
- `recrawler.yml`: 
- `release.yml`: 
- `spellcheck.yml`: 
- `test-js-packages.yml`: 
- `test-rust-workspace-msrv.yml`: 
- `test-rust-workspace.yml`: 

### `scripts\noir_src\.vscode`
- `extensions.json`: 
- `settings.json`: 

### `scripts\noir_src\.yarn\plugins\@yarnpkg`
- `plugin-interactive-tools.cjs`: 
- `plugin-typescript.cjs`: 
- `plugin-workspace-tools.cjs`: 

### `scripts\noir_src\.yarn\releases`
- `yarn-3.6.3.cjs`: 

### `scripts\noir_src\acvm-repo`
- `CHANGELOG.md`: 
- `README.md`: 

### `scripts\noir_src\acvm-repo\acir`
- `CHANGELOG.md`: 
- `Cargo.toml`: 
- `README.md`: 

### `scripts\noir_src\acvm-repo\acir\benches`
- `serialization.rs`: 

### `scripts\noir_src\acvm-repo\acir\codegen`
- `acir.cpp`: 
- `witness.cpp`: 

### `scripts\noir_src\acvm-repo\acir\src\circuit`
- `black_box_functions.rs`: 
- `brillig.rs`: 
- `directives.rs`: 
- `mod.rs`: 
- `opcodes.rs`: 

### `scripts\noir_src\acvm-repo\acir\src\circuit\opcodes`
- `black_box_function_call.rs`: 
- `memory_operation.rs`: 

### `scripts\noir_src\acvm-repo\acir\src`
- `lib.rs`: 

### `scripts\noir_src\acvm-repo\acir\src\native_types\expression`
- `mod.rs`: 
- `operators.rs`: 
- `ordering.rs`: 

### `scripts\noir_src\acvm-repo\acir\src\native_types`
- `mod.rs`: 
- `witness.rs`: 
- `witness_map.rs`: 
- `witness_stack.rs`: 

### `scripts\noir_src\acvm-repo\acir\tests`
- `test_program_serialization.rs`: 

### `scripts\noir_src\acvm-repo\acir_field`
- `.gitignore`: 
- `CHANGELOG.md`: 
- `Cargo.toml`: 

### `scripts\noir_src\acvm-repo\acir_field\proptest-regressions`
- `field_element.txt`: 

### `scripts\noir_src\acvm-repo\acir_field\src`
- `field_element.rs`: 
- `generic_ark.rs`: 
- `lib.rs`: 

### `scripts\noir_src\acvm-repo\acvm`
- `CHANGELOG.md`: 
- `Cargo.toml`: 

### `scripts\noir_src\acvm-repo\acvm\src\compiler`
- `mod.rs`: 

### `scripts\noir_src\acvm-repo\acvm\src\compiler\optimizers`
- `constant_backpropagation.rs`: 
- `general.rs`: 
- `mod.rs`: 
- `redundant_range.rs`: 
- `unused_memory.rs`: 

### `scripts\noir_src\acvm-repo\acvm\src\compiler\transformers`
- `csat.rs`: 
- `mod.rs`: 

### `scripts\noir_src\acvm-repo\acvm\src`
- `lib.rs`: 

### `scripts\noir_src\acvm-repo\acvm\src\pwg`
- `arithmetic.rs`: 
- `brillig.rs`: 
- `memory_op.rs`: 
- `mod.rs`: 

### `scripts\noir_src\acvm-repo\acvm\src\pwg\blackbox`
- `aes128.rs`: 
- `bigint.rs`: 
- `embedded_curve_ops.rs`: 
- `hash.rs`: 
- `logic.rs`: 
- `mod.rs`: 
- `pedersen.rs`: 
- `range.rs`: 
- `utils.rs`: 

### `scripts\noir_src\acvm-repo\acvm\src\pwg\blackbox\signature`
- `ecdsa.rs`: 
- `mod.rs`: 
- `schnorr.rs`: 

### `scripts\noir_src\acvm-repo\acvm\src\pwg\directives`
- `mod.rs`: 

### `scripts\noir_src\acvm-repo\acvm\tests`
- `solver.rs`: 

### `scripts\noir_src\acvm-repo\acvm_js\.cargo`
- `config.toml`: 

### `scripts\noir_src\acvm-repo\acvm_js`
- `.eslintignore`: 
- `.eslintrc.js`: 
- `.gitignore`: 
- `.mocharc.json`: 
- `CHANGELOG.md`: 
- `Cargo.toml`: 
- `README.md`: 
- `build.rs`: 
- `build.sh`: 
- `package.json`: 
- `tsconfig.json`: 
- `web-test-runner.config.mjs`: 

### `scripts\noir_src\acvm-repo\acvm_js\src`
- `black_box_solvers.rs`: 
- `build_info.rs`: 
- `compression.rs`: 
- `execute.rs`: 
- `js_execution_error.rs`: 
- `js_witness_map.rs`: 
- `js_witness_stack.rs`: 
- `lib.rs`: 
- `logging.rs`: 
- `public_witness.rs`: 

### `scripts\noir_src\acvm-repo\acvm_js\src\foreign_call`
- `inputs.rs`: 
- `mod.rs`: 
- `outputs.rs`: 

### `scripts\noir_src\acvm-repo\acvm_js\test\browser`
- `black_box_solvers.test.ts`: 
- `execute_circuit.test.ts`: 
- `witness_conversion.test.ts`: 

### `scripts\noir_src\acvm-repo\acvm_js\test\node`
- `black_box_solvers.test.ts`: 
- `build_info.test.ts`: 
- `execute_circuit.test.ts`: 
- `witness_conversion.test.ts`: 

### `scripts\noir_src\acvm-repo\acvm_js\test\shared`
- `addition.ts`: 
- `black_box_solvers.ts`: 
- `complex_foreign_call.ts`: 
- `foreign_call.ts`: 
- `memory_op.ts`: 
- `multi_scalar_mul.ts`: 
- `nested_acir_call.ts`: 
- `schnorr_verify.ts`: 
- `witness_compression.ts`: 

### `scripts\noir_src\acvm-repo\acvm_js\test`
- `types.ts`: 

### `scripts\noir_src\acvm-repo\blackbox_solver`
- `CHANGELOG.md`: 
- `Cargo.toml`: 

### `scripts\noir_src\acvm-repo\blackbox_solver\src`
- `aes128.rs`: 
- `bigint.rs`: 
- `curve_specific_solver.rs`: 
- `hash.rs`: 
- `lib.rs`: 
- `logic.rs`: 

### `scripts\noir_src\acvm-repo\blackbox_solver\src\ecdsa`
- `mod.rs`: 
- `secp256k1.rs`: 
- `secp256r1.rs`: 

### `scripts\noir_src\acvm-repo\bn254_blackbox_solver`
- `CHANGELOG.md`: 
- `Cargo.toml`: 

### `scripts\noir_src\acvm-repo\bn254_blackbox_solver\benches`
- `criterion.rs`: 

### `scripts\noir_src\acvm-repo\bn254_blackbox_solver\src`
- `embedded_curve_ops.rs`: 
- `lib.rs`: 
- `poseidon2.rs`: 

### `scripts\noir_src\acvm-repo\bn254_blackbox_solver\src\generator`
- `generators.rs`: 
- `hash_to_curve.rs`: 
- `mod.rs`: 

### `scripts\noir_src\acvm-repo\bn254_blackbox_solver\src\pedersen`
- `commitment.rs`: 
- `hash.rs`: 
- `mod.rs`: 

### `scripts\noir_src\acvm-repo\bn254_blackbox_solver\src\schnorr`
- `mod.rs`: 

### `scripts\noir_src\acvm-repo\brillig`
- `CHANGELOG.md`: 
- `Cargo.toml`: 

### `scripts\noir_src\acvm-repo\brillig\src`
- `black_box.rs`: 
- `foreign_call.rs`: 
- `lib.rs`: 
- `opcodes.rs`: 

### `scripts\noir_src\acvm-repo\brillig_vm`
- `CHANGELOG.md`: 
- `Cargo.toml`: 

### `scripts\noir_src\acvm-repo\brillig_vm\src`
- `arithmetic.rs`: 
- `black_box.rs`: 
- `lib.rs`: 
- `memory.rs`: 

### `scripts\noir_src\aztec_macros`
- `Cargo.toml`: 

### `scripts\noir_src\aztec_macros\src`
- `lib.rs`: 

### `scripts\noir_src\aztec_macros\src\transforms`
- `compute_note_hash_and_optionally_a_nullifier.rs`: 
- `contract_interface.rs`: 
- `events.rs`: 
- `functions.rs`: 
- `mod.rs`: 
- `note_interface.rs`: 
- `storage.rs`: 

### `scripts\noir_src\aztec_macros\src\utils`
- `ast_utils.rs`: 
- `checks.rs`: 
- `constants.rs`: 
- `errors.rs`: 
- `hir_utils.rs`: 
- `mod.rs`: 

### `scripts\noir_src\compiler\fm`
- `Cargo.toml`: 

### `scripts\noir_src\compiler\fm\src`
- `file_map.rs`: 
- `lib.rs`: 

### `scripts\noir_src\compiler\integration-tests`
- `.eslintignore`: 
- `.eslintrc.js`: 
- `.gitignore`: 
- `hardhat.config.ts`: 
- `package.json`: 
- `tsconfig.json`: 
- `web-test-runner.config.mjs`: 

### `scripts\noir_src\compiler\integration-tests\circuits\assert_lt`
- `Nargo.toml`: 

### `scripts\noir_src\compiler\integration-tests\circuits\assert_lt\src`
- `main.nr`: 

### `scripts\noir_src\compiler\integration-tests\circuits\fold_fibonacci`
- `Nargo.toml`: 

### `scripts\noir_src\compiler\integration-tests\circuits\fold_fibonacci\src`
- `main.nr`: 

### `scripts\noir_src\compiler\integration-tests\circuits\recursion`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\compiler\integration-tests\circuits\recursion\src`
- `main.nr`: 

### `scripts\noir_src\compiler\integration-tests\scripts`
- `codegen-verifiers.sh`: 
- `compile-programs.sh`: 
- `setup.sh`: 

### `scripts\noir_src\compiler\integration-tests\test\browser`
- `compile_prove_verify.test.ts`: 
- `recursion.test.ts`: 
- `utils.ts`: 

### `scripts\noir_src\compiler\integration-tests\test`
- `environment.ts`: 

### `scripts\noir_src\compiler\integration-tests\test\mocks`
- `os.js`: 

### `scripts\noir_src\compiler\integration-tests\test\node`
- `onchain_recursive_verification.test.ts`: 
- `prove_and_verify.test.ts`: 
- `smart_contract_verifier.test.ts`: 

### `scripts\noir_src\compiler\noirc_arena`
- `Cargo.toml`: 

### `scripts\noir_src\compiler\noirc_arena\src`
- `lib.rs`: 

### `scripts\noir_src\compiler\noirc_driver`
- `Cargo.toml`: 
- `build.rs`: 

### `scripts\noir_src\compiler\noirc_driver\src`
- `abi_gen.rs`: 
- `contract.rs`: 
- `debug.rs`: 
- `lib.rs`: 
- `program.rs`: 
- `stdlib.rs`: 

### `scripts\noir_src\compiler\noirc_driver\tests`
- `contracts.rs`: 
- `stdlib_warnings.rs`: 

### `scripts\noir_src\compiler\noirc_errors`
- `Cargo.toml`: 

### `scripts\noir_src\compiler\noirc_errors\src`
- `debug_info.rs`: 
- `lib.rs`: 
- `position.rs`: 
- `reporter.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator`
- `Cargo.toml`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\brillig`
- `brillig_gen.rs`: 
- `brillig_ir.rs`: 
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\brillig\brillig_gen`
- `brillig_black_box.rs`: 
- `brillig_block.rs`: 
- `brillig_block_variables.rs`: 
- `brillig_directive.rs`: 
- `brillig_fn.rs`: 
- `brillig_slice_ops.rs`: 
- `variable_liveness.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\brillig\brillig_ir`
- `artifact.rs`: 
- `brillig_variable.rs`: 
- `codegen_binary.rs`: 
- `codegen_calls.rs`: 
- `codegen_control_flow.rs`: 
- `codegen_intrinsic.rs`: 
- `codegen_memory.rs`: 
- `codegen_stack.rs`: 
- `debug_show.rs`: 
- `entry_point.rs`: 
- `instructions.rs`: 
- `registers.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src`
- `errors.rs`: 
- `lib.rs`: 
- `ssa.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\acir_gen`
- `acir_ir.rs`: 
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\acir_gen\acir_ir`
- `acir_variable.rs`: 
- `big_int.rs`: 
- `generated_acir.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\checks`
- `check_for_underconstrained_values.rs`: 
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\function_builder`
- `data_bus.rs`: 
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa`
- `ir.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\ir`
- `basic_block.rs`: 
- `cfg.rs`: 
- `dfg.rs`: 
- `dom.rs`: 
- `function.rs`: 
- `function_inserter.rs`: 
- `instruction.rs`: 
- `map.rs`: 
- `post_order.rs`: 
- `printer.rs`: 
- `types.rs`: 
- `value.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\ir\instruction`
- `binary.rs`: 
- `call.rs`: 
- `cast.rs`: 
- `constrain.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\opt`
- `array_set.rs`: 
- `as_slice_length.rs`: 
- `assert_constant.rs`: 
- `bubble_up_constrains.rs`: 
- `constant_folding.rs`: 
- `defunctionalize.rs`: 
- `die.rs`: 
- `flatten_cfg.rs`: 
- `inlining.rs`: 
- `mem2reg.rs`: 
- `mod.rs`: 
- `rc.rs`: 
- `remove_bit_shifts.rs`: 
- `remove_enable_side_effects.rs`: 
- `remove_if_else.rs`: 
- `resolve_is_unconstrained.rs`: 
- `runtime_separation.rs`: 
- `simplify_cfg.rs`: 
- `unrolling.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\opt\flatten_cfg`
- `branch_analysis.rs`: 
- `capacity_tracker.rs`: 
- `value_merger.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\opt\mem2reg`
- `alias_set.rs`: 
- `block.rs`: 

### `scripts\noir_src\compiler\noirc_evaluator\src\ssa\ssa_gen`
- `context.rs`: 
- `mod.rs`: 
- `program.rs`: 
- `value.rs`: 

### `scripts\noir_src\compiler\noirc_frontend`
- `Cargo.toml`: 
- `build.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\ast`
- `expression.rs`: 
- `function.rs`: 
- `mod.rs`: 
- `statement.rs`: 
- `structure.rs`: 
- `traits.rs`: 
- `type_alias.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\debug`
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\elaborator`
- `expressions.rs`: 
- `lints.rs`: 
- `mod.rs`: 
- `patterns.rs`: 
- `scope.rs`: 
- `statements.rs`: 
- `traits.rs`: 
- `types.rs`: 
- `unquote.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\graph`
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir\comptime`
- `errors.rs`: 
- `hir_to_display_ast.rs`: 
- `interpreter.rs`: 
- `mod.rs`: 
- `scan.rs`: 
- `tests.rs`: 
- `value.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir\comptime\interpreter`
- `builtin.rs`: 
- `unquote.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir\def_collector`
- `dc_crate.rs`: 
- `dc_mod.rs`: 
- `errors.rs`: 
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir\def_map`
- `item_scope.rs`: 
- `mod.rs`: 
- `module_data.rs`: 
- `module_def.rs`: 
- `namespace.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir`
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir\resolution`
- `errors.rs`: 
- `import.rs`: 
- `mod.rs`: 
- `path_resolver.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir\scope`
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir\type_check`
- `errors.rs`: 
- `mod.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\hir_def`
- `expr.rs`: 
- `function.rs`: 
- `mod.rs`: 
- `stmt.rs`: 
- `traits.rs`: 
- `types.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\lexer\blns`
- `LICENSE`: 
- `README.md`: 
- `blns.base64.json`: 

### `scripts\noir_src\compiler\noirc_frontend\src\lexer`
- `errors.rs`: 
- `lexer.rs`: 
- `mod.rs`: 
- `token.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src`
- `lib.rs`: 
- `locations.rs`: 
- `node_interner.rs`: 
- `noir_parser.lalrpop`: 
- `resolve_locations.rs`: 
- `tests.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\monomorphization`
- `ast.rs`: 
- `debug.rs`: 
- `debug_types.rs`: 
- `errors.rs`: 
- `mod.rs`: 
- `printer.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\parser`
- `errors.rs`: 
- `labels.rs`: 
- `mod.rs`: 
- `parser.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\parser\parser`
- `assertion.rs`: 
- `attributes.rs`: 
- `function.rs`: 
- `lambdas.rs`: 
- `literals.rs`: 
- `path.rs`: 
- `primitives.rs`: 
- `structs.rs`: 
- `test_helpers.rs`: 
- `traits.rs`: 
- `types.rs`: 

### `scripts\noir_src\compiler\noirc_frontend\src\tests`
- `name_shadowing.rs`: 

### `scripts\noir_src\compiler\noirc_printable_type`
- `Cargo.toml`: 

### `scripts\noir_src\compiler\noirc_printable_type\src`
- `lib.rs`: 

### `scripts\noir_src\compiler`
- `readme.md`: 

### `scripts\noir_src\compiler\wasm`
- `.eslintignore`: 
- `.eslintrc.js`: 
- `.gitignore`: 
- `.mocharc.json`: 
- `CHANGELOG.md`: 
- `Cargo.toml`: 
- `README.md`: 
- `build.rs`: 
- `package.json`: 
- `tsconfig.esm.json`: 
- `tsconfig.json`: 
- `tsconfig.webpack.json`: 
- `web-test-runner.config.mjs`: 
- `webpack.config.ts`: 

### `scripts\noir_src\compiler\wasm\scripts`
- `build-fixtures.sh`: 
- `command-check.sh`: 
- `install_wasm-pack.sh`: 

### `scripts\noir_src\compiler\wasm\src`
- `compile.rs`: 
- `compile_new.rs`: 
- `errors.rs`: 
- `index.cts`: 
- `index.mts`: 
- `lib.rs`: 
- `utils.ts`: 

### `scripts\noir_src\compiler\wasm\src\noir`
- `debug.ts`: 
- `noir-wasm-compiler.ts`: 
- `package.ts`: 

### `scripts\noir_src\compiler\wasm\src\noir\dependencies`
- `dependency-manager.ts`: 
- `dependency-resolver.ts`: 
- `github-dependency-resolver.ts`: 
- `local-dependency-resolver.ts`: 

### `scripts\noir_src\compiler\wasm\src\noir\file-manager`
- `file-manager.ts`: 
- `memfs-file-manager.ts`: 
- `nodejs-file-manager.ts`: 

### `scripts\noir_src\compiler\wasm\src\types`
- `noir_artifact.ts`: 
- `noir_package_config.ts`: 

### `scripts\noir_src\compiler\wasm\test\compiler\browser`
- `compile.test.ts`: 

### `scripts\noir_src\compiler\wasm\test\compiler\node`
- `compile.test.ts`: 

### `scripts\noir_src\compiler\wasm\test\compiler\shared`
- `compile.test.ts`: 

### `scripts\noir_src\compiler\wasm\test\dependencies`
- `dependency-manager.test.ts`: 
- `github-dependency-resolver.test.ts`: 
- `local-dependency-resolver.test.ts`: 

### `scripts\noir_src\compiler\wasm\test\file-manager`
- `file-manager.test.ts`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\deps\lib-a`
- `Nargo.toml`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\deps\lib-a\src`
- `lib.nr`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\deps\lib-b`
- `Nargo.toml`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\deps\lib-b\src`
- `lib.nr`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\deps\lib-c`
- `Nargo.toml`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\deps\lib-c\src`
- `lib.nr`: 
- `module.nr`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\deps\lib-c\src\module`
- `foo.nr`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\noir-contract`
- `Nargo.toml`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\noir-contract\src`
- `main.nr`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\simple`
- `Nargo.toml`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\simple\src`
- `main.nr`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\with-deps`
- `Nargo.toml`: 

### `scripts\noir_src\compiler\wasm\test\fixtures\with-deps\src`
- `main.nr`: 

### `scripts\noir_src\compiler\wasm\test`
- `shared.ts`: 

### `scripts\noir_src\compiler\wasm\test\wasm\browser`
- `index.test.ts`: 

### `scripts\noir_src\compiler\wasm\test\wasm\node`
- `index.test.ts`: 

### `scripts\noir_src\docs`
- `.eslintignore`: 
- `.gitignore`: 
- `.markdownlint.json`: 
- `.yarnrc.yml`: 
- `README.md`: 
- `docusaurus.config.ts`: 
- `link-check.config.json`: 
- `package.json`: 
- `sidebars.js`: 
- `tsconfig.json`: 

### `scripts\noir_src\docs\docs\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\docs\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\docs\getting_started\barretenberg`
- `_category_.json`: 
- `index.md`: 

### `scripts\noir_src\docs\docs\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\docs\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\docs\getting_started\tooling`
- `noir_codegen.md`: 

### `scripts\noir_src\docs\docs\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\docs\how_to\debugger`
- `_category_.json`: 
- `debugging_with_the_repl.md`: 
- `debugging_with_vs_code.md`: 

### `scripts\noir_src\docs\docs`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\docs\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.mdx`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.mdx`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\docs\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\docs\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\docs\noir\standard_library`
- `_category_.json`: 
- `bigint.md`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `is_unconstrained.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\docs\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\docs\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ciphers.mdx`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `embedded_curve_ops.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\docs\reference`
- `_category_.json`: 

### `scripts\noir_src\docs\docs\reference\debugger`
- `_category_.json`: 
- `debugger_known_limitations.md`: 
- `debugger_repl.md`: 
- `debugger_vscode.md`: 

### `scripts\noir_src\docs\docs\tooling`
- `debugger.md`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\docs\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\scripts`
- `codegen_nargo_reference.sh`: 
- `cut_version.sh`: 
- `setStable.ts`: 

### `scripts\noir_src\docs\scripts\preprocess`
- `include_code.js`: 
- `index.js`: 

### `scripts\noir_src\docs\src\components\Matomo`
- `matomo.jsx`: 

### `scripts\noir_src\docs\src\components\Notes`
- `_blackbox.mdx`: 
- `_experimental.mdx`: 

### `scripts\noir_src\docs\src\css`
- `custom.css`: 
- `sidebar.css`: 

### `scripts\noir_src\docs\src\pages`
- `index.jsx`: 

### `scripts\noir_src\docs\src\theme`
- `Root.js`: 

### `scripts\noir_src\docs\static`
- `.nojekyll`: 

### `scripts\noir_src\docs\static\img`
- `aztec_logo.png`: 
- `codelens_compile_execute.png`: 
- `codelens_run_test.png`: 
- `codelens_testing_panel.png`: 
- `favicon.ico`: 
- `homepage_header_pic.png`: 
- `logo.png`: 
- `logo.svg`: 
- `logoDark.svg`: 
- `noir_getting_started_1.png`: 
- `solidity_verifier_ex.png`: 

### `scripts\noir_src\docs\static\img\debugger`
- `1-started.png`: 
- `2-icon.png`: 
- `3-debug-pane.png`: 
- `4-debugger-buttons.png`: 
- `5-assert.png`: 
- `6-hover.png`: 
- `7-break.png`: 
- `debugger-intro.gif`: 
- `ref1-create-launch.png`: 

### `scripts\noir_src\docs\static\img\how-tos`
- `solidity_verifier_1.png`: 
- `solidity_verifier_2.png`: 
- `solidity_verifier_3.png`: 
- `solidity_verifier_4.png`: 
- `solidity_verifier_5.png`: 

### `scripts\noir_src\docs\static\img\memes`
- `flextape.jpeg`: 
- `matrix_oracle.jpeg`: 
- `titanic.jpeg`: 

### `scripts\noir_src\docs\static\video`
- `codespaces_showcase.mp4`: 

### `scripts\noir_src\docs\static\video\how-tos`
- `devcontainer.mp4`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\examples`
- `merkle-proof.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\getting_started`
- `00_nargo_installation.md`: 
- `01_hello_world.md`: 
- `02_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0`
- `index.md`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\language_concepts`
- `01_functions.md`: 
- `02_control_flow.md`: 
- `03_ops.md`: 
- `04_assert.md`: 
- `05_unconstrained.md`: 
- `06_generics.md`: 
- `07_mutability.md`: 
- `08_lambdas.md`: 
- `09_comments.md`: 
- `10_distinct.md`: 
- `11_shadowing.md`: 
- `data_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\language_concepts\data_types`
- `00_fields.md`: 
- `01_integers.md`: 
- `02_booleans.md`: 
- `03_strings.md`: 
- `04_arrays.md`: 
- `05_slices.mdx`: 
- `06_vectors.mdx`: 
- `07_tuples.md`: 
- `08_structs.md`: 
- `09_references.md`: 
- `10_function_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\modules_packages_crates`
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\nargo`
- `01_commands.md`: 
- `02_testing.md`: 
- `03_solidity_verifier.md`: 
- `04_language_server.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\noir_js\getting_started`
- `01_tiny_noir_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\noir_js`
- `noir_js.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\noir_js\reference`
- `01_noirjs.md`: 
- `02_bb_backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\standard_library`
- `black_box_fns.md`: 
- `cryptographic_primitives.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.17.0\standard_library\cryptographic_primitives`
- `00_hashes.mdx`: 
- `01_scalar.mdx`: 
- `02_schnorr.mdx`: 
- `03_ecdsa_sig_verification.mdx`: 
- `04_ec_primitives.md`: 
- `05_eddsa.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\examples`
- `merkle-proof.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\getting_started`
- `00_nargo_installation.md`: 
- `01_hello_world.md`: 
- `02_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0`
- `index.md`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\language_concepts`
- `01_functions.md`: 
- `02_control_flow.md`: 
- `03_ops.md`: 
- `04_assert.md`: 
- `05_unconstrained.md`: 
- `06_generics.md`: 
- `07_mutability.md`: 
- `08_lambdas.md`: 
- `09_comments.md`: 
- `10_distinct.md`: 
- `11_shadowing.md`: 
- `data_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\language_concepts\data_types`
- `00_fields.md`: 
- `01_integers.md`: 
- `02_booleans.md`: 
- `03_strings.md`: 
- `04_arrays.md`: 
- `05_slices.mdx`: 
- `06_vectors.mdx`: 
- `07_tuples.md`: 
- `08_structs.md`: 
- `09_references.md`: 
- `10_function_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\modules_packages_crates`
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\nargo`
- `01_commands.md`: 
- `02_testing.md`: 
- `03_solidity_verifier.md`: 
- `04_language_server.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\getting_started`
- `01_tiny_noir_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js`
- `noir_js.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference`
- `01_noirjs.md`: 
- `02_bb_backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\noir_js\reference\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\standard_library`
- `black_box_fns.md`: 
- `cryptographic_primitives.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.0\standard_library\cryptographic_primitives`
- `00_hashes.mdx`: 
- `01_scalar.mdx`: 
- `02_schnorr.mdx`: 
- `03_ecdsa_sig_verification.mdx`: 
- `04_ec_primitives.md`: 
- `05_eddsa.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\examples`
- `merkle-proof.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\getting_started`
- `00_nargo_installation.md`: 
- `01_hello_world.md`: 
- `02_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1`
- `index.md`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\language_concepts`
- `01_functions.md`: 
- `02_control_flow.md`: 
- `03_ops.md`: 
- `04_assert.md`: 
- `05_unconstrained.md`: 
- `06_generics.md`: 
- `07_mutability.md`: 
- `08_lambdas.md`: 
- `09_comments.md`: 
- `10_distinct.md`: 
- `11_shadowing.md`: 
- `data_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\language_concepts\data_types`
- `00_fields.md`: 
- `01_integers.md`: 
- `02_booleans.md`: 
- `03_strings.md`: 
- `04_arrays.md`: 
- `05_slices.mdx`: 
- `06_vectors.mdx`: 
- `07_tuples.md`: 
- `08_structs.md`: 
- `09_references.md`: 
- `10_function_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\modules_packages_crates`
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\nargo`
- `01_commands.md`: 
- `02_testing.md`: 
- `03_solidity_verifier.md`: 
- `04_language_server.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\getting_started`
- `01_tiny_noir_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js`
- `noir_js.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\reference\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\reference\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\reference\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\reference\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\reference\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\reference\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\reference\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\noir_js\reference\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\standard_library`
- `black_box_fns.md`: 
- `cryptographic_primitives.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.1\standard_library\cryptographic_primitives`
- `00_hashes.mdx`: 
- `01_scalar.mdx`: 
- `02_schnorr.mdx`: 
- `03_ecdsa_sig_verification.mdx`: 
- `04_ec_primitives.md`: 
- `05_eddsa.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\examples`
- `merkle-proof.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\getting_started`
- `00_nargo_installation.md`: 
- `01_hello_world.md`: 
- `02_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2`
- `index.md`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\language_concepts`
- `01_functions.md`: 
- `02_control_flow.md`: 
- `03_ops.md`: 
- `04_assert.md`: 
- `05_unconstrained.md`: 
- `06_generics.md`: 
- `07_mutability.md`: 
- `08_lambdas.md`: 
- `09_comments.md`: 
- `10_distinct.md`: 
- `11_shadowing.md`: 
- `data_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\language_concepts\data_types`
- `00_fields.md`: 
- `01_integers.md`: 
- `02_booleans.md`: 
- `03_strings.md`: 
- `04_arrays.md`: 
- `05_slices.mdx`: 
- `06_vectors.mdx`: 
- `07_tuples.md`: 
- `08_structs.md`: 
- `09_references.md`: 
- `10_function_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\modules_packages_crates`
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\nargo`
- `01_commands.md`: 
- `02_testing.md`: 
- `03_solidity_verifier.md`: 
- `04_language_server.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\getting_started`
- `01_tiny_noir_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js`
- `noir_js.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\reference\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\reference\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\reference\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\reference\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\reference\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\reference\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\reference\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\noir_js\reference\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\standard_library`
- `black_box_fns.md`: 
- `cryptographic_primitives.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.2\standard_library\cryptographic_primitives`
- `00_hashes.mdx`: 
- `01_scalar.mdx`: 
- `02_schnorr.mdx`: 
- `03_ecdsa_sig_verification.mdx`: 
- `04_ec_primitives.md`: 
- `05_eddsa.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\examples`
- `merkle-proof.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\getting_started`
- `00_nargo_installation.md`: 
- `01_hello_world.md`: 
- `02_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3`
- `index.md`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\language_concepts`
- `01_functions.md`: 
- `02_control_flow.md`: 
- `03_ops.md`: 
- `04_assert.md`: 
- `05_unconstrained.md`: 
- `06_generics.md`: 
- `07_mutability.md`: 
- `08_lambdas.md`: 
- `09_comments.md`: 
- `10_distinct.md`: 
- `11_shadowing.md`: 
- `data_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\language_concepts\data_types`
- `00_fields.md`: 
- `01_integers.md`: 
- `02_booleans.md`: 
- `03_strings.md`: 
- `04_arrays.md`: 
- `05_slices.mdx`: 
- `06_vectors.mdx`: 
- `07_tuples.md`: 
- `08_structs.md`: 
- `09_references.md`: 
- `10_function_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\modules_packages_crates`
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\nargo`
- `01_commands.md`: 
- `02_testing.md`: 
- `03_solidity_verifier.md`: 
- `04_language_server.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\getting_started`
- `01_tiny_noir_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js`
- `noir_js.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\reference\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\reference\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\reference\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\reference\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\reference\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\reference\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\reference\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\noir_js\reference\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\standard_library`
- `black_box_fns.md`: 
- `cryptographic_primitives.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.3\standard_library\cryptographic_primitives`
- `00_hashes.mdx`: 
- `01_scalar.mdx`: 
- `02_schnorr.mdx`: 
- `03_ecdsa_sig_verification.mdx`: 
- `04_ec_primitives.md`: 
- `05_eddsa.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\examples`
- `merkle-proof.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\getting_started`
- `00_nargo_installation.md`: 
- `01_hello_world.md`: 
- `02_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4`
- `index.md`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\language_concepts`
- `01_functions.md`: 
- `02_control_flow.md`: 
- `03_ops.md`: 
- `04_assert.md`: 
- `05_unconstrained.md`: 
- `06_generics.md`: 
- `07_mutability.md`: 
- `08_lambdas.md`: 
- `09_comments.md`: 
- `10_distinct.md`: 
- `11_shadowing.md`: 
- `data_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\language_concepts\data_types`
- `00_fields.md`: 
- `01_integers.md`: 
- `02_booleans.md`: 
- `03_strings.md`: 
- `04_arrays.md`: 
- `05_slices.mdx`: 
- `06_vectors.mdx`: 
- `07_tuples.md`: 
- `08_structs.md`: 
- `09_references.md`: 
- `10_function_types.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\modules_packages_crates`
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\nargo`
- `01_commands.md`: 
- `02_testing.md`: 
- `03_solidity_verifier.md`: 
- `04_language_server.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\getting_started`
- `01_tiny_noir_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js`
- `noir_js.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\reference\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\reference\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\reference\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\reference\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\reference\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\reference\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\reference\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\noir_js\reference\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `InputMap.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\standard_library`
- `black_box_fns.md`: 
- `cryptographic_primitives.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.19.4\standard_library\cryptographic_primitives`
- `00_hashes.mdx`: 
- `01_scalar.mdx`: 
- `02_schnorr.mdx`: 
- `03_ecdsa_sig_verification.mdx`: 
- `04_ec_primitives.md`: 
- `05_eddsa.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\explainers`
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\explanations\noir`
- `traits.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\explanations\standard_library`
- `traits.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\getting_started`
- `_category_.json`: 
- `create_a_project.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\getting_started\tooling`
- `_category_.json`: 
- `index.md`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\how_to`
- `_category_.json`: 
- `how-to-recursion.md`: 
- `merkle-proof.mdx`: 
- `solidity_verifier.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0`
- `index.md`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\noir\standard_library`
- `_category_.json`: 
- `black_box_fns.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `scalar.mdx`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\noir\syntax`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `distinct.md`: 
- `functions.md`: 
- `generics.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `shadowing.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\noir\syntax\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 
- `vectors.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference\NoirJS\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference\NoirJS\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `InputMap.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.22.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\getting_started\tooling`
- `_category_.json`: 
- `index.mdx`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `distinct.md`: 
- `functions.md`: 
- `generics.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 
- `vectors.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir\standard_library`
- `_category_.json`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `scalar.mdx`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir_js\reference\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir_js\reference\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir_js\reference\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir_js\reference\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir_js\reference\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir_js\reference\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir_js\reference\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\noir_js\reference\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `InputMap.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `InputMap.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference\NoirJS\noir_wasm\type-aliases`
- `CompilationResult.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.23.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\getting_started\tooling`
- `_category_.json`: 
- `index.mdx`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `distinct.md`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 
- `vectors.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\noir\standard_library`
- `_category_.json`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `scalar.mdx`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.24.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\getting_started\tooling`
- `_category_.json`: 
- `index.mdx`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `distinct.md`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\noir\standard_library`
- `_category_.json`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `scalar.mdx`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\backend_barretenberg\interfaces`
- `Backend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 
- `CompiledCircuit.md`: 
- `ProofData.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\noir_js\type-aliases`
- `CompiledCircuit.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `InputMap.md`: 
- `ProofData.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `compile_contract.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.25.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\getting_started\tooling`
- `_category_.json`: 
- `index.mdx`: 
- `language_server.md`: 
- `noir_codegen.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `distinct.md`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\noir\standard_library`
- `_category_.json`: 
- `bigint.md`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `scalar.mdx`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\noir_js\type-aliases`
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `compile_contract.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.26.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\getting_started\tooling`
- `_category_.json`: 
- `index.mdx`: 
- `language_server.md`: 
- `noir_codegen.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `distinct.md`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\noir\standard_library`
- `_category_.json`: 
- `bigint.md`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `scalar.mdx`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\noir_js\type-aliases`
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `compile_contract.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.27.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\getting_started\tooling`
- `noir_codegen.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\how_to\debugger`
- `_category_.json`: 
- `debugging_with_the_repl.md`: 
- `debugging_with_vs_code.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `distinct.md`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\noir\standard_library`
- `_category_.json`: 
- `bigint.md`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `scalar.mdx`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 
- `BarretenbergVerifier.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\noir_js\type-aliases`
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `compile_contract.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\reference\debugger`
- `_category_.json`: 
- `debugger_known_limitations.md`: 
- `debugger_repl.md`: 
- `debugger_vscode.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\tooling`
- `debugger.md`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.28.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\getting_started\tooling`
- `noir_codegen.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\how_to\debugger`
- `_category_.json`: 
- `debugging_with_the_repl.md`: 
- `debugging_with_vs_code.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\noir\standard_library`
- `_category_.json`: 
- `bigint.md`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `scalar.mdx`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 
- `BarretenbergVerifier.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\noir_js\type-aliases`
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `compile_contract.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\reference\debugger`
- `_category_.json`: 
- `debugger_known_limitations.md`: 
- `debugger_repl.md`: 
- `debugger_vscode.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\tooling`
- `debugger.md`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.29.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\getting_started\tooling`
- `noir_codegen.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\how_to\debugger`
- `_category_.json`: 
- `debugging_with_the_repl.md`: 
- `debugging_with_vs_code.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\noir\standard_library`
- `_category_.json`: 
- `bigint.md`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ciphers.mdx`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `embedded_curve_ops.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 
- `BarretenbergVerifier.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\noir_js\type-aliases`
- `ErrorWithPayload.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `compile_contract.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\reference\debugger`
- `_category_.json`: 
- `debugger_known_limitations.md`: 
- `debugger_repl.md`: 
- `debugger_vscode.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\tooling`
- `debugger.md`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.30.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\getting_started\barretenberg`
- `_category_.json`: 
- `index.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\getting_started\tooling`
- `noir_codegen.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\how_to\debugger`
- `_category_.json`: 
- `debugging_with_the_repl.md`: 
- `debugging_with_vs_code.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.md`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.md`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\noir\standard_library`
- `_category_.json`: 
- `bigint.md`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `is_unconstrained.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ciphers.mdx`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `embedded_curve_ops.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 
- `BarretenbergVerifier.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\noir_js\type-aliases`
- `ErrorWithPayload.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `compile_contract.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\reference\debugger`
- `_category_.json`: 
- `debugger_known_limitations.md`: 
- `debugger_repl.md`: 
- `debugger_vscode.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\tooling`
- `debugger.md`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.31.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\explainers`
- `explainer-oracle.md`: 
- `explainer-recursion.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\getting_started`
- `_category_.json`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\getting_started\barretenberg`
- `_category_.json`: 
- `index.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\getting_started\hello_noir`
- `_category_.json`: 
- `index.md`: 
- `project_breakdown.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\getting_started\installation`
- `_category_.json`: 
- `index.md`: 
- `other_install_methods.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\getting_started\tooling`
- `noir_codegen.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\how_to`
- `_category_.json`: 
- `how-to-oracles.md`: 
- `how-to-recursion.md`: 
- `how-to-solidity-verifier.md`: 
- `merkle-proof.mdx`: 
- `using-devcontainers.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\how_to\debugger`
- `_category_.json`: 
- `debugging_with_the_repl.md`: 
- `debugging_with_vs_code.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0`
- `index.mdx`: 
- `migration_notes.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\noir\concepts`
- `_category_.json`: 
- `assert.md`: 
- `comments.md`: 
- `control_flow.md`: 
- `data_bus.mdx`: 
- `functions.md`: 
- `generics.md`: 
- `globals.md`: 
- `lambdas.md`: 
- `mutability.md`: 
- `ops.md`: 
- `oracles.mdx`: 
- `shadowing.md`: 
- `traits.md`: 
- `unconstrained.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\noir\concepts\data_types`
- `_category_.json`: 
- `arrays.md`: 
- `booleans.md`: 
- `fields.md`: 
- `function_types.md`: 
- `index.md`: 
- `integers.md`: 
- `references.md`: 
- `slices.mdx`: 
- `strings.md`: 
- `structs.md`: 
- `tuples.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\noir\modules_packages_crates`
- `_category_.json`: 
- `crates_and_packages.md`: 
- `dependencies.md`: 
- `modules.md`: 
- `workspaces.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\noir\standard_library`
- `_category_.json`: 
- `bigint.md`: 
- `black_box_fns.md`: 
- `bn254.md`: 
- `is_unconstrained.md`: 
- `logging.md`: 
- `merkle_trees.md`: 
- `options.md`: 
- `recursion.md`: 
- `traits.md`: 
- `zeroed.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\noir\standard_library\containers`
- `boundedvec.md`: 
- `hashmap.md`: 
- `index.md`: 
- `vec.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\noir\standard_library\cryptographic_primitives`
- `_category_.json`: 
- `ciphers.mdx`: 
- `ec_primitives.md`: 
- `ecdsa_sig_verification.mdx`: 
- `eddsa.mdx`: 
- `embedded_curve_ops.mdx`: 
- `hashes.mdx`: 
- `index.md`: 
- `schnorr.mdx`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\backend_barretenberg`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\backend_barretenberg\classes`
- `BarretenbergBackend.md`: 
- `BarretenbergVerifier.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\backend_barretenberg\type-aliases`
- `BackendOptions.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\noir_js`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\noir_js\classes`
- `Noir.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\noir_js\functions`
- `and.md`: 
- `blake2s256.md`: 
- `ecdsa_secp256k1_verify.md`: 
- `ecdsa_secp256r1_verify.md`: 
- `keccak256.md`: 
- `sha256.md`: 
- `xor.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\noir_js\type-aliases`
- `ErrorWithPayload.md`: 
- `ForeignCallHandler.md`: 
- `ForeignCallInput.md`: 
- `ForeignCallOutput.md`: 
- `WitnessMap.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\noir_wasm`
- `.nojekyll`: 
- `index.md`: 
- `typedoc-sidebar.cjs`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\NoirJS\noir_wasm\functions`
- `compile.md`: 
- `compile_contract.md`: 
- `createFileManager.md`: 
- `inflateDebugSymbols.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference`
- `_category_.json`: 
- `nargo_commands.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\reference\debugger`
- `_category_.json`: 
- `debugger_known_limitations.md`: 
- `debugger_repl.md`: 
- `debugger_vscode.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\tooling`
- `debugger.md`: 
- `language_server.md`: 
- `testing.md`: 

### `scripts\noir_src\docs\versioned_docs\version-v0.32.0\tutorials`
- `noirjs_app.md`: 

### `scripts\noir_src\docs\versioned_sidebars`
- `version-v0.17.0-sidebars.json`: 
- `version-v0.19.0-sidebars.json`: 
- `version-v0.19.1-sidebars.json`: 
- `version-v0.19.2-sidebars.json`: 
- `version-v0.19.3-sidebars.json`: 
- `version-v0.19.4-sidebars.json`: 
- `version-v0.22.0-sidebars.json`: 
- `version-v0.23.0-sidebars.json`: 
- `version-v0.24.0-sidebars.json`: 
- `version-v0.25.0-sidebars.json`: 
- `version-v0.26.0-sidebars.json`: 
- `version-v0.27.0-sidebars.json`: 
- `version-v0.28.0-sidebars.json`: 
- `version-v0.29.0-sidebars.json`: 
- `version-v0.30.0-sidebars.json`: 
- `version-v0.31.0-sidebars.json`: 
- `version-v0.32.0-sidebars.json`: 

### `scripts\noir_src\examples`
- `.gitignore`: 

### `scripts\noir_src\examples\codegen_verifier`
- `.gitignore`: 
- `Nargo.toml`: 
- `Prover.toml`: 
- `codegen_verifier.sh`: 
- `foundry.toml`: 
- `test.sh`: 

### `scripts\noir_src\examples\codegen_verifier\src`
- `main.nr`: 

### `scripts\noir_src\examples\prove_and_verify`
- `Nargo.toml`: 
- `Prover.toml`: 
- `prove_and_verify.sh`: 
- `test.sh`: 

### `scripts\noir_src\examples\prove_and_verify\src`
- `main.nr`: 

### `scripts\noir_src\examples\recursion`
- `.gitignore`: 
- `Nargo.toml`: 
- `generate_recursive_proof.sh`: 
- `test.sh`: 

### `scripts\noir_src\examples\recursion\recurse_leaf`
- `Nargo.toml`: 

### `scripts\noir_src\examples\recursion\recurse_leaf\src`
- `main.nr`: 

### `scripts\noir_src\examples\recursion\recurse_node`
- `Nargo.toml`: 

### `scripts\noir_src\examples\recursion\recurse_node\src`
- `main.nr`: 

### `scripts\noir_src\examples\recursion\sum`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\examples\recursion\sum\src`
- `main.nr`: 

### `scripts\noir_src\noir_stdlib`
- `Nargo.toml`: 

### `scripts\noir_src\noir_stdlib\src`
- `aes128.nr`: 
- `append.nr`: 
- `array.nr`: 
- `bigint.nr`: 
- `cmp.nr`: 
- `compat.nr`: 
- `convert.nr`: 
- `default.nr`: 
- `ecdsa_secp256k1.nr`: 
- `ecdsa_secp256r1.nr`: 
- `eddsa.nr`: 
- `embedded_curve_ops.nr`: 
- `lib.nr`: 
- `merkle.nr`: 
- `option.nr`: 
- `prelude.nr`: 
- `runtime.nr`: 
- `schnorr.nr`: 
- `sha256.nr`: 
- `sha512.nr`: 
- `slice.nr`: 
- `string.nr`: 
- `test.nr`: 
- `uint128.nr`: 
- `unsafe.nr`: 

### `scripts\noir_src\noir_stdlib\src\collections`
- `bounded_vec.nr`: 
- `map.nr`: 
- `mod.nr`: 
- `vec.nr`: 

### `scripts\noir_src\noir_stdlib\src\ec\consts`
- `mod.nr`: 
- `te.nr`: 

### `scripts\noir_src\noir_stdlib\src\ec`
- `mod.nr`: 
- `montcurve.nr`: 
- `swcurve.nr`: 
- `tecurve.nr`: 

### `scripts\noir_src\noir_stdlib\src\field`
- `bn254.nr`: 
- `mod.nr`: 

### `scripts\noir_src\noir_stdlib\src\hash`
- `keccak.nr`: 
- `mimc.nr`: 
- `mod.nr`: 
- `poseidon2.nr`: 

### `scripts\noir_src\noir_stdlib\src\hash\poseidon`
- `bn254.nr`: 
- `mod.nr`: 

### `scripts\noir_src\noir_stdlib\src\hash\poseidon\bn254`
- `consts.nr`: 
- `perm.nr`: 

### `scripts\noir_src\noir_stdlib\src\meta`
- `mod.nr`: 
- `quoted.nr`: 
- `trait_constraint.nr`: 
- `type_def.nr`: 

### `scripts\noir_src\noir_stdlib\src\ops`
- `arith.nr`: 
- `bit.nr`: 
- `mod.nr`: 

### `scripts\noir_src\scripts`
- `benchmark_start.sh`: 
- `benchmark_stop.sh`: 
- `bump-bb.sh`: 
- `count_loc.sh`: 
- `install_bb.sh`: 
- `redo-typo-pr.sh`: 
- `update-acvm-workspace-versions.sh`: 

### `scripts\noir_src\security\insectarium`
- `noir_stdlib.md`: 

### `scripts\noir_src\test_programs`
- `.gitignore`: 
- `README.md`: 
- `format.sh`: 
- `gates_report.sh`: 
- `rebuild.sh`: 

### `scripts\noir_src\test_programs\benchmarks\bench_eddsa_poseidon`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_eddsa_poseidon\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon2_hash`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon2_hash\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon2_hash_100`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon2_hash_100\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon2_hash_30`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon2_hash_30\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash\bench_poseidon_hash_100`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash\bench_poseidon_hash_100\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash\bench_poseidon_hash_30`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash\bench_poseidon_hash_30\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash_100`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash_100\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash_30`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_poseidon_hash_30\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_sha256`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_sha256\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_sha256_100`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_sha256_100\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\benchmarks\bench_sha256_30`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\benchmarks\bench_sha256_30\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\array_length_defaulting`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\array_length_defaulting\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_array`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_array\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_plus`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_plus\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_slice`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_slice\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_struct_array`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_struct_array\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_struct_field`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_struct_field\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_struct_slice`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_struct_slice\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_tuple`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_dynamic_tuple\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_fail`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_fail\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_false`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_constant_false\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\assert_eq_struct`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\assert_eq_struct\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\brillig_mut_ref_from_acir`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\brillig_mut_ref_from_acir\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\brillig_nested_slices`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\brillig_nested_slices\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\brillig_slice_to_acir`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\brillig_slice_to_acir\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\brillig_vec_to_acir`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\brillig_vec_to_acir\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\builtin_function_declaration`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\builtin_function_declaration\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\comptime_var_not_defined`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\comptime_var_not_defined\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\constrain_typo`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\constrain_typo\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\custom_entry_not_found`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\custom_entry_not_found\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\cyclic_dep`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\cyclic_dep\dep1`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\cyclic_dep\dep1\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_failure\cyclic_dep\dep2`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\cyclic_dep\dep2\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_failure\cyclic_dep\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dep_impl_primitive`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dep_impl_primitive\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dep_submodule_overlap`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dep_submodule_overlap\src`
- `lib.nr`: 
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\depend_on_bin`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\depend_on_bin\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_implementation_4`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_implementation_4\src`
- `main.nr`: 
- `module1.nr`: 
- `module2.nr`: 
- `module3.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_implementation_5`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_implementation_5\src`
- `main.nr`: 
- `module1.nr`: 
- `module2.nr`: 
- `module3.nr`: 
- `module4.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_1`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_1\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_2`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_2\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_3`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_3\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_4`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_4\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_5`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_5\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_6`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\dup_trait_items_6\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\duplicate_declaration`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\duplicate_declaration\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\field_modulo`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\field_modulo\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\foreign_function_declaration`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\foreign_function_declaration\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\integer_too_large`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\integer_too_large\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\invalid_dependency_name`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\invalid_dependency_name\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\invalid_main_sub_lib`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\invalid_main_sub_lib\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\invalid_main_sub_lib\src\main`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_failure\invalid_mod_mod_path`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\invalid_mod_mod_path\main`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_failure\invalid_mod_mod_path\src`
- `main.nr`: 
- `mod.nr`: 

### `scripts\noir_src\test_programs\compile_failure\multiple_primary_attributes_fail`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\multiple_primary_attributes_fail\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\mutability_regression_2911`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\mutability_regression_2911\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\negate_unsigned`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\negate_unsigned\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\nested_slice_declared_type`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\nested_slice_declared_type\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\nested_slice_literal`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\nested_slice_literal\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\nested_slice_struct`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\nested_slice_struct\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\no_impl_from_function`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\no_impl_from_function\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\no_nested_impl`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\no_nested_impl\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\non_comptime_local_fn_call`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\non_comptime_local_fn_call\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\option_expect_bad_input`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\option_expect_bad_input\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\orphaned_trait_impl`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\orphaned_trait_impl\crate1`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\orphaned_trait_impl\crate1\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_failure\orphaned_trait_impl\crate2`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\orphaned_trait_impl\crate2\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_failure\orphaned_trait_impl\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_dep_and_mod`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_dep_and_mod\bin`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_dep_and_mod\bin\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_dep_and_mod\foo`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_dep_and_mod\foo\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_generic_impls`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_generic_impls\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_mod`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_mod\src`
- `foo.nr`: 
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\overlapping_mod\src\foo`
- `mod.nr`: 

### `scripts\noir_src\test_programs\compile_failure\package_name_empty`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\package_name_empty\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\package_name_hyphen`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\package_name_hyphen\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\primary_attribute_struct`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\primary_attribute_struct\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\radix_non_constant_length`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\radix_non_constant_length\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\raw_string_huge`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\raw_string_huge\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\regression_5008`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\regression_5008\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\regression_5065_failure`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\regression_5065_failure\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\restricted_bit_sizes`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\restricted_bit_sizes\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\self_referential_struct`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\self_referential_struct\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\signed_integer_literal_overflow`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\signed_integer_literal_overflow\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\signed_integer_literal_underflow`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\signed_integer_literal_underflow\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\static_assert_dynamic_array_len`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\static_assert_dynamic_array_len\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\static_assert_dynamic_slice`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\static_assert_dynamic_slice\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\static_assert_plus`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\static_assert_plus\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\trait_incorrect_generic_count`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\trait_incorrect_generic_count\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\turbofish_generic_count`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\turbofish_generic_count\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\type_definition_annotation`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\type_definition_annotation\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\typevar_default`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\typevar_default\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\unary_not_on_field_type_variable`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\unary_not_on_field_type_variable\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\unconstrained_oracle`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\unconstrained_oracle\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\unconstrained_ref`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\unconstrained_ref\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\unsigned_integer_literal_overflow`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\unsigned_integer_literal_overflow\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\unsigned_integer_literal_underflow`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\unsigned_integer_literal_underflow\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\workspace_missing_toml`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\workspace_missing_toml\crates\a\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_failure\workspace_missing_toml\crates\b`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_failure\workspace_missing_toml\crates\b\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_contract\abi_attribute`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_contract\abi_attribute\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_contract\contract_with_impl`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_contract\contract_with_impl\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_contract\fold_non_contract_method`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_contract\fold_non_contract_method\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_contract\non_entry_point_method`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_contract\non_entry_point_method\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_contract\recursive_method`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_contract\recursive_method\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_contract\simple_contract`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_contract\simple_contract\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\assert_constant`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\assert_constant\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\attribute_args`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\attribute_args\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\attributes_multiple`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\attributes_multiple\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\attributes_struct`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\attributes_struct\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\auto_deref`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\auto_deref\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_cast`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_cast\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_field_binary_operations`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_field_binary_operations\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_integer_binary_operations`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_integer_binary_operations\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_modulo`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_modulo\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_slice_input`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\brillig_slice_input\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\closure_explicit_types`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\closure_explicit_types\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_array_len`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_array_len\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_as_slice`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_as_slice\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_mut_global`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_mut_global\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_recursion_regression`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_recursion_regression\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_slice_methods`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_slice_methods\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_trait_constraint`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_trait_constraint\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_traits`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_traits\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_type_definition`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\comptime_type_definition\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\conditional_regression_579`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\conditional_regression_579\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\conditional_regression_to_bits`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\conditional_regression_to_bits\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\derive_impl`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\derive_impl\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\ec_baby_jubjub`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\ec_baby_jubjub\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\function_attribute`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\function_attribute\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\generators`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\generators\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\higher_order_fn_selector`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\higher_order_fn_selector\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\impl_from_where_impl`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\impl_from_where_impl\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\impl_where_clause`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\impl_where_clause\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\inner_outer_cl`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\inner_outer_cl\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\instruction_deduplication`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\instruction_deduplication\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\intrinsic_die`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\intrinsic_die\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\let_stmt`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\let_stmt\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\literal_not_simplification`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\literal_not_simplification\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\macros`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\macros\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\method_call_regression`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\method_call_regression\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\mod_nr_entrypoint`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\mod_nr_entrypoint\src`
- `baz.nr`: 
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\mod_nr_entrypoint\src\foo`
- `bar.nr`: 
- `mod.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\no_duplicate_methods`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\no_duplicate_methods\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\numeric_generics`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\numeric_generics\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\numeric_generics_explicit`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\numeric_generics_explicit\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\option`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\option\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\overlapping_dep_and_mod`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\overlapping_dep_and_mod\bin`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\overlapping_dep_and_mod\bin\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\overlapping_dep_and_mod\foo`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\overlapping_dep_and_mod\foo\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\raw_string`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\raw_string\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\reexports`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\reexports\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\references_aliasing`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\references_aliasing\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_2099`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_2099\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_3635`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_3635\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_3964`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_3964\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_4383`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_4383\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_4436`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_4436\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_4635`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_4635\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_5065`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_5065\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_5428`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\regression_5428\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\ret_fn_ret_cl`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\ret_fn_ret_cl\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\simple_program_no_body`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\simple_program_no_body\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\simple_range`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\simple_range\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\slice_init_with_complex_type`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\slice_init_with_complex_type\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\slice_join`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\slice_join\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\specialization`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\specialization\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\static_assert`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\static_assert\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\str_as_bytes`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\str_as_bytes\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\to_bits`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\to_bits\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_allowed_item_name_matches`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_allowed_item_name_matches\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_associated_member_names_clashes`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_associated_member_names_clashes\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_attribute`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_attribute\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_default_implementation`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_default_implementation\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_function_calls`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_function_calls\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_generics`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_generics\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_impl_generics`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_impl_generics\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_impl_with_where_clause`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_impl_with_where_clause\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_multi_module_test`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_multi_module_test\src`
- `main.nr`: 
- `module1.nr`: 
- `module2.nr`: 
- `module3.nr`: 
- `module4.nr`: 
- `module5.nr`: 
- `module6.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_override_implementation`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_override_implementation\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_static_methods`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_static_methods\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_where_clause`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\trait_where_clause\src`
- `main.nr`: 
- `the_trait.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\traits`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\traits\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\unary_operators`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\unary_operators\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\unit`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\unit\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\unquote`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\unquote\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\unquote_multiple_items_from_annotation`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\unquote_multiple_items_from_annotation\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\unused_variables`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\unused_variables\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\vectors`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\vectors\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\workspace_reexport_bug`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\workspace_reexport_bug\binary`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\workspace_reexport_bug\binary\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\workspace_reexport_bug\library2`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\workspace_reexport_bug\library2\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_success_empty\workspace_reexport_bug\library`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_empty\workspace_reexport_bug\library\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\compile_success_no_bug\check_uncostrained_regression`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\compile_success_no_bug\check_uncostrained_regression\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\assert_msg_runtime`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\assert_msg_runtime\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\brillig_assert_fail`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\brillig_assert_fail\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\brillig_assert_msg_runtime`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\brillig_assert_msg_runtime\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\div_by_zero_constants`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\div_by_zero_constants\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\div_by_zero_modulo`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\div_by_zero_modulo\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\div_by_zero_numerator_witness`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\div_by_zero_numerator_witness\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\div_by_zero_witness`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\div_by_zero_witness\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\dyn_index_fail_nested_array`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\dyn_index_fail_nested_array\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\dynamic_index_failure`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\dynamic_index_failure\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\fold_dyn_index_fail`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\fold_dyn_index_fail\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\fold_nested_brillig_assert_fail`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\fold_nested_brillig_assert_fail\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\hashmap_load_factor`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\hashmap_load_factor\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\option_expect`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_failure\option_expect\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\regression_5202`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_failure\regression_5202\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\slice_access_failure`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\slice_access_failure\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\slice_insert_failure`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\slice_insert_failure\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\slice_remove_failure`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\slice_remove_failure\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\workspace_fail`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_failure\workspace_fail\crates\a`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\workspace_fail\crates\a\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_failure\workspace_fail\crates\b`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_failure\workspace_fail\crates\b\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\1327_concrete_in_generic`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\1327_concrete_in_generic\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\1_mul`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\1_mul\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\2_div`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\2_div\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\3_add`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\3_add\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\4_sub`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\4_sub\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\5_over`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\5_over\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\6`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\6\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\6_array`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\6_array\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\7`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\7\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\7_function`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\7_function\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\acir_inside_brillig_recursion`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\acir_inside_brillig_recursion\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\aes128_encrypt`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\aes128_encrypt\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\arithmetic_binary_operations`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\arithmetic_binary_operations\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_dynamic`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_dynamic\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_dynamic_blackbox_input`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_dynamic_blackbox_input\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_dynamic_main_output`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_dynamic_main_output\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_dynamic_nested_blackbox_input`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_dynamic_nested_blackbox_input\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_eq`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_eq\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_if_cond_simple`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_if_cond_simple\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_len`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_len\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_neq`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_neq\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_sort`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_sort\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_to_slice`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_to_slice\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\array_to_slice_constant_length`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\array_to_slice_constant_length\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\as_witness`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\as_witness\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\assert`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\assert\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\assert_statement`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\assert_statement\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\assert_statement_recursive`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\assert_statement_recursive\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\assign_ex`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\assign_ex\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\bench_ecdsa_secp256k1`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\bench_ecdsa_secp256k1\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\bigint`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\bigint\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\binary_operator_overloading`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\binary_operator_overloading\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\bit_and`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\bit_and\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\bit_not`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\bit_not\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\bit_shifts_comptime`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\bit_shifts_comptime\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\bit_shifts_runtime`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\bit_shifts_runtime\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\blake3`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\blake3\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\bool_not`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\bool_not\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\bool_or`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\bool_or\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\break_and_continue`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\break_and_continue\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_acir_as_brillig`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_acir_as_brillig\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_array_to_slice`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_array_to_slice\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_arrays`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_arrays\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_assert`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_assert\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_blake2s`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_blake2s\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_blake3`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_blake3\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_block_parameter_liveness`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_block_parameter_liveness\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_calls`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_calls\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_calls_array`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_calls_array\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_calls_conditionals`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_calls_conditionals\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_conditional`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_conditional\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_cow`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_cow\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_cow_assign`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_cow_assign\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_cow_regression`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_cow_regression\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_ecdsa_secp256k1`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_ecdsa_secp256k1\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_ecdsa_secp256r1`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_ecdsa_secp256r1\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_fns_as_values`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_fns_as_values\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_hash_to_field`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_hash_to_field\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_identity_function`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_identity_function\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_keccak`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_keccak\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_loop`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_loop\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_nested_arrays`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_nested_arrays\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_not`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_not\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_oracle`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_oracle\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_pedersen`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_pedersen\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_recursion`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_recursion\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_references`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_references\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_sha256`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_sha256\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_slices`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_slices\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\brillig_unitialised_arrays`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\brillig_unitialised_arrays\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\cast_and_shift_global`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\cast_and_shift_global\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\cast_bool`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\cast_bool\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\closures_mut_ref`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\closures_mut_ref\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\comptime_println`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\comptime_println\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\comptime_slice_equality`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\comptime_slice_equality\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\conditional_1`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\conditional_1\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\conditional_2`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\conditional_2\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_421`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_421\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_547`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_547\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_661`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_661\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_short_circuit`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_short_circuit\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_underflow`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\conditional_regression_underflow\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\custom_entry`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\custom_entry\src`
- `foobarbaz.nr`: 

### `scripts\noir_src\test_programs\execution_success\databus`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\databus\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\debug_logs`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\debug_logs\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\diamond_deps_0`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\diamond_deps_0\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\double_verify_nested_proof`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\double_verify_nested_proof\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\double_verify_proof`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\double_verify_proof\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\double_verify_proof_recursive`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\double_verify_proof_recursive\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\ecdsa_secp256k1`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\ecdsa_secp256k1\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\ecdsa_secp256r1`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\ecdsa_secp256r1\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\ecdsa_secp256r1_3x`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\ecdsa_secp256r1_3x\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\eddsa`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\eddsa\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\embedded_curve_ops`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\embedded_curve_ops\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\empty`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\empty\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\field_attribute`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\field_attribute\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\fold_after_inlined_calls`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\fold_after_inlined_calls\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\fold_basic`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\fold_basic\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\fold_basic_nested_call`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\fold_basic_nested_call\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\fold_call_witness_condition`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\fold_call_witness_condition\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\fold_complex_outputs`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\fold_complex_outputs\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\fold_distinct_return`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\fold_distinct_return\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\fold_fibonacci`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\fold_fibonacci\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\fold_numeric_generic_poseidon`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\fold_numeric_generic_poseidon\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\generics`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\generics\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\global_consts`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\global_consts\src`
- `baz.nr`: 
- `foo.nr`: 
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\global_consts\src\foo`
- `bar.nr`: 

### `scripts\noir_src\test_programs\execution_success\hash_to_field`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\hash_to_field\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\hashmap`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\hashmap\src`
- `main.nr`: 
- `utils.nr`: 

### `scripts\noir_src\test_programs\execution_success\higher_order_functions`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\higher_order_functions\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\if_else_chain`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\if_else_chain\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\import`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\import\src`
- `import.nr`: 
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\inline_never_basic`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\inline_never_basic\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\integer_array_indexing`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\integer_array_indexing\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\is_unconstrained`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\is_unconstrained\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\keccak256`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\keccak256\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\main_bool_arg`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\main_bool_arg\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\main_return`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\main_return\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\merkle_insert`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\merkle_insert\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\missing_closure_env`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\missing_closure_env\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\modules`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\modules\src`
- `foo.nr`: 
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\modules_more`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\modules_more\src`
- `foo.nr`: 
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\modules_more\src\foo`
- `bar.nr`: 

### `scripts\noir_src\test_programs\execution_success\modulus`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\modulus\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\nested_array_dynamic`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\nested_array_dynamic\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\nested_array_dynamic_simple`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\nested_array_dynamic_simple\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\nested_array_in_slice`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\nested_array_in_slice\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\nested_arrays_from_brillig`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\nested_arrays_from_brillig\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\no_predicates_basic`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\no_predicates_basic\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\no_predicates_brillig`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\no_predicates_brillig\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\no_predicates_numeric_generic_poseidon`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\no_predicates_numeric_generic_poseidon\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\overlapping_dep_and_mod`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\overlapping_dep_and_mod\bin`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\overlapping_dep_and_mod\bin\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\overlapping_dep_and_mod\foo`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\overlapping_dep_and_mod\foo\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\execution_success\pedersen_check`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\pedersen_check\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\pedersen_commitment`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\pedersen_commitment\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\pedersen_hash`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\pedersen_hash\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\poseidon2`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\poseidon2\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\poseidon_bn254_hash`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\poseidon_bn254_hash\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\poseidon_bn254_hash_width_3`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\poseidon_bn254_hash_width_3\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\poseidonsponge_x5_254`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\poseidonsponge_x5_254\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\pred_eq`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\pred_eq\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\prelude`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\prelude\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\references`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\references\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_2660`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_2660\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_3051`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_3051\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_3394`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_3394\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_3607`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_3607\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_3889`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_3889\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_4088`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_4088\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_4124`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_4124\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_4202`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_4202\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_4449`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_4449\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_4709`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_4709\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_5045`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_5045\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_5252`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_5252\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_5435`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_5435\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_capacity_tracker`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_capacity_tracker\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_mem_op_predicate`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_mem_op_predicate\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_method_cannot_be_found`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_method_cannot_be_found\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\regression_struct_array_conditional`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\regression_struct_array_conditional\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\schnorr`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\schnorr\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\sha256`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\sha256\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\sha2_byte`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\sha2_byte\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\side_effects_constrain_array`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\side_effects_constrain_array\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\signed_arithmetic`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\signed_arithmetic\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\signed_cmp`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\signed_cmp\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\signed_comparison`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\signed_comparison\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\signed_div`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\signed_div\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\signed_division`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\signed_division\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_2d_array`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_2d_array\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_add_and_ret_arr`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_add_and_ret_arr\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_array_param`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_array_param\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_bitwise`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_bitwise\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_comparison`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_comparison\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_mut`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_mut\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_not`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_not\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_print`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_print\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_program_addition`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_program_addition\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_radix`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_radix\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_shield`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_shield\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\simple_shift_left_right`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\simple_shift_left_right\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\slice_coercion`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\slice_coercion\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\slice_dynamic_index`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\slice_dynamic_index\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\slice_loop`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\slice_loop\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\slices`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\slices\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\strings`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\strings\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\struct`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\struct\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\struct_array_inputs`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\struct_array_inputs\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\struct_fields_ordering`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\struct_fields_ordering\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\struct_inputs`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\struct_inputs\src`
- `foo.nr`: 
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\struct_inputs\src\foo`
- `bar.nr`: 

### `scripts\noir_src\test_programs\execution_success\submodules`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\submodules\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\to_be_bytes`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\to_be_bytes\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\to_bits`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\to_bits\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\to_bytes_consistent`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\to_bytes_consistent\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\to_bytes_integration`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\to_bytes_integration\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\to_le_bytes`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\to_le_bytes\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\trait_as_return_type`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\trait_as_return_type\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\trait_impl_base_type`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\trait_impl_base_type\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\trait_method_mut_self`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\trait_method_mut_self\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_1`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_1\crate1`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_1\crate1\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_1\crate2`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_1\crate2\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_1\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_2`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_2\crate1`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_2\crate1\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_2\crate2`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_2\crate2\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\execution_success\traits_in_crates_2\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\tuple_inputs`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\tuple_inputs\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\tuples`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\tuples\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\turbofish_call_func_diff_types`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\turbofish_call_func_diff_types\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\type_aliases`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\type_aliases\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\u128`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\u128\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\u16_support`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\u16_support\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\unary_operator_overloading`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\unary_operator_overloading\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\unit_value`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\unit_value\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\unsafe_range_constraint`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\unsafe_range_constraint\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\wildcard_type`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\wildcard_type\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\witness_compression`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\witness_compression\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\workspace`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\execution_success\workspace\crates\a`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\workspace\crates\a\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\workspace\crates\b`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\workspace\crates\b\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\workspace_default_member`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\workspace_default_member\a`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\workspace_default_member\a\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\workspace_default_member\b`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\workspace_default_member\b\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\wrapping_operations`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\wrapping_operations\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\execution_success\xor`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\execution_success\xor\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_failure\should_fail_mismatch`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\noir_test_failure\should_fail_mismatch\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_failure\should_fail_suite_with_one_failure`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\noir_test_failure\should_fail_suite_with_one_failure\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\bounded_vec`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\bounded_vec\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\brillig_overflow_checks`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\brillig_overflow_checks\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\comptime_globals`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\comptime_globals\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\embedded_curve_ops`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\embedded_curve_ops\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\field_comparisons`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\field_comparisons\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\fuzzer_checks`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\fuzzer_checks\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\ignored_oracle`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\ignored_oracle\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\mock_oracle`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\mock_oracle\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\out_of_bounds_alignment`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\out_of_bounds_alignment\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\regression_4080`
- `Nargo.toml`: 
- `Prover.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\regression_4080\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\regression_4561`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\regression_4561\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\noir_test_success\should_fail_with_matches`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\noir_test_success\should_fail_with_matches\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\test_libraries\bad_impl`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\test_libraries\bad_impl\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\test_libraries\bad_name`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\test_libraries\bad_name\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\test_libraries\bin_dep`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\test_libraries\bin_dep\src`
- `main.nr`: 

### `scripts\noir_src\test_programs\test_libraries\diamond_deps_1`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\test_libraries\diamond_deps_1\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\test_libraries\diamond_deps_2`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\test_libraries\diamond_deps_2\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\test_libraries\exporting_lib`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\test_libraries\exporting_lib\src`
- `lib.nr`: 

### `scripts\noir_src\test_programs\test_libraries\reexporting_lib`
- `Nargo.toml`: 

### `scripts\noir_src\test_programs\test_libraries\reexporting_lib\src`
- `lib.nr`: 

### `scripts\noir_src\tooling\acvm_cli`
- `Cargo.toml`: 

### `scripts\noir_src\tooling\acvm_cli\src\cli`
- `execute_cmd.rs`: 
- `mod.rs`: 

### `scripts\noir_src\tooling\acvm_cli\src\cli\fs`
- `inputs.rs`: 
- `mod.rs`: 
- `witness.rs`: 

### `scripts\noir_src\tooling\acvm_cli\src`
- `errors.rs`: 
- `main.rs`: 

### `scripts\noir_src\tooling\debugger`
- `Cargo.toml`: 
- `README.md`: 
- `build.rs`: 
- `ignored-tests.txt`: 

### `scripts\noir_src\tooling\debugger\src`
- `context.rs`: 
- `dap.rs`: 
- `errors.rs`: 
- `foreign_calls.rs`: 
- `lib.rs`: 
- `repl.rs`: 
- `source_code_printer.rs`: 

### `scripts\noir_src\tooling\debugger\tests`
- `debug.rs`: 

### `scripts\noir_src\tooling\fuzzer`
- `Cargo.toml`: 

### `scripts\noir_src\tooling\fuzzer\src\dictionary`
- `mod.rs`: 

### `scripts\noir_src\tooling\fuzzer\src`
- `lib.rs`: 
- `types.rs`: 

### `scripts\noir_src\tooling\fuzzer\src\strategies`
- `int.rs`: 
- `mod.rs`: 
- `uint.rs`: 

### `scripts\noir_src\tooling\lsp`
- `Cargo.toml`: 

### `scripts\noir_src\tooling\lsp\src`
- `lib.rs`: 
- `solver.rs`: 
- `test_utils.rs`: 
- `types.rs`: 

### `scripts\noir_src\tooling\lsp\src\notifications`
- `mod.rs`: 

### `scripts\noir_src\tooling\lsp\src\requests`
- `code_lens_request.rs`: 
- `document_symbol.rs`: 
- `goto_declaration.rs`: 
- `goto_definition.rs`: 
- `hover.rs`: 
- `inlay_hint.rs`: 
- `mod.rs`: 
- `profile_run.rs`: 
- `references.rs`: 
- `rename.rs`: 
- `test_run.rs`: 
- `tests.rs`: 

### `scripts\noir_src\tooling\lsp\test_programs\document_symbol`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\document_symbol\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\go_to_definition`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\go_to_definition\src`
- `bar.nr`: 
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\inlay_hints`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\inlay_hints\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\local_variable`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\local_variable\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_function`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_function\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_function_use`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_function_use\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_global`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_global\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_qualified`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_qualified\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_qualified_function`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_qualified_function\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_struct`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_struct\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_trait`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_trait\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_type_alias`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\rename_type_alias\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\struct_member`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\struct_member\src`
- `main.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\workspace`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\workspace\one`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\workspace\one\src`
- `lib.nr`: 

### `scripts\noir_src\tooling\lsp\test_programs\workspace\two`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\lsp\test_programs\workspace\two\src`
- `lib.nr`: 
- `other.nr`: 

### `scripts\noir_src\tooling\nargo`
- `Cargo.toml`: 

### `scripts\noir_src\tooling\nargo\src`
- `constants.rs`: 
- `errors.rs`: 
- `lib.rs`: 
- `package.rs`: 
- `workspace.rs`: 

### `scripts\noir_src\tooling\nargo\src\ops`
- `compile.rs`: 
- `execute.rs`: 
- `foreign_calls.rs`: 
- `mod.rs`: 
- `optimize.rs`: 
- `test.rs`: 
- `transform.rs`: 

### `scripts\noir_src\tooling\nargo_cli`
- `Cargo.toml`: 
- `build.rs`: 

### `scripts\noir_src\tooling\nargo_cli\benches`
- `criterion.rs`: 
- `iai.rs`: 
- `utils.rs`: 

### `scripts\noir_src\tooling\nargo_cli\src\cli`
- `check_cmd.rs`: 
- `compile_cmd.rs`: 
- `dap_cmd.rs`: 
- `debug_cmd.rs`: 
- `execute_cmd.rs`: 
- `export_cmd.rs`: 
- `fmt_cmd.rs`: 
- `info_cmd.rs`: 
- `init_cmd.rs`: 
- `lsp_cmd.rs`: 
- `mod.rs`: 
- `new_cmd.rs`: 
- `test_cmd.rs`: 

### `scripts\noir_src\tooling\nargo_cli\src\cli\fs`
- `inputs.rs`: 
- `mod.rs`: 
- `program.rs`: 
- `witness.rs`: 

### `scripts\noir_src\tooling\nargo_cli\src\cli\noir_template_files`
- `binary.nr`: 
- `contract.nr`: 
- `library.nr`: 

### `scripts\noir_src\tooling\nargo_cli\src`
- `errors.rs`: 
- `main.rs`: 

### `scripts\noir_src\tooling\nargo_cli\tests`
- `execute.rs`: 
- `hello_world.rs`: 
- `stdlib-tests.rs`: 

### `scripts\noir_src\tooling\nargo_fmt`
- `Cargo.toml`: 
- `build.rs`: 

### `scripts\noir_src\tooling\nargo_fmt\src`
- `config.rs`: 
- `errors.rs`: 
- `items.rs`: 
- `lib.rs`: 
- `rewrite.rs`: 
- `utils.rs`: 
- `visitor.rs`: 

### `scripts\noir_src\tooling\nargo_fmt\src\rewrite`
- `array.rs`: 
- `expr.rs`: 
- `imports.rs`: 
- `infix.rs`: 
- `parenthesized.rs`: 
- `typ.rs`: 

### `scripts\noir_src\tooling\nargo_fmt\src\visitor`
- `expr.rs`: 
- `item.rs`: 
- `stmt.rs`: 

### `scripts\noir_src\tooling\nargo_fmt\tests`
- `execute.rs`: 

### `scripts\noir_src\tooling\nargo_fmt\tests\expected`
- `add.nr`: 
- `array.nr`: 
- `assert.nr`: 
- `call.nr`: 
- `cast.nr`: 
- `comment.nr`: 
- `contract.nr`: 
- `databus.nr`: 
- `empty.nr`: 
- `expr.nr`: 
- `fn.nr`: 
- `for.nr`: 
- `global.nr`: 
- `if.nr`: 
- `ignore.nr`: 
- `impl.nr`: 
- `impl_trait_fn_parameter.nr`: 
- `import_braces.nr`: 
- `index.nr`: 
- `infix.nr`: 
- `let.nr`: 
- `literals.nr`: 
- `member_access.nr`: 
- `method_call.nr`: 
- `module.nr`: 
- `nested_if_else.nr`: 
- `nested_parens.nr`: 
- `parens.nr`: 
- `print.nr`: 
- `print2.nr`: 
- `read_array.nr`: 
- `single_fn.nr`: 
- `single_mod.nr`: 
- `singleton_import.nr`: 
- `struct.nr`: 
- `submodule.nr`: 
- `tuple.nr`: 
- `turbofish_call.nr`: 
- `turbofish_method_call.nr`: 
- `unary_operators.nr`: 
- `use_super.nr`: 
- `vec.nr`: 

### `scripts\noir_src\tooling\nargo_fmt\tests\input`
- `add.nr`: 
- `array.nr`: 
- `assert.nr`: 
- `call.nr`: 
- `cast.nr`: 
- `comment.nr`: 
- `contract.nr`: 
- `databus.nr`: 
- `empty.nr`: 
- `expr.nr`: 
- `fn.nr`: 
- `for.nr`: 
- `global.nr`: 
- `if.nr`: 
- `ignore.nr`: 
- `impl.nr`: 
- `impl_trait_fn_parameter.nr`: 
- `import_braces.nr`: 
- `index.nr`: 
- `infix.nr`: 
- `let.nr`: 
- `literals.nr`: 
- `member_access.nr`: 
- `method_call.nr`: 
- `module.nr`: 
- `nested_if_else.nr`: 
- `nested_parens.nr`: 
- `parens.nr`: 
- `print.nr`: 
- `print2.nr`: 
- `read_array.nr`: 
- `single_fn.nr`: 
- `single_mod.nr`: 
- `singleton_import.nr`: 
- `struct.nr`: 
- `submodule.nr`: 
- `tuple.nr`: 
- `turbofish_call.nr`: 
- `turbofish_method_call.nr`: 
- `unary_operators.nr`: 
- `use_super.nr`: 
- `vec.nr`: 

### `scripts\noir_src\tooling\nargo_toml`
- `Cargo.toml`: 

### `scripts\noir_src\tooling\nargo_toml\src`
- `errors.rs`: 
- `git.rs`: 
- `lib.rs`: 
- `semver.rs`: 

### `scripts\noir_src\tooling\noir_codegen`
- `.eslintignore`: 
- `.eslintrc.cjs`: 
- `.gitignore`: 
- `.mocharc.json`: 
- `README.md`: 
- `package.json`: 
- `tsconfig.json`: 

### `scripts\noir_src\tooling\noir_codegen\src`
- `index.ts`: 
- `main.ts`: 
- `parseArgs.ts`: 

### `scripts\noir_src\tooling\noir_codegen\src\utils`
- `abi_type_with_generics.ts`: 
- `demonomorphizer.ts`: 
- `glob.ts`: 
- `typings_generator.ts`: 

### `scripts\noir_src\tooling\noir_codegen\test`
- `index.test.ts`: 

### `scripts\noir_src\tooling\noir_codegen\test\test_lib`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\noir_codegen\test\test_lib\src`
- `lib.nr`: 

### `scripts\noir_src\tooling\noir_js`
- `.eslintignore`: 
- `.eslintrc.cjs`: 
- `.gitignore`: 
- `.mocharc.cjs.json`: 
- `.mocharc.json`: 
- `package.json`: 
- `tsc-multi.json`: 
- `tsconfig.json`: 

### `scripts\noir_src\tooling\noir_js\scripts`
- `compile_test_programs.sh`: 

### `scripts\noir_src\tooling\noir_js\src`
- `base64_decode.ts`: 
- `index.ts`: 
- `program.ts`: 
- `witness_generation.ts`: 

### `scripts\noir_src\tooling\noir_js\test\node`
- `cjs.test.cjs`: 
- `execute.test.ts`: 
- `smoke.test.ts`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples\assert_lt`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples\assert_lt\src`
- `main.nr`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples\assert_msg_runtime`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples\assert_msg_runtime\src`
- `main.nr`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples\assert_raw_payload`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples\assert_raw_payload\src`
- `main.nr`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples\fold_fibonacci`
- `Nargo.toml`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples\fold_fibonacci\src`
- `main.nr`: 

### `scripts\noir_src\tooling\noir_js\test\noir_compiled_examples`
- `readme.md`: 

### `scripts\noir_src\tooling\noir_js_backend_barretenberg`
- `.eslintignore`: 
- `.eslintrc.cjs`: 
- `.gitignore`: 
- `.mocharc.json`: 
- `fixup.sh`: 
- `package.json`: 
- `tsconfig.cjs.json`: 
- `tsconfig.json`: 

### `scripts\noir_src\tooling\noir_js_backend_barretenberg\src`
- `backend.ts`: 
- `base64_decode.ts`: 
- `index.ts`: 
- `public_inputs.ts`: 
- `serialize.ts`: 
- `types.ts`: 
- `verifier.ts`: 

### `scripts\noir_src\tooling\noir_js_types`
- `.eslintignore`: 
- `.eslintrc.cjs`: 
- `.gitignore`: 
- `.prettierrc`: 
- `package.json`: 
- `tsconfig.json`: 

### `scripts\noir_src\tooling\noir_js_types\src`
- `types.ts`: 

### `scripts\noir_src\tooling\noirc_abi`
- `Cargo.toml`: 

### `scripts\noir_src\tooling\noirc_abi\src`
- `arbitrary.rs`: 
- `errors.rs`: 
- `lib.rs`: 
- `serialization.rs`: 

### `scripts\noir_src\tooling\noirc_abi\src\input_parser`
- `json.rs`: 
- `mod.rs`: 
- `toml.rs`: 

### `scripts\noir_src\tooling\noirc_abi_wasm`
- `.eslintignore`: 
- `.eslintrc.js`: 
- `.mocharc.json`: 
- `CHANGELOG.md`: 
- `Cargo.toml`: 
- `README.md`: 
- `build.rs`: 
- `build.sh`: 
- `package.json`: 
- `tsconfig.json`: 
- `web-test-runner.config.mjs`: 

### `scripts\noir_src\tooling\noirc_abi_wasm\src`
- `errors.rs`: 
- `js_witness_map.rs`: 
- `lib.rs`: 

### `scripts\noir_src\tooling\noirc_abi_wasm\test\browser`
- `abi_encode.test.ts`: 
- `decode_error.test.ts`: 
- `errors.test.ts`: 
- `structs.test.ts`: 

### `scripts\noir_src\tooling\noirc_abi_wasm\test\node`
- `abi_encode.test.ts`: 
- `decode_error.test.ts`: 
- `errors.test.ts`: 
- `structs.test.ts`: 

### `scripts\noir_src\tooling\noirc_abi_wasm\test\shared`
- `abi_encode.ts`: 
- `array_as_field.ts`: 
- `decode_error.ts`: 
- `field_as_array.ts`: 
- `structs.ts`: 
- `uint_overflow.ts`: 

### `scripts\noir_src\tooling\noirc_abi_wasm\test`
- `types.ts`: 

### `scripts\noir_src\tooling\noirc_artifacts`
- `Cargo.toml`: 

### `scripts\noir_src\tooling\noirc_artifacts\src`
- `contract.rs`: 
- `debug.rs`: 
- `debug_vars.rs`: 
- `lib.rs`: 
- `program.rs`: 

### `scripts\noir_src\tooling\profiler`
- `Cargo.toml`: 

### `scripts\noir_src\tooling\profiler\src\cli`
- `gates_flamegraph_cmd.rs`: 
- `mod.rs`: 
- `opcodes_flamegraph_cmd.rs`: 

### `scripts\noir_src\tooling\profiler\src`
- `flamegraph.rs`: 
- `fs.rs`: 
- `gates_provider.rs`: 
- `main.rs`: 
- `opcode_formatter.rs`: 

### `scripts\noir_src\tooling`
- `readme.md`: 

### `scripts\noir_src\utils\iter-extended`
- `Cargo.toml`: 

### `scripts\noir_src\utils\iter-extended\src`
- `lib.rs`: 


## Forensic Findings

### 1. Routes Bypassing Service Layers
- **zkp_routes.py**: `list_jobs` directly accesses the DB via `db.query(ProofJob)` instead of a repository/service method.
- **sbom_routes.py**: `list_sboms` directly accesses `session.query(SBOMUpload)`.
- **verification_routes.py**: `list_certificates` directly queries the DB.
- **policy_routes.py**: `list_policies` directly queries the DB.

### 2. Models Not Represented in Migrations & Schemas Inconsistent with DB Models
- The migration `001_initial_schema.py` is missing the `user_id` column for the following tables that exist in the SQLAlchemy models:
  - `sbom.applications`
  - `sbom.sbom_uploads`
  - `zkp.proof_jobs`
  - `verification.verification_requests`

### 3. Tests Testing Obsolete/Fake Behavior
- **test_sbom_intake.py**: Uses `@patch` and `MagicMock` extensively to mock `SBOMRepository` and `get_session`. Mocking security layers and DB in API tests is a security gap (bypasses actual behavior).

### 4. Production Code Accidentally Using Development Code
- **backend/shared/crypto/profile.json**: Sets `"active_profile": "dev"`, defaulting the entire application (including production) to use the development profile and mutated cryptographic circuits.

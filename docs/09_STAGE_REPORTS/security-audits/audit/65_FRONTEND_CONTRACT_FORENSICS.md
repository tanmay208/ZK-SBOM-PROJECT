# Phase 13: Frontend Contract Readiness Audit

## Scope
Audit of API schemas, CORS policies, and route response serialization to ensure the backend is fully prepared to service a web-based frontend dashboard without 500 crashes or cross-origin blocks.

## Findings

### 1. Pydantic Serialization Crash (Missing Field Alias)
- **Status:** **FAIL / HIGH DEFECT**
- **Location:** `sbom_service/app/api/routes/sbom_routes.py` and `sbom_schemas.py`
- **Details:** The `list_sboms` endpoint queries the database and returns a list of raw `SBOMUpload` SQLAlchemy models. FastAPI attempts to serialize these using the `SBOMUploadResponse` Pydantic model (`response_model=List[SBOMUploadResponse]`). However, the `SBOMUploadResponse` schema explicitly defines `upload_id: UUID`, while the database model defines the primary key as `id: UNIQUEIDENTIFIER`.
- **Impact:** Because there is no `validation_alias` or `alias` configured in the Pydantic schema, and because the route handler does not manually map the fields (unlike `upload_sbom`), the `list_sboms` endpoint will violently crash with a 500 Internal Server Error (`pydantic_core._pydantic_core.ValidationError: 1 validation error for SBOMUploadResponse \n upload_id \n Field required`) the moment the frontend dashboard attempts to load the SBOM history.

### 2. CORS Policy Readiness
- **Status:** **PASS**
- **Location:** `shared/app_factory.py`
- **Details:** The API factory configures the `CORSMiddleware` with safe, explicit development origins (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:8000`) and supports dynamic overrides via the `CORS_ORIGINS` environment variable. `allow_credentials=True` and `allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]` are correctly configured to support SPA framework preflight requests.

### 3. Safe Schema Serialization
- **Status:** **PASS**
- **Location:** `vulnerability_schemas.py`, `verification_schemas.py`, `policy_schemas.py`
- **Details:** With the exception of the `sbom_service` bug above, all other bounded contexts utilize proper `.from_model()` mappers (e.g., `VulnerabilitySnapshotResponse.from_model()`, `PolicyResponse.from_model()`) or maintain strict structural parity between the ORM fields and the Pydantic schema fields. Private Data remains securely encapsulated.

## Required Fixes
- **SBOM Response Normalization:** Update `SBOMUploadResponse` in `sbom_schemas.py` to use `id: UUID` (matching the DB model) instead of `upload_id: UUID`, or implement a `from_model()` mapper to explicitly cast `upload.id` to `upload_id` during serialization, ensuring `list_sboms` functions correctly.

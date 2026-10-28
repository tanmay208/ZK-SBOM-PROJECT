# Documentation Index

This index separates **AUTHORITATIVE / CURRENT** material from **HISTORICAL / EVIDENCE**. Current documents describe checked-in implementation or scoped limits. Historical reports are preserved for provenance and may describe earlier designs or statuses; do not treat them as current specifications unless noted here.

## 1. Project
- **AUTHORITATIVE / CURRENT:** [Project status](01_PROJECT/PROJECT_STATUS.md), [project scope](01_PROJECT/PROJECT_SCOPE.md)

## 2. Architecture
- **AUTHORITATIVE / CURRENT:** [System architecture](02_ARCHITECTURE/SYSTEM_ARCHITECTURE.md), [data flow](02_ARCHITECTURE/DATA_FLOW.md), [service contracts](02_ARCHITECTURE/SERVICE_CONTRACTS.md)
- **HISTORICAL / EVIDENCE:** [Original architecture](09_STAGE_REPORTS/original-project-documents/ARCHITECTURE.md), [logic flow](09_STAGE_REPORTS/original-project-documents/LOGIC_FLOW.md), [service contracts](09_STAGE_REPORTS/original-project-documents/SERVICE_CONTRACTS.md)

## 3. Database
- **AUTHORITATIVE / CURRENT:** [Database schema and migration evidence](03_DATABASE/DATABASE_SCHEMA.md)

## 4. Security
- **AUTHORITATIVE / CURRENT:** [Security model](04_SECURITY/SECURITY_MODEL.md), [threat model](04_SECURITY/THREAT_MODEL.md)
- **HISTORICAL / EVIDENCE:** [Security audit and remediation archive](09_STAGE_REPORTS/security-audits/)

## 5. Cryptography
- **AUTHORITATIVE / CURRENT:** [Cryptographic design](05_CRYPTOGRAPHY/CRYPTOGRAPHIC_DESIGN.md), [validation methodology](05_CRYPTOGRAPHY/VALIDATION_METHODOLOGY.md)
- **HISTORICAL / EVIDENCE:** [Stage21 crypto/vector reports](09_STAGE_REPORTS/stage-21/)

## 6. Backend
- **AUTHORITATIVE / CURRENT:** [Backend architecture](06_BACKEND/BACKEND_ARCHITECTURE.md), [proof and certificate lifecycle](06_BACKEND/PROOF_AND_CERTIFICATE_LIFECYCLE.md)

## 7. Frontend
- **AUTHORITATIVE / CURRENT:** [Frontend architecture](07_FRONTEND/FRONTEND_ARCHITECTURE.md), [Stage22 final audit](09_STAGE_REPORTS/STAGE_22_FINAL.md)
- **HISTORICAL / EVIDENCE:** [Frontend stage records, Stages 0–14](09_STAGE_REPORTS/stages-00-14-frontend/)

## 8. Validation
- **AUTHORITATIVE / CURRENT:** [Validation and evidence register](08_VALIDATION/VALIDATION_AND_EVIDENCE.md)
- **HISTORICAL / EVIDENCE:** Stage-specific test, runtime, migration, and audit reports under [Stage Reports](09_STAGE_REPORTS/)

## 9. Stage Reports
- **AUTHORITATIVE / CURRENT:** [Stage22 final audit](09_STAGE_REPORTS/STAGE_22_FINAL.md)
- **HISTORICAL / EVIDENCE:** [Stages 0–14 frontend](09_STAGE_REPORTS/stages-00-14-frontend/), [Stage16](09_STAGE_REPORTS/stage-16/), [Stage17](09_STAGE_REPORTS/stage-17/), [Stage18](09_STAGE_REPORTS/stage-18/), [Stage19](09_STAGE_REPORTS/stage-19/), [Stage20](09_STAGE_REPORTS/stage-20/), [Stage21](09_STAGE_REPORTS/stage-21/), [original project documents](09_STAGE_REPORTS/original-project-documents/), [security audit evidence](09_STAGE_REPORTS/security-audits/)

## 10. Research
- **AUTHORITATIVE / CURRENT:** [Research overview](10_RESEARCH/RESEARCH_OVERVIEW.md)

## 11. Operations
- **AUTHORITATIVE / CURRENT:** [Local development](11_OPERATIONS/LOCAL_DEVELOPMENT.md)
- **AUTHORITATIVE / CURRENT — DEFERRED SCOPE:** [Deployment/TLS boundary](11_OPERATIONS/DEPLOYMENT_TLS_BOUNDARY.md)

Historical report wording is retained. Where an earlier report conflicts with current implementation, use the source-grounded current document and interpret the historical report in its stage/date context.
One machine-specific user-home path in a historical cleanup log was redacted for privacy; the report records that redaction. Other historical local tool paths are generic environment evidence.

---
trigger: model_decision
description: Apply when changing or reviewing security boundaries, authentication, authorization, verification decisions, certificates, or sensitive data handling.
---

# Security Boundaries & Operational Isolation

**Authoritative Specification**: [`project_context/SECURITY_RULES.md`](file:///E:/Main%20Project/project_context/SECURITY_RULES.md)

1. **Untrusted Client Inputs**: Treat all incoming client requests, forms, and proof artifacts as untrusted. Enforce authorization, tenant ownership, and validated schemas in backend services.
2. **Tenant Isolation & Separation of Duties**: Enforce tenant isolation (`user_id` scoping on applications and proof jobs via composite unique constraint) and Separation of Duties (`trusted_importer` for CVE ingestion; `admin` for snapshot approval/freezing).
3. **Fail-Closed Verification**: Only an explicit Boolean `true` from `BarretenbergVerifier.verifyProof()` may issue a certificate. Mismatched roots, invalid bytes, or crashed processes fail closed.
4. **Data Privacy**: Private vendor data (raw CycloneDX JSON, PURLs, component versions) must never be returned across buyer-facing endpoints or logged in plaintext.
5. **Local-Only & Gate 5R Isolation**: Operating mode is strictly LOCAL-ONLY. No remote operations, deployments, or external environment access without explicit authorization. Gate 5R is blocked. Database target selection requires a verified environment assessment and explicit owner confirmation; no mutations or schema changes are permitted pre-D1.
6. **Secrets Protection**: Never expose `.env`, credentials, JWT secrets, private keys, or tokens in outputs, logs, or commits.
7. **Canonical References**: Consult [`project_context/SECURITY_RULES.md`](file:///E:/Main%20Project/project_context/SECURITY_RULES.md) and [`project_context/ARCHITECTURE.md`](file:///E:/Main%20Project/project_context/ARCHITECTURE.md).

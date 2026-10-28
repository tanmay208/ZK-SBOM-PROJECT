# Admin & Security Intelligence Workflow Architecture

Date: 2026-10-01
Stage: 12 — ADMIN & SECURITY INTELLIGENCE

## 1. Core Workflow
- Admin intelligence routes consist of `/admin/policies` and `/admin/vulnerabilities`.
- They read and interact with `policyService` and `vulnerabilityService`.
- These modules form the root authoritative configuration for all downstream Zero-Knowledge execution.

## 2. Policy Constraints
- Policies specify constraints (e.g. `max_cvss_score`).
- The frontend treats these as opaque parameters dispatched to the backend, refraining from local checks. 
- Vendors and Auditors may only *read* these configurations, relying strictly on Role checks.

## 3. Vulnerability Lifecycle
- Vulnerability snapshots progress linearly: `pending` -> `approved` -> `revoked`.
- **Pending**: Safely staged in the database but invalid for production proofs.
- **Approved**: The cryptographic root is actively trusted.
- **Revoked**: The root is explicitly blocked.
- Ingestion explicitly triggers *Pending* statuses, isolating the creation lifecycle from immediate trust.

## 4. Cryptographic Security Boundary
- The frontend absolutely never ingests CVE feeds itself or scores components. 
- It relies explicitly on manual admin payloads array matching `VulnerabilityIngestionItem` schema mapping directly to the DB.
- Raw vulnerability databases and internal representations remain unrendered, restricted purely to `snapshot_label` and `record_count`.

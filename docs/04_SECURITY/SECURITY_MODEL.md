# Security Model

## Principals and boundaries

The application distinguishes authenticated users, API roles such as vendor/admin/auditor, public certificate validators, and administrators who manage policy or vulnerability snapshot state. Frontend route/role checks improve navigation but do not enforce authorization; API authorization and resource ownership are authoritative.

## Authentication and secrets

The frontend keeps its bearer access token in module memory rather than browser persistent storage. The API client attaches it to authenticated requests. Public certificate validation opts out of bearer transport. Backend startup configuration requires database connectivity values and strong, distinct JWT and certificate secrets; secret values are not intended for logs or source control. A safe placeholder-only [.env.example](../../.env.example) documents variable names.

## Tenant and resource authorization

Private SBOM, proof-job, verification, and certificate resources are subject to backend authentication/ownership checks. Public certificate validation is a deliberately narrower contract. Do not treat frontend hiding, unguessable identifiers, or public validation as authorization for private retrieval. See the dated Stage21N security evidence and Stage22 frontend audit for scope and limits.

## Cryptographic assurance boundary

Application verification checks the proof and context the backend receives. A commitment or proof does not guarantee the source SBOM or vulnerability feed was complete, correctly curated, or current. The application cannot infer more than the encoded statement and authoritative persisted state support.

## Network and deployment boundary

Repository nginx is HTTP-only and internal to the Compose network, with no host-published port in the checked-in Compose file. This does not prove a future deployment's network configuration. External HTTPS/TLS, firewall controls, origin isolation, and public reachability are Stage23 responsibilities; see [deployment boundary](../11_OPERATIONS/DEPLOYMENT_TLS_BOUNDARY.md).

## Limits

This is a source-grounded summary, not a security certification. It does not claim exhaustive penetration testing, formal verification of the full application, or production readiness. Refer to preserved [security audits](../09_STAGE_REPORTS/security-audits/) for historical findings and dated disposition.

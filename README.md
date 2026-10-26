# Privacy-Preserving Zero-Knowledge SBOM Vulnerability Verification Platform

> [!IMPORTANT]
> **Authoritative Documentation & Governance:**
> All project documentation, agent operating rules, locked six-stage roadmap, and session handoffs are consolidated in:
> [`MASTER_PROJECT_CONTEXT/`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT) (see [`MASTER_PROJECT_CONTEXT/README.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/README.md)).
> For cleanup and audit logs, see [`MASTER_PROJECT_CONTEXT/REPOSITORY_CLEANUP_AUDIT.md`](file:///E:/Main%20Project/MASTER_PROJECT_CONTEXT/REPOSITORY_CLEANUP_AUDIT.md).

## Overview

This research and engineering prototype lets a software supplier create a zero-knowledge proof that an SBOM satisfies a policy against a specified, committed vulnerability snapshot. A verifier can check the proof and, after successful verification, consult a certificate-validation endpoint without receiving the private SBOM component list.

The system makes a narrow statement about the inputs and policy encoded for a verification. It does not establish that a vulnerability feed or SBOM is complete, or that software is safe in every respect.

## Problem Statement

Sharing a full SBOM with every customer or evaluator can disclose dependency and product information. This project explores proving policy compliance against committed data while limiting disclosure of the underlying component inventory.

## Proposed Solution

The application ingests and canonicalizes SBOM data, uses vulnerability and policy records to define verification context, generates a proof using Noir circuits, verifies the resulting proof material, persists the outcome, and exposes a constrained certificate-validation result. The workflow binds a verification to an SBOM root, vulnerability snapshot root, and policy hash.

## Core Innovation / Contribution

The repository implements a privacy-oriented SBOM compliance workflow combining committed SBOM and vulnerability data, policy binding, a decomposed SMT proof topology, application-level proof verification, and certificate lifecycle handling. This describes the implementation; the repository does not establish a first-of-its-kind claim or independently substantiate research novelty.

## Key Features

- SBOM upload, parsing, normalization, identity handling, and commitment.
- Vulnerability snapshot and policy management APIs.
- Noir-based proof generation with configured chunk/segment artifacts.
- Verification requests bound to the proof job and public context.
- Persistent verification and certificate records, including revocation state.
- Public certificate validation separate from authenticated certificate retrieval.
- Next.js App Router interface for user and administrator workflows.

## System Architecture

    Browser → Next.js frontend → internal nginx gateway
                                   ├─ SBOM service
                                   ├─ Vulnerability service
                                   ├─ Policy service
                                   ├─ ZKP service → Nargo / Barretenberg
                                   └─ Verification/platform API → PostgreSQL

Compose defines the gateway and application containers. It does not define PostgreSQL, a frontend container, a public host port, or a TLS terminator. The nginx hop is HTTP inside the Compose network. Production ingress and hosting are Stage 23 work; see [project status](docs/01_PROJECT/PROJECT_STATUS.md) and [deployment boundary](docs/11_OPERATIONS/DEPLOYMENT_TLS_BOUNDARY.md).

## Core Workflow

    SBOM → vulnerability snapshot and policy → ZKP generation → verification
         → certificate → public status validation

Proof-generation completion is not itself a verification result.

## Technology Stack

| Area | Repository evidence |
| --- | --- |
| Frontend | Next.js 16.3.5, React 19.2.8, TypeScript, TanStack React Query |
| API services | Python 3.11 container images, FastAPI 0.115.6, SQLAlchemy 2.0.36 |
| Persistence | PostgreSQL, psycopg2, Alembic; Stage21N report records PostgreSQL 17.11 |
| ZKP | Noir circuits; Nargo 0.32.0 in circuit manifests/profile |
| Proof runtime | Stage21L report records Barretenberg 0.46.1 for that historical run |
| Containers | Docker Compose and nginx |

## Security Model

The browser keeps its bearer token in memory and sends it to authenticated API methods. Public certificate validation omits the token; private-resource authorization remains a backend responsibility. Backend startup validates database settings and independent JWT/certificate secrets. Secrets belong in local/deployment environment configuration and must not be committed.

Compose does not prove a production network boundary. It publishes no app or gateway port to the host, but external HTTPS termination, firewalling, and origin isolation are not defined here. See [security model](docs/04_SECURITY/SECURITY_MODEL.md).

## Privacy Model

The intended property is that a verifier can check the encoded compliance statement without receiving the original SBOM component list. Public inputs, commitments, and status metadata remain observable. Commitments are not encryption; no claim is made that all metadata is non-linkable or every side channel has been excluded.

## Validation / Testing

Stage22.9 historically reports 32 frontend tests passed and successful TypeScript typecheck, ESLint, and Next.js production build. In this consolidation, the backend suite passed 533 tests (56 warnings); frontend typecheck, ESLint, and production build passed. The current npm test passed 32 tests after npx fetched the undeclared tsx runner with network access; clean/offline test reproducibility is still not established. Stage22.9 also records a limited 390 px local-browser smoke, not authenticated backend integration.

The Stage21L report documents a historical 1,024-component workload, 32 chunks, 8 SMT segments per chunk, and 256 proof generations/verifications. This consolidation did not rerun it. See [Stage21L evidence](docs/09_STAGE_REPORTS/stage-21/STAGE21L_CRYPTOGRAPHIC_RUNTIME_VALIDATION_REPORT.md).

## Repository Structure

- backend/ — FastAPI services, shared code, SQLAlchemy models, migrations, and tests.
- frontend/ — Next.js application, API client, auth provider, UI components, and tests.
- circuits/ and circuits_dev/ — production-profile and development Noir sources/artifacts.
- segment_* — decomposed segment circuit artifacts.
- scripts/ — vector, circuit, validation, and archive utilities.
- archive/ — reusable project assets and retained proof/archive evidence.
- master_archive/ — retained historical non-production material (excluded from source ZIP).
- docker/ and docker-compose.yml — application containers and internal nginx.
- docs/ — current documentation index and preserved historical reports.

## Local Development

Frontend checks (from frontend/):

    npm ci
    npm test
    npx tsc --noEmit
    npx eslint .
    npm run build
    npm run dev

npm test invokes npx tsx; tsx is not declared in the frontend package manifest, so clean/offline test reproducibility is not established. The API client defaults to http://localhost:8000; make the API reachable there or set NEXT_PUBLIC_API_URL in the frontend environment.

Backend tests (from the repository root):

    python -m pip install -r requirements-dev.txt
    python -m pytest -q

For container startup, configure a reachable PostgreSQL database and strong, distinct local secrets using [.env.example](.env.example), then run docker compose up --build. Compose has no database or frontend and does not publish the gateway to the host; it starts an internal application topology, not a ready public or browser-accessible deployment. Proof operations also require the configured cryptographic artifacts and toolchain. See [local development](docs/11_OPERATIONS/LOCAL_DEVELOPMENT.md).

## Documentation

Start at the [documentation index](docs/README.md), which labels current authoritative material separately from historical evidence.

## Research / Academic Context

The research question is whether a supplier can prove compliance of committed SBOM data against an identified snapshot and policy without disclosing its component inventory. The repository contains an engineering prototype and historical feasibility/runtime evidence. No peer-reviewed result, comparative performance claim, or novelty priority is asserted; see [research overview](docs/10_RESEARCH/RESEARCH_OVERVIEW.md).

## Deployment

Production hosting, HTTPS/TLS termination, external ingress, origin isolation, firewall/network controls, production secrets/database, external reachability, and final security verification are Stage23. No deployment claim is made here.

## Limitations

- A proof is scoped to its circuit statement, public inputs, policy, and committed data; it is not a general guarantee of no vulnerabilities.
- Snapshot provenance/freshness depend on the supplied data and operational process.
- The Stage22 audit did not exercise a complete authenticated live backend workflow.
- Browser/accessibility testing was limited; comprehensive keyboard, assistive-technology, contrast, and breakpoint testing is not documented as complete.
- Historical documents preserve earlier, sometimes conflicting designs; they are not current specifications.
- Production deployment and acceptance remain Stage23.

## Authors / Project Information

The repository does not maintain a named author/contact list in its root project metadata. Project scope and current status are documented in [Project Status](docs/01_PROJECT/PROJECT_STATUS.md).

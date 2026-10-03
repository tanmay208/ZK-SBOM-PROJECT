# System Architecture

## Current topology

    Browser → Next.js frontend → internal nginx gateway (HTTP)
                                   ├─ SBOM service
                                   ├─ Vulnerability service
                                   ├─ Policy service
                                   ├─ ZKP service → configured Noir/Barretenberg runtime and artifacts
                                   └─ Verification/platform API
                                               ↓
                                  PostgreSQL configured separately

The backend is implemented as five FastAPI service applications with shared configuration, database, security, schema, and cryptographic modules. Compose builds the service containers and nginx gateway. The verification service entry point also mounts auth, metrics, policy, SBOM, ZKP, and vulnerability routers for a unified API process; Compose separately defines service containers and routes API paths to them.

The Next.js frontend uses an API client and domain services, an in-memory auth provider, and a shared React Query provider. Public certificate validation calls a narrower unauthenticated contract; private certificate retrieval is separate.

## Persistence and external dependencies

SQLAlchemy models share PostgreSQL persistence, with logical schemas represented in the models/migrations. Alembic provides schema evolution. Compose does not start PostgreSQL; a reachable database must be configured separately. Proof operations additionally depend on profile-selected circuit artifacts and Nargo/Barretenberg executables.

## Network boundary

Checked-in nginx listens on HTTP port 80. Compose declares the gateway as expose-only and does not publish gateway or application ports with a host ports mapping. No external TLS terminator, firewall/network policy, cloud ingress, or deployment resource is defined here. These files describe an internal application topology only; production ingress is deferred to Stage 23. See [deployment boundary](../11_OPERATIONS/DEPLOYMENT_TLS_BOUNDARY.md).

## Source references

- docker-compose.yml and docker/nginx.conf
- backend service app entry points and backend/shared/app_factory.py
- frontend/src/app, frontend/src/api, frontend/src/auth, and frontend/src/providers

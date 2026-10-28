# Backend Architecture

The backend is organized into five FastAPI service packages: sbom_service, vulnerability_service, policy_service, zkp_service, and verification_service. Shared infrastructure under backend/shared/ provides configuration, database/session setup, authentication, common schemas, exception handling, logging, request-size/security middleware, and cryptographic utilities.

Each service has API routes, schemas, models, and, where applicable, repositories/services. Dockerfiles build service applications from a common backend context and install the shared runtime dependency set. The nginx gateway routes API path families to the service containers. The verification service entry point also imports platform routers for a unified API process used in frontend development.

PostgreSQL persistence uses SQLAlchemy. Alembic revisions are under backend/alembic/versions. See [database schema](../03_DATABASE/DATABASE_SCHEMA.md) for migration evidence and its date limits.

Backend API authorization, tenant ownership, validation, and cryptographic verification are authoritative. Frontend role visibility is not a security boundary.

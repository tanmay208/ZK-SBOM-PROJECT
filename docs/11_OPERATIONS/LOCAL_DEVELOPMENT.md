# Local Development

## Prerequisites

- Python 3.11 is used by backend Dockerfiles.
- Node/npm compatible with the locked Next.js 16.3.5 application. The package manifest does not declare an exact Node version.
- PostgreSQL reachable with the schema migrated to the revision required by the code. Compose does not provide a database.
- For proof execution: profile-selected circuit artifacts and matching Nargo/Barretenberg tools.

## Environment

Copy variable names from the root .env.example into a local ignored .env or set equivalent environment variables. The example contains placeholders only; replace secret placeholders locally with distinct, strong values. Never commit .env, credential-bearing database URLs, signing secrets, or private keys.

The backend reads environment variables. Docker Compose reads the root .env; Next.js reads frontend environment from its own project directory. The frontend API base URL defaults to http://localhost:8000 and may be set with NEXT_PUBLIC_API_URL for local use.

## Frontend

From frontend/:

    npm ci
    npm test
    npx tsc --noEmit
    npx eslint .
    npm run build
    npm run dev

The test script calls npx tsx; tsx is not currently a declared frontend dependency. A clean network-isolated install may not run that script reproducibly.

The root requirements.txt composes backend/shared runtime dependencies with python-dotenv for the Alembic environment. requirements-dev.txt adds the pinned pytest and httpx versions used by the backend tests.

## Backend tests

From the repository root:

    python -m pip install -r requirements-dev.txt
    python -m pytest -q

## Backend/container startup

For local API development, configure database, secrets, profile, and service variables, then from backend/ run a selected FastAPI entry point, for example:

    python -m uvicorn verification_service.app.main:app --host 127.0.0.1 --port 8000

App startup validates configuration and database initialization, so a working PostgreSQL connection and configured crypto profile are required. Proof operations also require the command-line toolchain and artifacts.

Compose starts an internal gateway and service containers but has no database or frontend service and no host ports mapping. Its default database host is a Compose service name and must be configured for the actual local database. The internal gateway is not reachable from a host browser by default. Production ingress/TLS is Stage23, not part of these steps.

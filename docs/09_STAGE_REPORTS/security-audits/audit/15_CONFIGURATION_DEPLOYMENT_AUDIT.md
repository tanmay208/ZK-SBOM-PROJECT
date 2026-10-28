# Configuration and Deployment Audit

## Findings

- Compose exposes host ports 80 and 1433; the database comment says development only, but no production Compose profile or network restriction enforces that. Classification: SECURITY WEAKNESS.
- Services bind `0.0.0.0` in Docker. This is expected inside a container but relies on network isolation/reverse proxy controls not evidenced.
- `docker-compose.yml` references `docker/nginx.conf`, which is absent, and builds `frontend` from `frontend/`, where `Dockerfile` is absent. Compose deployment is therefore not demonstrated and likely cannot build as written. Classification: CONFIRMED DEPLOYMENT DEFECT.
- Application factory catches database initialization failures and continues serving a healthy app. The health endpoint always reports `healthy` without checking DB or cryptographic tool readiness. Classification: SECURITY WEAKNESS and misleading health signal.
- `DEBUG=false` is the example default, but configuration validation only requires DB password/host/name and does not require JWT secret, production profile, TLS, or artifact availability.
- CORS has explicit defaults but `allow_credentials=True` and wildcard request headers; it is an application default rather than a deployment policy. CSRF impact depends on token storage, which the frontend does not implement in inspected source. Classification: HARDENING RECOMMENDATION.
- No resource limits, worker policy, TLS configuration, metrics authentication beyond bearer dependency, audit sink, or reverse proxy evidence was found.

## Production Status

The frontend production build succeeded, but this is not a full deployment test. Docker Compose, production database, production circuit, and reverse-proxy paths were not executed. Production readiness: UNVERIFIED — INSUFFICIENT EVIDENCE.

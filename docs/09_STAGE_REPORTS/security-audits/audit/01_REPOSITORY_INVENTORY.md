# Repository Inventory

## Components Observed

- Five FastAPI services: SBOM, vulnerability, policy, ZKP, and verification.
- Shared Python package: configuration, SQLAlchemy engine/session, auth, security middleware, logging, exceptions, crypto, schemas, and user model.
- Frontend: Next.js 16.3.5 / React 19.2.8 static dashboard shell with no observed API/auth client code.
- Circuit packages: `circuits/` and `circuits_dev/`, each with Noir source, Prover.toml or proof artifacts, and target artifacts.
- Scripts: Python/Noir crypto-vector, circuit compatibility, size-analysis, and experiment tooling.
- Database: Alembic migration and SQLAlchemy models using five SQL Server schemas.
- Deployment: service Dockerfiles, `docker-compose.yml`, and `docker/Dockerfile.noir`.
- Documentation: architecture, contracts, threat model, security boundary, crypto interoperability, and implementation plan.

## Actual Implementation Surfaces

- Routes: `backend/*/app/api/routes/*.py` plus `backend/shared/api/auth_routes.py` and `metrics_routes.py`.
- Persistence: SQLAlchemy ORM repositories and direct service queries against the shared engine.
- Authentication: `backend/shared/auth.py`; registration/login in `shared/api/auth_routes.py`.
- Authorization: authenticated-user dependency is present on some routes, but no role-check dependency or ownership predicate was found.
- Parsing: JSON CycloneDX parser, validator, canonicalizer, PURL utility.
- Crypto: byte-to-field encoding, Poseidon permutation/sponge, component hashing, fixed Merkle tree, sparse Merkle tree.
- Subprocess: `zkp_service/app/services/prover_service.py` and `verification_service/app/core/verifier.py` invoke WSL, Nargo, and Barretenberg.
- Certificates: `verification_service/app/repositories/verification_repository.py` creates a database certificate after verifier status `verified`.
- Filesystem: per-job Prover.toml, witness/proof target files, and verification proof files under circuit directories.

## Dependencies and Artifacts

- Backend requirements are pinned in `backend/shared/requirements.txt` and inherited by all service requirements.
- Frontend has `frontend/package.json` and `frontend/package-lock.json`.
- No Nargo dependency entries are present in either circuit `Nargo.toml`.
- Production compiled target is approximately 55 MB and lacks `circuits/target/vk`; development target includes `circuits_dev/target/vk`.
- Committed/untracked proof-like files include a 10-byte production proof placeholder, fake and mutated development proofs, and large target JSON artifacts.

## Inventory Limitations

No CI workflow was found under `.github/`; `docker/nginx.conf` and `frontend/Dockerfile` referenced by Compose were not present. Inventory does not imply that an absent file is ignored by a deployment system outside this repository.

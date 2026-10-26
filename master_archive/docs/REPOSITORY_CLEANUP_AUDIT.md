# Repository Cleanup Audit

**Audit date:** 2026-10-04  
**Scope:** Read-only inventory, reference analysis, secret-hygiene review, and removal of only high-confidence cache artifacts.  
**Safety posture:** No application behavior, API contract, database schema, cryptographic logic, circuit source, tests, deployment configuration, documentation evidence, or Git history was changed.

## 1. Repository inventory summary

- Git-tracked files at audit start: 531.
- Git status entries at audit start: 337. These include pre-existing staged additions, modified files, and untracked proof/research material; they were preserved.
- Major project areas inspected: `backend/`, `frontend/`, `circuits/`, `circuits_dev/`, `scripts/`, `docs/`, `archives/`, Docker/Compose configuration, Alembic migrations, tests, manifests, and environment configuration.
- The working tree contains substantial untracked research and cryptographic outputs. Their presence is intentional or uncertain and is not treated as disposable based on naming alone.

## 2. Required and preserved files/directories

The following categories were preserved:

- Runtime source and tests in `backend/` and `frontend/`.
- Alembic configuration and all migrations in `backend/alembic/`.
- Production and development Noir sources, `Nargo.toml` files, circuit targets, proof material, and cryptographic vectors.
- `archives/proofs/`, including the completed ZIP archive and 256 temporary segment proofs. Application code writes and reads this location, and multiple Stage 21 audit documents identify the archive as evidence.
- `circuits_dev/`, which is referenced by benchmark scripts and Stage 17/18 evidence as a known-good development circuit.
- `scripts/`, including the currently staged Noir compatibility/experiment files and size-analysis/proof scripts.
- `segment_*` directories, which contain Noir sources and compiled/proof artifacts and are treated as research/evaluation evidence or uncertain generated cryptographic material.
- Documentation, historical audit reports, validation evidence, and research/evaluation documents under `docs/`.
- Dockerfiles, Compose configuration, package manifests, requirements files, lock/configuration files, `.env.example`, and the local `.bin/nargo` development tool.
- `.env`, `staged_files.txt`, and other local-only files were not deleted because they are untracked/ignored and may contain credentials or user work.

## 3. Classification

| Category | Findings |
|---|---|
| A. Required runtime | Backend services, shared libraries, frontend source, Docker/Compose files |
| B. Required testing | Backend and frontend tests, vectors, pytest/TypeScript configuration |
| C. Required development tooling | `.bin/nargo`, scripts, package/requirements manifests, editor configuration |
| D. Required cryptographic/ZKP material | `circuits/`, `circuits_dev/`, `segment_*`, proof archives, crypto profile/vectors |
| E. Required database/migration material | `backend/alembic/`, Alembic configuration, database initialization and models |
| F. Required documentation | README, architecture/security/operations/research documents |
| G. Historical/audit evidence | Stage reports and security-audit directories |
| H. Research/evaluation evidence | Benchmark scripts, Noir experiments, segment outputs, proof archive |
| I. Possibly obsolete | Some experimental scripts and generated targets; preserved because staged, referenced, or cryptographically relevant |
| J. Clearly generated/cache/temp | Python `__pycache__` directories and pytest cache directories |
| K. Clearly scratch/experimental | Names such as `temp_merkle.py` and Noir experiments exist, but are staged or potentially research evidence; preserved |
| L. Unknown | `.env`, `staged_files.txt`, local binary, proof segments, and any artifact without explicit disposal proof |

## 4. Security-sensitive findings

- `.env` exists and is ignored by Git. It contains credential-related configuration keys. Values were not printed or copied. It was preserved and should be handled/rotated separately according to operational policy.
- `.env.example` was preserved.
- Repository-wide secret-pattern scanning found expected references in configuration, authentication, certificate, database, tests, and documentation. Pattern matches were not treated as proof of an embedded secret.
- No private-key or credential value was copied into this report.

## 5. Duplicate configuration findings

- Both `.env` and `.env.example` exist. They serve different purposes; `.env` is local runtime configuration and `.env.example` is the committed template. Neither was deleted.
- No duplicate package manifest, migration chain, circuit configuration, or deployment configuration was deleted.

## 6. Generated/cache artifacts

The following are standard reproducible Python/pytest caches, ignored by `.gitignore`, with no runtime or documentation references:

- Root `.pytest_cache/`
- Backend `.pytest_cache/`
- All 44 project `__pycache__/` directories under the repository, excluding the virtual environment

Python caches contain no source or authoritative evidence and are regenerated automatically.

## 7. Experimental/scratch artifacts

The following were inspected but preserved:

- `scripts/noir_compatibility/`, `scripts/noir_experiment/`, and staged Noir helper scripts.
- `scripts/temp_merkle.py`, `scripts/size_analysis.py`, `scripts/true_max_size.py`, and `scripts/true_valid_max_size.py`.
- `segment_final*`, `segment_init*`, and `segment_mid*`.
- `archives/proofs/temp/`.
- `staged_files.txt`.

These items are either staged, referenced by scripts/docs, cryptographic outputs, or insufficiently proven to be disposable.

## 8. Reference-analysis results

- `archives/` is referenced by the README, proof-generation/verification services, verification scripts, and security/audit reports.
- `circuits_dev/` is referenced by benchmark scripts, the README, and Stage 17/18 documentation.
- `circuits/`, `scripts/`, migrations, frontend/backend source, and tests are part of the tracked/staged project surface.
- No current code, test, build, deployment, migration, circuit, benchmark, or documentation reference was found for the Python cache directories.
- Generic credential terms occur in expected security/configuration code and documentation; no secret values were included in this report.

## 9. Exact deletion list

Only the following were removed:

- `.pytest_cache/` — CATEGORY J, cache; no references; no runtime impact; reproducible; HIGH confidence.
- `backend/.pytest_cache/` — CATEGORY J, cache; no references; no runtime impact; reproducible; HIGH confidence.
- `backend/**/__pycache__/` — CATEGORY J, Python bytecode cache; no references; no runtime impact; reproducible; HIGH confidence.
- `scripts/__pycache__/` — CATEGORY J, Python bytecode cache; no references; no runtime impact; reproducible; HIGH confidence.
- `frontend/.next/` — CATEGORY J, reproducible Next.js build output; no runtime/source references; no repository impact; HIGH confidence.

No files in `archives/`, `circuits/`, `circuits_dev/`, `segment_*`, `scripts/` source, `docs/`, `backend/`, `frontend/`, or deployment/configuration areas were removed.

## 10. Exact preservation decision

All non-cache candidates listed in Sections 2 and 7 were preserved. In particular, no proof, certificate, circuit, target, archive, migration, source file, test, research result, audit report, environment file, local credential file, or development binary was removed.

## 11. Validation plan

After cache removal:

1. Re-check Git status and confirm only the requested reports and cache removals are attributable to this cleanup.
2. Search for deleted cache paths and verify no source/script/documentation references exist.
3. Run targeted backend import/startup and pytest validation where the existing environment supports it.
4. Run frontend tests, TypeScript check, ESLint, and production build where the existing dependencies/supporting services permit it.
5. Run Alembic current/heads/check where a configured database is available.
6. Run circuit compilation and relevant cryptographic/proof regression checks where Nargo/Barretenberg and required inputs are available.
7. Record unavailable checks explicitly rather than claiming success.

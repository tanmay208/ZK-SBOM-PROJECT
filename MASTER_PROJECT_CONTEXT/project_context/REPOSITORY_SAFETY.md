# Repository Safety, Database Isolation & Operational Rules

**Document Version:** 2.0.0-consolidated  
**Workspace Root:** `E:\Main Project`  
**Authoritative Location:** `project_context/REPOSITORY_SAFETY.md`  
**Effective Date:** 14 October 2026  

---

## 1. Git Working Tree Preservation

1. **Pre/Post-Operation Inspection**:
   - Always run and inspect `git status --short --branch` before and after making repository modifications.
   - Preserve all pre-existing tracked changes and untracked files unless there is clear empirical evidence establishing an error.
2. **Strictly Forbidden Destructive Commands**:
   - `git clean -fd` or `git clean -f`: **FORBIDDEN**. This would irreversibly destroy untracked migrations `012`, `013`, `014`, local archives, and governance documents.
   - `git reset --hard`: **FORBIDDEN**. This would discard uncommitted security and concurrency fixes.
   - `git checkout -- .`: **FORBIDDEN**.
   - Broad recursive deletes targeting `archive/`, `master_archive/`, or circuit witness directories.
3. **Narrowly Scoped Work Units**:
   - Apply edits surgically in small, easily reviewable units. Avoid large batch refactoring that touches dozens of files simultaneously.

---

## 2. Protected Untracked Assets

The following local untracked assets are essential to the project and must **never** be cleaned, deleted, or overwritten:
- **Untracked Alembic Migrations**:
  - `backend/alembic/versions/012_vulnerability_ingestion_provenance.py`
  - `backend/alembic/versions/013_add_vuln_lifecycle.py`
  - `backend/alembic/versions/014_application_tenant_isolation.py`
- **Root Archives**:
  - `archive/` (Contains active verification keys, proofs, manifests, and test fixtures).
  - `master_archive/` (Contains historical evidence and past run captures).
- **Context & Safety Documents**:
  - `AGENTS.md`, `PROJECT_CONTEXT.md`, and the `project_context/` directory.

---

## 3. Two-Folder Archive Policy

To prevent directory bloat and broken relative paths, the repository maintains an explicit archive structure:
1. **`archive/`**: Contains reusable runtime assets, circuit verification keys (`.vk`), and test manifests.
2. **`master_archive/`**: Contains historical evidence, superseded test artifacts, and audit snapshots. Excluded from the source distribution ZIP.
3. **Forbidden Folders**: Never create or restore `archives/` (plural) or `backend/archives/`. All references must resolve to `archive/` or `master_archive/`.

---

## 4. Database Environment Policy & Target Selection

The repository recognizes two distinct local database environments:

| Database Instance | Host & Port | Target DB Name | Operational Status & Policy |
| :--- | :--- | :--- | :--- |
| **Development Database** | `127.0.0.1:5433` | `ZKP_SBOM_LOCAL_DEV` (Alembic rev `014`) | **PREFERRED DEV/TESTING CANDIDATE**. Intended for development, testing, migration validation, debugging, and integration testing, subject to explicit authorization before database operations. Present state has not been verified by this documentation task. |
| **Main Database** | `127.0.0.1:5432` | `ZKP_SBOM` (Alembic rev `007`) | **INTENDED FINAL MAIN-PROJECT TARGET / PROTECTED**. Intended main database for the completed project. Currently protected/frozen during development and validation; do not access or modify without separate, explicit authorization. Will only be considered for operational use after validation, recovery planning, and separate explicit authorization. |

### Database Rules Pre-D1:
1. **Preserve Distinction**: Maintain clear separation between the two environments.
2. **No Unverified Assumptions**: Do not claim either environment's current contents, backup status, schema equivalence, or operational state without empirical evidence.
3. **No Blanket Permanent Prohibition**: PostgreSQL 17 is the intended final main-project target, not permanently banned. It will be considered for operational use only after validation, recovery planning, and separate explicit authorization.
4. **Zero Mutations Pre-D1**: Do not run migrations, write queries, seed data, truncate tables, drop objects, restart containers, recreate containers, or remove volumes on either instance prior to authorized D1 work. Stage D1 remains unauthorized and has not started.
5. **Secret Protection**: Read-only inspection of database configuration must never expose connection passwords or print `.env`.
6. **Outstanding Decisions Preserved**: Keep unresolved until separately reviewed and approved: `public.users` migration-baseline strategy, migration-chain safety and compatibility, backup and recovery requirements before any future transition to PostgreSQL 17, cross-tenant/buyer verification architecture, certificate-revocation authorization policy, and user-management/role scope.

---

## 5. Local-Only & Gate 5R Operational Boundaries

1. **Local-Only Operating Mode**:
   - Operating mode is strictly **LOCAL-ONLY**. No remote operations, deployments, or external environment access without explicit authorization.
   - Never attempt remote database connections, remote staging queries, or remote migrations.
2. **Gate 5R — Strictly Blocked**:
   - Staging inspection, staging deployment, container restarts, and secret rotations on remote infrastructure are strictly blocked.
   - Do not cross into operational deployment commands.

---

## 6. Secret Protection & Root `.env` Rules

1. **Root `.env` Inviolability**:
   - The root `.env` file contains remote Supabase credentials.
   - It must **never** be printed in chat or logs, edited, committed, or used as a credential source for local development.
2. **Zero Secret Persistence**:
   - Development credentials and cryptographic keys (`JWT_SECRET_KEY`, `CERTIFICATE_SECRET_KEY`, `DB_PASSWORD`) must be passed strictly via process-scoped environment variables in local terminals.
   - Never set machine-wide or user-wide Windows environment variables for secrets.
   - Never hardcode credentials into Python scripts, TypeScript files, or documentation.

---

## 7. Packaging & External Distribution Caution

- The source distribution archive `dist/zkp-sbom-source.zip` is generated via filename/extension filtering (`package_source_zip.py`).
- It is **NOT certified safe for external distribution** until a comprehensive content-level secret audit has been authorized and completed.
- Never distribute zip archives outside the local development environment without authorization.

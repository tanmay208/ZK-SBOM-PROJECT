---
trigger: model_decision
description: Apply before repository inspection, edits, cleanup, test execution, or artifact handling.
---

# Repository Safety & Operational Preservation

**Authoritative Specification**: [`project_context/REPOSITORY_SAFETY.md`](file:///E:/Main%20Project/project_context/REPOSITORY_SAFETY.md)

1. **Git Working Tree Preservation**: Inspect `git status --short --branch` before and after actions. Never run destructive commands: `git reset --hard`, `git clean -fd`, or blanket restores.
2. **Protected Untracked Assets**: Preserve untracked migrations `012`, `013`, `014`, `archive/`, `master_archive/`, proofs, VKs, and `project_context/`.
3. **Two-Folder Archive Policy**: The root directory maintains exactly `archive/` (reusable assets) and `master_archive/` (historical evidence). Never delete `master_archive/`. Never create `archives/` or `backend/archives/`.
4. **Database Strategy & Environment Policy**:
   - `127.0.0.1:5433` (`ZKP_SBOM_LOCAL_DEV`): Docker PostgreSQL 16 development database. Preferred development and testing candidate for dev, test, migration validation, debugging, and integration testing, subject to explicit authorization before database operations. Present state unverified by this task.
   - `127.0.0.1:5432` (`ZKP_SBOM`): Main PostgreSQL 17 database. Intended final main-project target; currently protected/frozen during development and validation. Will only be considered for operational use after validation, recovery planning, and separate explicit authorization.
   - Strictly no database writes, migrations, seeds, table drops, or container resets pre-D1. Stage D1 remains unauthorized and has not started.
5. **Secret Protection**: Never print, copy, or expose `.env`, tokens, credentials, or private keys into reports, logs, or context files. The root `.env` must never be modified or used for local development credentials.
6. **Narrowly Scoped Work Units**: Use small implementation units and focused prompts. Avoid batch refactoring.
7. **Canonical References**: Consult [`project_context/README.md`](file:///E:/Main%20Project/project_context/README.md) and [`project_context/EXECUTION_MAP.md`](file:///E:/Main%20Project/project_context/EXECUTION_MAP.md).

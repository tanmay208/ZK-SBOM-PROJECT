# 72 — Gitignore Quality and Repository Hygiene Verification

## Executive Summary
This document reviews the hygiene of the repository's `.gitignore` configuration. It documents a critical defect fix where frontend library code was shadowed by an overly broad rule, details new exclusions implemented during cleanup, and verifies that no source files, tests, migrations, circuits, or security documents are inadvertently excluded.

---

## 1. Defect Remediation: Accidental Shadowing of `frontend/src/lib/`

### The Defect
In the original `.gitignore`, lines 14–15 contained:
```gitignore
lib/
lib64/
```
In Git's path matching specification, an expression without a leading slash (`lib/`) matches any directory named `lib` at *any nesting depth* across the entire repository. As a direct consequence, the production frontend utility file:
- `frontend/src/lib/utils.ts`
was being silently ignored by Git (`git check-ignore frontend/src/lib/utils.ts` returned exit code 0).

### The Remediation
The rules were scoped to the repository root by prefixing with a leading slash:
```gitignore
/lib/
/lib64/
```
Following this change, `git check-ignore frontend/src/lib/utils.ts` confirmed that the frontend source is now properly recognized and tracked by Git.

---

## 2. Updated Exclusions and Rationale

The following rules were incorporated into `.gitignore`:

| Added Rule | Section | Technical Justification |
| :--- | :--- | :--- |
| `.pytest_cache/` | Python | Pytest automatically generates this cache at root during test runs; prevents Git noise. |
| `/lib/`, `/lib64/` | Python | Anchors legacy virtualenv directory rules to root; protects nested source directories. |
| `coverage/`, `.coverage` | Testing & Coverage | Test coverage databases and HTML coverage reports. |
| `*.log`, `logs/` | Logs | Application and service execution logs. |
| `.next/` | Node | Next.js compilation cache (rebuilt dynamically via `npm run build`). |
| `.env.*`, `!.env.example` | Node / Config | Prevents inadvertent commits of local environment secrets (e.g. `.env.local`, `.env.production`) while guaranteeing `.env.example` is committed. |
| `.bin/` | Tooling | Local Linux toolchain directory containing `.bin/nargo` (preserves binary for WSL without committing 45MB to Git). |
| `desktop.ini` | OS | Windows Explorer folder customization metadata. |

---

## 3. Non-Exclusion Invariant Verification

We verified that `.gitignore` does **NOT** ignore any required production or verification assets:

```powershell
git check-ignore backend/shared/crypto/profile.json
git check-ignore backend/shared/tests/vectors/crypto_vectors.json
git check-ignore backend/alembic/versions/001_initial_schema.py
git check-ignore backend/alembic/versions/002_add_rbac_ownership_columns.py
git check-ignore circuits/src/main.nr
git check-ignore circuits_dev/src/main.nr
git check-ignore frontend/src/lib/utils.ts
git check-ignore .env.example
git check-ignore docs/security/audit/66_RELEASE_GATE_SUMMARY.md
```
**Result**: All commands exited with code 1 (none of these critical paths are ignored).

---

## 4. Current Full `.gitignore` Specification

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
/lib/
/lib64/
parts/
sdist/
var/
*.egg-info/
.installed.cfg
*.egg
venv/
.venv/
.pytest_cache/

# Testing & Coverage
coverage/
.coverage

# Logs
*.log
logs/

# Node
node_modules/
.next/
dist/
build/
.env
.env.*
!.env.example

# Noir/Nargo & Local Tooling
target/
Prover.toml
Verifier.toml
proofs/
.bin/

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
desktop.ini

# Project specific
data/*
!data/.gitkeep
scripts/noir_src/
```

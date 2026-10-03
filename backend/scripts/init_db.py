"""
Database initialisation script.

Usage:
  python -m scripts.init_db

Creates the ZKP_SBOM database (if it does not exist), the five logical
SQL schemas, and runs Alembic migrations to bring the schema to head.

Requires DB_HOST, DB_USER, DB_PASSWORD environment variables.
"""

import sys
import os
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import create_engine, text

from shared.config import get_db_settings
from shared.database import ensure_schemas


def create_database_if_not_exists() -> None:
    """Connect to 'master' and create ZKP_SBOM if it does not exist."""
    settings = get_db_settings()
    master_url = (
        f"mssql+pyodbc://{settings.user}:{settings.password}@{settings.host}:{settings.port}"
        f"/master?driver={settings.driver}&TrustServerCertificate=yes"
    )
    engine = create_engine(master_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        result = conn.execute(
            text(f"SELECT db_id('{settings.name}')")
        ).scalar()
        if result is None:
            print(f"Creating database '{settings.name}'...")
            conn.execute(text(f"CREATE DATABASE [{settings.name}]"))
            print(f"Database '{settings.name}' created.")
        else:
            print(f"Database '{settings.name}' already exists.")
    engine.dispose()


def run_alembic_upgrade() -> None:
    """Run alembic upgrade head."""
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=backend_dir,
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"Alembic error:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print("Alembic upgrade complete.")


def main() -> None:
    print("=== ZKP-SBOM Database Initialisation ===")
    print()

    # Step 1: Create database
    try:
        create_database_if_not_exists()
    except Exception as e:
        print(f"Could not connect to SQL Server: {e}")
        print("Ensure SQL Server is running and DB_* env vars are set.")
        sys.exit(1)

    # Step 2: Create schemas
    settings = get_db_settings()
    from shared.database import init_engine
    engine = init_engine(settings)
    ensure_schemas(engine)
    print("Logical schemas verified.")

    # Step 3: Run migrations
    run_alembic_upgrade()
    print()
    print("=== Initialisation complete ===")


if __name__ == "__main__":
    main()

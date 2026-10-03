"""
Alembic environment configuration for SQL Server 2022.

This env.py:
1. Overrides the sqlalchemy.url from shared config (no hard-coded credentials)
2. Imports ALL service models so autogenerate can see every table
3. Includes all five logical schemas in version_table_schema
"""

import sys
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text
from dotenv import load_dotenv

# Load environment variables
load_dotenv(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.env")))


# Ensure backend root is on the path for shared + service imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.config import get_db_settings
from shared.database import Base, SQL_SCHEMAS

# ------------------------------------------------------------------
# Import ALL models so Base.metadata has the complete picture.
# These imports cause the models to register with Base.
# ------------------------------------------------------------------
import sbom_service.app.models.sbom_models  # noqa: F401
import vulnerability_service.app.models.vulnerability_models  # noqa: F401
import policy_service.app.models.policy_models  # noqa: F401
import zkp_service.app.models.zkp_models  # noqa: F401
import verification_service.app.models.verification_models  # noqa: F401
import shared.models.user  # noqa: F401

# Alembic Config object
config = context.config

# Set up loggers from the config file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate
target_metadata = Base.metadata

# Override URL from environment (never hard-code credentials)
db_settings = get_db_settings()
config.set_main_option("sqlalchemy.url", db_settings.url.replace('%', '%%'))


def include_schemas(names):
    """Include all five project schemas in autogenerate."""
    names.add(None)  # default schema
    for schema in SQL_SCHEMAS:
        names.add(schema)
    return names


def include_name(name, type_, parent_names):
    """Ignore schemas/tables owned by Supabase or other external services."""
    if type_ == "schema":
        return name is None or name in SQL_SCHEMAS
    if type_ == "table":
        if name == "alembic_version":
            return False
        schema_name = parent_names.get("schema_name")
        return schema_name is None or schema_name in SQL_SCHEMAS
    return True


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (SQL script generation)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (direct DB connection)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # Ensure schemas exist before running migrations
        for schema in SQL_SCHEMAS:
            connection.execute(
                text(
                    f'CREATE SCHEMA IF NOT EXISTS "{schema}"'
                )
            )
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            include_name=include_name,
            version_table_schema="public",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

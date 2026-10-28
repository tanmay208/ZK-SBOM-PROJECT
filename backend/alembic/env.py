"""
Alembic environment configuration for PostgreSQL.

This env.py:
1. Overrides the sqlalchemy.url from shared config (no hard-coded credentials)
2. Imports ALL service models so autogenerate can see every table
3. Includes all five logical schemas in version_table_schema
4. Enforces staging migration safety via staging_guard helpers
"""

import sys
import os
from logging.config import fileConfig

# ---------------------------------------------------------------------------
# Path setup — established BEFORE importing staging_guard or shared modules.
# 1. alembic directory on sys.path allows importing local staging_guard.
# 2. backend directory on sys.path allows importing shared + service packages.
# ---------------------------------------------------------------------------
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

_backend_root = os.path.abspath(os.path.join(_this_dir, ".."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

from alembic import context
from sqlalchemy import engine_from_config, pool

from staging_guard import (
    load_environment,
    parse_staging_mode,
    validate_staging_target,
    verify_connection_identity,
    orchestrate_online_migrations,
    classify_online_command as _classify_online_command,
    validate_supplied_connection,
    StagingConfigError,
)

# Load environment variables via the staging guard.
# - Non-staging: loads ../../.env (existing behaviour).
# - STAGING_MODE=true: validates and loads ../../.env.staging.
# - Invalid STAGING_MODE: fails closed immediately.
load_environment()

# Cache staging flag for use in online/offline migration functions.
_is_staging = parse_staging_mode()

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
config = getattr(context, "config", None)

if config is not None:
    # Set up loggers from the config file
    if config.config_file_name is not None:
        fileConfig(config.config_file_name)

    # Target metadata for autogenerate
    target_metadata = Base.metadata

    # Override URL from environment (never hard-code credentials)
    # Only configure sqlalchemy.url from shared settings if no connection was explicitly supplied
    if "connection" in config.attributes:
        # Fail closed immediately if an invalid connection was supplied
        validate_supplied_connection(config.attributes["connection"])
    else:
        db_settings = get_db_settings()
        config.set_main_option("sqlalchemy.url", db_settings.url.replace('%', '%%'))
else:
    target_metadata = Base.metadata


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
    """Run migrations in 'offline' mode (SQL script generation).

    NOTE: Offline mode generates SQL without connecting to a server.
    URL validation cannot prove the identity of the server that will
    eventually execute the generated SQL.  Offline staging migrations
    require separate explicit operator approval.
    """
    if "connection" in config.attributes:
        raise RuntimeError(
            "Cannot run offline migrations with an externally supplied connection."
        )

    url = config.get_main_option("sqlalchemy.url")

    if _is_staging:
        # Validate the URL targets the staging database.
        # This uses structured URL parsing, not substring matching.
        from sqlalchemy.engine.url import make_url
        parsed = make_url(url)
        if parsed.database != "ZKP_SBOM_STAGING":
            raise RuntimeError(
                "Staging offline migration aborted: "
                "configured URL does not target ZKP_SBOM_STAGING."
            )

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
    # 1. Caller-supplied, already-verified connection path
    if "connection" in config.attributes:
        connection = validate_supplied_connection(config.attributes["connection"])

        # Pre-connection validation in staging mode:
        if _is_staging:
            validate_staging_target()
            verify_connection_identity(connection)

        is_inspect, _ = _classify_online_command(config, context)
        target_db = config.attributes.get("target_database")
        if not _is_staging:
            if not target_db or not str(target_db).strip():
                raise StagingConfigError(
                    "Target database identity ('target_database') is mandatory in config.attributes "
                    "for externally supplied connections in local development mode — aborting."
                )

        allow_unv = bool(
            config.attributes.get("allow_unversioned_baseline", False)
            or (os.environ.get("ALLOW_UNVERSIONED_BASELINE") == "true")
        )

        orchestrate_online_migrations(
            connectable=connection,
            is_staging=_is_staging,
            target_metadata=target_metadata,
            include_name=include_name,
            context=context,
            schemas=SQL_SCHEMAS,
            check_users_baseline=False if (is_inspect and not _is_staging) else True,
            create_schemas=not is_inspect,
            target_database=target_db,
            is_connection=True,
            allow_unversioned_baseline=allow_unv,
        )
        return

    # 2. Standard CLI path (no connection supplied)
    # Pre-connection validation: confirm the resolved environment
    # targets the staging database before creating an engine.
    if _is_staging:
        validate_staging_target()

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    is_inspect, _ = _classify_online_command(config, context)

    orchestrate_online_migrations(
        connectable=connectable,
        is_staging=_is_staging,
        target_metadata=target_metadata,
        include_name=include_name,
        context=context,
        schemas=SQL_SCHEMAS,
        check_users_baseline=False if (is_inspect and not _is_staging) else True,
        create_schemas=not is_inspect,
    )


if hasattr(context, "is_offline_mode") and getattr(context, "config", None) is not None:
    if context.is_offline_mode():
        run_migrations_offline()
    else:
        run_migrations_online()

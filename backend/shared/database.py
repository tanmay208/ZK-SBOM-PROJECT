"""
Database connection abstraction.

Provides a SQLAlchemy engine factory, session dependency for FastAPI,
and the declarative Base used by all service models.

All five services share ONE SQL Server 2022 instance (DATABASE_SCHEMA.md).
Logical separation is achieved through SQL schemas:
  sbom, vulnerability, policy, zkp, verification

Service names (sbom_service, etc.) are NOT the same as SQL schema names.
"""

from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from .config import DatabaseSettings, get_db_settings

Base = declarative_base()

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None

# The five logical SQL schemas mandated by DATABASE_SCHEMA.md
SQL_SCHEMAS = ("sbom", "vulnerability", "policy", "zkp", "verification")


def init_engine(settings: DatabaseSettings | None = None) -> Engine:
    """Create the module-level engine and session factory.

    Returns the engine so callers can inspect it if needed.
    """
    global _engine, _SessionLocal
    if settings is None:
        settings = get_db_settings()
    _engine = create_engine(
        settings.url,
        echo=settings.echo,
        pool_pre_ping=True,
    )
    _SessionLocal = sessionmaker(
        bind=_engine, autocommit=False, autoflush=False
    )
    return _engine


def get_engine() -> Engine:
    """Return the current engine, initialising if necessary."""
    if _engine is None:
        init_engine()
    return _engine


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    if _SessionLocal is None:
        init_engine()
    session = _SessionLocal()
    try:
        yield session
    finally:
        session.close()


def ensure_schemas(engine: Engine) -> None:
    """Create the five logical SQL schemas if they do not exist.

    SQL Server requires explicit schema creation before tables can
    reference them.  This is idempotent.
    """
    with engine.connect() as conn:
        for schema in SQL_SCHEMAS:
            conn.execute(
                text(
                    f'CREATE SCHEMA IF NOT EXISTS "{schema}"'
                )
            )
        conn.commit()

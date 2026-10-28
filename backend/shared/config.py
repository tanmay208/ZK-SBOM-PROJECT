"""
Centralized configuration management.

Loads settings from environment variables with sensible defaults
for development. No credentials are hard-coded; all secrets must
come from the environment or a .env file loaded by the caller.

SECURITY_BOUNDARY.md §6, DEVELOPMENT_RULES.md §19:
  - DB_PASSWORD must never be logged, printed, or returned in responses.
  - The `safe_url` property and `__repr__` mask the password.
  - `validate_config()` fails closed on missing critical secrets.
"""

from __future__ import annotations

import logging
import os
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.engine import URL

logger = logging.getLogger(__name__)

SUPPORTED_SSL_MODES = frozenset(
    {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
)


@dataclass(frozen=True)
class DatabaseSettings:
    """PostgreSQL connection parameters."""

    host: str = field(default_factory=lambda: os.getenv("DB_HOST", "localhost"))
    port: int = field(
        default_factory=lambda: int(os.getenv("DB_PORT", "5432"))
    )
    user: str = field(default_factory=lambda: os.getenv("DB_USER", "postgres"))
    password: str = field(
        default_factory=lambda: os.getenv("DB_PASSWORD", "")
    )
    name: str = field(
        default_factory=lambda: os.getenv("DB_NAME", "ZKP_SBOM")
    )
    ssl_mode: str = field(
        default_factory=lambda: os.getenv("DB_SSL_MODE", "require")
    )
    ssl_root_cert: str | None = field(
        default_factory=lambda: os.getenv("DB_SSL_ROOT_CERT")
    )
    echo: bool = field(
        default_factory=lambda: os.getenv("DB_ECHO", "false").lower() == "true"
    )

    @property
    def normalized_ssl_mode(self) -> str:
        """Return the normalized lowercase and stripped SSL mode."""
        return self.ssl_mode.strip().lower() if self.ssl_mode else ""

    def validate_tls(self) -> None:
        """Validate TLS configuration and fail closed on invalid settings."""
        mode = self.normalized_ssl_mode
        if mode not in SUPPORTED_SSL_MODES:
            raise ConfigurationError(
                f"Invalid DB_SSL_MODE '{self.ssl_mode}'; must be one of {sorted(SUPPORTED_SSL_MODES)}"
            )

        if mode in ("verify-ca", "verify-full"):
            if not self.ssl_root_cert or not self.ssl_root_cert.strip():
                raise ConfigurationError(
                    f"DB_SSL_ROOT_CERT is required when DB_SSL_MODE is '{self.ssl_mode}'"
                )
            cert_path = self.ssl_root_cert.strip()
            if not os.path.exists(cert_path) or not os.path.isfile(cert_path):
                raise ConfigurationError(
                    "Configured DB_SSL_ROOT_CERT does not exist or is not a regular file"
                )
            if not os.access(cert_path, os.R_OK):
                raise ConfigurationError(
                    "Configured DB_SSL_ROOT_CERT is not readable"
                )
            if os.path.getsize(cert_path) == 0:
                raise ConfigurationError(
                    "Configured DB_SSL_ROOT_CERT file is empty"
                )

    def as_url(self) -> URL:
        """Return a SQLAlchemy URL object with safely encoded components."""
        self.validate_tls()
        query: dict[str, str] = {"sslmode": self.normalized_ssl_mode}
        if self.ssl_root_cert and self.ssl_root_cert.strip():
            query["sslrootcert"] = self.ssl_root_cert.strip()
        return URL.create(
            drivername="postgresql+psycopg2",
            username=self.user,
            password=self.password,
            host=self.host,
            port=self.port,
            database=self.name,
            query=query,
        )

    @property
    def url(self) -> str:
        """Serialized connection URL string."""
        return self.as_url().render_as_string(hide_password=False)

    @property
    def safe_url(self) -> str:
        """Connection string with the password masked for safe logging."""
        raw = self.as_url().render_as_string(hide_password=True)
        return raw.replace(":***@", ":****@")

    @property
    def connect_args(self) -> dict[str, Any]:
        """Connection arguments suitable for psycopg2 / create_engine(..., connect_args=...)."""
        self.validate_tls()
        args: dict[str, Any] = {"sslmode": self.normalized_ssl_mode}
        if self.ssl_root_cert and self.ssl_root_cert.strip():
            args["sslrootcert"] = self.ssl_root_cert.strip()
        return args

    def __repr__(self) -> str:
        """Mask password in repr to prevent accidental credential leakage."""
        return (
            f"DatabaseSettings(host={self.host!r}, port={self.port!r}, "
            f"user={self.user!r}, password='****', name={self.name!r}, "
            f"ssl_mode={self.ssl_mode!r}, ssl_root_cert={self.ssl_root_cert!r})"
        )

    def __str__(self) -> str:
        """Mask password in str output."""
        return self.__repr__()


@dataclass(frozen=True)
class ServiceSettings:
    """Per-service runtime configuration."""

    service_name: str
    host: str = field(
        default_factory=lambda: os.getenv("SERVICE_HOST", "0.0.0.0")
    )
    port: int = field(
        default_factory=lambda: int(os.getenv("SERVICE_PORT", "8000"))
    )
    debug: bool = field(
        default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true"
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )


def get_settings(service_name: str) -> ServiceSettings:
    """Build a ServiceSettings instance for the named service."""
    return ServiceSettings(service_name=service_name)


def get_db_settings() -> DatabaseSettings:
    """Build a DatabaseSettings instance from the environment."""
    return DatabaseSettings()


class ConfigurationError(RuntimeError):
    """Raised when a critical configuration value is missing or invalid."""
    pass


_INSECURE_SECRET_PLACEHOLDERS = frozenset(
    {
        "default_insecure_jwt_secret",
        "default_insecure_cert_secret",
        "test_secret",
        "change_me",
        "changeme",
        "password",
        "secret",
        "your_secret_here",
    }
)


def _secret_is_repeated(value: str) -> bool:
    """Return whether *value* consists entirely of a short repeated pattern."""
    for pattern_length in range(1, min(16, len(value) // 2) + 1):
        if len(value) % pattern_length == 0:
            pattern = value[:pattern_length]
            if pattern * (len(value) // pattern_length) == value:
                return True
    return False


def _secret_error(name: str, value: str) -> str | None:
    """Return a validation error for a weak secret without exposing its value."""
    if not value or not value.strip():
        return f"{name} must not be empty or whitespace-only"
    if len(value) < 32:
        return f"{name} must be at least 32 characters"
    if value.strip().lower() in _INSECURE_SECRET_PLACEHOLDERS:
        return f"{name} must not use a placeholder value"
    if _secret_is_repeated(value):
        return f"{name} must not use a trivial or repeated value"
    return None


def validate_config(db_settings: DatabaseSettings | None = None) -> DatabaseSettings:
    """Validate critical configuration and fail closed on errors.

    Raises ConfigurationError if:
      - DB_PASSWORD is empty or unset
      - DB_HOST is empty
      - DB_NAME is empty
      - JWT_SECRET_KEY or CERTIFICATE_SECRET_KEY is weak, missing, or shared

    This enforces DEVELOPMENT_RULES.md §19 (no sensitive data fallbacks)
    and the general fail-closed security posture.
    """
    if db_settings is None:
        db_settings = get_db_settings()

    errors: list[str] = []

    if not db_settings.password:
        errors.append("DB_PASSWORD is not set — refusing to start with empty password")

    if not db_settings.host:
        errors.append("DB_HOST is not set")

    if not db_settings.name:
        errors.append("DB_NAME is not set")

    # Enforce strict local database isolation allowlists
    environment = os.environ.get("ENVIRONMENT", "").strip().lower()
    if environment == "local_dev":
        if db_settings.name != "ZKP_SBOM_LOCAL_DEV":
            errors.append(
                f"Local development mode (ENVIRONMENT=local_dev) must target database "
                f"'ZKP_SBOM_LOCAL_DEV', but got '{db_settings.name}'."
            )
        host_norm = db_settings.host.strip().lower()
        if host_norm == "127.0.0.1":
            if db_settings.port != 5433:
                errors.append(
                    f"Local development mode on host (127.0.0.1) must target port 5433 (disposable instance), "
                    f"but got port {db_settings.port}. Connecting to protected port 5432 is strictly prohibited."
                )
        elif host_norm == "zkp_sbom_local_dev":
            if db_settings.port != 5432:
                errors.append(
                    f"Local development mode in container must target internal port 5432 on host 'zkp_sbom_local_dev', "
                    f"but got port {db_settings.port}."
                )
        else:
            errors.append(
                f"Local development mode (ENVIRONMENT=local_dev) only permits host '127.0.0.1' (port 5433) "
                f"or 'zkp_sbom_local_dev' (port 5432), but got '{db_settings.host}'."
            )
    elif environment == "stage_g":
        if db_settings.port == 5433:
            errors.append(
                "Stage G authoritative mode (ENVIRONMENT=stage_g) prohibits targeting "
                "port 5433 (PostgreSQL 16 development instance). "
                "Authoritative operations require PostgreSQL 17."
            )
        if db_settings.name == "ZKP_SBOM_LOCAL_DEV":
            errors.append(
                "Stage G authoritative mode (ENVIRONMENT=stage_g) prohibits targeting "
                "database 'ZKP_SBOM_LOCAL_DEV'. Authoritative operations require PostgreSQL 17."
            )
        host_norm = db_settings.host.strip().lower()
        if host_norm not in ("127.0.0.1", "localhost"):
            if db_settings.normalized_ssl_mode in ("disable", "allow"):
                errors.append(
                    f"Stage G authoritative mode on remote target '{db_settings.host}' "
                    f"prohibits insecure SSL mode '{db_settings.ssl_mode}'. "
                    "Must be 'require', 'verify-ca', or 'verify-full'."
                )

    try:
        db_settings.validate_tls()
    except ConfigurationError as err:
        errors.append(str(err))
        
    jwt_secret = os.environ.get("JWT_SECRET_KEY", "")
    cert_secret = os.environ.get("CERTIFICATE_SECRET_KEY", "")
    for secret_name, secret_value in (
        ("JWT_SECRET_KEY", jwt_secret),
        ("CERTIFICATE_SECRET_KEY", cert_secret),
    ):
        secret_error = _secret_error(secret_name, secret_value)
        if secret_error:
            errors.append(
                f"{secret_error}; strong, unique secrets are required in all modes"
            )

    if jwt_secret and cert_secret and jwt_secret == cert_secret:
        errors.append(
            "JWT_SECRET_KEY and CERTIFICATE_SECRET_KEY must be separate values"
        )

    if errors:
        # Log the errors but never log the actual values
        for err in errors:
            logger.error("Configuration validation failed: %s", err)
        raise ConfigurationError(
            "Critical configuration missing. "
            f"{len(errors)} error(s): {'; '.join(errors)}"
        )

    # Validate crypto profile to fail closed on invalid profiles
    from .crypto.config import get_crypto_profile
    try:
        get_crypto_profile()
    except Exception as e:
        logger.error("Crypto profile validation failed: %s", str(e))
        raise ConfigurationError(f"Invalid crypto profile: {e}")

    # Log safe connection info for operational visibility
    logger.info("Configuration validated — connecting to %s", db_settings.safe_url)
    return db_settings

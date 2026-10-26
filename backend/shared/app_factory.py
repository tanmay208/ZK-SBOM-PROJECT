"""
FastAPI application factory.

Creates a consistently configured FastAPI instance for any service,
wiring up:
  - API versioning prefix
  - exception handlers
  - health endpoint
  - structured logging
  - security middleware (headers, request-size limits)
  - lifespan hooks with audit logging
  - fail-closed configuration validation
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import os
from typing import AsyncIterator

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_db_settings, get_settings, validate_config
from .database import init_engine
from .exceptions import register_exception_handlers
from .logging import audit_log, setup_logging
from .schemas import HealthResponse
from .security import (
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)

APP_VERSION = "0.1.0"


def create_app(
    service_name: str,
    title: str,
    description: str,
    *,
    domain_router: APIRouter | None = None,
) -> FastAPI:
    """
    Build a fully-wired FastAPI application for *service_name*.

    Parameters
    ----------
    service_name:
        Identifier matching the architecture (e.g. ``sbom_service``).
    title:
        Human-readable title shown in OpenAPI docs.
    description:
        Short description shown in OpenAPI docs.
    domain_router:
        Optional APIRouter carrying the service's domain routes.
        Mounted under ``/api/v1/{prefix}``.
    """
    settings = get_settings(service_name)
    logger = setup_logging(service_name, level=settings.log_level)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        audit_log(service_name, "startup", f"Starting {service_name}")
        try:
            db_settings = get_db_settings()
            # Validate configuration — fail closed on missing secrets
            validate_config(db_settings)
            
            from .crypto.config import get_crypto_profile
            # Validates CRYPTO_PROFILE and all associated artifacts/VK hashes
            get_crypto_profile()
            

            
            init_engine(db_settings)
            audit_log(service_name, "db_init", "Database engine initialised")
        except Exception as exc:
            # Log the failure type but not credentials
            logger.error(
                "Application failed to initialize (%s) — "
                "service cannot start.",
                type(exc).__name__,
            )
            raise exc
        yield
        audit_log(service_name, "shutdown", f"Shutting down {service_name}")

    app = FastAPI(
        title=title,
        description=description,
        version=APP_VERSION,
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )

    # --- Security middleware ------------------------------------------
    # Order matters: security headers wrap everything, size limit is inner.
    cors_origins_raw = os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000"
    )
    allowed_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        # The session contract uses an Authorization header, not cookies.
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    # RequestSizeLimitMiddleware is a raw ASGI middleware (Stage 4.7 hardened)
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=10 * 1024 * 1024)

    # --- Exception handlers -------------------------------------------
    register_exception_handlers(app)

    # --- Health endpoint ----------------------------------------------
    health_router = APIRouter()

    @health_router.get(
        "/api/v1/health",
        response_model=HealthResponse,
        tags=["health"],
    )
    async def health() -> HealthResponse:
        return HealthResponse(
            service=service_name,
            status="healthy",
            version=APP_VERSION,
        )

    app.include_router(health_router)

    # --- Domain router ------------------------------------------------
    if domain_router is not None:
        app.include_router(domain_router)

    return app

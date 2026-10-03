"""
Centralized exception handling for FastAPI services.

Registers global exception handlers that return safe, structured
JSON error responses.  Stack traces and internal details are never
exposed (SECURITY_BOUNDARY.md §6, DEVELOPMENT_RULES.md §19-§20).

All unhandled exceptions are logged server-side for operational
visibility while returning a generic message to the client.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import json

from .security import InputValidationError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class ServiceError(Exception):
    """Base exception for domain-level service errors."""

    def __init__(
        self,
        detail: str,
        status_code: int = 400,
        error_code: str = "BAD_REQUEST",
    ) -> None:
        self.detail = detail
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(detail)


class NotFoundError(ServiceError):
    """Resource not found."""

    def __init__(self, detail: str = "Resource not found") -> None:
        super().__init__(detail=detail, status_code=404, error_code="NOT_FOUND")


class ConflictError(ServiceError):
    """Conflicting state."""

    def __init__(self, detail: str = "Conflict") -> None:
        super().__init__(detail=detail, status_code=409, error_code="CONFLICT")


class ValidationError(ServiceError):
    """Request validation failure."""

    def __init__(self, detail: str = "Validation error") -> None:
        super().__init__(
            detail=detail, status_code=422, error_code="VALIDATION_ERROR"
        )


class ForbiddenError(ServiceError):
    """Operation not permitted."""

    def __init__(self, detail: str = "Forbidden") -> None:
        super().__init__(detail=detail, status_code=403, error_code="FORBIDDEN")


# ---------------------------------------------------------------------------
# Handler registration
# ---------------------------------------------------------------------------

def register_exception_handlers(app: FastAPI) -> None:
    """Attach safe global exception handlers to *app*.

    Response format is always:
        {"error": "<safe message>", "code": "<ERROR_CODE>"}

    SECURITY_BOUNDARY.md §6:
      - Never return stack traces
      - Never return internal connection strings
      - Never return credentials
    """

    @app.exception_handler(ServiceError)
    async def _service_error_handler(
        _request: Request, exc: ServiceError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "code": exc.error_code},
        )

    @app.exception_handler(InputValidationError)
    async def _input_validation_handler(
        _request: Request, exc: InputValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": f"Invalid {exc.field}: {exc.detail}",
                "code": "VALIDATION_ERROR",
            },
        )

    @app.exception_handler(RequestValidationError)
    async def _request_validation_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # FastAPI's default RequestValidationError exposes `input` which can leak 
        # private SBOM fields or credentials. We construct a safe generic response.
        errors = []
        for error in exc.errors():
            safe_error = {
                "loc": error.get("loc", []),
                "msg": error.get("msg", "Invalid input"),
                "type": error.get("type", "value_error")
            }
            errors.append(safe_error)
            
        return JSONResponse(
            status_code=422,
            content={
                "error": "Request validation failed",
                "code": "VALIDATION_ERROR",
                "details": errors
            },
        )

    @app.exception_handler(json.JSONDecodeError)
    async def _json_decode_error_handler(
        _request: Request, exc: json.JSONDecodeError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "Malformed JSON",
                "code": "VALIDATION_ERROR",
            },
        )

    @app.exception_handler(HTTPException)
    async def _http_error_handler(
        _request: Request, exc: HTTPException
    ) -> JSONResponse:
        code_by_status = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            409: "CONFLICT",
            413: "REQUEST_TOO_LARGE",
            422: "VALIDATION_ERROR",
            429: "RATE_LIMITED",
            502: "BAD_GATEWAY",
            503: "SERVICE_UNAVAILABLE",
        }
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
        headers = exc.headers or {}
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": detail,
                "code": code_by_status.get(exc.status_code, "HTTP_ERROR"),
            },
            headers=headers,
        )

    @app.exception_handler(Exception)
    async def _unhandled_error_handler(
        _request: Request, exc: Exception
    ) -> JSONResponse:
        # Log the exception type and message server-side for debugging.
        # Never expose the details to the client.
        logger.error(
            "Unhandled exception: %s: %s",
            type(exc).__name__,
            str(exc)[:200],  # Truncate to prevent log flooding
        )
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "code": "INTERNAL_ERROR"},
        )

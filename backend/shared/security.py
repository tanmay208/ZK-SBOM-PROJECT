"""
Shared security infrastructure.

Implements the application-level security controls mandated by:
  - SECURITY_BOUNDARY.md §1–§6 (data classification, boundary enforcement)
  - DEVELOPMENT_RULES.md §3, §4, §19, §20 (private data handling)
  - THREAT_MODEL.md §13, §14 (log/API leakage prevention)

This module provides:
  - Data classification constants and sanitisation utilities
  - Input validators for identifiers and hashes
  - FastAPI middleware for request-size limits and security headers
  - Service-boundary classification enum

CRITICAL: This is the application security layer only.
It does NOT implement ZKP protocol security, proof generation,
proof verification, or cryptographic commitments.
"""

from __future__ import annotations

import enum
import logging
import re
import uuid
from typing import Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


# ---------------------------------------------------------------------------
# §1 — Data classification patterns
# ---------------------------------------------------------------------------
# Terms that MUST NEVER appear in logs or buyer-facing API responses.
# These are checked by the SecurityAwareFilter attached to all loggers
# and by sanitize_log_message().
#
# SECURITY_BOUNDARY.md §1 Private Data list:
#   Raw SBOM files, component names/versions/identities, PURLs,
#   dependency relationships, vulnerability witness info, Merkle/SMT paths,
#   the complete ZKP private witness, internal processing data.
#
# We match on structural patterns (purl schemes, key names) rather than
# trying to enumerate every possible component name.

PRIVATE_DATA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"pkg:[a-z]+/", re.IGNORECASE),          # PURL scheme
    re.compile(r"private_witness", re.IGNORECASE),       # ZKP witness
    re.compile(r"merkle_path", re.IGNORECASE),           # Merkle paths
    re.compile(r"smt_proof", re.IGNORECASE),             # SMT proofs
    re.compile(r"witness_data", re.IGNORECASE),          # witness payload
    re.compile(r"raw_sbom", re.IGNORECASE),              # raw SBOM content
    re.compile(r"dependency_graph", re.IGNORECASE),      # dep graphs
    re.compile(r"component_hash\"?\s*:\s*\"[0-9a-f]{32,}", re.IGNORECASE),
]

# Additional keywords that must never appear in buyer-side responses
PRIVATE_FIELD_NAMES = frozenset({
    "raw_content", "purl", "purl_canonical", "component_hash",
    "component_name", "component_version", "dependency_graph",
    "private_witness", "merkle_path", "smt_proof", "witness_data",
})


# ---------------------------------------------------------------------------
# §2 — Service boundary classification
# ---------------------------------------------------------------------------

class ServiceBoundary(str, enum.Enum):
    """Classifies each service per SECURITY_BOUNDARY.md §3."""
    VENDOR = "vendor"    # Processes private data
    BUYER = "buyer"      # Operates strictly on public data
    MIXED = "mixed"      # Ingests private, outputs public


# Authoritative mapping from SECURITY_BOUNDARY.md §3
SERVICE_BOUNDARIES: dict[str, ServiceBoundary] = {
    "sbom_service":          ServiceBoundary.VENDOR,
    "vulnerability_service": ServiceBoundary.MIXED,
    "policy_service":        ServiceBoundary.BUYER,
    "zkp_service":           ServiceBoundary.MIXED,
    "verification_service":  ServiceBoundary.BUYER,
}


def get_service_boundary(service_name: str) -> ServiceBoundary:
    """Return the data-classification boundary for *service_name*."""
    return SERVICE_BOUNDARIES.get(service_name, ServiceBoundary.VENDOR)


# ---------------------------------------------------------------------------
# §3 — Sanitisation utilities
# ---------------------------------------------------------------------------

_REDACTED = "[REDACTED]"


def sanitize_log_message(message: str) -> str:
    """Scrub *message* of any private-data patterns.

    Returns the cleaned message.  If a pattern is found the matching
    portion is replaced with [REDACTED].
    """
    for pattern in PRIVATE_DATA_PATTERNS:
        message = pattern.sub(_REDACTED, message)
    return message


def mask_connection_string(conn_str: str) -> str:
    """Replace password values in ODBC-style connection strings."""
    return re.sub(
        r"(PWD|Password|DB_PASSWORD)\s*=\s*[^;&]+",
        r"\1=****",
        conn_str,
        flags=re.IGNORECASE,
    )


# ---------------------------------------------------------------------------
# §4 — Logging filter
# ---------------------------------------------------------------------------

class SecurityAwareFilter(logging.Filter):
    """Logging filter that redacts private data from log records.

    Attached to all service loggers to enforce SECURITY_BOUNDARY.md §6
    and DEVELOPMENT_RULES.md §19.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg and isinstance(record.msg, str):
            record.msg = sanitize_log_message(record.msg)
        # Also sanitise args if they are strings
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: sanitize_log_message(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    sanitize_log_message(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        return True  # Always emit (after redaction)


# ---------------------------------------------------------------------------
# §5 — Input validators
# ---------------------------------------------------------------------------

class InputValidationError(ValueError):
    """Raised when user input fails validation."""

    def __init__(self, field: str, detail: str) -> None:
        self.field = field
        self.detail = detail
        super().__init__(f"Invalid {field}: {detail}")


def validate_uuid(value: str, field_name: str = "id") -> uuid.UUID:
    """Parse and validate a UUID string.

    Raises InputValidationError on malformed input.
    Prevents SQL injection via malformed identifiers.
    """
    if not isinstance(value, str):
        raise InputValidationError(field_name, "must be a string")
    # Strip whitespace
    value = value.strip()
    # Reject obviously malicious input
    if len(value) > 50:
        raise InputValidationError(field_name, "invalid format")
    try:
        return uuid.UUID(value, version=4)
    except (ValueError, AttributeError):
        raise InputValidationError(field_name, "must be a valid UUID v4")


def validate_hex_hash(
    value: str,
    *,
    expected_length: int | None = None,
    field_name: str = "hash",
) -> str:
    """Validate a hex-encoded hash string.

    Returns the lowercased, validated hex string.
    """
    if not isinstance(value, str):
        raise InputValidationError(field_name, "must be a string")
    value = value.strip().lower()
    if not value:
        raise InputValidationError(field_name, "must not be empty")
    if expected_length is not None and len(value) != expected_length:
        raise InputValidationError(
            field_name,
            f"must be exactly {expected_length} hex characters",
        )
    if not re.fullmatch(r"[0-9a-f]+", value):
        raise InputValidationError(field_name, "must contain only hex characters")
    if len(value) > 256:
        raise InputValidationError(field_name, "exceeds maximum length")
    return value


class OversizedRequestError(Exception):
    """Raised when the request body exceeds the maximum allowed size."""
    pass


# ---------------------------------------------------------------------------
# §6 — FastAPI middleware
# ---------------------------------------------------------------------------

class RequestSizeLimitMiddleware:
    """Reject request bodies exceeding a configurable size limit.

    Default: 10 MB.  Prevents denial-of-service via oversized uploads
    before the application layer has to process them.

    SECURITY HARDENING (Stage 4.7):
      The original implementation only checked the Content-Length header,
      which is trivially bypassed by omitting the header or using chunked
      transfer encoding. This version:
        1. Checks Content-Length header as a fast reject path.
        2. Actually reads and bounds the request body stream.
        3. Replaces the body so downstream handlers see the already-read bytes.

    Effective limit: 10 MB (10,485,760 bytes) by default.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int = 10 * 1024 * 1024) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast reject: check Content-Length header if present
        headers = dict(
            (k.lower(), v) for k, v in
            [(h[0].decode("latin-1"), h[1].decode("latin-1"))
             for h in scope.get("headers", [])]
        )
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    response = Response(
                        content='{"error": "Request body too large", "code": "REQUEST_TOO_LARGE"}',
                        status_code=413,
                        media_type="application/json",
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                pass  # Malformed header — continue to body check

        # Body-level enforcement: actually read and bound the stream
        body_size = 0
        oversized = False

        async def bounded_receive():
            nonlocal body_size, oversized
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                body_size += len(chunk)
                if body_size > self.max_bytes:
                    oversized = True
                    raise OversizedRequestError()
            return message

        response_started = False
        body_sent = False
        async def bounded_send(message):
            nonlocal response_started, body_sent
            if oversized:
                body_bytes = b'{"error": "Request body too large", "code": "REQUEST_TOO_LARGE"}'
                # Intercept downstream error response generated by the framework
                # when it catches OversizedRequestError. We rewrite it to 413.
                if message["type"] == "http.response.start":
                    message["status"] = 413
                    headers = [
                        (k, v) for k, v in message.get("headers", [])
                        if k.lower() != b"content-length"
                    ]
                    headers.append((b"content-length", str(len(body_bytes)).encode("latin-1")))
                    message["headers"] = headers
                elif message["type"] == "http.response.body":
                    if not body_sent:
                        message["body"] = body_bytes
                        body_sent = True
                    else:
                        message["body"] = b""
                        message["more_body"] = False
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            # Wrap receive to enforce limit during body consumption
            await self.app(scope, bounded_receive, bounded_send)
        except OversizedRequestError:
            if response_started:
                # If we detected oversized body during processing and the response
                # has already started, we must close the connection.
                raise
            
            response = Response(
                content='{"error": "Request body too large", "code": "REQUEST_TOO_LARGE"}',
                status_code=413,
                media_type="application/json",
            )
            await response(scope, receive, send)
            return

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to every response.

    Follows OWASP secure-headers recommendations relevant to an API service.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

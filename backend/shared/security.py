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
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE),  # Authorization Bearer tokens
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+"),  # JWT-shaped tokens
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
        # Also sanitise args if they are strings or structured containers
        if record.args:
            if isinstance(record.args, dict):
                sanitized_dict = {}
                for k, v in record.args.items():
                    k_str = str(k).lower()
                    if k_str in PRIVATE_FIELD_NAMES or any(
                        s in k_str for s in ("password", "secret", "token", "certificate_data")
                    ):
                        sanitized_dict[k] = _REDACTED
                    elif isinstance(v, str):
                        sanitized_dict[k] = sanitize_log_message(v)
                    else:
                        sanitized_dict[k] = v
                record.args = sanitized_dict
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
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response


# ---------------------------------------------------------------------------
# §5 — Application-Layer Rate Limiting (Stage G3)
# ---------------------------------------------------------------------------

import os
import time
import threading
from collections import defaultdict, deque
from fastapi import HTTPException, status


class RateLimiter:
    """
    Thread-safe, sliding-window in-memory rate limiter with Retry-After calculation.

    Architectural boundary disclosure (Stage G3):
    In single-process execution (and test fixtures), this provides strict in-process
    rate limiting. In a multi-worker distributed container deployment, a distributed
    shared state backend (e.g. Redis) or reverse-proxy throttling (e.g. Nginx limit_req)
    is the required deployment prerequisite.
    """

    def __init__(self, max_requests: int, window_seconds: int, scope: str = "default"):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.scope = scope
        self._history = defaultdict(deque)
        self._lock = threading.Lock()

    def get_client_identifier(self, request: Request, user_id: str | None = None) -> str:
        """
        Derive client identifier safely:
        - If user_id is provided (authenticated routes), key on user_id.
        - For unauthenticated routes, use request.client.host.
        - Do NOT blindly trust arbitrary client-supplied forwarding headers unless
          the direct peer IP is explicitly configured in TRUSTED_PROXIES.
        """
        if user_id:
            return f"user:{user_id}"

        client_ip = request.client.host if request.client else "127.0.0.1"
        trusted_proxies_raw = os.environ.get("TRUSTED_PROXIES", "")
        if trusted_proxies_raw:
            trusted_proxies = {p.strip() for p in trusted_proxies_raw.split(",") if p.strip()}
            if client_ip in trusted_proxies:
                forwarded_for = request.headers.get("X-Forwarded-For")
                if forwarded_for:
                    client_ip = forwarded_for.split(",")[0].strip()
        return f"ip:{client_ip}"

    def check(self, request: Request, user_id: str | None = None) -> None:
        """
        Evaluate rate limit against the client identifier.
        Raises HTTPException(429) with Retry-After header if limit exceeded.
        """
        if os.environ.get("DISABLE_RATE_LIMITS", "false").lower() == "true":
            return

        identifier = self.get_client_identifier(request, user_id=user_id)
        now = time.time()
        key = f"{self.scope}:{identifier}"

        with self._lock:
            queue = self._history[key]
            cutoff = now - self.window_seconds
            while queue and queue[0] <= cutoff:
                queue.popleft()

            if len(queue) >= self.max_requests:
                oldest_in_window = queue[0]
                retry_after = max(1, int(oldest_in_window + self.window_seconds - now))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )

            queue.append(now)

    def reset(self, identifier: str | None = None) -> None:
        """Reset history for testing or manual recovery."""
        with self._lock:
            if identifier is None:
                self._history.clear()
            else:
                self._history.pop(f"{self.scope}:{identifier}", None)


# Pre-configured scoped rate limiters
login_rate_limiter = RateLimiter(max_requests=10, window_seconds=60, scope="auth_login")
register_rate_limiter = RateLimiter(max_requests=10, window_seconds=60, scope="auth_register")
zkp_generate_rate_limiter = RateLimiter(max_requests=10, window_seconds=60, scope="zkp_generate")


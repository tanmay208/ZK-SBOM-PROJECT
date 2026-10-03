"""
Structured logging configuration.

SECURITY_BOUNDARY.md §6 — Logging Restrictions:
Application logs must NEVER contain Private Data (component names,
PURLs, private hashes, Merkle paths).  This module configures a
JSON-structured logger with sensible defaults.

All loggers are protected by a SecurityAwareFilter that redacts
classified data patterns before they reach any handler.
"""

from __future__ import annotations

import logging
import sys

from .security import SecurityAwareFilter


def setup_logging(service_name: str, level: str = "INFO") -> logging.Logger:
    """Return a configured, security-filtered logger for *service_name*."""
    logger = logging.getLogger(service_name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt=(
                '{"timestamp":"%(asctime)s",'
                '"level":"%(levelname)s",'
                '"service":"%(name)s",'
                '"message":"%(message)s"}'
            ),
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        # Attach the security filter to prevent private-data leakage
        handler.addFilter(SecurityAwareFilter())
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger


def audit_log(service_name: str, event: str, detail: str = "") -> None:
    """Emit a structured audit-level log entry.

    Used for security-relevant events such as:
      - configuration validation outcomes
      - service startup / shutdown
      - request rejection (oversized, malformed)
      - authentication/authorisation boundaries (future)

    SECURITY_BOUNDARY.md §6: Detail must not contain private data.
    The SecurityAwareFilter provides a safety net, but callers should
    avoid passing classified information in the first place.
    """
    logger = logging.getLogger(f"{service_name}.audit")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt=(
                '{"timestamp":"%(asctime)s",'
                '"level":"%(levelname)s",'
                '"service":"%(name)s",'
                '"event":"' + event + '",'
                '"message":"%(message)s"}'
            ),
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(SecurityAwareFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    logger.info("%s: %s", event, detail)

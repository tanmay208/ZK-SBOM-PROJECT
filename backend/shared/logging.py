"""
Structured logging configuration.

SECURITY_BOUNDARY.md §6 — Logging Restrictions:
Application logs must NEVER contain Private Data (component names,
PURLs, private hashes, Merkle paths).  This module configures a
JSON-structured logger with sensible defaults.

All loggers are protected by a SecurityAwareFilter that redacts
classified data patterns before they reach any handler.
"""
import json
import logging
import sys
from typing import Any

from .security import SecurityAwareFilter, sanitize_log_message


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


class AuditJsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured security audit logs.

    Dynamically extracts structured audit metadata from LogRecord attributes,
    formats a clean JSON object, and ensures all fields are redacted against
    private data patterns before output.
    """

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%SZ")
        event = getattr(record, "audit_event", record.getMessage())
        actor_id = getattr(record, "actor_id", None)
        resource_type = getattr(record, "resource_type", None)
        resource_id = getattr(record, "resource_id", None)
        outcome = getattr(record, "outcome", "success")

        # Format message string safely
        msg = record.getMessage()

        # Build structured event dictionary
        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "service": record.name,
            "event": sanitize_log_message(str(event)) if event else "",
            "outcome": str(outcome),
            "message": sanitize_log_message(msg),
        }
        if actor_id is not None:
            payload["actor_id"] = sanitize_log_message(str(actor_id))
        if resource_type is not None:
            payload["resource_type"] = sanitize_log_message(str(resource_type))
        if resource_id is not None:
            payload["resource_id"] = sanitize_log_message(str(resource_id))

        # Include any extra non-private metadata attached to record
        audit_extra = getattr(record, "audit_extra", None)
        if isinstance(audit_extra, dict):
            for k, v in audit_extra.items():
                k_clean = str(k).lower()
                if any(s in k_clean for s in ("token", "secret", "password", "key", "cert", "raw_sbom", "proof")):
                    payload[k] = "[REDACTED]"
                elif isinstance(v, str):
                    payload[k] = sanitize_log_message(v)
                else:
                    payload[k] = v

        return json.dumps(payload, separators=(",", ":"))


def audit_log(
    service_name: str,
    event: str,
    detail: str = "",
    *,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    outcome: str = "success",
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit a structured audit-level log entry for critical security events.

    Used for security-relevant operations including:
      - vulnerability snapshot ingestion, approval, freezing, and revocation
      - verification certificate issuance and revocation
      - administrator user-role and account-status changes
      - authentication/authorisation security boundaries

    SECURITY_BOUNDARY.md §6 & D7-2 Requirements:
      - Never log credentials, bearer tokens, JWTs, signing keys, private SBOM contents,
        proof bytes, or raw request payloads.
      - Detail and all attributes are passed through SecurityAwareFilter and sanitization.

    Fail-Safe Audit Logging Policy:
      Audit logging failures must never abort an already committed business operation
      or produce misleading status responses. In the event of an unexpected logging
      infrastructure failure, an emergency diagnosis is written to sys.stderr, and
      execution continues safely.
    """
    try:
        logger = logging.getLogger(f"{service_name}.audit")
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(AuditJsonFormatter(datefmt="%Y-%m-%dT%H:%M:%SZ"))
            handler.addFilter(SecurityAwareFilter())
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
        else:
            # Ensure existing handlers use AuditJsonFormatter
            for h in logger.handlers:
                if not isinstance(h.formatter, AuditJsonFormatter):
                    h.setFormatter(AuditJsonFormatter(datefmt="%Y-%m-%dT%H:%M:%SZ"))

        # Attach structured fields via extra dictionary
        record_extra = {
            "audit_event": event,
            "actor_id": actor_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "audit_extra": extra,
        }
        if detail:
            logger.info("%s: %s", event, detail, extra=record_extra)
        else:
            logger.info("%s", event, extra=record_extra)
    except Exception as exc:
        # Failure policy: Do not crash business operations on audit logging errors;
        # emit emergency diagnosis to stderr.
        try:
            sys.stderr.write(f"[AUDIT_LOG_FAILURE] service={service_name} event={event} error={exc}\n")
            sys.stderr.flush()
        except Exception:
            pass

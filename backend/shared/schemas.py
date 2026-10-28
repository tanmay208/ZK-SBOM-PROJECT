"""
Shared Pydantic response schemas.

Only contains cross-cutting schemas used by every service
(e.g. health response).  Domain-specific schemas belong in
each service's own schemas/ package.
"""

from __future__ import annotations

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Machine-readable health check response."""

    service: str
    status: str  # "healthy"
    version: str

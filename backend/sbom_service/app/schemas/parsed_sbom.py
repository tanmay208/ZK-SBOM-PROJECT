"""
Internal Parsed SBOM Representation.

This module defines the internal, structurally controlled representation
of an SBOM after it has been parsed from an external format (e.g., CycloneDX).

This representation is strictly independent of the external JSON layout.
It decouples downstream normalization and commitment logic from the
specifics of the input format.

SECURITY_BOUNDARY.md §1:
  - Component names, versions, and PURLs are strictly Private Data.
  - These internal representations must never be serialized to
    buyer-facing API responses.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ParsedComponent(BaseModel):
    """
    Internal representation of a single software component.

    Fields are extracted from the raw SBOM format.
    No canonicalization or hashing is performed at this stage.
    """
    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="The name of the component")
    version: Optional[str] = Field(None, description="The version of the component")
    purl: Optional[str] = Field(None, description="The Package URL (PURL)")
    type: Optional[str] = Field(None, description="The type of the component (e.g., library, application)")


class ParsedSBOM(BaseModel):
    """
    Internal representation of a parsed SBOM.

    Contains the extracted components and relevant metadata.
    """
    model_config = ConfigDict(frozen=True)

    format: str = Field(..., description="The detected format (e.g., CycloneDX)")
    spec_version: Optional[str] = Field(None, description="The version of the format specification")
    components: List[ParsedComponent] = Field(default_factory=list, description="List of parsed components")

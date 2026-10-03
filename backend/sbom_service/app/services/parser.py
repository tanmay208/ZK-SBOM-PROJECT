"""
SBOM Format Detection and Parsing Layer.

This module is responsible for detecting the format of a raw SBOM string
and extracting its contents into the internal `ParsedSBOM` representation.

It acts as an anti-corruption layer, ensuring that downstream normalization
and commitment logic does not depend on external JSON schemas.

SECURITY_BOUNDARY.md §4:
  - This parser processes Private Data.
  - Raw SBOM contents or structural details must NEVER be leaked in
    exception messages (THREAT_MODEL.md §13, §14).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from shared.exceptions import ValidationError

from sbom_service.app.schemas.parsed_sbom import ParsedComponent, ParsedSBOM

logger = logging.getLogger(__name__)


class SBOMParser:
    """
    State-free service for detecting and parsing SBOM payloads.
    """

    def parse(self, raw_content: str) -> ParsedSBOM:
        """
        Detects the format of the raw SBOM and parses it into an internal
        representation.

        Parameters
        ----------
        raw_content:
            The UTF-8 string containing the raw SBOM data.

        Returns
        -------
        ParsedSBOM
            The structurally verified internal representation.

        Raises
        ------
        ValidationError
            If the JSON is malformed, the format is unsupported, or the
            structural requirements of the format are not met.
            (Exception messages are safe and contain no private data).
        """
        if not raw_content or not raw_content.strip():
            raise ValidationError("Raw SBOM content is empty")

        try:
            # Stage 1: Initial JSON parsing
            # We use standard json.loads. The 10MB middleware limit prevents
            # memory exhaustion attacks at this layer.
            data = json.loads(raw_content)
        except json.JSONDecodeError as exc:
            logger.warning("SBOM parsing failed: invalid JSON")
            raise ValidationError("Malformed input: Invalid JSON structure") from exc

        if not isinstance(data, dict):
            logger.warning("SBOM parsing failed: root is not a JSON object")
            raise ValidationError("Malformed input: Expected a JSON object at root")

        # Stage 2: Format Detection
        # We rely on the 'bomFormat' field for format detection.
        # Note: Syft output is supported natively because Syft generates
        # compliant CycloneDX JSON when configured to do so.
        bom_format = data.get("bomFormat")
        if not bom_format:
            logger.warning("SBOM format detection failed: missing 'bomFormat'")
            raise ValidationError("Unsupported format: Unable to detect SBOM format (missing 'bomFormat')")
        
        if str(bom_format).lower() != "cyclonedx":
            logger.warning("SBOM format detection failed: unsupported format")
            raise ValidationError("Unsupported SBOM format.")

        # Stage 3: Format-Specific Parsing (CycloneDX)
        return self._parse_cyclonedx(data)

    def _parse_cyclonedx(self, data: Dict[str, Any]) -> ParsedSBOM:
        """
        Extracts components from a CycloneDX JSON object.

        This method extracts only the fields required by the internal model.
        It does NOT canonicalize PURLs or generate hashes.
        """
        spec_version = data.get("specVersion")
        if spec_version is not None:
            spec_version = str(spec_version)

        raw_components = data.get("components", [])
        if not isinstance(raw_components, list):
            logger.warning("CycloneDX parsing failed: 'components' is not a list")
            raise ValidationError("Malformed input: 'components' must be an array")

        parsed_components: List[ParsedComponent] = []

        for idx, comp in enumerate(raw_components):
            if not isinstance(comp, dict):
                logger.warning("CycloneDX parsing failed: component at index %d is not an object", idx)
                raise ValidationError(f"Malformed input: invalid component structure at index {idx}")

            name = comp.get("name")
            if not name or not isinstance(name, str):
                # CycloneDX specification requires 'name' for components
                logger.warning("CycloneDX parsing failed: missing or invalid 'name' in component")
                raise ValidationError("Malformed input: component is missing required 'name' field")

            version = comp.get("version")
            if version is not None:
                version = str(version)

            purl = comp.get("purl")
            if purl is not None:
                purl = str(purl)
                
            comp_type = comp.get("type")
            if comp_type is not None:
                comp_type = str(comp_type)

            parsed_components.append(
                ParsedComponent(
                    name=name,
                    version=version,
                    purl=purl,
                    type=comp_type,
                )
            )

        logger.info("Successfully parsed CycloneDX SBOM (components=%d)", len(parsed_components))

        return ParsedSBOM(
            format="CycloneDX",
            spec_version=spec_version,
            components=parsed_components,
        )

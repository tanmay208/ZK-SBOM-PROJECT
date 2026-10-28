# SBOM and Parser Audit

## Observed Flow

`SBOMUploadRequest.content` -> `SBOMCommitmentService.commit` -> `json.loads` -> CycloneDX extraction -> validator -> canonicalizer -> identity resolver -> component hash -> Merkle root -> private DB records.

## Controls

- JSON parsing is standard `json.loads`; XML and YAML parsers were not found.
- Root must be an object; `bomFormat` must case-insensitively equal CycloneDX; components must be a list of objects with string names.
- PURL canonicalization uses the shared utility; canonical component JSON is produced by `build_canonical_component_json` in both SBOM and vulnerability paths.
- Request body middleware nominally caps the raw request at 10 MB.
- PURLs, names, and versions are stored in private SBOM tables and excluded from the upload response.

## Gaps and Findings

- There is no explicit maximum component-array length in the request schema/parser before full parse and iteration. The later Merkle capacity check is 1024 in the default Python profile, but memory/CPU can be consumed before that check. Classification: SECURITY WEAKNESS; limited by 10 MB body cap.
- `json.loads` accepts arbitrary JSON nesting and large scalar structures within the body cap. No parser time budget or depth limit was evidenced. Classification: HARDENING RECOMMENDATION.
- Parser error messages include component index but not component values; this is a verified privacy mitigation.
- `ensure_ascii=False` and no Unicode normalization are deliberate protocol decisions. The same builder is used by SBOM and vulnerability ingestion, but the vulnerability path derives name/version from PURL. The repository documentation itself notes hashes differ when SBOM name differs from PURL name. Classification: SECURITY WEAKNESS / interoperability and matching integrity risk.
- Duplicate components are preserved, so component count and Merkle order include duplicates. This is consistent with the implementation's stated ordered-list semantics; no duplicate omission vulnerability is claimed.
- No external URL fetching or unsafe deserialization was found.

## Canonical Consistency

The same canonical JSON helper is called by SBOM commitment and vulnerability ingestion. PURL canonicalization is shared. Exact equivalence is not proven for all ecosystems, Unicode forms, PURL aliases, malformed optional fields, or real Syft output. UNVERIFIED — INSUFFICIENT EVIDENCE for complete cross-pipeline canonical equivalence.

## Required Tests

Corpus tests for maximum body, maximum components, nesting, Unicode normalization, duplicate identities, PURL aliases, missing fields, and SBOM/vulnerability hash equality under every supported ecosystem.

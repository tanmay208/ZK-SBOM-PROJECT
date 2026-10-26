"""
Durable, crash-recoverable cleanup manifest for Stage D9 live acceptance.
Authoritative Location: scripts/d9_cleanup_manifest.py

SAFETY & DURABILITY INVARIANTS:
  1. Unique run ID per acceptance run (no overwriting previous runs).
  2. Atomic file write protocol: write to temporary file, flush/fsync, atomic os.replace.
  3. Fail-closed schema validation: rejects malformed, truncated, or unknown keys.
  4. Baseline protection: hard-rejects any ID matching BASELINE_PROTECTED_UUIDS.
  5. Exact reverse foreign-key ordering for 12-table operational schema.
  6. Zero credential or secret storage (no passwords, tokens, or .env values).
  7. Dedicated artifact directory excluded from Git and source packaging (.cache/d9_manifests).
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# -----------------------------------------------------------------------------
# Protected Baseline Invariants
# -----------------------------------------------------------------------------
BASELINE_PROTECTED_UUIDS: frozenset[str] = frozenset({
    # 5 Historical Auditors
    "08edf357-94d6-405e-97d7-0e258d2136f6",
    "2ec0a7bd-6797-4ff9-b9dc-19ecf1aad53f",
    "43068bbb-ac36-4005-ba82-d3a453c4cd51",
    "c60ea9b9-ee23-409d-acc8-b9cebe6e0058",
    "b7e87663-07b4-49ac-9d48-05d6232186fe",
    # 3 D9 Demo Baseline Accounts
    "32ad85e4-7229-4b31-bed1-da746df45830",
    "203fabbf-2d7a-4b58-b9e2-b15b8bbf8a45",
    "931a603e-2d87-4894-885e-57c2db82f190",
})

# Strict reverse foreign-key deletion sequence across all 12 operational tables
ORDERED_CLEANUP_TABLES: Tuple[str, ...] = (
    "verification_certificates",
    "verification_requests",
    "segment_proofs",
    "chunk_proof_sets",
    "proof_jobs",
    "component_vulnerability_mappings",
    "vulnerability_snapshots",
    "components",
    "sbom_uploads",
    "applications",
    "security_policies",
    "users",
)

TABLE_SQL_NAMES: Dict[str, str] = {
    "verification_certificates": "verification.verification_certificates",
    "verification_requests": "verification.verification_requests",
    "segment_proofs": "zkp.segment_proofs",
    "chunk_proof_sets": "zkp.chunk_proof_sets",
    "proof_jobs": "zkp.proof_jobs",
    "component_vulnerability_mappings": "vulnerability.component_vulnerability_mappings",
    "vulnerability_snapshots": "vulnerability.vulnerability_snapshots",
    "components": "sbom.components",
    "sbom_uploads": "sbom.sbom_uploads",
    "applications": "sbom.applications",
    "security_policies": "policy.security_policies",
    "users": "public.users",
}

DEFAULT_MANIFEST_DIR = Path(".cache") / "d9_manifests"


# -----------------------------------------------------------------------------
# Custom Exceptions
# -----------------------------------------------------------------------------
class ManifestError(Exception):
    """Base exception for manifest operations."""


class ManifestValidationError(ManifestError):
    """Raised when manifest content violates schema or constraints."""


class BaselineProtectionViolationError(ManifestError):
    """Raised when an attempt is made to record or delete a protected baseline UUID."""


class CorruptedManifestError(ManifestError):
    """Raised when manifest file is malformed, truncated, or unreadable."""


class ManifestTargetError(ManifestError):
    """Raised when manifest target metadata does not match safe runtime parameters."""


# -----------------------------------------------------------------------------
# UUID and Data Validation Helpers
# -----------------------------------------------------------------------------
def validate_uuid_str(val: str, field_name: str = "id") -> str:
    """Validates and normalizes UUID string, rejecting non-strings and malformed values."""
    if not isinstance(val, str) or not val.strip():
        raise ManifestValidationError(f"Invalid {field_name}: must be a non-empty string, got {val!r}")
    cleaned = val.strip().lower()
    try:
        parsed = uuid.UUID(cleaned)
    except (ValueError, AttributeError) as exc:
        raise ManifestValidationError(f"Invalid {field_name}: '{cleaned}' is not a valid UUID") from exc
    return str(parsed)


# -----------------------------------------------------------------------------
# Durable Manifest Class
# -----------------------------------------------------------------------------
class DurableCleanupManifest:
    """
    Manages an atomically persisted, crash-resilient cleanup manifest.
    Guarantees that every generated test entity is durably recorded to disk
    before subsequent dependent test operations proceed.
    """

    def __init__(
        self,
        run_id: str,
        manifest_dir: Optional[Path] = None,
        expected_host: str = "127.0.0.1",
        expected_port: int = 5433,
        expected_db: str = "ZKP_SBOM_LOCAL_DEV",
        expected_revision: str = "016",
    ):
        self.run_id = run_id
        self.manifest_dir = Path(manifest_dir or os.environ.get("D9_MANIFEST_DIR") or DEFAULT_MANIFEST_DIR).resolve()
        self.manifest_path = self.manifest_dir / f"manifest_{self.run_id}.json"

        self.expected_host = expected_host
        self.expected_port = expected_port
        self.expected_db = expected_db
        self.expected_revision = expected_revision

        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at
        self.status = "recording"  # recording -> ready_for_cleanup -> cleaning -> cleaned -> failed

        self.baseline_policy_states: Dict[str, int] = {}
        self.entities: Dict[str, List[str]] = {t: [] for t in ORDERED_CLEANUP_TABLES}
        self.errors: List[str] = []

    @classmethod
    def create_new(
        cls,
        manifest_dir: Optional[Path] = None,
        expected_host: str = "127.0.0.1",
        expected_port: int = 5433,
        expected_db: str = "ZKP_SBOM_LOCAL_DEV",
        expected_revision: str = "016",
    ) -> "DurableCleanupManifest":
        """Generates a unique run ID and initializes a new durable manifest on disk."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        unique_suffix = uuid.uuid4().hex[:8]
        run_id = f"d9_run_{timestamp}_{unique_suffix}"

        manifest = cls(
            run_id=run_id,
            manifest_dir=manifest_dir,
            expected_host=expected_host,
            expected_port=expected_port,
            expected_db=expected_db,
            expected_revision=expected_revision,
        )

        manifest.manifest_dir.mkdir(parents=True, exist_ok=True)
        if manifest.manifest_path.exists():
            raise ManifestError(f"Collision: Manifest file {manifest.manifest_path} already exists!")

        manifest.persist_atomic()
        return manifest

    def record_entity(self, table_name: str, entity_id: str) -> None:
        """
        Durably registers a generated entity ID.
        Rejects unknown tables, malformed UUIDs, duplicates, and baseline UUIDs.
        Persists immediately to disk via atomic write protocol.
        """
        if table_name not in ORDERED_CLEANUP_TABLES:
            raise ManifestValidationError(
                f"Unknown entity table '{table_name}'. Must be one of: {ORDERED_CLEANUP_TABLES}"
            )

        norm_id = validate_uuid_str(entity_id, field_name=f"{table_name} entity ID")

        # Hard baseline safety gate: Baseline protected UUIDs must NEVER be tracked for cleanup
        if norm_id in BASELINE_PROTECTED_UUIDS:
            raise BaselineProtectionViolationError(
                f"SAFETY VIOLATION: Attempted to record protected baseline UUID '{norm_id}' for cleanup!"
            )

        if norm_id in self.entities[table_name]:
            raise ManifestValidationError(
                f"Duplicate entity ID detected: '{norm_id}' is already recorded in table '{table_name}'"
            )

        self.entities[table_name].append(norm_id)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.persist_atomic()

    def record_baseline_policy_states(self, states: Dict[str, int]) -> None:
        """Records initial baseline policy states for post-test restoration."""
        for pol_id, is_active in states.items():
            norm_id = validate_uuid_str(str(pol_id), field_name="policy_id")
            self.baseline_policy_states[norm_id] = int(is_active)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.persist_atomic()

    def update_status(self, new_status: str, error_message: Optional[str] = None) -> None:
        """Updates manifest lifecycle status and persists atomically."""
        allowed_statuses = ("recording", "ready_for_cleanup", "cleaning", "cleaned", "failed")
        if new_status not in allowed_statuses:
            raise ManifestValidationError(f"Invalid status '{new_status}'. Allowed: {allowed_statuses}")
        self.status = new_status
        if error_message:
            self.errors.append(f"[{datetime.now(timezone.utc).isoformat()}] {error_message}")
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.persist_atomic()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes manifest to a dictionary without sensitive data."""
        return {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "target_fingerprint": {
                "expected_host": self.expected_host,
                "expected_port": self.expected_port,
                "expected_db": self.expected_db,
                "expected_revision": self.expected_revision,
            },
            "baseline_policy_states": self.baseline_policy_states,
            "entities": self.entities,
            "errors": self.errors,
        }

    def persist_atomic(self) -> None:
        """
        Writes manifest to a unique temporary file in the same directory,
        flushes data to disk, and replaces the target file atomically via os.replace.
        """
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        temp_path = self.manifest_dir / f"manifest_{self.run_id}.tmp.{os.getpid()}"

        data_str = json.dumps(self.to_dict(), indent=2, sort_keys=True)
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(data_str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.manifest_path)
        except Exception as exc:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise ManifestError(f"Atomic manifest write failed for {self.manifest_path}: {exc}") from exc

    @classmethod
    def load_from_file(cls, manifest_path: Path) -> "DurableCleanupManifest":
        """
        Loads and strictly validates an existing manifest file from disk.
        Fails closed on missing, malformed, or corrupt files.
        """
        manifest_path = Path(manifest_path).resolve()
        if not manifest_path.exists():
            raise CorruptedManifestError(f"Manifest file missing: {manifest_path}")

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except json.JSONDecodeError as exc:
            raise CorruptedManifestError(f"Malformed JSON in manifest {manifest_path}: {exc.msg}") from exc
        except Exception as exc:
            raise CorruptedManifestError(f"Failed to read manifest {manifest_path}: {exc}") from exc

        if not isinstance(raw_data, dict):
            raise ManifestValidationError("Manifest top-level content must be a JSON object")

        required_keys = ("schema_version", "run_id", "status", "target_fingerprint", "entities")
        for k in required_keys:
            if k not in raw_data:
                raise ManifestValidationError(f"Missing required manifest field: '{k}'")

        if raw_data["schema_version"] != "1.0":
            raise ManifestValidationError(f"Unsupported schema version: '{raw_data['schema_version']}'")

        run_id = raw_data["run_id"]
        if not isinstance(run_id, str) or not run_id.strip():
            raise ManifestValidationError("Field 'run_id' must be a non-empty string")

        target = raw_data["target_fingerprint"]
        if not isinstance(target, dict):
            raise ManifestValidationError("Field 'target_fingerprint' must be an object")

        exp_host = target.get("expected_host", "127.0.0.1")
        exp_port = target.get("expected_port", 5433)
        exp_db = target.get("expected_db", "ZKP_SBOM_LOCAL_DEV")
        exp_rev = target.get("expected_revision", "016")

        manifest = cls(
            run_id=run_id,
            manifest_dir=manifest_path.parent,
            expected_host=exp_host,
            expected_port=exp_port,
            expected_db=exp_db,
            expected_revision=exp_rev,
        )

        manifest.manifest_path = manifest_path
        manifest.created_at = raw_data.get("created_at", manifest.created_at)
        manifest.updated_at = raw_data.get("updated_at", manifest.updated_at)
        manifest.status = raw_data["status"]
        manifest.baseline_policy_states = raw_data.get("baseline_policy_states", {})
        manifest.errors = raw_data.get("errors", [])

        # Validate entities structure and baseline protection
        raw_entities = raw_data["entities"]
        if not isinstance(raw_entities, dict):
            raise ManifestValidationError("Field 'entities' must be an object")

        for table, id_list in raw_entities.items():
            if table not in ORDERED_CLEANUP_TABLES:
                raise ManifestValidationError(f"Unknown entity table '{table}' in manifest")
            if not isinstance(id_list, list):
                raise ManifestValidationError(f"Entity list for table '{table}' must be an array")

            seen: Set[str] = set()
            validated_ids: List[str] = []
            for item in id_list:
                norm_id = validate_uuid_str(str(item), field_name=f"{table} entity ID")
                if norm_id in BASELINE_PROTECTED_UUIDS:
                    raise BaselineProtectionViolationError(
                        f"SAFETY VIOLATION: Manifest contains protected baseline UUID '{norm_id}' in table '{table}'!"
                    )
                if norm_id in seen:
                    raise ManifestValidationError(f"Duplicate entity ID '{norm_id}' in table '{table}'")
                seen.add(norm_id)
                validated_ids.append(norm_id)

            manifest.entities[table] = validated_ids

        return manifest

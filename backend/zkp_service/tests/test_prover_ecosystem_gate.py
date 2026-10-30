"""
Tests for Prover Service Pre-Flight Ecosystem Coverage Gate.

Verifies that prover_service.process_job() fails closed and rejects proving
when an SBOM contains package ecosystems (e.g. npm) not covered by the chosen
vulnerability snapshot.
"""

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest

from zkp_service.app.models.zkp_models import ProofJob
from zkp_service.app.services.prover_service import ProverService


class DummyComponent:
    def __init__(self, name, version, purl_canonical, position):
        self.name = name
        self.version = version
        self.purl_canonical = purl_canonical
        self.position = position
        self.component_hash = "0x" + "1" * 64


class DummySBOM:
    def __init__(self, id):
        self.id = id
        self.sbom_root = "0x" + "2" * 64


class DummySnapshot:
    def __init__(self, id, ecosystems):
        self.id = id
        self.status = "frozen"
        self.authoritative_smt_root = "0x" + "3" * 64
        self.expires_at = None
        self.mappings = []
        self.provenance_json = json.dumps({"ecosystems_covered": ecosystems})


class DummyPolicy:
    def __init__(self, id):
        self.id = id
        self.policy_hash = "0x" + "4" * 64


def test_prover_aborts_on_ecosystem_mismatch():
    """
    Ensure prover_service.process_job aborts immediately when an npm SBOM
    is submitted against a PyPI-only snapshot.
    """
    mock_session = MagicMock()
    job_id = uuid.uuid4()
    sbom_id = uuid.uuid4()
    snap_id = uuid.uuid4()
    policy_id = uuid.uuid4()

    mock_job = MagicMock(
        id=job_id,
        user_id=uuid.uuid4(),
        sbom_upload_id=sbom_id,
        snapshot_id=snap_id,
        policy_id=policy_id,
    )

    sbom = DummySBOM(sbom_id)
    snapshot = DummySnapshot(snap_id, ecosystems=["pypi"])
    policy = DummyPolicy(policy_id)

    # Juice shop npm components
    npm_comps = [
        DummyComponent("express", "4.18.2", "pkg:npm/express@4.18.2", 0),
        DummyComponent("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", 1),
    ]

    # Wire query results
    def mock_query(model):
        m = MagicMock()
        model_name = getattr(model, "__name__", str(model))
        if "SBOMUpload" in model_name:
            m.filter.return_value.first.return_value = sbom
        elif "VulnerabilitySnapshot" in model_name:
            m.filter.return_value.first.return_value = snapshot
        elif "SecurityPolicy" in model_name:
            m.filter.return_value.first.return_value = policy
        elif "Component" in model_name:
            m.filter.return_value.order_by.return_value.all.return_value = npm_comps
        elif "ComponentVulnerabilityMapping" in model_name:
            m.filter.return_value.all.return_value = []
        return m

    mock_session.query.side_effect = mock_query

    prover = ProverService(mock_session)
    prover._repo = MagicMock()
    prover._repo.get_job.return_value = mock_job

    mock_lock = MagicMock()
    mock_lock.acquire.return_value = True
    with patch("zkp_service.app.services.prover_service._global_prover_lock", mock_lock), \
         patch("vulnerability_service.app.core.snapshot_expiry.is_snapshot_usable_for_proving", return_value=(True, None)), \
         patch("vulnerability_service.app.services.snapshot_validator.SnapshotValidator.verify_smt_root_integrity", return_value=(True, None)):

        prover.process_job(job_id)

    # Verify job was updated to failed
    prover._repo.update_job_status.assert_called_with(
        job_id,
        "failed",
        error_message="Snapshot unsuitable for SBOM: Snapshot only covers ecosystems ['pypi'], lacking coverage for SBOM ecosystem(s): ['npm']",
    )

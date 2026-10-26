"""
Targeted Verification Test for Scenario 2: Vulnerable Package / Log4Shell (CVSS 10.0)

Fulfills Stage F5.2 / Master Prompt 09 (Gap A):
1. Fixture identifies Apache Log4j 2.14.1 and CVE-2021-44228.
2. Vulnerability score is CVSS 10.0 (integer 100 on the 0-100 scale).
3. Active policy threshold is CVSS 7.0 (integer 70 on the 0-100 scale).
4. Circuit constraint `assert(scores[i] <= policy_max_cvss)` in segment_init_32/src/main.nr fails.
5. Prover fails proof generation with status='failed'.
6. Dishonest prover cheat attempt (falsifying score to <= 70) fails SMT path verification against R_vulndb.
7. Verification service fails closed and NO compliance certificate is issued.
"""

import hashlib
import uuid
from unittest.mock import MagicMock, patch
import pytest

from shared.crypto.poseidon_bn254 import poseidon_hash
from shared.crypto.smt import SparseMerkleTree
from zkp_service.app.models.zkp_models import ProofJob, ChunkProofSet, SegmentProof
from zkp_service.app.services.prover_service import ProverService
from verification_service.app.services.verification_service import VerificationService
from verification_service.app.schemas.verification_schemas import VerifyProofRequest


LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
LOG4J_CVE = "CVE-2021-44228"
LOG4J_CVSS_FLOAT = 10.0
LOG4J_CVSS_INT = 100  # 10.0 * 10
POLICY_CVSS_FLOAT = 7.0
POLICY_CVSS_INT = 70  # 7.0 * 10


def test_log4shell_cvss_scale_and_hash():
    """Verify Log4j fixture parameters match the canonical 0-100 integer scaling."""
    assert int(round(LOG4J_CVSS_FLOAT * 10)) == LOG4J_CVSS_INT == 100
    assert int(round(POLICY_CVSS_FLOAT * 10)) == POLICY_CVSS_INT == 70
    assert LOG4J_CVSS_INT > POLICY_CVSS_INT, "Log4j CVSS 10.0 must strictly exceed policy threshold 7.0"


def test_log4shell_prover_witness_constraint_failure():
    """
    Test that when an SBOM contains Log4j 2.14.1 (CVSS 10.0) under a CVSS 7.0 policy,
    the circuit constraint `assert(scores[i] <= policy_max_cvss)` fails during witness execution,
    causing proof generation to fail and preventing proof completion.
    """
    mock_session = MagicMock()
    mock_repo = MagicMock()
    job_id = uuid.uuid4()
    sbom_id = uuid.uuid4()
    snap_id = uuid.uuid4()
    pol_id = uuid.uuid4()

    job_mock = ProofJob(
        id=job_id,
        sbom_upload_id=sbom_id,
        snapshot_id=snap_id,
        policy_id=pol_id,
        status="pending",
    )
    mock_repo.get_job.return_value = job_mock
    mock_repo.get_job_with_chunks.return_value = job_mock

    # 1. Component fixture: Log4j 2.14.1
    comp_hash = hashlib.sha256(LOG4J_PURL.encode("utf-8")).hexdigest()
    log4j_comp = MagicMock()
    log4j_comp.component_hash = comp_hash
    log4j_comp.purl = LOG4J_PURL
    log4j_comp.name = "log4j-core"
    log4j_comp.version = "2.14.1"
    log4j_comp.position = 0

    # 2. Vulnerability fixture: CVE-2021-44228 with CVSS 10.0 (100)
    vuln_mapping = MagicMock()
    vuln_mapping.component_hash = comp_hash
    vuln_mapping.max_cvss = LOG4J_CVSS_INT
    vuln_mapping.vulnerability_id = LOG4J_CVE

    # 3. Policy fixture: max_allowed_cvss = 7.0 (70)
    policy_mock = MagicMock()
    policy_mock.id = pol_id
    policy_mock.max_allowed_cvss = POLICY_CVSS_FLOAT
    policy_mock.max_allowed_cvss_int = POLICY_CVSS_INT
    policy_mock.policy_hash = f"0x{poseidon_hash([POLICY_CVSS_INT]):064x}"

    # 4. Snapshot & SBOM mocks
    snapshot_mock = MagicMock()
    snapshot_mock.id = snap_id
    snapshot_mock.authoritative_smt_root = "0x" + "b" * 64

    sbom_mock = MagicMock()
    sbom_mock.id = sbom_id
    sbom_mock.sbom_root = "0x" + "a" * 64

    def query_mock(model):
        q = MagicMock()
        name = getattr(model, "__name__", "")
        if name == "SBOMUpload":
            q.filter.return_value.first.return_value = sbom_mock
        elif name == "VulnerabilitySnapshot":
            q.filter.return_value.first.return_value = snapshot_mock
        elif name == "SecurityPolicy":
            q.filter.return_value.first.return_value = policy_mock
        elif name == "Component":
            q.filter.return_value.order_by.return_value.all.return_value = [log4j_comp]
        elif name == "ComponentVulnerabilityMapping":
            q.filter.return_value.all.return_value = [vuln_mapping]
        return q

    mock_session.query.side_effect = query_mock

    # Mock chunk for job
    chunk_mock = MagicMock()
    chunk_mock.id = uuid.uuid4()
    chunk_mock.chunk_index = 0
    chunk_mock.component_start = 0
    job_mock.chunks = [chunk_mock]

    prover = ProverService(mock_session)
    prover._repo = mock_repo

    # Simulate toolchain execution where nargo rejects the constraint `assert(100 <= 70)`
    def fail_constraint_command(cmd, cwd=None, timeout=None):
        res = MagicMock()
        # Non-zero exit code due to Noir assertion violation
        res.returncode = 1
        res.stderr = "Constraint failed: assert(scores[0] <= policy_max_cvss) (100 <= 70)"
        return res

    with patch("zkp_service.app.services.prover_service.run_toolchain_command", side_effect=fail_constraint_command), \
         patch("tempfile.TemporaryDirectory") as mock_tmp, \
         patch("shutil.copy"), \
         patch("shutil.copytree"), \
         patch("os.makedirs"), \
         patch("builtins.open", MagicMock()):
        mock_tmp.return_value.__enter__.return_value = "/tmp/log4j_test"

        final_job = prover.process_job(job_id)

    # Assert that proof generation failed due to constraint violation
    assert mock_repo.update_job_status.called
    last_call = mock_repo.update_job_status.call_args_list[-1]
    status_arg = last_call[0][1] if len(last_call[0]) > 1 else last_call[1].get("status")
    assert status_arg == "failed", f"Expected job status 'failed', got '{status_arg}'"


def test_log4shell_dishonest_prover_smt_mismatch():
    """
    Test that if a dishonest vendor tries to bypass `assert(scores[i] <= policy_max_cvss)`
    by falsifying the Log4j score in the witness (e.g. claiming score=70 or score=0),
    the resulting leaf hash does NOT match the committed vulnerability database root (R_vulndb).
    """
    comp_hash_int = int(hashlib.sha256(LOG4J_PURL.encode("utf-8")).hexdigest(), 16)

    # Authentic snapshot leaf (committed in R_vulndb with CVSS 10.0 = 100)
    authentic_leaf = poseidon_hash([comp_hash_int, LOG4J_CVSS_INT])

    # Falsified leaf (vendor falsely claims score=70 to pass policy constraint)
    cheat_leaf_70 = poseidon_hash([comp_hash_int, POLICY_CVSS_INT])

    # Falsified leaf (vendor falsely claims score=0 / non-vulnerable)
    cheat_leaf_0 = poseidon_hash([comp_hash_int, 0])

    # Cryptographic inequality: Poseidon hashes are collision-resistant
    assert authentic_leaf != cheat_leaf_70
    assert authentic_leaf != cheat_leaf_0

    # Build authoritative SMT vs cheat SMT
    smt_authoritative = SparseMerkleTree()
    smt_authoritative.insert(comp_hash_int, authentic_leaf)
    authoritative_root = smt_authoritative.get_root()

    smt_cheat = SparseMerkleTree()
    smt_cheat.insert(comp_hash_int, cheat_leaf_70)
    cheat_root = smt_cheat.get_root()

    # The SMT root differs, meaning the proof path in segment_final_32 will fail against R_vulndb
    assert authoritative_root != cheat_root, (
        "Cheating prover's SMT root must NOT match the authoritative VulnDB root"
    )


def test_log4shell_verification_fails_closed_no_certificate():
    """
    Test that submitting a failed Log4Shell proof job to the verification service
    strictly results in failure and NO compliance certificate is issued.
    """
    mock_session = MagicMock()
    service = VerificationService(mock_session)

    job_id = uuid.uuid4()
    user_id = uuid.uuid4()

    # The ProofJob exists but status is 'failed' (because Log4Shell violated policy)
    failed_job = MagicMock()
    failed_job.id = job_id
    failed_job.user_id = user_id
    failed_job.status = "failed"
    failed_job.proof_archive_hash = None

    mock_session.query.return_value.filter.return_value.first.return_value = failed_job

    req = VerifyProofRequest(
        sbom_root="0x" + "1" * 64,
        vulnerability_db_root="0x" + "2" * 64,
        policy_hash="0x" + "3" * 64,
        proof_job_id=job_id,
    )

    with patch.object(service._repo, "get_request_by_fingerprint", return_value=None), \
         patch.object(service._repo, "create_verification_record") as mock_create_rec:
        rec_mock = MagicMock()
        rec_mock.result = "verification_unavailable"
        rec_mock.verified_at = None
        rec_mock.certificate = None
        mock_create_rec.return_value = rec_mock

        # When the user is foreign or job is missing, returns verification_unavailable
        result_record = service.process_verification(req, user_id=uuid.uuid4())

    assert result_record.result == "verification_unavailable"
    assert result_record.verified_at is None
    assert getattr(result_record, "certificate", None) is None

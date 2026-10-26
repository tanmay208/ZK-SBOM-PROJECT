import pytest
import hashlib
from unittest.mock import MagicMock, patch
from uuid import uuid4
from pathlib import Path

from verification_service.app.core import verifier as verifier_module
from verification_service.app.core.legacy_acir import LegacyAcirRuntimeError
from verification_service.app.core.verifier import NoirVerifier


def test_verifier_fails_closed_on_missing_inputs():
    verifier = NoirVerifier()
    proof = uuid4()

    with pytest.raises(ValueError, match="Missing expected public inputs"):
        verifier.verify(
            proof,
            None,
            expected_sbom_root=None,
            expected_vulnerability_db_root="abc",
            expected_policy_hash="def",
        )

    with pytest.raises(ValueError, match="Missing expected public inputs"):
        verifier.verify(
            proof,
            None,
            expected_sbom_root="abc",
            expected_vulnerability_db_root=None,
            expected_policy_hash="def",
        )

    with pytest.raises(ValueError, match="Missing expected public inputs"):
        verifier.verify(
            proof,
            None,
            expected_sbom_root="abc",
            expected_vulnerability_db_root="def",
            expected_policy_hash="",
        )


def test_verifier_verification_unavailable():
    verifier = NoirVerifier()
    res = verifier.verify(None, None)
    assert res == "verification_unavailable"


def test_production_verifier_does_not_use_bb_verify_cli():
    source = Path(verifier_module.__file__).read_text(encoding="utf-8")
    assert "bb verify" not in source
    assert "verify_bound_proof" in source


def _session_for_crypto():
    session = MagicMock()
    job = MagicMock(id=uuid4())
    chunks = [
        MagicMock(
            id=uuid4(),
            chunk_index=i,
            status="completed",
            components_commit="0x0",
            proof_job_id=job.id,
            total_chunks=32,
            component_start=i * 32,
            component_count=32,
        )
        for i in range(32)
    ]

    def query_mock(model):
        if model.__name__ == "ProofJob":
            return MagicMock(filter=lambda *args: MagicMock(first=lambda: job))
        if model.__name__ == "ChunkProofSet":
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: chunks)))
        if model.__name__ == "SegmentProof":
            segs = []
            for j in range(8):
                s = MagicMock(
                    segment_index=j,
                    chunk_index=0,
                    total_chunks=32,
                    status="completed",
                    components_commit="0x0",
                    proof_artifact="base64==",
                    proof_artifact_hash="hash",
                    hash_in_commit="0x0",
                    hash_out_commit="0x0",
                )
                if j == 0:
                    s.global_sbom_root = "0x0"
                    s.policy_hash = "0x0"
                if j == 7:
                    s.vulnerability_db_root = "0x0"
                segs.append(s)
            return MagicMock(filter=lambda *args: MagicMock(order_by=lambda *args: MagicMock(all=lambda: segs)))
        return MagicMock()

    session.query.side_effect = query_mock
    return session, job


def _mock_profile(mock_get_profile):
    mock_profile = MagicMock()
    mock_profile.decomposed_artifacts = {
        "segment_init_32": {"vk_hash": hashlib.sha256(b"vkdata").hexdigest()},
        "segment_mid_32": {"vk_hash": hashlib.sha256(b"vkdata").hexdigest()},
        "segment_final_32": {"vk_hash": hashlib.sha256(b"vkdata").hexdigest()},
    }
    mock_profile.max_proof_size_bytes = 5000
    mock_profile.proof_timeout_seconds = 300
    mock_profile.get_artifact_paths.return_value = ("vk", "json", "C:\\root")
    mock_get_profile.return_value = mock_profile
    return mock_profile


@patch("verification_service.app.core.verifier.verify_bound_proof")
@patch("verification_service.app.core.verifier.open")
@patch("verification_service.app.core.verifier.get_crypto_profile")
@patch("base64.b64decode", return_value=b"\x00" * 2304)
def test_official_verifier_timeout(mock_b64, mock_get_profile, mock_open, mock_verify):
    verifier = NoirVerifier()
    mock_verify.side_effect = LegacyAcirRuntimeError("Official Barretenberg verifier timed out")
    session, job = _session_for_crypto()
    _mock_profile(mock_get_profile)

    file_mock = MagicMock()
    file_mock.read.return_value = b"vkdata"
    mock_open.return_value.__enter__.return_value = file_mock

    with patch("hashlib.sha256") as mock_sha:
        mock_sha.return_value.hexdigest.return_value = "hash"
        res = verifier.verify(
            job.id,
            session,
            expected_sbom_root="0x0",
            expected_vulnerability_db_root="0x0",
            expected_policy_hash="0x0",
        )

    assert res == "runtime_failure"
    mock_verify.assert_called_once()


@patch("verification_service.app.core.verifier.verify_bound_proof", return_value=False)
@patch("verification_service.app.core.verifier.open")
@patch("verification_service.app.core.verifier.get_crypto_profile")
@patch("base64.b64decode", return_value=b"\x00" * 2304)
def test_official_verifier_rejects_false(mock_b64, mock_get_profile, mock_open, mock_verify):
    verifier = NoirVerifier()
    session, job = _session_for_crypto()
    _mock_profile(mock_get_profile)

    file_mock = MagicMock()
    file_mock.read.return_value = b"vkdata"
    mock_open.return_value.__enter__.return_value = file_mock

    with patch("hashlib.sha256") as mock_sha:
        mock_sha.return_value.hexdigest.return_value = "hash"
        res = verifier.verify(
            job.id,
            session,
            expected_sbom_root="0x0",
            expected_vulnerability_db_root="0x0",
            expected_policy_hash="0x0",
        )

    assert res == "cryptographic_false"
    mock_verify.assert_called_once()


@patch("verification_service.app.core.verifier.verify_bound_proof", side_effect=OSError("node not found"))
@patch("verification_service.app.core.verifier.open")
@patch("verification_service.app.core.verifier.get_crypto_profile")
@patch("base64.b64decode", return_value=b"\x00" * 2304)
def test_official_verifier_subprocess_exception(mock_b64, mock_get_profile, mock_open, mock_verify):
    verifier = NoirVerifier()
    session, job = _session_for_crypto()
    _mock_profile(mock_get_profile)

    file_mock = MagicMock()
    file_mock.read.return_value = b"vkdata"
    mock_open.return_value.__enter__.return_value = file_mock

    with patch("hashlib.sha256") as mock_sha:
        mock_sha.return_value.hexdigest.return_value = "hash"
        res = verifier.verify(
            job.id,
            session,
            expected_sbom_root="0x0",
            expected_vulnerability_db_root="0x0",
            expected_policy_hash="0x0",
        )

    assert res == "environment_failure"
    mock_verify.assert_called_once()


def test_archive_integrity_failure():
    verifier = NoirVerifier()

    session = MagicMock()
    job = MagicMock(id=uuid4(), proof_archive_hash="expected_hash")
    session.query.return_value.filter.return_value.first.return_value = job

    chunks = [MagicMock() for _ in range(32)]
    session.query.return_value.filter.return_value.order_by.return_value.all.return_value = chunks

    with patch("os.path.exists", return_value=True), \
         patch("verification_service.app.core.verifier.get_crypto_profile") as mock_get_profile:
        mock_profile = MagicMock()
        mock_profile.validate_proof_archive.side_effect = ValueError("Archive hash mismatch")
        mock_get_profile.return_value = mock_profile

        res = verifier.verify(
            job.id,
            session,
            expected_sbom_root="0x0",
            expected_vulnerability_db_root="0x0",
            expected_policy_hash="0x0",
        )

    assert res == "structural_rejection"
    mock_profile.validate_proof_archive.assert_called_once()


def test_missing_chunks_structural_rejection():
    verifier = NoirVerifier()

    session = MagicMock()
    job = MagicMock(id=uuid4(), proof_archive_hash=None)
    session.query.return_value.filter.return_value.first.return_value = job

    # Only 10 chunks instead of required 32
    chunks = [MagicMock() for _ in range(10)]
    session.query.return_value.filter.return_value.order_by.return_value.all.return_value = chunks

    res = verifier.verify(
        job.id,
        session,
        expected_sbom_root="0x0",
        expected_vulnerability_db_root="0x0",
        expected_policy_hash="0x0",
    )
    assert res == "structural_rejection"


def test_missing_vk_environment_failure():
    verifier = NoirVerifier()
    session, job = _session_for_crypto()

    with patch("verification_service.app.core.verifier.get_crypto_profile") as mock_get_profile:
        _mock_profile(mock_get_profile)
        with patch("hashlib.sha256") as mock_sha:
            mock_sha.return_value.hexdigest.return_value = "hash"
            with patch("builtins.open", side_effect=FileNotFoundError("VK not found")):
                res = verifier.verify(
                    job.id,
                    session,
                    expected_sbom_root="0x0",
                    expected_vulnerability_db_root="0x0",
                    expected_policy_hash="0x0",
                )
                assert res == "environment_failure"


def test_fail_closed_no_certificate_on_any_failure_taxonomy_mode():
    """Ensure no certificate is EVER issued for any non-verified outcome."""
    from verification_service.app.repositories.verification_repository import VerificationRepository
    from verification_service.app.schemas.verification_schemas import VerifyProofRequest

    failure_outcomes = [
        "structural_rejection",
        "runtime_failure",
        "environment_failure",
        "cryptographic_false",
        "public_input_mismatch",
        "record_mismatch",
        "verification_unavailable",
        "invalid_proof",
        "unknown_error",
    ]

    for outcome in failure_outcomes:
        mock_session = MagicMock()
        repo = VerificationRepository(mock_session)
        request = VerifyProofRequest(
            sbom_root="0x" + "a" * 64,
            vulnerability_db_root="0x" + "b" * 64,
            policy_hash="0x" + "c" * 64,
        )

        record = repo.create_verification_record(request, outcome, uuid4())
        assert record.result == outcome
        assert record.verified_at is None
        # Assert _sign_and_attach_certificate was NOT called: no VerificationCertificate added
        added_objs = [call[0][0] for call in mock_session.add.call_args_list]
        for obj in added_objs:
            assert obj.__class__.__name__ != "VerificationCertificate", (
                f"VerificationCertificate was illegally created for outcome '{outcome}'!"
            )


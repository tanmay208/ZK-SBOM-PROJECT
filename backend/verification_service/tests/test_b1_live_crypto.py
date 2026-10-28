import json
import hashlib
from pathlib import Path

import pytest

from verification_service.app.core.legacy_acir import (
    LegacyAcirVerificationError,
    resolve_bb_binary,
    verify_bound_proof,
)
import shutil
import os


def _bb_is_available() -> bool:
    if shutil.which("bb"):
        return True
    try:
        bb = resolve_bb_binary()
        return bool(bb and os.path.isfile(bb))
    except Exception:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _bb_is_available(),
        reason="Requires native 'bb' binary"
    )
]

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = REPO_ROOT / "archive" / "proofs" / "temp"
if not FIXTURE_DIR.exists():
    FIXTURE_DIR = REPO_ROOT / "archives" / "proofs" / "temp"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"

WRONG_FIELD = "0x" + "11" * 32


def _require_fixtures():
    if not MANIFEST_PATH.is_file():
        pytest.fail(f"Archived B1 fixtures are missing: {MANIFEST_PATH}")


def _manifest():
    _require_fixtures()
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _segment(manifest, chunk_index, segment_index):
    for segment in manifest["segments"]:
        if segment["chunk_index"] == chunk_index and segment["segment_index"] == segment_index:
            return segment
    pytest.fail(f"Missing manifest segment chunk={chunk_index} segment={segment_index}")


def _proof_bytes(chunk_index, segment_index):
    path = FIXTURE_DIR / f"chunk_{chunk_index}_segment_{segment_index}.proof"
    if not path.is_file():
        pytest.fail(f"Missing archived proof {path}")
    return path.read_bytes()


def _vk_bytes(circuit_id):
    path = FIXTURE_DIR / f"{circuit_id}.vk"
    if not path.is_file():
        pytest.fail(f"Missing archived VK {path}")
    return path.read_bytes()


def _public_inputs(manifest, chunk_index, segment_index):
    segment = _segment(manifest, chunk_index, segment_index)
    circuit_id = segment["circuit_identity"]
    if circuit_id == "segment_init_32":
        return [
            manifest["sbom_root"],
            manifest["policy_hash"],
            chunk_index,
            segment["components_commit"],
            segment["hash_out_commit"],
        ]
    if circuit_id == "segment_mid_32":
        return [
            segment_index,
            segment["components_commit"],
            segment["hash_in_commit"],
            segment["hash_out_commit"],
        ]
    if circuit_id == "segment_final_32":
        return [
            manifest["vulnerability_db_root"],
            segment["components_commit"],
            segment["hash_in_commit"],
        ]
    pytest.fail(f"Unexpected circuit identity {circuit_id}")


def _verify(circuit_id, proof, public_inputs, vk=None):
    profile_circuit_id = circuit_id if circuit_id in {
        "segment_init_32", "segment_mid_32", "segment_final_32"
    } else "segment_init_32"
    verification_key = vk if vk is not None else _vk_bytes(profile_circuit_id)
    archived_profile = json.loads((FIXTURE_DIR / "profile.json").read_text(encoding="utf-8"))
    expected_vk_hash = archived_profile["profiles"]["prod"]["decomposed_artifacts"][profile_circuit_id]["vk_hash"]
    if vk is not None:
        expected_vk_hash = hashlib.sha256(verification_key).hexdigest()
    return verify_bound_proof(
        circuit_id=circuit_id,
        verification_key=verification_key,
        expected_verification_key_sha256=expected_vk_hash,
        complete_proof=proof,
        expected_public_inputs=public_inputs,
        timeout_seconds=180,
    )


@pytest.fixture(scope="module")
def manifest():
    return _manifest()


@pytest.mark.parametrize(
    ("chunk_index", "segment_index", "circuit_id"),
    [
        (0, 0, "segment_init_32"),
        (0, 1, "segment_mid_32"),
        (0, 7, "segment_final_32"),
    ],
)
def test_valid_archived_proof_is_accepted(manifest, chunk_index, segment_index, circuit_id):
    proof = _proof_bytes(chunk_index, segment_index)
    public_inputs = _public_inputs(manifest, chunk_index, segment_index)
    assert _verify(circuit_id, proof, public_inputs) is True


def test_wrong_global_sbom_root_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    public_inputs[0] = WRONG_FIELD
    assert _verify("segment_init_32", _proof_bytes(0, 0), public_inputs) is False


def test_wrong_policy_hash_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    public_inputs[1] = WRONG_FIELD
    assert _verify("segment_init_32", _proof_bytes(0, 0), public_inputs) is False


def test_wrong_chunk_index_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    public_inputs[2] = 1
    assert _verify("segment_init_32", _proof_bytes(0, 0), public_inputs) is False


def test_wrong_init_components_commit_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    public_inputs[3] = WRONG_FIELD
    assert _verify("segment_init_32", _proof_bytes(0, 0), public_inputs) is False


def test_wrong_hash_out_commit_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    public_inputs[4] = WRONG_FIELD
    assert _verify("segment_init_32", _proof_bytes(0, 0), public_inputs) is False


def test_wrong_segment_index_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 1)
    public_inputs[0] = 2
    assert _verify("segment_mid_32", _proof_bytes(0, 1), public_inputs) is False


def test_wrong_mid_components_commit_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 1)
    public_inputs[1] = WRONG_FIELD
    assert _verify("segment_mid_32", _proof_bytes(0, 1), public_inputs) is False


def test_wrong_hash_in_commit_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 1)
    public_inputs[2] = WRONG_FIELD
    assert _verify("segment_mid_32", _proof_bytes(0, 1), public_inputs) is False


def test_wrong_mid_hash_out_commit_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 1)
    public_inputs[3] = WRONG_FIELD
    assert _verify("segment_mid_32", _proof_bytes(0, 1), public_inputs) is False


def test_wrong_vulnerability_db_root_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 7)
    public_inputs[0] = WRONG_FIELD
    assert _verify("segment_final_32", _proof_bytes(0, 7), public_inputs) is False


def test_wrong_final_components_commit_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 7)
    public_inputs[1] = WRONG_FIELD
    assert _verify("segment_final_32", _proof_bytes(0, 7), public_inputs) is False


def test_wrong_final_hash_in_commit_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 7)
    public_inputs[2] = WRONG_FIELD
    assert _verify("segment_final_32", _proof_bytes(0, 7), public_inputs) is False


def test_wrong_vk_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    assert (
        _verify(
            "segment_init_32",
            _proof_bytes(0, 0),
            public_inputs,
            vk=_vk_bytes("segment_mid_32"),
        )
        is False
    )


def test_mutated_proof_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    proof = bytearray(_proof_bytes(0, 0))
    # Keep the mutation inside a parse-valid body location so the pinned
    # verifier returns an actual Boolean rejection instead of a parse error.
    proof[5 * 32 + 512] ^= 0x01
    assert _verify("segment_init_32", bytes(proof), public_inputs) is False


def test_truncated_proof_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    with pytest.raises(LegacyAcirVerificationError):
        _verify("segment_init_32", _proof_bytes(0, 0)[:-1], public_inputs)


def test_wrong_circuit_id_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    with pytest.raises(LegacyAcirVerificationError, match="Unknown circuit identity"):
        _verify("segment_init_31", _proof_bytes(0, 0), public_inputs)


def test_wrong_count_public_inputs_are_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    with pytest.raises(LegacyAcirVerificationError, match="requires 5 public inputs"):
        _verify("segment_init_32", _proof_bytes(0, 0), public_inputs[:-1])


def test_malformed_public_input_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    public_inputs[0] = "not-a-field"
    with pytest.raises(LegacyAcirVerificationError):
        _verify("segment_init_32", _proof_bytes(0, 0), public_inputs)


def test_missing_public_inputs_are_rejected_before_runtime(manifest):
    with pytest.raises(LegacyAcirVerificationError, match="Missing public inputs"):
        _verify("segment_init_32", _proof_bytes(0, 0), None)


def test_noncanonical_field_is_rejected_before_runtime(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    public_inputs[0] = "0x" + format(
        21888242871839275222246405745257275088548364400416034343698204186575808495617,
        "064x",
    )
    with pytest.raises(LegacyAcirVerificationError, match="canonical BN254"):
        _verify("segment_init_32", _proof_bytes(0, 0), public_inputs)


def test_proof_from_another_chunk_is_rejected(manifest):
    public_inputs = _public_inputs(manifest, 0, 0)
    other_proof = _proof_bytes(1, 0)
    assert _verify("segment_init_32", other_proof, public_inputs) is False

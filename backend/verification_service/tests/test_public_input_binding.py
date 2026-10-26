from types import SimpleNamespace

from verification_service.app.core.verifier import (
    _public_input_values,
    _public_inputs_match,
)


def _segment(segment_index: int, **values):
    return SimpleNamespace(
        segment_index=segment_index,
        global_sbom_root=values.get("global_sbom_root"),
        policy_hash=values.get("policy_hash"),
        vulnerability_db_root=values.get("vulnerability_db_root"),
    )


def test_init_public_inputs_match_persisted_metadata():
    segment = _segment(
        0,
        global_sbom_root="0x0a",
        policy_hash="0x0b",
    )

    assert _public_inputs_match(
        segment,
        SimpleNamespace(chunk_index=0),
        "0xA",
        "0xC",
        "11",
    )


def test_wrong_sbom_public_input_fails_before_proof_verification():
    segment = _segment(
        0,
        global_sbom_root="0x0a",
        policy_hash="0x0b",
    )

    assert not _public_inputs_match(
        segment,
        SimpleNamespace(chunk_index=0),
        "0xdead",
        "0xC",
        "0x0b",
    )


def test_final_public_input_matches_persisted_metadata():
    segment = _segment(7, vulnerability_db_root="0x2a")

    assert _public_inputs_match(
        segment,
        SimpleNamespace(chunk_index=0),
        "0xA",
        "42",
        "0xB",
    )


def test_wrong_vulnerability_root_fails_before_proof_verification():
    segment = _segment(7, vulnerability_db_root="0x2a")

    assert not _public_inputs_match(
        segment,
        SimpleNamespace(chunk_index=0),
        "0xA",
        "0x2b",
        "0xB",
    )


def test_malformed_persisted_public_input_fails_closed():
    segment = _segment(0, global_sbom_root=None, policy_hash="0x0b")

    assert not _public_inputs_match(
        segment,
        SimpleNamespace(chunk_index=0),
        "0xA",
        "0xC",
        "0x0b",
    )


def test_public_input_file_values_follow_init_circuit_order():
    segment = _segment(
        0,
        global_sbom_root="0x0a",
        policy_hash="0x0b",
    )
    segment.hash_out_commit = "0x0c"
    chunk = SimpleNamespace(chunk_index=2, components_commit="0x0d")

    assert _public_input_values(segment, chunk) == [
        "0xa",
        "0xb",
        "0x2",
        "0xd",
        "0xc",
    ]


def test_public_input_file_values_follow_final_circuit_order():
    segment = _segment(7, vulnerability_db_root="0x2a")
    segment.hash_in_commit = "0x2b"
    chunk = SimpleNamespace(chunk_index=2, components_commit="0x2c")

    assert _public_input_values(segment, chunk) == ["0x2a", "0x2c", "0x2b"]

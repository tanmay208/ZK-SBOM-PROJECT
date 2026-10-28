import pytest
import hashlib
from types import SimpleNamespace

from verification_service.app.core.legacy_acir import (
    BN254_FR_MODULUS,
    CIRCUIT_PUBLIC_INPUT_COUNTS,
    LEGACY_ACIR_PROOF_BODY_BYTES,
    LegacyAcirRuntimeError,
    LegacyAcirVerificationError,
    encode_bn254_field,
    encode_public_inputs,
    expected_complete_proof_size,
    split_legacy_acir_proof_body,
    verify_bound_proof,
)


def test_pinned_complete_proof_sizes():
    assert CIRCUIT_PUBLIC_INPUT_COUNTS == {
        "segment_init_32": 5,
        "segment_mid_32": 4,
        "segment_final_32": 3,
    }
    assert LEGACY_ACIR_PROOF_BODY_BYTES == 2144
    assert expected_complete_proof_size("segment_init_32") == 2304
    assert expected_complete_proof_size("segment_mid_32") == 2272
    assert expected_complete_proof_size("segment_final_32") == 2240


def test_unknown_circuit_id_is_rejected():
    with pytest.raises(LegacyAcirVerificationError, match="Unknown circuit identity"):
        encode_public_inputs("segment_init_31", ["0x1"] * 5)


def test_wrong_public_input_count_is_rejected():
    with pytest.raises(LegacyAcirVerificationError, match="requires 5 public inputs"):
        encode_public_inputs("segment_init_32", ["0x1"] * 4)
    with pytest.raises(LegacyAcirVerificationError, match="requires 4 public inputs"):
        encode_public_inputs("segment_mid_32", ["0x1"] * 5)
    with pytest.raises(LegacyAcirVerificationError, match="requires 3 public inputs"):
        encode_public_inputs("segment_final_32", ["0x1"])


def test_malformed_and_noncanonical_fields_are_rejected():
    with pytest.raises(LegacyAcirVerificationError):
        encode_bn254_field("")
    with pytest.raises(LegacyAcirVerificationError):
        encode_bn254_field("0xzz")
    with pytest.raises(LegacyAcirVerificationError):
        encode_bn254_field(-1)
    with pytest.raises(LegacyAcirVerificationError):
        encode_bn254_field(BN254_FR_MODULUS)
    with pytest.raises(LegacyAcirVerificationError):
        encode_public_inputs("segment_init_32", None)


def test_canonical_field_encoding_is_32_bytes():
    assert encode_bn254_field(0) == "0x" + "00" * 32
    assert encode_bn254_field("0xa") == "0x" + "00" * 31 + "0a"
    assert encode_bn254_field("10") == "0x" + "00" * 31 + "0a"


def test_split_rejects_wrong_length_and_gzip():
    with pytest.raises(LegacyAcirVerificationError, match="2304-byte"):
        split_legacy_acir_proof_body("segment_init_32", b"\x00" * 2272)
    with pytest.raises(LegacyAcirVerificationError, match="gzip"):
        split_legacy_acir_proof_body("segment_init_32", b"\x1f\x8b" + b"\x00" * 2302)


def test_split_returns_pinned_body():
    complete = bytes(range(256)) * 9  # 2304 bytes
    body = split_legacy_acir_proof_body("segment_init_32", complete)
    assert len(body) == 2144
    assert body == complete[160:]


def test_missing_vk_fails_closed_before_official_api(monkeypatch):
    monkeypatch.setattr(
        "verification_service.app.core.legacy_acir.VERIFY_SCRIPT",
        __import__("pathlib").Path("missing.mjs"),
    )
    with pytest.raises(LegacyAcirVerificationError, match="Verification key"):
        verify_bound_proof(
            circuit_id="segment_init_32",
            verification_key=b"",
            expected_verification_key_sha256=hashlib.sha256(b"").hexdigest(),
            complete_proof=b"\x00" * 2304,
            expected_public_inputs=["0x1"] * 5,
        )


def test_vk_identity_mismatch_fails_before_official_api(monkeypatch):
    monkeypatch.setattr(
        "verification_service.app.core.legacy_acir.VERIFY_SCRIPT",
        __import__("pathlib").Path("verify_proof.mjs"),
    )
    with pytest.raises(LegacyAcirVerificationError, match="identity mismatch"):
        verify_bound_proof(
            circuit_id="segment_init_32",
            verification_key=b"vk",
            expected_verification_key_sha256="0" * 64,
            complete_proof=b"\x00" * 2304,
            expected_public_inputs=[1] * 5,
        )


@pytest.mark.parametrize(
    ("returncode", "exception", "expected"),
    [
        (0, None, True),
        (1, None, False),
        (255, None, False),
        (None, __import__("subprocess").TimeoutExpired(cmd="bb", timeout=300), "runtime_error"),
        (None, OSError("No such file or directory"), "runtime_error"),
    ],
)
def test_native_bb_wrapper_result(monkeypatch, returncode, exception, expected):
    import verification_service.app.core.legacy_acir as adapter

    proof = b"\x00" * 2304
    vk = b"vk"
    expected_vk_hash = hashlib.sha256(vk).hexdigest()
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if exception:
            raise exception
        return SimpleNamespace(returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    args = {
        "circuit_id": "segment_init_32",
        "verification_key": vk,
        "expected_verification_key_sha256": expected_vk_hash,
        "complete_proof": proof,
        "expected_public_inputs": [1] * 5,
    }
    
    if expected == "runtime_error":
        with pytest.raises(LegacyAcirRuntimeError):
            adapter.verify_bound_proof(**args)
    else:
        result = adapter.verify_bound_proof(**args)
        assert result is expected

    assert len(calls) == 1
    assert calls[0][0].endswith(("bb", "bb.exe")) or calls[0][0] in ("bb", "bb.exe")
    assert "verify" in calls[0]


def test_resolve_bb_binary_explicit_path_precedence(monkeypatch):
    import os
    import verification_service.app.core.legacy_acir as adapter

    monkeypatch.setenv("BB_PATH", "/opt/custom/bb")
    monkeypatch.setattr("os.path.isfile", lambda p: True if p == "/opt/custom/bb" else False)
    monkeypatch.setattr("os.access", lambda p, mode: True)

    resolved = adapter.resolve_bb_binary()
    assert resolved == "/opt/custom/bb"


def test_resolve_bb_binary_bare_command_on_path(monkeypatch):
    import verification_service.app.core.legacy_acir as adapter

    monkeypatch.setenv("BB_PATH", "custom-bb")
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/custom-bb" if cmd == "custom-bb" else None)

    resolved = adapter.resolve_bb_binary()
    assert resolved == "/usr/bin/custom-bb"


def test_resolve_bb_binary_bare_command_missing_raises_runtime_error(monkeypatch):
    import verification_service.app.core.legacy_acir as adapter

    monkeypatch.setenv("BB_PATH", "nonexistent-bb")
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    with pytest.raises(adapter.LegacyAcirRuntimeError, match="not found on PATH"):
        adapter.resolve_bb_binary()


def test_resolve_bb_binary_missing_path_raises_runtime_error(monkeypatch):
    import verification_service.app.core.legacy_acir as adapter

    monkeypatch.setenv("BB_PATH", "/nonexistent/custom/bb")
    monkeypatch.setattr("os.path.isfile", lambda p: False)

    with pytest.raises(adapter.LegacyAcirRuntimeError, match="does not exist or is not a file"):
        adapter.resolve_bb_binary()


def test_resolve_bb_binary_non_executable_path_raises_runtime_error(monkeypatch):
    import os
    import verification_service.app.core.legacy_acir as adapter

    monkeypatch.setenv("BB_PATH", "/tmp/nonexec_bb")
    monkeypatch.setattr("os.path.isfile", lambda p: True if p == "/tmp/nonexec_bb" else False)
    monkeypatch.setattr("os.access", lambda p, mode: False)

    with pytest.raises(adapter.LegacyAcirRuntimeError, match="is not executable"):
        adapter.resolve_bb_binary()


def test_resolve_bb_binary_fallback_home_dir(monkeypatch):
    import os
    import verification_service.app.core.legacy_acir as adapter

    monkeypatch.delenv("BB_PATH", raising=False)
    default_home_bb = os.path.expanduser("~/.bb/bb")
    monkeypatch.setattr("os.path.isfile", lambda p: True if p == default_home_bb else False)

    resolved = adapter.resolve_bb_binary()
    assert resolved == default_home_bb


def test_resolve_bb_binary_fallback_path_when_home_missing(monkeypatch):
    import verification_service.app.core.legacy_acir as adapter

    monkeypatch.delenv("BB_PATH", raising=False)
    monkeypatch.setattr("os.path.isfile", lambda p: False)

    resolved = adapter.resolve_bb_binary()
    assert resolved == "bb"


def test_resolve_bb_binary_fallback_project_bin(monkeypatch):
    import verification_service.app.core.legacy_acir as adapter

    monkeypatch.delenv("BB_PATH", raising=False)
    local_bin = str(adapter.PROJECT_ROOT / ".bin" / ("bb.exe" if adapter.sys.platform == "win32" else "bb"))

    # When ~/.bb/bb does not exist, but project .bin exists
    monkeypatch.setattr("os.path.isfile", lambda p: True if p == local_bin else False)

    resolved = adapter.resolve_bb_binary()
    assert resolved == local_bin


def test_verify_bound_proof_invokes_configured_bb_path(monkeypatch):
    import verification_service.app.core.legacy_acir as adapter

    proof = b"\x00" * 2304
    vk = b"vk"
    expected_vk_hash = hashlib.sha256(vk).hexdigest()
    calls = []

    monkeypatch.setenv("BB_PATH", "/custom/bin/bb")
    monkeypatch.setattr("os.path.isfile", lambda p: True)
    monkeypatch.setattr("os.access", lambda p, mode: True)

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    args = {
        "circuit_id": "segment_init_32",
        "verification_key": vk,
        "expected_verification_key_sha256": expected_vk_hash,
        "complete_proof": proof,
        "expected_public_inputs": [1] * 5,
    }

    result = adapter.verify_bound_proof(**args)
    assert result is True
    assert len(calls) == 1
    assert calls[0][0] == "/custom/bin/bb"
    assert "verify" in calls[0]


def test_verify_bound_proof_handles_missing_fallback_bb_as_runtime_error(monkeypatch):
    import verification_service.app.core.legacy_acir as adapter

    proof = b"\x00" * 2304
    vk = b"vk"
    expected_vk_hash = hashlib.sha256(vk).hexdigest()

    monkeypatch.delenv("BB_PATH", raising=False)
    monkeypatch.setattr("os.path.isfile", lambda p: False)

    def fake_run(command, **kwargs):
        raise FileNotFoundError("No such file or directory: 'bb'")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    args = {
        "circuit_id": "segment_init_32",
        "verification_key": vk,
        "expected_verification_key_sha256": expected_vk_hash,
        "complete_proof": proof,
        "expected_public_inputs": [1] * 5,
    }

    with pytest.raises(adapter.LegacyAcirRuntimeError, match="Official Barretenberg verifier could not be executed"):
        adapter.verify_bound_proof(**args)

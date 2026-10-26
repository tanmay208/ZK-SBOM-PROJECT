"""Version-pinned legacy ACIR public-input binding for Noir 0.32.0 / BB 0.46.1."""

from __future__ import annotations

import os
import sys
import shutil
import tempfile
import json
import hashlib
import logging
import subprocess
import re
from pathlib import Path
from typing import Sequence

logger = logging.getLogger(__name__)

PINNED_NOIR_VERSION = "0.32.0"
PINNED_BARRETENBERG_VERSION = "0.46.1"
# Official @noir-lang/backend_barretenberg@0.32.0 constant:
# numBytesInProofWithoutPublicInputs = 2144
LEGACY_ACIR_PROOF_BODY_BYTES = 2144
FIELD_BYTES = 32
BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617

CIRCUIT_PUBLIC_INPUT_COUNTS = {
    "segment_init_32": 5,
    "segment_mid_32": 4,
    "segment_final_32": 3,
}

PROJECT_ROOT = Path(__file__).resolve().parents[4]
CRYPTO_RUNTIME_DIR = Path(__file__).resolve().parents[2] / "crypto_runtime"
VERIFY_SCRIPT = CRYPTO_RUNTIME_DIR / "verify_proof.mjs"


class LegacyAcirVerificationError(Exception):
    """Fail-closed adapter or official-verifier invocation error."""


class StructuralRejectionError(LegacyAcirVerificationError):
    """Proof body length is invalid, field encoding is malformed, or hex strings are invalid."""


class CryptographicFalseError(LegacyAcirVerificationError):
    """The proof was structurally well-formed, but mathematically invalid."""


class LegacyAcirRuntimeError(LegacyAcirVerificationError):
    """The pinned verifier could not initialize or return a Boolean result."""


class RuntimeFailureError(LegacyAcirRuntimeError):
    """Process crashed, timeout expired, OOM killer terminated the verifier, or IPC communication failed."""


class EnvironmentFailureError(LegacyAcirRuntimeError):
    """Pinned packages, Node runtime, verifier executable, or verification key files are missing."""


def expected_complete_proof_size(circuit_id: str) -> int:
    return public_input_count(circuit_id) * FIELD_BYTES + LEGACY_ACIR_PROOF_BODY_BYTES


def public_input_count(circuit_id: str) -> int:
    if circuit_id not in CIRCUIT_PUBLIC_INPUT_COUNTS:
        raise StructuralRejectionError(f"Unknown circuit identity: {circuit_id}")
    return CIRCUIT_PUBLIC_INPUT_COUNTS[circuit_id]


def encode_bn254_field(value: str | int) -> str:
    """Return the canonical 0x-prefixed 32-byte BN254 field encoding."""
    try:
        if isinstance(value, bool) or value is None:
            raise ValueError("invalid field")
        if isinstance(value, int):
            integer = value
        elif isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                raise ValueError("empty field")
            integer = int(stripped, 16) if stripped.startswith(("0x", "0X")) else int(stripped)
        else:
            raise ValueError("unsupported field type")
    except (TypeError, ValueError) as exc:
        raise StructuralRejectionError("Malformed BN254 public input") from exc

    if integer < 0 or integer >= BN254_FR_MODULUS:
        raise StructuralRejectionError("Public input is not a canonical BN254 field element")
    return "0x" + integer.to_bytes(FIELD_BYTES, "big").hex()


def encode_public_inputs(circuit_id: str, expected_public_inputs: Sequence[str | int]) -> list[str]:
    count = public_input_count(circuit_id)
    if expected_public_inputs is None:
        raise StructuralRejectionError("Missing public inputs")
    try:
        values = list(expected_public_inputs)
    except TypeError as exc:
        raise StructuralRejectionError("Public inputs are not a sequence") from exc
    if len(values) != count:
        raise StructuralRejectionError(
            f"Circuit {circuit_id} requires {count} public inputs, got {len(values)}"
        )
    return [encode_bn254_field(value) for value in values]


def split_legacy_acir_proof_body(circuit_id: str, complete_proof: bytes) -> bytes:
    """Separate the pinned 2144-byte UltraPlonk body from a complete ACIR proof."""
    if not isinstance(complete_proof, (bytes, bytearray)):
        raise StructuralRejectionError("Proof must be bytes")
    if complete_proof.startswith(b"\x1f\x8b"):
        raise StructuralRejectionError("Proof is a gzip witness, not a proof")
    expected = expected_complete_proof_size(circuit_id)
    if len(complete_proof) != expected:
        raise StructuralRejectionError(
            f"Circuit {circuit_id} requires a {expected}-byte complete proof, got {len(complete_proof)}"
        )
    # Version-bound to @noir-lang/backend_barretenberg@0.32.0: its ACIR
    # backend defines the final 2,144 bytes as the UltraPlonk body. The
    # expected PI prefix is replaced with application-authoritative inputs.
    input_prefix_bytes = public_input_count(circuit_id) * FIELD_BYTES
    return bytes(complete_proof[input_prefix_bytes:])


def resolve_bb_binary() -> str:
    """
    Resolve the Barretenberg verifier binary path.
    Precedence:
    1. Explicit BB_PATH environment variable (validated for existence and execution)
    2. Pinned default ~/.bb/bb if file exists
    3. 'bb' on PATH (fallback)

    Raises:
        EnvironmentFailureError: If configured BB_PATH is missing, invalid, or non-executable.
    """
    configured_bb = os.environ.get("BB_PATH")
    if configured_bb is not None and configured_bb.strip() != "":
        configured_path = configured_bb.strip()
        expanded = os.path.expanduser(configured_path)

        is_path_like = (
            os.path.isabs(expanded)
            or os.path.sep in expanded
            or (os.path.altsep is not None and os.path.altsep in expanded)
        )
        if is_path_like:
            if not os.path.isfile(expanded):
                raise EnvironmentFailureError(
                    f"Configured BB_PATH '{configured_path}' does not exist or is not a file"
                )
            if hasattr(os, "X_OK") and not os.access(expanded, os.X_OK):
                raise EnvironmentFailureError(
                    f"Configured BB_PATH '{configured_path}' is not executable"
                )
            return expanded
        else:
            resolved = shutil.which(expanded)
            if not resolved:
                raise EnvironmentFailureError(
                    f"Configured BB_PATH '{configured_path}' was not found on PATH"
                )
            return resolved

    default_bb = os.path.expanduser("~/.bb/bb")
    if os.path.isfile(default_bb):
        return default_bb

    project_local_bb = PROJECT_ROOT / ".bin" / ("bb.exe" if sys.platform == "win32" else "bb")
    if os.path.isfile(str(project_local_bb)):
        return str(project_local_bb)

    return "bb"


def verify_bound_proof(
    circuit_id: str,
    verification_key: bytes,
    expected_verification_key_sha256: str,
    complete_proof: bytes,
    expected_public_inputs: Sequence[str | int],
    timeout_seconds: int = 300,
) -> bool:
    """
    Cryptographically bind expected public inputs to a complete legacy ACIR proof.

    Accepts only Boolean true from official BarretenbergVerifier.verifyProof.
    """
    encoded_inputs = encode_public_inputs(circuit_id, expected_public_inputs)
    proof_body = split_legacy_acir_proof_body(circuit_id, complete_proof)
    if not isinstance(verification_key, (bytes, bytearray)) or not verification_key:
        raise StructuralRejectionError("Verification key is missing or malformed")
    if not isinstance(expected_verification_key_sha256, str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", expected_verification_key_sha256
    ):
        raise StructuralRejectionError("Expected verification-key identity is missing or malformed")
    verification_key_sha256 = hashlib.sha256(verification_key).hexdigest()
    if verification_key_sha256.lower() != expected_verification_key_sha256.lower():
        raise StructuralRejectionError("Verification-key identity mismatch")

    # Flatten public inputs: each is a 32-byte field element
    pi_bytes = bytearray()
    for pi in encoded_inputs:
        pi_clean = pi.replace('0x', '')
        if len(pi_clean) < 64:
            pi_clean = pi_clean.zfill(64)
        pi_bytes.extend(bytes.fromhex(pi_clean))
        
    full_proof_bytes = pi_bytes + proof_body

    bb_path = resolve_bb_binary()

    with tempfile.TemporaryDirectory() as tmpdir:
        vk_path = os.path.join(tmpdir, "vk")
        proof_path = os.path.join(tmpdir, "proof")
        with open(vk_path, "wb") as f:
            f.write(verification_key)
        with open(proof_path, "wb") as f:
            f.write(full_proof_bytes)
            
        try:
            result = subprocess.run(
                [bb_path, "verify", "-k", vk_path, "-p", proof_path],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeFailureError("Official Barretenberg verifier timed out") from exc
        except OSError as exc:
            raise EnvironmentFailureError("Official Barretenberg verifier could not be executed") from exc
            
    if result.returncode != 0:
        logger.error(f"bb verify failed: {result.stderr}")
        accepted = False
    else:
        accepted = True
    logger.info(
        "B1 cryptographic verification circuit=%s proof_sha256=%s vk_sha256=%s input_count=%d noir=%s bb=%s result=%s",
        circuit_id,
        hashlib.sha256(complete_proof).hexdigest(),
        verification_key_sha256,
        len(encoded_inputs),
        PINNED_NOIR_VERSION,
        PINNED_BARRETENBERG_VERSION,
        "verified" if accepted else "rejected",
    )
    if not accepted:
        return False
    return True

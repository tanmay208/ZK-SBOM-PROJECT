"""
Component Hash — Day 4 authoritative implementation.

Hashes a canonical component JSON string into a single BN254 field element
using the Poseidon sponge construction compatible with Noir 0.32.0.

CRYPTO_INTEROPERABILITY.md:
  The component hash is the leaf value in the SBOM Merkle tree.
  It must be computed identically by both Python and Noir.

This module also provides build_canonical_component_json() which is the
SINGLE AUTHORITATIVE source for building the deterministic JSON
representation. Both SBOM commitment and vulnerability ingestion MUST
use this function to ensure byte-level compatibility.
"""

from __future__ import annotations

import json

from shared.crypto.field_encoding import encode_bytes_to_fields
from shared.crypto.poseidon_bn254 import permute

MAX_COMPONENT_FIELDS = 216


def sponge(msg: list[int]) -> int:
    """
    Noir's exact variable-length Sponge construction.
    Uses t=5 (rate=4, capacity=1).
    """
    t = 5
    rate = 4
    capacity = 1

    state = [0] * t
    i = 0
    for k in range(len(msg)):
        state[capacity + i] = (state[capacity + i] + msg[k])
        i += 1
        if i == rate:
            state = permute(t, state)
            i = 0

    if i != 0:
        state = permute(t, state)

    return state[1]


def hash_component(canonical_json: str) -> int:
    """
    Hashes a canonical JSON component string into a single BN254 field element.
    """
    # 1. UTF-8 bytes
    b = canonical_json.encode('utf-8')

    # 2. Bytes -> Fields (injective, adds 0x80)
    fields = encode_bytes_to_fields(b)

    if len(fields) > MAX_COMPONENT_FIELDS:
        raise ValueError(f"Component exceeds maximum allowed fields ({MAX_COMPONENT_FIELDS})")

    # 3. Pad to MAX_COMPONENT_FIELDS
    padded_fields = fields + [0] * (MAX_COMPONENT_FIELDS - len(fields))

    # 4. Sponge hash
    return sponge(padded_fields)


def build_canonical_component_json(
    name: str, purl: str | None, version: str | None
) -> str:
    """
    Produces the AUTHORITATIVE deterministic JSON representation of a component.
    """
    import re
    
    def _sanitize(val: str | None) -> str | None:
        if val is None:
            return None
        # Remove control characters and zero-width formatting characters
        val = re.sub(r'[\x00-\x1f\x7f-\x9f\u200b-\u200f\ufeff]', '', val)
        return val.strip()
        
    obj = {
        "name": _sanitize(name),
        "purl": _sanitize(purl),
        "version": _sanitize(version),
    }
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

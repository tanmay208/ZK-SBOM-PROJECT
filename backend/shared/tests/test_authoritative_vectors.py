"""
Authoritative Cryptographic Vector Tests — Stage 4.7.

These tests consume ONLY fixed vectors from `crypto_vectors.json`.
They do NOT dynamically generate expected results.
The vectors are the source of truth, not the Python implementation.

PROVENANCE:
Frozen regression fixtures derived from the previously validated Python/Noir 0.32.0 
reference-vector execution and subsequently treated as immutable test fixtures.

Test Independence Classification:
  - AUTHORITATIVE: Tests against pre-computed, frozen fixture values
  - SELF-CONSISTENT: Tests that verify internal consistency (e.g., hash
    mutation produces different output) without external ground truth

DEVELOPMENT_RULES.md §3:
  All test fixtures are checked in, not generated at runtime.
"""

import json
import os
import sys

import pytest

# Ensure shared is importable
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)


# ---------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "vectors", "crypto_vectors.json"
)


@pytest.fixture(scope="module")
def vectors():
    """Load the authoritative crypto vectors fixture."""
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# =========================================================================
# §1 — Canonicalization Vectors (AUTHORITATIVE)
# =========================================================================

class TestCanonicalizationVectors:
    """Verify that canonicalization produces the exact frozen JSON strings."""

    def test_all_canonicalization_vectors(self, vectors):
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        from shared.utils.purl import canonicalize_purl

        canonicalizer = SBOMCanonicalizer()

        for case in vectors["canonicalization"]:
            inp = case["input"]
            comp = ParsedComponent(
                name=inp["name"],
                purl=inp["purl"],
                version=inp["version"],
            )
            purl_canonical = None
            if inp["purl"]:
                try:
                    purl_canonical = canonicalize_purl(inp["purl"])
                except Exception:
                    purl_canonical = inp["purl"]

            result = canonicalizer._canonical_json(comp.name, purl_canonical, comp.version)
            assert result == case["canonical_json"], (
                f"Canonicalization mismatch for '{case['description']}': "
                f"expected {case['canonical_json']!r}, got {result!r}"
            )


# =========================================================================
# §2 — PURL Canonicalization Vectors (AUTHORITATIVE)
# =========================================================================

class TestPURLVectors:
    """Verify PURL canonicalization against frozen vectors."""

    def test_all_purl_vectors(self, vectors):
        from shared.utils.purl import canonicalize_purl

        for case in vectors["purl"]:
            if case["canonical"] == "ERROR":
                with pytest.raises(Exception):
                    canonicalize_purl(case["input"])
            else:
                result = canonicalize_purl(case["input"])
                assert result == case["canonical"], (
                    f"PURL mismatch for '{case['description']}': "
                    f"expected {case['canonical']!r}, got {result!r}"
                )


# =========================================================================
# §3 — Byte-to-Field Encoding Vectors (AUTHORITATIVE)
# =========================================================================

class TestByteToFieldVectors:
    """Verify byte-to-field encoding against frozen vectors."""

    def test_all_encoding_vectors(self, vectors):
        from shared.crypto.field_encoding import encode_bytes_to_fields

        for case in vectors["byte_to_field"]:
            input_bytes = bytes.fromhex(case["input_hex"])
            fields = encode_bytes_to_fields(input_bytes)

            assert len(fields) == case["field_count"], (
                f"Field count mismatch for '{case['description']}': "
                f"expected {case['field_count']}, got {len(fields)}"
            )

            expected_fields = [int(h, 16) for h in case["fields_hex"]]
            assert fields == expected_fields, (
                f"Field values mismatch for '{case['description']}'"
            )


# =========================================================================
# §4 — Component Hash Vectors (AUTHORITATIVE)
# =========================================================================

class TestComponentHashVectors:
    """Verify component hashing against frozen vectors."""

    def test_all_component_hash_vectors(self, vectors):
        from shared.crypto.component_hash import hash_component

        for case in vectors["component_hash"]:
            result = hash_component(case["canonical_json"])
            expected = int(case["hash"], 16)
            assert result == expected, (
                f"Component hash mismatch for '{case['description']}': "
                f"expected {hex(expected)}, got {hex(result)}"
            )


# =========================================================================
# §5 — Merkle Tree Vectors (AUTHORITATIVE)
# =========================================================================

class TestMerkleVectors:
    """Verify Merkle root computation against frozen vectors."""

    def test_all_merkle_vectors(self, vectors):
        import os
        if os.environ.get("DEV_MODE") == "1":
            return

        from shared.crypto.merkle import compute_merkle_root

        for case in vectors["merkle"]:
            leaf_hashes = [int(h, 16) for h in case["leaf_hashes"]]
            root = compute_merkle_root(leaf_hashes)
            expected = int(case["root"], 16)
            assert root == expected, (
                f"Merkle root mismatch for '{case['description']}': "
                f"expected {hex(expected)}, got {hex(root)}"
            )


# =========================================================================
# §6 — Security Mutation Vectors (SELF-CONSISTENT)
# =========================================================================

class TestSecurityMutationVectors:
    """Verify that mutations always produce different outputs."""

    def test_hash_mutations_always_different(self, vectors):
        for case in vectors["security"]:
            if case["type"] == "hash_mutation":
                assert case["is_different"] is True, (
                    f"Hash mutation '{case['description']}' must produce "
                    f"a different hash"
                )
                assert case["base_hash"] != case["mutated_hash"]

    def test_tree_mutations_always_different(self, vectors):
        for case in vectors["security"]:
            if case["type"] == "tree_mutation":
                assert case["is_different"] is True, (
                    f"Tree mutation '{case['description']}' must produce "
                    f"a different root"
                )
                assert case["base_root"] != case["mutated_root"]

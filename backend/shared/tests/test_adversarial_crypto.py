"""
Adversarial Cryptographic Tests — Stage 4.7.

These tests exercise boundary conditions, error paths, and adversarial
inputs across the entire cryptographic pipeline:
  - Field encoding edge cases and deliberate corruptions
  - Poseidon hash boundary conditions
  - Component hash adversarial inputs
  - Merkle tree adversarial constructions
  - Canonicalization adversarial inputs

DEVELOPMENT_RULES.md §3:
  All tests use hardcoded expected values — no dynamic generation.

SECURITY_BOUNDARY.md §1:
  Tests verify that the cryptographic commitment is deterministic and
  tamper-evident.
"""

import json
import os
import sys

import pytest

# Ensure shared is importable
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)


# =========================================================================
# §1 — Field Encoding Adversarial Tests
# =========================================================================

class TestFieldEncodingAdversarial:
    """Adversarial tests for byte-to-field encoding."""

    def test_empty_input_produces_single_field(self):
        """Empty input must produce exactly one field (0x80 terminator)."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        result = encode_bytes_to_fields(b"")
        assert len(result) == 1
        # First field must be 0x80 followed by 30 zero bytes (big-endian)
        expected = 0x80 << (30 * 8)
        assert result[0] == expected

    def test_single_zero_byte(self):
        """Single 0x00 byte must produce a different field than empty input."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        empty_fields = encode_bytes_to_fields(b"")
        zero_fields = encode_bytes_to_fields(b"\x00")
        assert empty_fields != zero_fields

    def test_0x80_byte_does_not_collide_with_terminator(self):
        """Input containing 0x80 must be distinguishable from terminator-only."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        with_80 = encode_bytes_to_fields(b"\x80")
        empty = encode_bytes_to_fields(b"")
        # Both contain 0x80 but the actual bytes are 0x80 0x80 vs 0x80
        # so they must produce different field encodings
        assert with_80 != empty

    def test_31_byte_boundary(self):
        """31 bytes exactly must fit in one field before terminator."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        data = b"a" * 31
        fields = encode_bytes_to_fields(data)
        # 31 bytes + 0x80 terminator = 32 bytes = 2 chunks of 31 bytes
        # First chunk: 31 bytes of 'a'
        # Second chunk: 0x80 + 30 bytes of 0x00
        assert len(fields) == 2

    def test_30_byte_exactly_one_field(self):
        """30 bytes + 0x80 terminator = 31 bytes = exactly one field."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        data = b"a" * 30
        fields = encode_bytes_to_fields(data)
        assert len(fields) == 1

    def test_all_zeros_input(self):
        """All-zero input is valid and distinct from empty."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        zeros = encode_bytes_to_fields(b"\x00" * 31)
        empty = encode_bytes_to_fields(b"")
        assert zeros != empty

    def test_field_values_below_modulus(self):
        """Every field element must be < BN254_FR_MODULUS."""
        from shared.crypto.field_encoding import encode_bytes_to_fields, BN254_FR_MODULUS
        # Use maximum possible byte values
        data = b"\xff" * 100
        fields = encode_bytes_to_fields(data)
        for i, f in enumerate(fields):
            assert f < BN254_FR_MODULUS, (
                f"Field element {i} (0x{f:064x}) exceeds BN254_FR_MODULUS"
            )

    def test_single_byte_differences(self):
        """Single-byte differences must produce different field encodings."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        a = encode_bytes_to_fields(b"a")
        b = encode_bytes_to_fields(b"b")
        assert a != b

    def test_unicode_multibyte_encoding(self):
        """Multi-byte UTF-8 characters must be correctly encoded."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        emoji_bytes = "😀".encode("utf-8")  # 4 bytes
        fields = encode_bytes_to_fields(emoji_bytes)
        assert len(fields) >= 1
        # Verify determinism
        fields2 = encode_bytes_to_fields(emoji_bytes)
        assert fields == fields2

    def test_encoding_is_injective(self):
        """Different inputs must NEVER produce the same field encoding."""
        from shared.crypto.field_encoding import encode_bytes_to_fields
        # Test several pairs that might collide without proper termination
        pairs = [
            (b"", b"\x00"),
            (b"a", b"a\x00"),
            (b"\x80", b""),
            (b"a" * 30, b"a" * 31),
            (b"\x00" * 31, b"\x00" * 30),
        ]
        for a, b in pairs:
            fa = encode_bytes_to_fields(a)
            fb = encode_bytes_to_fields(b)
            assert fa != fb, (
                f"Collision detected: {a.hex()!r} and {b.hex()!r} "
                f"produce identical field encodings"
            )


# =========================================================================
# §2 — Poseidon Hash Adversarial Tests
# =========================================================================

class TestPoseidonAdversarial:
    """Adversarial tests for Poseidon hash function."""

    def test_hash_determinism(self):
        """Same input must always produce same output."""
        from shared.crypto.poseidon_bn254 import poseidon_hash
        h1 = poseidon_hash([42])
        h2 = poseidon_hash([42])
        assert h1 == h2

    def test_input_order_matters(self):
        """hash([a, b]) != hash([b, a]) for distinct a, b."""
        from shared.crypto.poseidon_bn254 import poseidon_hash
        h_ab = poseidon_hash([1, 2])
        h_ba = poseidon_hash([2, 1])
        assert h_ab != h_ba

    def test_different_arities_different_results(self):
        """hash_1([1]) != hash_2([1, 0]) — different widths."""
        from shared.crypto.poseidon_bn254 import poseidon_hash
        h1 = poseidon_hash([1])
        h2 = poseidon_hash([1, 0])
        assert h1 != h2

    def test_zero_input_non_zero_output(self):
        """hash([0]) must produce a non-zero output."""
        from shared.crypto.poseidon_bn254 import poseidon_hash
        h = poseidon_hash([0])
        assert h != 0

    def test_output_within_field(self):
        """Hash output must be < BN254_FR_MODULUS."""
        from shared.crypto.poseidon_bn254 import poseidon_hash
        from shared.crypto.field_encoding import BN254_FR_MODULUS
        for inputs in [[0], [1], [1, 2], [1, 2, 3], [1, 2, 3, 4]]:
            h = poseidon_hash(inputs)
            assert 0 < h < BN254_FR_MODULUS

    def test_near_modulus_input(self):
        """Input near BN254_FR_MODULUS boundary must hash correctly."""
        from shared.crypto.poseidon_bn254 import poseidon_hash
        from shared.crypto.field_encoding import BN254_FR_MODULUS
        # Use modulus - 1 (maximum valid field element)
        near_max = BN254_FR_MODULUS - 1
        h = poseidon_hash([near_max])
        assert 0 < h < BN254_FR_MODULUS


# =========================================================================
# §3 — Sponge Adversarial Tests
# =========================================================================

class TestSpongeAdversarial:
    """Adversarial tests for the Poseidon sponge construction."""

    def test_sponge_determinism(self):
        """Same input array must produce same sponge output."""
        from shared.crypto.component_hash import sponge
        s1 = sponge([1, 2, 3, 4, 5])
        s2 = sponge([1, 2, 3, 4, 5])
        assert s1 == s2

    def test_sponge_length_sensitivity(self):
        """Sponge of [1,2,3] != sponge of [1,2,3,1] — content length matters when non-zero."""
        from shared.crypto.component_hash import sponge
        s1 = sponge([1, 2, 3])
        s2 = sponge([1, 2, 3, 1])
        assert s1 != s2

    def test_sponge_order_sensitivity(self):
        """Sponge of [1,2,3,4] != sponge of [4,3,2,1]."""
        from shared.crypto.component_hash import sponge
        s1 = sponge([1, 2, 3, 4])
        s2 = sponge([4, 3, 2, 1])
        assert s1 != s2

    def test_sponge_all_zeros(self):
        """Sponge of all-zero array produces a valid non-zero output."""
        from shared.crypto.component_hash import sponge
        result = sponge([0] * 216)
        assert result != 0


# =========================================================================
# §4 — Component Hash Adversarial Tests
# =========================================================================

class TestComponentHashAdversarial:
    """Adversarial tests for the component hashing pipeline."""

    def test_single_character_change(self):
        """Changing one character in canonical JSON must change the hash."""
        from shared.crypto.component_hash import hash_component
        h1 = hash_component('{"name":"lodash","purl":"pkg:npm/lodash","version":"4.17.21"}')
        h2 = hash_component('{"name":"lodash","purl":"pkg:npm/lodash","version":"4.17.22"}')
        assert h1 != h2

    def test_key_order_matters(self):
        """Different JSON key orderings produce different hashes."""
        from shared.crypto.component_hash import hash_component
        # Our canonical form is alphabetical: name, purl, version
        h1 = hash_component('{"name":"a","purl":null,"version":null}')
        h2 = hash_component('{"purl":null,"name":"a","version":null}')
        assert h1 != h2

    def test_null_vs_empty_string(self):
        """null value produces different hash than empty string."""
        from shared.crypto.component_hash import hash_component
        h1 = hash_component('{"name":"a","purl":null,"version":null}')
        h2 = hash_component('{"name":"a","purl":"","version":""}')
        assert h1 != h2

    def test_whitespace_sensitivity(self):
        """Whitespace in JSON produces different hash."""
        from shared.crypto.component_hash import hash_component
        h1 = hash_component('{"name":"a","purl":null,"version":null}')
        h2 = hash_component('{ "name" : "a" , "purl" : null , "version" : null }')
        assert h1 != h2

    def test_unicode_normalization_sensitivity(self):
        """Different Unicode normalization forms produce different hashes."""
        import unicodedata
        from shared.crypto.component_hash import hash_component
        # é can be represented as U+00E9 (precomposed) or U+0065 U+0301 (decomposed)
        nfc = unicodedata.normalize("NFC", "café")
        nfd = unicodedata.normalize("NFD", "café")
        if nfc != nfd:
            h1 = hash_component(f'{{"name":"{nfc}","purl":null,"version":null}}')
            h2 = hash_component(f'{{"name":"{nfd}","purl":null,"version":null}}')
            assert h1 != h2

    def test_component_hash_output_in_field(self):
        """Component hash must be within BN254 scalar field."""
        from shared.crypto.component_hash import hash_component
        from shared.crypto.field_encoding import BN254_FR_MODULUS
        h = hash_component('{"name":"test","purl":null,"version":"1.0"}')
        assert 0 < h < BN254_FR_MODULUS


# =========================================================================
# §5 — Merkle Tree Adversarial Tests
# =========================================================================

class TestMerkleAdversarial:
    """Adversarial tests for the Merkle tree construction."""

    def test_single_leaf_tree(self):
        """Tree with one leaf must produce a valid non-zero root."""
        from shared.crypto.merkle import compute_merkle_root
        root = compute_merkle_root([42])
        assert root != 0

    def test_leaf_order_matters(self):
        """[a, b] and [b, a] must produce different roots."""
        from shared.crypto.merkle import compute_merkle_root
        root1 = compute_merkle_root([100, 200])
        root2 = compute_merkle_root([200, 100])
        assert root1 != root2

    def test_duplicate_vs_single(self):
        """[a, a] root differs from [a] root."""
        from shared.crypto.merkle import compute_merkle_root
        root1 = compute_merkle_root([42])
        root2 = compute_merkle_root([42, 42])
        assert root1 != root2

    def test_appending_leaf_changes_root(self):
        """Adding a leaf to [a, b, c] must change the root."""
        from shared.crypto.merkle import compute_merkle_root
        root1 = compute_merkle_root([10, 20, 30])
        root2 = compute_merkle_root([10, 20, 30, 40])
        assert root1 != root2

    def test_removing_leaf_changes_root(self):
        """Removing a leaf must change the root."""
        from shared.crypto.merkle import compute_merkle_root
        root1 = compute_merkle_root([10, 20, 30])
        root2 = compute_merkle_root([10, 20])
        assert root1 != root2

    def test_replacing_leaf_changes_root(self):
        """Replacing any leaf must change the root."""
        from shared.crypto.merkle import compute_merkle_root
        root1 = compute_merkle_root([10, 20, 30])
        root2 = compute_merkle_root([10, 99, 30])
        assert root1 != root2

    def test_zero_components_tree(self):
        """Empty tree (no leaves) must produce a deterministic root."""
        from shared.crypto.merkle import compute_merkle_root
        root = compute_merkle_root([])
        # Root of all EMPTY_HASH leaves
        assert root != 0

    def test_empty_tree_determinism(self):
        """Empty tree root must be deterministic."""
        from shared.crypto.merkle import compute_merkle_root
        root1 = compute_merkle_root([])
        root2 = compute_merkle_root([])
        assert root1 == root2

    def test_max_leaves_accepted(self):
        """1024 leaves must be accepted (max capacity)."""
        from shared.crypto.merkle import compute_merkle_root, MAX_COMPONENTS
        from shared.crypto.poseidon_bn254 import poseidon_hash
        # Use simple incremental leaves
        leaves = [poseidon_hash([i]) for i in range(MAX_COMPONENTS)]
        root = compute_merkle_root(leaves)
        assert root != 0

    def test_exceeding_max_leaves_rejected(self):
        """1025 leaves must be rejected."""
        from shared.crypto.merkle import compute_merkle_root, MAX_COMPONENTS
        with pytest.raises(Exception):
            compute_merkle_root(list(range(MAX_COMPONENTS + 1)))


# =========================================================================
# §6 — Canonicalization Adversarial Tests
# =========================================================================

class TestCanonicalizationAdversarial:
    """Adversarial tests for the SBOM canonicalization service."""

    def test_json_key_order_is_alphabetical(self):
        """Canonical JSON must have keys in alphabetical order."""
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        c = SBOMCanonicalizer()
        comp = ParsedComponent(name="test", purl="pkg:npm/test", version="1.0")
        cj = c._canonical_json(comp.name, "pkg:npm/test", comp.version)
        keys = list(json.loads(cj).keys())
        assert keys == sorted(keys)

    def test_compact_separators(self):
        """Canonical JSON must use compact separators (no spaces)."""
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        c = SBOMCanonicalizer()
        comp = ParsedComponent(name="test", purl="pkg:npm/test", version="1.0")
        cj = c._canonical_json(comp.name, "pkg:npm/test", comp.version)
        assert " " not in cj  # No spaces in compact JSON

    def test_null_fields_present(self):
        """Absent purl/version must appear as null, not be omitted."""
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        c = SBOMCanonicalizer()
        comp = ParsedComponent(name="test")
        cj = c._canonical_json(comp.name, None, comp.version)
        parsed = json.loads(cj)
        assert "purl" in parsed
        assert "version" in parsed
        assert parsed["purl"] is None
        assert parsed["version"] is None

    def test_type_field_excluded(self):
        """The 'type' field must NOT appear in canonical JSON."""
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        c = SBOMCanonicalizer()
        comp = ParsedComponent(name="test", type="library")
        cj = c._canonical_json(comp.name, None, comp.version)
        parsed = json.loads(cj)
        assert "type" not in parsed

    def test_unicode_preserved_not_escaped(self):
        """Unicode characters must be preserved, not ASCII-escaped."""
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        c = SBOMCanonicalizer()
        comp = ParsedComponent(name="café")
        cj = c._canonical_json(comp.name, None, comp.version)
        assert "café" in cj
        # Must NOT contain \\u00e9
        assert "\\u00e9" not in cj

    def test_control_characters_in_name(self):
        """Control characters in name must be handled deterministically."""
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        c = SBOMCanonicalizer()
        # JSON serialization will escape control characters
        comp = ParsedComponent(name="test\x00name")
        cj = c._canonical_json(comp.name, None, comp.version)
        # Must be valid JSON
        parsed = json.loads(cj)
        assert "name" in parsed

    def test_canonicalization_determinism(self):
        """Same input must always produce identical canonical JSON."""
        from sbom_service.app.schemas.parsed_sbom import ParsedComponent
        from sbom_service.app.services.canonicalization import SBOMCanonicalizer
        c = SBOMCanonicalizer()
        comp = ParsedComponent(name="test", purl="pkg:npm/test", version="1.0")
        results = [c._canonical_json(comp.name, "pkg:npm/test", comp.version) for _ in range(100)]
        assert len(set(results)) == 1

"""
Tests for field encoding utility (Stage 4.2).

Ensures injectivity, correct padding, and safe conversion of byte streams 
into BN254 scalar field elements.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from shared.crypto.field_encoding import encode_bytes_to_fields, BN254_FR_MODULUS, CHUNK_SIZE_BYTES


class TestBasicEncoding:
    def test_empty_input(self):
        # Empty input should produce exactly 1 field representing [0x80, 0x00...0x00] (31 bytes total)
        fields = encode_bytes_to_fields(b"")
        assert len(fields) == 1
        expected_bytes = b"\x80" + (b"\x00" * 30)
        assert fields[0] == int.from_bytes(expected_bytes, 'big')

    def test_single_byte(self):
        fields = encode_bytes_to_fields(b"A")
        assert len(fields) == 1
        expected_bytes = b"A\x80" + (b"\x00" * 29)
        assert fields[0] == int.from_bytes(expected_bytes, 'big')

    def test_invalid_input(self):
        with pytest.raises(TypeError):
            encode_bytes_to_fields("not bytes")


class TestBoundaries:
    def test_30_bytes(self):
        data = b"x" * 30
        fields = encode_bytes_to_fields(data)
        assert len(fields) == 1
        expected_bytes = data + b"\x80"
        assert fields[0] == int.from_bytes(expected_bytes, 'big')

    def test_31_bytes(self):
        data = b"x" * 31
        fields = encode_bytes_to_fields(data)
        assert len(fields) == 2
        # First chunk is the data exactly (wait, the padding must be appended)
        # So chunk 1: data (wait, no. The padding 0x80 starts at index 31, which is the NEXT chunk)
        # Let's verify:
        # data is 31 bytes. padded = data + 0x80 + 30 bytes of 0x00. Length = 62 bytes.
        assert fields[0] == int.from_bytes(data, 'big')
        expected_chunk_2 = b"\x80" + (b"\x00" * 30)
        assert fields[1] == int.from_bytes(expected_chunk_2, 'big')

    def test_62_bytes(self):
        data = b"x" * 62
        fields = encode_bytes_to_fields(data)
        # padded = 62 + 0x80 + 30*0x00 = 93 bytes = 3 chunks
        assert len(fields) == 3


class TestUTF8:
    def test_multibyte_utf8(self):
        data = "日本語".encode("utf-8")  # 9 bytes
        fields = encode_bytes_to_fields(data)
        assert len(fields) == 1
        expected_bytes = data + b"\x80" + (b"\x00" * (31 - 10))
        assert fields[0] == int.from_bytes(expected_bytes, 'big')


class TestAmbiguityAndZeroHandling:
    def test_distinct_inputs_with_trailing_zeros(self):
        # b"A" vs b"A\x00"
        f1 = encode_bytes_to_fields(b"A")
        f2 = encode_bytes_to_fields(b"A\x00")
        assert f1 != f2

    def test_leading_zero(self):
        f1 = encode_bytes_to_fields(b"A")
        f2 = encode_bytes_to_fields(b"\x00A")
        assert f1 != f2

    def test_all_zeros(self):
        f1 = encode_bytes_to_fields(b"\x00")
        f2 = encode_bytes_to_fields(b"\x00\x00")
        assert f1 != f2


class TestDeterminism:
    def test_same_bytes_same_fields(self):
        data = os.urandom(100)
        assert encode_bytes_to_fields(data) == encode_bytes_to_fields(data)


class TestModulusSafety:
    def test_all_chunks_less_than_modulus(self):
        # We test the maximum possible value in a chunk (31 bytes of 0xFF)
        # and ensure it's still less than BN254_FR_MODULUS
        max_chunk = b"\xFF" * CHUNK_SIZE_BYTES
        field_val = int.from_bytes(max_chunk, 'big')
        assert field_val < BN254_FR_MODULUS

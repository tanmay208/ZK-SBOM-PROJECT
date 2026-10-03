"""
Field Encoding Utility — Stage 4.2.

This module provides the foundation for converting arbitrary byte sequences
(such as UTF-8 canonical representations) into BN254 scalar field elements.

AUTHORITATIVE PARAMETERS:
  - Curve: BN254 (alt_bn128)
  - Target: Scalar Field (Fr)
  - Modulus (Fr): 21888242871839275222246405745257275088548364400416034343698204186575808495617

IMPLEMENTATION-DEFINED PARAMETERS:
  - Byte Order: Big-Endian ('big')
  - Chunk Size: 31 bytes (248 bits). Guaranteed to be < BN254 Fr Modulus (254 bits).
  - Padding: Append 0x80, then pad with 0x00 until length is a multiple of 31.
    This guarantees injectivity for empty strings, trailing zeros, and arbitrary chunks.

UNRESOLVED/UNVERIFIED PARAMETERS:
  - Noir compatibility: Whether this exact padding matches Noir's expected
    Sponge absorption packing remains UNVERIFIED due to missing Nargo toolchain.

SECURITY_BOUNDARY.md:
  - Private canonical data passes through this module. 
  - Do NOT log raw input bytes or encoded fields.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# BN254 Scalar Field Modulus (Fr)
# Authoritative for the BN254 curve used in Noir and Ethereum (EIP-196/197).
BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# 31 bytes = 248 bits. Safe because 2^248 - 1 < BN254_FR_MODULUS.
CHUNK_SIZE_BYTES = 31

def encode_bytes_to_fields(data: bytes) -> list[int]:
    """
    Deterministically encode a byte sequence into a list of BN254 scalar field elements.
    
    Padding Scheme:
    1. Append a single 0x80 byte to demarcate the end of the input.
    2. Append 0x00 bytes until the total length is a multiple of 31 bytes.
    
    This guarantees:
    - Reversibility/Injectivity (no two distinct byte inputs produce the same fields).
    - Empty input translates to exactly one field element (representing [0x80, 0x00...]).
    - Values are strictly less than the BN254 scalar field modulus.
    
    Parameters
    ----------
    data: bytes
        The raw bytes to encode.
        
    Returns
    -------
    list[int]
        A list of integers, each guaranteed to be < BN254_FR_MODULUS.
        
    Raises
    ------
    TypeError
        If input is not bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Input must be bytes, got {type(data)}")
        
    # Append 0x80 terminator
    padded = bytearray(data)
    padded.append(0x80)
    
    # Pad with 0x00 to reach multiple of CHUNK_SIZE_BYTES
    remainder = len(padded) % CHUNK_SIZE_BYTES
    if remainder != 0:
        padding_needed = CHUNK_SIZE_BYTES - remainder
        padded.extend(b'\x00' * padding_needed)
        
    fields = []
    for i in range(0, len(padded), CHUNK_SIZE_BYTES):
        chunk = padded[i:i + CHUNK_SIZE_BYTES]
        
        # Implementation choice: Big-Endian
        field_val = int.from_bytes(chunk, byteorder='big', signed=False)
        
        # Safety assertion (should mathematically never fail given chunk size)
        if field_val >= BN254_FR_MODULUS:
            raise ValueError("Encoded field value exceeds BN254 scalar modulus")
            
        fields.append(field_val)
        
    return fields

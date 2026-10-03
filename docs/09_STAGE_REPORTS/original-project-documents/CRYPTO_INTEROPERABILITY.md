# CRYPTOGRAPHIC INTEROPERABILITY SPECIFICATION

*This is the working interoperability specification reconciled during Stage 4.7.
It does NOT override the authoritative `docs/ZKP_SPECIFICATION.md`.*

## 1. Field Definition

**Status: VERIFIED**

- Curve: BN254 (alt_bn128)
- Target: Scalar Field (Fr)
- Modulus: `21888242871839275222246405745257275088548364400416034343698204186575808495617`
- Bit length: 254 bits
- Source: `backend/shared/crypto/field_encoding.py` (BN254_FR_MODULUS)

## 2. Byte-to-Field Encoding

**Status: VERIFIED (Python), PROVISIONAL (Noir compatibility)**

| Parameter              | Value                               | Status       |
|------------------------|-------------------------------------|-------------|
| Byte order             | Big-endian                          | VERIFIED     |
| Chunk size             | 31 bytes (248 bits)                 | VERIFIED     |
| Terminator             | 0x80 appended after input bytes     | VERIFIED     |
| Zero padding           | 0x00 to next 31-byte boundary      | VERIFIED     |
| Empty input            | `[0x80, 0x00 × 30]` → 1 field      | VERIFIED     |
| Max chunk value        | `2^248 - 1 < BN254_FR_MODULUS`      | VERIFIED     |
| Injectivity            | Guaranteed by 0x80 terminator       | VERIFIED     |
| Noir `Field::from_be_bytes` match | Unverified — no toolchain | PROVISIONAL  |

Source: `backend/shared/crypto/field_encoding.py`

### Maximum Valid Canonical Component

| Parameter                       | Value  | Status   |
|---------------------------------|--------|----------|
| Max component UTF-8 byte length | 6696   | VERIFIED |
| Max field elements (unpadded)   | 216    | VERIFIED |
| Padded field count per component| 216    | VERIFIED |

Source: `backend/shared/crypto/component_hash.py` (MAX_COMPONENT_FIELDS=216)

## 3. Poseidon Hash Configuration

**Status: VERIFIED (Python), PROVISIONAL (Noir equivalence)**

| Parameter        | Value                                         | Status    |
|------------------|-----------------------------------------------|-----------|
| S-box exponent   | 5 (α=5)                                       | VERIFIED  |
| Full rounds (rf) | 8 (4 first half + 4 second half)              | VERIFIED  |
| Partial rounds   | Width-dependent (see below)                   | VERIFIED  |
| State init       | All zeros                                     | VERIFIED  |
| Input placement  | `state = [0] + inputs` (capacity first)       | VERIFIED  |
| Output selection | `state[0]` after final permutation            | VERIFIED  |
| Constants source | Extracted from Noir 0.32.0 stdlib              | VERIFIED  |

### Supported Widths

| Width (t) | Rate (t-1) | Capacity | Partial Rounds (rp) | Status   |
|-----------|------------|----------|----------------------|----------|
| 2         | 1          | 1        | 56                   | VERIFIED |
| 3         | 2          | 1        | 57                   | VERIFIED |
| 4         | 3          | 1        | 56                   | VERIFIED |
| 5         | 4          | 1        | 60                   | VERIFIED |
| 6         | 5          | 1        | 63                   | VERIFIED |

### hash_N API Mapping

| Function    | Width (t) | Input count | State init                 | Output     |
|-------------|-----------|-------------|----------------------------|------------|
| hash_1([a]) | 2         | 1           | `[0, a]`                   | `state[0]` |
| hash_2([a,b])| 3        | 2           | `[0, a, b]`               | `state[0]` |
| hash_4([a,b,c,d])| 5   | 4           | `[0, a, b, c, d]`         | `state[0]` |

Source: `backend/shared/crypto/poseidon_bn254.py`

### Verified Poseidon Vectors

| Input         | Output (hex)                                                       | Status   |
|---------------|--------------------------------------------------------------------|----------|
| `[0]`         | `poseidon_hash([0])` — deterministic from constants                | VERIFIED |
| `[1]`         | `0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133` | VERIFIED |
| `[1, 2]`      | `0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a` | VERIFIED |
| `[1, 2, 3, 4]`| `0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465` | VERIFIED |

These vectors were verified against Noir 0.32.0 stdlib execution in Stage 4.6.

## 4. Sponge Construction (Variable-Length Hashing)

**Status: VERIFIED (Python), PROVISIONAL (Noir API equivalence)**

| Parameter        | Value                           | Status      |
|------------------|---------------------------------|-------------|
| Width (t)        | 5                               | VERIFIED    |
| Rate             | 4                               | VERIFIED    |
| Capacity         | 1                               | VERIFIED    |
| Absorption       | `state[capacity + i] += msg[k]` | VERIFIED    |
| Permutation      | After every `rate` elements      | VERIFIED    |
| Final permutation| If any partial block absorbed    | VERIFIED    |
| Output           | `state[1]` (first rate element)  | VERIFIED    |
| Padding          | No explicit sponge padding       | VERIFIED    |

Source: `backend/shared/crypto/component_hash.py` (sponge function)

**Noir API:** `std::hash::poseidon::bn254::sponge()` — PROVISIONAL (API observed but
exact absorption behavior unverified without executable Noir toolchain).

## 5. Component Hash Construction

**Status: VERIFIED (Python), PROVISIONAL (Noir equivalence)**

```
canonical_json (str)
    → UTF-8 bytes
    → byte_to_field encoding (31-byte big-endian + 0x80 terminator)
    → field elements (N ≤ 216)
    → zero-pad to 216 fields
    → Poseidon sponge(t=5, rate=4)
    → component_hash (single field element)
```

## 6. Canonical Component Serialization

**Status: VERIFIED**

| Parameter          | Value                                       | Status   |
|--------------------|---------------------------------------------|----------|
| Format             | JSON                                        | VERIFIED |
| Participating fields| `name`, `purl`, `version`                  | VERIFIED |
| Excluded fields    | `type`                                      | VERIFIED |
| Key order          | Alphabetical (sorted_keys=True)             | VERIFIED |
| Separators         | Compact: `(",", ":")`                       | VERIFIED |
| ensure_ascii       | False                                       | VERIFIED |
| Null handling      | All three keys present; absent → `null`     | VERIFIED |
| Unicode norm       | None (no NFC/NFD/NFKC/NFKD)                | VERIFIED |
| Whitespace trim    | None on values                              | VERIFIED |

Source: `backend/sbom_service/app/services/canonicalization.py`

## 7. Component Ordering

**Status: VERIFIED**

| Parameter          | Value                                       | Status   |
|--------------------|---------------------------------------------|----------|
| Sort key           | Canonical JSON string (lexicographic)       | VERIFIED |
| Stability          | Python sorted() is stable                   | VERIFIED |
| Duplicate handling | Preserved (no deduplication)                | VERIFIED |
| component_count    | Physical count including duplicates         | VERIFIED |

Source: `backend/sbom_service/app/services/canonicalization.py`,
`backend/sbom_service/app/services/identity.py`

## 8. Merkle Tree Construction

**Status: VERIFIED (Python), PROVISIONAL (Noir equivalence)**

| Parameter          | Value                                       | Status         |
|--------------------|---------------------------------------------|----------------|
| Type               | Standard complete binary tree               | VERIFIED       |
| Depth              | 10                                          | VERIFIED       |
| Leaf capacity      | 1024 (2^10)                                 | VERIFIED       |
| Leaves             | Component hashes (ordered)                  | VERIFIED       |
| EMPTY_HASH         | `poseidon_hash([0])` (hash_1(0))            | VERIFIED       |
| Internal nodes     | `poseidon_hash([left, right])` (hash_2)     | VERIFIED       |
| Padding            | Unused leaves filled with EMPTY_HASH        | VERIFIED       |
| Child ordering     | Left then right (positional)                | VERIFIED       |
| Duplicate leaves   | Preserved                                   | VERIFIED       |
| Subtree collapsing | None — full tree always constructed         | VERIFIED       |
| ZK proving capacity| NOT BENCHMARKED                             | NOT BENCHMARKED|

Source: `backend/shared/crypto/merkle.py`

## 9. SBOM_ROOT

**Status: VERIFIED (computation), NOT BENCHMARKED (proving)**

`SBOM_ROOT = Merkle root of 1024-leaf tree`

This is one of the three public ZKP inputs. It represents the complete
fixed-size committed SBOM tree.

**1024 leaves is TREE CAPACITY, not proven ZK circuit capacity.**

## 10. Toolchain Status

| Tool       | Status         | Notes                                     |
|------------|----------------|-------------------------------------------|
| Python     | 3.12.10        | VERIFIED                                  |
| Rust/Cargo | Not installed  | Required for Noir compilation             |
| Nargo      | Not installed  | Required for circuit tests                |
| Barretenberg| Not installed | Required for proof generation             |

## 11. Unresolved Questions (Carried Forward)

1. Does Noir's `std::hash::poseidon::bn254::sponge()` absorption exactly match
   the Python sponge implementation? — PROVISIONAL (observed match in Stage 4.6
   WSL execution, but toolchain not available for re-verification)
2. Does `Field::from_be_bytes` in Noir match Python's `int.from_bytes(chunk, 'big')`
   for all chunk values? — PROVISIONAL
3. Are domain separation tags required? — NOT IMPLEMENTED (none used currently)
4. Does Noir enforce the same S-box exponent (α=5)? — VERIFIED via Stage 4.6
   constant extraction from Noir 0.32.0 source

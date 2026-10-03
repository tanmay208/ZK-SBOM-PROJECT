import os
from shared.crypto.poseidon_bn254 import poseidon_hash

is_dev = os.environ.get("DEV_MODE") == "1"
MAX_COMPONENTS = 8 if is_dev else 1024
MERKLE_DEPTH = 3 if is_dev else 10


def hash_1(val: int) -> int:
    return poseidon_hash([val])

def hash_2(left: int, right: int) -> int:
    return poseidon_hash([left, right])

# Precompute empty hashes
def compute_empty_hashes(depth: int) -> list[int]:
    empty_hashes = [hash_1(0)]  # Level 0 (leaf)
    for i in range(depth):
        prev = empty_hashes[-1]
        empty_hashes.append(hash_2(prev, prev))
    return empty_hashes

EMPTY_HASHES = compute_empty_hashes(MERKLE_DEPTH)

def compute_merkle_root(leaves: list[int]) -> int:
    """
    Computes the standard binary Merkle tree root for a list of leaf hashes.
    Pads the list with empty leaves up to MAX_COMPONENTS.
    """
    if len(leaves) > MAX_COMPONENTS:
        raise ValueError(f"Too many leaves: {len(leaves)} > {MAX_COMPONENTS}")
        
    # Pad to MAX_COMPONENTS
    current_level = leaves + [EMPTY_HASHES[0]] * (MAX_COMPONENTS - len(leaves))
    
    for level in range(MERKLE_DEPTH):
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1]
            next_level.append(hash_2(left, right))
        current_level = next_level
        
    return current_level[0]

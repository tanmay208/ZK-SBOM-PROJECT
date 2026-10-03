import os
import threading
from shared.crypto.poseidon_bn254 import poseidon_hash

SMT_DEPTH = 3 if os.environ.get('DEV_MODE') == '1' else 256

def hash_2(left: int, right: int) -> int:
    return poseidon_hash([left, right])

def compute_smt_empty_hashes(depth: int) -> list[int]:
    empty_hashes = [0]
    for i in range(depth):
        prev = empty_hashes[-1]
        empty_hashes.append(hash_2(prev, prev))
    return empty_hashes

EMPTY_HASHES = compute_smt_empty_hashes(SMT_DEPTH)

class SparseMerkleTree:
    """
    A Sparse Merkle Tree (SMT) with depth 256 for BN254 constraints.
    Uses Poseidon hash for internal nodes.
    """
    def __init__(self, depth: int = SMT_DEPTH):
        self.leaves = {}
        self.depth = depth
        self._cached_levels = None
        self._lock = threading.Lock()
        
    def insert(self, key: int, value: int) -> None:
        with self._lock:
            self.leaves[key] = value
            self._cached_levels = None
            
    def _build_levels(self):
        with self._lock:
            if self._cached_levels is not None:
                return self._cached_levels
                
            levels = [self.leaves.copy()]
            current_level = levels[0]
            
            for d in range(self.depth):
                next_level = {}
                parents = set(k >> 1 for k in current_level.keys())
                for p in parents:
                    left_idx = p << 1
                    right_idx = (p << 1) | 1
                    left_val = current_level.get(left_idx, EMPTY_HASHES[d])
                    right_val = current_level.get(right_idx, EMPTY_HASHES[d])
                    next_level[p] = hash_2(left_val, right_val)
                levels.append(next_level)
                current_level = next_level
                
            self._cached_levels = levels
            return self._cached_levels
            
    def get_root(self) -> int:
        if not self.leaves:
            return EMPTY_HASHES[self.depth]
            
        levels = self._build_levels()
        return levels[-1][0]
        
    def get_path(self, key: int) -> list[int]:
        levels = self._build_levels()
        path = []
        for d in range(self.depth):
            node_idx = key >> d
            sibling_idx = node_idx ^ 1
            sibling_val = levels[d].get(sibling_idx, EMPTY_HASHES[d])
            path.append(sibling_val)
        return path

import pytest
import threading
from shared.crypto.smt import SparseMerkleTree, EMPTY_HASHES, hash_2, SMT_DEPTH

def test_smt_empty_root():
    smt = SparseMerkleTree()
    root = smt.get_root()
    assert root == EMPTY_HASHES[SMT_DEPTH]

def test_smt_insert():
    smt = SparseMerkleTree()
    smt.insert(1, 123)
    root = smt.get_root()
    assert root != EMPTY_HASHES[SMT_DEPTH]

def test_smt_path():
    smt = SparseMerkleTree()
    smt.insert(0, 123)
    path = smt.get_path(0)
    assert len(path) == SMT_DEPTH
    
    current = 123
    for i in range(SMT_DEPTH):
        current = hash_2(current, path[i])
    assert current == smt.get_root()

def test_smt_concurrency():
    smt = SparseMerkleTree()
    
    def worker(start_idx, count):
        for i in range(start_idx, start_idx + count):
            smt.insert(i, 1000 + i)
            # interleave read
            smt.get_root()
            
    threads = []
    for i in range(4):
        t = threading.Thread(target=worker, args=(i * 10, 10))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    # We inserted 0..39
    assert len(smt.leaves) == 40
    for i in range(40):
        assert smt.leaves[i] == 1000 + i
    
    root = smt.get_root()
    assert root != EMPTY_HASHES[SMT_DEPTH]

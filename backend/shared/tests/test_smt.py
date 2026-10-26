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


def test_smt_explicit_depth_production_accepted():
    """Explicit depth 256 is accepted under production configuration."""
    smt = SparseMerkleTree(256)
    assert smt.depth == 256
    assert smt.get_root() == EMPTY_HASHES[256]
    smt.insert(1, 456)
    assert smt.get_root() != EMPTY_HASHES[256]
    path = smt.get_path(1)
    assert len(path) == 256


def test_smt_explicit_smaller_depth_accepted():
    """Explicit depth smaller than capacity (e.g. depth 3) is accepted and valid."""
    smt = SparseMerkleTree(3)
    assert smt.depth == 3
    assert smt.get_root() == EMPTY_HASHES[3]
    smt.insert(0, 999)
    path = smt.get_path(0)
    assert len(path) == 3
    current = 999
    for i in range(3):
        current = hash_2(current, path[i])
    assert current == smt.get_root()


def test_smt_invalid_depth_type_and_sign_rejected():
    """Non-positive integers and invalid types are rejected with controlled ValueError."""
    for invalid_depth in [0, -1, -256, True, False, "256", 3.5, None]:
        with pytest.raises(ValueError, match="SMT depth must be a positive integer"):
            SparseMerkleTree(invalid_depth)


def test_smt_depth_exceeding_capacity_rejected_production():
    """Depths exceeding available empty-hash capacity are rejected with controlled ValueError."""
    for excessive_depth in [257, 300, 1024]:
        with pytest.raises(ValueError, match="exceeds available empty-hash capacity"):
            SparseMerkleTree(excessive_depth)


def test_smt_dev_mode_isolation():
    """Verify SMT behavior in an isolated subprocess where DEV_MODE=1."""
    import os
    import sys
    import subprocess

    code = """
import os
assert os.environ.get("DEV_MODE") == "1"
from shared.crypto.smt import SparseMerkleTree, EMPTY_HASHES, SMT_DEPTH

# 1. Constants in DEV_MODE
assert SMT_DEPTH == 3, f"Expected SMT_DEPTH 3, got {SMT_DEPTH}"
assert len(EMPTY_HASHES) == 4, f"Expected 4 empty hashes, got {len(EMPTY_HASHES)}"

# 2. Default constructor uses SMT_DEPTH=3
smt_default = SparseMerkleTree()
assert smt_default.depth == 3
assert smt_default.get_root() == EMPTY_HASHES[3]
smt_default.insert(0, 42)
path = smt_default.get_path(0)
assert len(path) == 3

# 3. Explicit depth 3 succeeds
smt_3 = SparseMerkleTree(3)
assert smt_3.depth == 3

# 4. Explicit depth 256 is rejected with controlled ValueError
try:
    SparseMerkleTree(256)
    raise AssertionError("Expected ValueError for depth 256 in DEV_MODE=1")
except ValueError as e:
    assert "exceeds available empty-hash capacity" in str(e)
    assert "DEV_MODE=1" in str(e)

# 5. Out-of-bounds depth (e.g. 4) is rejected
try:
    SparseMerkleTree(4)
    raise AssertionError("Expected ValueError for depth 4 in DEV_MODE=1")
except ValueError as e:
    assert "exceeds available empty-hash capacity" in str(e)

# 6. Invalid non-positive depth is rejected
try:
    SparseMerkleTree(0)
    raise AssertionError("Expected ValueError for depth 0")
except ValueError as e:
    assert "positive integer" in str(e)

print("DEV_MODE_ISOLATION_OK")
"""
    env = os.environ.copy()
    env["DEV_MODE"] = "1"
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    env["PYTHONPATH"] = backend_dir

    res = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Subprocess failed:\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}"
    assert "DEV_MODE_ISOLATION_OK" in res.stdout


def test_smt_prod_mode_isolation():
    """Verify SMT behavior in an isolated subprocess where DEV_MODE is not set."""
    import os
    import sys
    import subprocess

    code = """
import os
assert os.environ.get("DEV_MODE") != "1"
from shared.crypto.smt import SparseMerkleTree, EMPTY_HASHES, SMT_DEPTH

# 1. Constants in production mode
assert SMT_DEPTH == 256, f"Expected SMT_DEPTH 256, got {SMT_DEPTH}"
assert len(EMPTY_HASHES) == 257, f"Expected 257 empty hashes, got {len(EMPTY_HASHES)}"

# 2. Default constructor uses SMT_DEPTH=256
smt_default = SparseMerkleTree()
assert smt_default.depth == 256
assert smt_default.get_root() == EMPTY_HASHES[256]

# 3. Explicit depth 256 succeeds
smt_256 = SparseMerkleTree(256)
assert smt_256.depth == 256

# 4. Out-of-bounds depth (257) is rejected
try:
    SparseMerkleTree(257)
    raise AssertionError("Expected ValueError for depth 257 in production")
except ValueError as e:
    assert "exceeds available empty-hash capacity" in str(e)

print("PROD_MODE_ISOLATION_OK")
"""
    env = os.environ.copy()
    env.pop("DEV_MODE", None)
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    env["PYTHONPATH"] = backend_dir

    res = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Subprocess failed:\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}"
    assert "PROD_MODE_ISOLATION_OK" in res.stdout


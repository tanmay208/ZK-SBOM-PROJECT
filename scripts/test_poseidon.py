from poseidon_py.poseidon_hash import poseidon_hash, poseidon_hash_single

try:
    print("poseidon_hash_single(1):", hex(poseidon_hash_single(1)))
except Exception as e:
    print("Error:", e)

try:
    print("poseidon_hash([1]):", hex(poseidon_hash([1])))
except Exception as e:
    print("Error:", e)

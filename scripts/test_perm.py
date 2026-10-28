import sys
from backend.shared.crypto.poseidon_bn254 import permute

expected = [
    0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a, 
    0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29, 
    0x0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c
]

res = permute(3, [0, 1, 2])

success = True
for i in range(3):
    if res[i] != expected[i]:
        print(f"Mismatch at index {i}!")
        print(f"Expected: {hex(expected[i])}")
        print(f"Got     : {hex(res[i])}")
        success = False

if success:
    print("MATCH! Permute works exactly as Noir.")
else:
    sys.exit(1)

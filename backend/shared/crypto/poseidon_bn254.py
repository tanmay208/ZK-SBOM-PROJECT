try:
    from backend.shared.crypto.poseidon_constants import POSEIDON_CONSTANTS
except ImportError:
    from shared.crypto.poseidon_constants import POSEIDON_CONSTANTS

BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def apply_matrix(matrix, vec, p):
    n = len(vec)
    out = [0] * n
    for i in range(n):
        for j in range(n):
            out[i] = (out[i] + vec[j] * matrix[j][i]) % p
    return out

def sigma(x, p):
    return [pow(e, 5, p) for e in x]

def permute(t, state):
    if t not in POSEIDON_CONSTANTS:
        raise ValueError(f"Unsupported arity width t={t}")
        
    config = POSEIDON_CONSTANTS[t]
    rf = 8
    rp = config['rp']
    alpha = 5
    rc = config['rc']
    mds = config['mds']
    presparse_mds = config['presparse_mds']
    sparse_mds = config['sparse_mds']
    p = BN254_PRIME
    
    # 1. Initial round constants
    for i in range(t):
        state[i] = (state[i] + rc[i]) % p
        
    # 2. First half of full rounds (rf/2 - 1 = 3)
    for r in range(rf // 2 - 1):
        state = sigma(state, p)
        for i in range(t):
            state[i] = (state[i] + rc[t * (r + 1) + i]) % p
        state = apply_matrix(mds, state, p)
        
    # 3. Final full round of the first half
    state = sigma(state, p)
    for i in range(t):
        state[i] = (state[i] + rc[t * (rf // 2) + i]) % p
    state = apply_matrix(presparse_mds, state, p)
    
    # 4. Partial rounds
    for r in range(rp):
        state[0] = pow(state[0], alpha, p)
        state[0] = (state[0] + rc[(rf // 2 + 1) * t + r]) % p
        
        new_state_0 = 0
        for j in range(t):
            new_state_0 = (new_state_0 + sparse_mds[(t * 2 - 1) * r + j] * state[j]) % p
            
        for k in range(1, t):
            state[k] = (state[k] + state[0] * sparse_mds[(t * 2 - 1) * r + t + k - 1]) % p
            
        state[0] = new_state_0
        
    # 5. Second half of full rounds (rf/2 - 1 = 3)
    for r in range(rf // 2 - 1):
        state = sigma(state, p)
        for i in range(t):
            state[i] = (state[i] + rc[(rf // 2 + 1) * t + rp + r * t + i]) % p
        state = apply_matrix(mds, state, p)
        
    # 6. Final full round
    state = sigma(state, p)
    state = apply_matrix(mds, state, p)
    
    return state

def poseidon_hash(inputs: list[int]) -> int:
    """
    Hashes a list of BN254 field elements using Noir-compatible Poseidon.
    """
    n = len(inputs)
    t = n + 1
    if t > 17:
        raise ValueError("Inputs too long for current Poseidon hasher implementation.")
        
    state = [0] + inputs
    
    # Run permutation
    state = permute(t, state)
    return state[0]

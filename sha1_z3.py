from z3 import *

# --- SHA-1 Constants ---
H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0

def LROTATE(x, c):
    """Z3 friendly 32-bit left rotate"""
    return (x << c) | LShR(x, 32 - c)

def sha1_compress(M, A, B, C, D, E):
    W = [None] * 80
    for t in range(16):
        W[t] = M[t]
    for t in range(16, 80):
        W[t] = LROTATE(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)

    a, b, c, d, e = A, B, C, D, E

    for t in range(80):
        if 0 <= t <= 19:
            f = (b & c) | (~b & d)
            k = 0x5A827999
        elif 20 <= t <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= t <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else: 
            f = b ^ c ^ d
            k = 0xCA62C1D6
            
        temp = LROTATE(a, 5) + f + e + BitVecVal(k, 32) + W[t]
        
        e = d
        d = c
        c = LROTATE(b, 30)
        b = a
        a = temp

    return (a + A, b + B, c + C, d + D, e + E)

def apply_wang_differentials(solver, M1, M2):
    """
    Applies the starting message differential constraints based on Wang et al. (2005)
    and the SHAttered (2017) attack vectors. 
    This forces the solver to only look at message pairs that have a specific 
    mathematical XOR difference, drastically narrowing the search space.
    """
    print("Applying Wang/Stevens Message Differential Constraints...")
    
    # In a full differential attack (like SHAttered), the attacker dictates EXACTLY 
    # which bits must differ in the 16 message words. 
    # Below is an illustrative example of forcing a specific XOR difference 
    # delta M = M1 ^ M2 for the first 16 words.
    
    # For example, forcing a difference only in specific bits of specific words:
    # (These are structural examples of how a Disturbance Vector is applied to the message)
    # W_diff[i] = 0 means the words are identical.
    # W_diff[i] = 0x00000002 means they differ only at bit 1.
    
    W_diff = [0] * 16
    W_diff[4] = 1 << 1   # Difference at bit 1
    W_diff[5] = 1 << 31  # Difference at bit 31
    # ... In a real attack, these 16 values are derived from the Disturbance Vector
    
    for i in range(16):
        # Force the XOR difference between the two messages to match the differential path
        solver.add(M1[i] ^ M2[i] == BitVecVal(W_diff[i], 32))

    # NOTE: A full attack also requires constraining the intermediate A,B,C,D,E states 
    # at specific rounds (e.g. forcing carry bits to propagate in a specific way)
    # to ensure the "local collisions" actually happen.

if __name__ == "__main__":
    print("Initializing Z3 Solver for SHA-1...")
    solver = Solver()
    
    M1 = [BitVec(f"m1_{i}", 32) for i in range(16)]
    M2 = [BitVec(f"m2_{i}", 32) for i in range(16)]
    
    A = BitVecVal(H0, 32)
    B = BitVecVal(H1, 32)
    C = BitVecVal(H2, 32)
    D = BitVecVal(H3, 32)
    E = BitVecVal(H4, 32)
    
    out1 = sha1_compress(M1, A, B, C, D, E)
    out2 = sha1_compress(M2, A, B, C, D, E)
    
    for i in range(5):
        solver.add(out1[i] == out2[i])
        
    # Inject the differential characteristic to narrow the search space
    apply_wang_differentials(solver, M1, M2)
        
    print("SHA-1 80-round compression and differential architecture modeled in Z3 successfully.")

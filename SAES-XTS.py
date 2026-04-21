"""
Simplified AES (S-AES) implementation with XTS operation mode.
Charbel Maroun 60346
Description: Implements S-AES from scratch along with XTS mode and a Brute-Force attack for cryptanalysis.
"""
import time

# S-AES Constants & Tables
SBOX = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
]

INV_SBOX = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE]
]

# GF(2^4) Multiplication using irreducible polynomial x^4 + x + 1 (10011 -> 0x13)
def gf_mult(a, b):
    p = 0
    for _ in range(4):
        if b & 1: p ^= a
        hi_bit_set = a & 0x8
        a <<= 1
        if hi_bit_set: a ^= 0x13
        b >>= 1
    return p & 0xF

# S-AES Core Functions
def sub_nibbles(state, sbox):
    return (sbox[(state >> 12) & 3][(state >> 14) & 3] << 12) | \
           (sbox[(state >> 8) & 3][(state >> 10) & 3] << 8) | \
           (sbox[(state >> 4) & 3][(state >> 6) & 3] << 4) | \
           (sbox[state & 3][(state >> 2) & 3])

def get_nibble(state, i): return (state >> (12 - 4*i)) & 0xF
def set_nibble(state, i, val): return (state & ~(0xF << (12 - 4*i))) | (val << (12 - 4*i))

def sub_word(word):
    n0 = get_nibble(word << 8, 0)
    n1 = get_nibble(word << 8, 1)
    return (SBOX[n0 >> 2][n0 & 3] << 4) | SBOX[n1 >> 2][n1 & 3]

def rot_word(word):
    return ((word & 0x0F) << 4) | ((word & 0xF0) >> 4)

def key_expansion(key):
    # Generates 3 16-bit round keys (K0, K1, K2)
    w = [0, 0, 0, 0, 0, 0]
    w[0] = (key & 0xFF00) >> 8
    w[1] = key & 0x00FF
    w[2] = w[0] ^ 0x80 ^ sub_word(rot_word(w[1]))
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ 0x30 ^ sub_word(rot_word(w[3]))
    w[5] = w[4] ^ w[3]
    return [(w[0] << 8) | w[1], (w[2] << 8) | w[3], (w[4] << 8) | w[5]]

def shift_rows(state):
    # Swap nibble 1 and nibble 3 (0-indexed: 0, 1, 2, 3)
    n0, n1, n2, n3 = get_nibble(state, 0), get_nibble(state, 1), get_nibble(state, 2), get_nibble(state, 3)
    return (n0 << 12) | (n3 << 8) | (n2 << 4) | n1

def mix_columns(state):
    n0, n1, n2, n3 = get_nibble(state, 0), get_nibble(state, 1), get_nibble(state, 2), get_nibble(state, 3)
    r0 = n0 ^ gf_mult(4, n1)
    r1 = gf_mult(4, n0) ^ n1
    r2 = n2 ^ gf_mult(4, n3)
    r3 = gf_mult(4, n2) ^ n3
    return (r0 << 12) | (r1 << 8) | (r2 << 4) | r3

def inv_mix_columns(state):
    n0, n1, n2, n3 = get_nibble(state, 0), get_nibble(state, 1), get_nibble(state, 2), get_nibble(state, 3)
    r0 = gf_mult(9, n0) ^ gf_mult(2, n1)
    r1 = gf_mult(2, n0) ^ gf_mult(9, n1)
    r2 = gf_mult(9, n2) ^ gf_mult(2, n3)
    r3 = gf_mult(2, n2) ^ gf_mult(9, n3)
    return (r0 << 12) | (r1 << 8) | (r2 << 4) | r3

def sub_state(state, sbox):
    return (sbox[get_nibble(state, 0) >> 2][get_nibble(state, 0) & 3] << 12) | \
           (sbox[get_nibble(state, 1) >> 2][get_nibble(state, 1) & 3] << 8) | \
           (sbox[get_nibble(state, 2) >> 2][get_nibble(state, 2) & 3] << 4) | \
           sbox[get_nibble(state, 3) >> 2][get_nibble(state, 3) & 3]

def saes_encrypt(block, key):
    keys = key_expansion(key)
    state = block ^ keys[0]
    state = sub_state(state, SBOX)
    state = shift_rows(state)
    state = mix_columns(state)
    state = state ^ keys[1]
    state = sub_state(state, SBOX)
    state = shift_rows(state)
    return state ^ keys[2]

def saes_decrypt(block, key):
    keys = key_expansion(key)
    state = block ^ keys[2]
    state = shift_rows(state)
    state = sub_state(state, INV_SBOX)
    state = state ^ keys[1]
    state = inv_mix_columns(state)
    state = shift_rows(state)
    state = sub_state(state, INV_SBOX)
    return state ^ keys[0]

# XTS Mode Operations
# GF(2^16) mult by alpha for Tweak shifting. Poly: x^16 + x^5 + x^3 + x^2 + 1 (0x002D)
def mult_alpha_16(t):
    shifted = (t << 1) & 0xFFFF
    return shifted ^ 0x002D if (t & 0x8000) else shifted

def xts_encrypt(plaintext_blocks, key1, key2, tweak):
    ciphertext_blocks = []
    T = saes_encrypt(tweak, key2)
    
    for block in plaintext_blocks:
        pp = block ^ T
        cc = saes_encrypt(pp, key1)
        c = cc ^ T
        ciphertext_blocks.append(c)
        T = mult_alpha_16(T)
        
    return ciphertext_blocks

def xts_decrypt(ciphertext_blocks, key1, key2, tweak):
    plaintext_blocks = []
    T = saes_encrypt(tweak, key2)
    
    for block in ciphertext_blocks:
        cc = block ^ T
        pp = saes_decrypt(cc, key1)
        p = pp ^ T
        plaintext_blocks.append(p)
        T = mult_alpha_16(T)
        
    return plaintext_blocks

# Utilities
def string_to_blocks(text):
    if len(text) % 2 != 0: text += " "
    blocks = []
    for i in range(0, len(text), 2):
        blocks.append((ord(text[i]) << 8) | ord(text[i+1]))
    return blocks

def blocks_to_string(blocks):
    return "".join(chr(b >> 8) + chr(b & 0xFF) for b in blocks).rstrip()

# Brute Force Cryptanalysis Attack
def brute_force_xts(target_ciphertext, known_plaintext, tweak):
    print("\n[+] Starting Brute-Force Attack on XTS Mode...")
    print("Targeting K1. Assuming K2 is fixed/known for demonstration purposes to keep demo within < 5 seconds.")
    
    actual_k2 = 0xABCD # Known K2 context for the attack simulation
    known_blocks = string_to_blocks(known_plaintext)
    
    start_time = time.time()
    for potential_k1 in range(0xFFFF + 1):
        # We only need to check the first block for a fast validation
        T = saes_encrypt(tweak, actual_k2)
        cc = target_ciphertext[0] ^ T
        pp = saes_decrypt(cc, potential_k1)
        p = pp ^ T
        
        # If first block matches, verify the rest
        if p == known_blocks[0]:
            decrypted = xts_decrypt(target_ciphertext, potential_k1, actual_k2, tweak)
            if decrypted == known_blocks:
                end_time = time.time()
                print(f"\n[!] Key Found! K1: {hex(potential_k1)}, K2: {hex(actual_k2)}")
                print(f"[!] Time taken: {end_time - start_time:.2f} seconds")
                return potential_k1, actual_k2
            
    print("[-] Attack failed. Key not found.")
    return None, None

if __name__ == "__main__":
    print("=== SAES-XTS Implementation ===")
    
    # 1. Keys and Tweak
    K1_base = 0x1234
    K2_base = 0xABCD
    sector_tweak = 0x0001
    
    plaintext = "Secret Data!"
    print(f"Original Plaintext : '{plaintext}'")
    
    # 2. Conversion
    pt_blocks = string_to_blocks(plaintext)
    
    # 3. Encryption
    ct_blocks = xts_encrypt(pt_blocks, K1_base, K2_base, sector_tweak)
    print(f"Ciphertext (blocks): {[hex(b) for b in ct_blocks]}")
    
    # 4. Decryption
    decrypted_blocks = xts_decrypt(ct_blocks, K1_base, K2_base, sector_tweak)
    decrypted_text = blocks_to_string(decrypted_blocks)
    print(f"Decrypted Text     : '{decrypted_text}'")
    
    assert plaintext == decrypted_text, "Decryption failed to match original plaintext!"
    print("\n[+] Encryption/Decryption Validation Passed!")
    
    # 5. Cryptanalysis / Brute-Force Attack
    brute_force_xts(ct_blocks, plaintext, sector_tweak)
"""
Simplified AES (S-AES) implementation with XTS operation mode.
Charbel Maroun 60346

BINARY MATH USED IN THIS CODE
1. Hexadecimal (0x...): Base-16 math. '0xF' is 15 in decimal, or '1111' in binary.
2. Bitwise AND (&): Acts like a filter (mask). e.g., (number & 0xF) keeps only the last 4 bits and zeroes out the rest.
3. Bitwise OR (|): Acts like glue. It combines bits together. We use it to rebuild our 16-bit blocks after slicing them apart.
4. Bitwise XOR (^): The heart of cryptography. If bits are same, result is 0. If different, result is 1. It acts as our mathematical addition without carrying over.
5. Bitwise Shift Left (<<): Pushes bits to the left. Mathematically, it's like multiplying by 2. 
6. Bitwise Shift Right (>>): Pushes bits to the right. Mathematically, it's like dividing by 2. We use this to slide specific bits into the exact position so we can read them.
"""
import time

# 1. S-AES Constants & Tables

# SBOX (Substitution Box) provides "Confusion". 
# It takes a 4-bit chunk of data (a "nibble") and completely swaps it for an unrelated one.
# So attackers can't trace a straight mathematical line from the ciphertext back to the plaintext.
SBOX = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
]

# INV_SBOX does the reverse of SBOX. We use this during Decryption.
INV_SBOX = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE]
]

# 2. Finite Field Math
# Normal multiplication carries over numbers (e.g., 5 * 5 = 25). 
# If we do that in a 4-bit system (max value 15), the computer overflows and crashes.
# GF(2^4) math guarantees we never exceed 4 bits. When we go over, we XOR by a "primitive polynomial" (0x13).
def gf_mult(a, b):
    p = 0
    for _ in range(4):
        # b & 1 checks if the right-most bit of b is 1. 
        # If it is, we XOR (add) 'a' into our running total 'p'.
        if b & 1: p ^= a 
        
        # Check if 'a' is about to overflow our 4-bit limit (is the 4th bit a 1? 0x8 is 1000 in binary)
        hi_bit_set = a & 0x8 
        
        # Shift 'a' left by 1 (like multiplying by x)
        a <<= 1 
        
        # If it overflowed, we must shrink it back down using the polynomial 0x13 (modulo reduction)
        if hi_bit_set: a ^= 0x13 
        
        # Shift 'b' right to process the next bit in the loop
        b >>= 1 
        
    return p & 0xF # The & 0xF guarantees we return ONLY 4 bits (filters anything greater than 1111)

# 3. S-AES Core Functions

def get_nibble(state, i): 
    # Grab a specific 4-bit chunk (nibble) from the 16-bit state.
    # E.g., if i=0, we shift right by 12. If the state is [N0][N1][N2][N3], shifting right 12 leaves only [N0].
    return (state >> (12 - 4*i)) & 0xF

def set_nibble(state, i, val): 
    # Wipes out the current nibble at position 'i' and glues the new 'val' into its place using bitwise OR (|).
    return (state & ~(0xF << (12 - 4*i))) | (val << (12 - 4*i))

def sub_word(word):
    # Takes an 8-bit word, splits it into two 4-bit nibbles, swaps both through the SBOX, and glues them back.
    n0 = get_nibble(word << 8, 0)
    n1 = get_nibble(word << 8, 1)
    return (SBOX[n0 >> 2][n0 & 3] << 4) | SBOX[n1 >> 2][n1 & 3]

def rot_word(word):
    # Swaps the left nibble with the right nibble. E.g., 0xA4 becomes 0x4A.
    return ((word & 0x0F) << 4) | ((word & 0xF0) >> 4)

def key_expansion(key):
    # AES encrypts in 'rounds'. We can't use the same key every round, or it's easy to hack.
    # This expands our 1 SINGLE 16-bit master key into 3 DIFFERENT round keys (K0, K1, K2).
    w = [0, 0, 0, 0, 0, 0]
    w[0] = (key & 0xFF00) >> 8 # First 8 bits
    w[1] = key & 0x00FF        # Second 8 bits
    
    # 0x80 and 0x30 are "Round Constants". They inject unpredictable bits into the key math.
    w[2] = w[0] ^ 0x80 ^ sub_word(rot_word(w[1]))
    w[3] = w[2] ^ w[1]
    
    w[4] = w[2] ^ 0x30 ^ sub_word(rot_word(w[3]))
    w[5] = w[4] ^ w[3]
    
    # Combine the 8-bit pieces back into 16-bit keys
    return [(w[0] << 8) | w[1], (w[2] << 8) | w[3], (w[4] << 8) | w[5]]

# 4. The Encryption Matrix Manipulations

def sub_state(state, sbox):
    # Runs the entire 16-bit block through the SBOX to scramble the letters (Confusion step).
    # Split each 4-bit nibble: (n >> 2) = top 2 bits (row), (n & 3) = bottom 2 bits (col)
    # lookup sbox[row][col]
    # Reassemble result: <<12 (1st/MSB), <<8 (2nd), <<4 (3rd), no shift (last/LSB)
    return (sbox[get_nibble(state, 0) >> 2][get_nibble(state, 0) & 3] << 12) | \
           (sbox[get_nibble(state, 1) >> 2][get_nibble(state, 1) & 3] << 8) | \
           (sbox[get_nibble(state, 2) >> 2][get_nibble(state, 2) & 3] << 4) | \
           sbox[get_nibble(state, 3) >> 2][get_nibble(state, 3) & 3]

def shift_rows(state):
    # Diffusion step. Spreads changes out so they affect everything.
    # It swaps the position of nibble 1 and nibble 3.
    n0, n1, n2, n3 = get_nibble(state, 0), get_nibble(state, 1), get_nibble(state, 2), get_nibble(state, 3)
    # Rebuilding out of order: N0, N3, N2, N1
    return (n0 << 12) | (n3 << 8) | (n2 << 4) | n1

def mix_columns(state):
    # Heavy Diffusion step. Mixes the columns together mathematically using the Galois Field multiplication defined earlier.
    n0, n1, n2, n3 = get_nibble(state, 0), get_nibble(state, 1), get_nibble(state, 2), get_nibble(state, 3)
    r0 = n0 ^ gf_mult(4, n1)             # multiply n1 by 4 in GF(2^4), then XOR with n0
    r1 = gf_mult(4, n0) ^ n1
    r2 = n2 ^ gf_mult(4, n3)
    r3 = gf_mult(4, n2) ^ n3
    return (r0 << 12) | (r1 << 8) | (r2 << 4) | r3

def inv_mix_columns(state):
    # Exact opposite of MixColumns, used for decryption. The math uses '9' and '2' instead of '4' to reverse the polynomial sequence.
    n0, n1, n2, n3 = get_nibble(state, 0), get_nibble(state, 1), get_nibble(state, 2), get_nibble(state, 3)
    r0 = gf_mult(9, n0) ^ gf_mult(2, n1)
    r1 = gf_mult(2, n0) ^ gf_mult(9, n1)
    r2 = gf_mult(9, n2) ^ gf_mult(2, n3)
    r3 = gf_mult(2, n2) ^ gf_mult(9, n3)
    return (r0 << 12) | (r1 << 8) | (r2 << 4) | r3

# 5. The Main S-AES Wrapper

def saes_encrypt(block, key):
    # This is the recipe that cooks the block
    keys = key_expansion(key)            # Step 1: Expand the key
    state = block ^ keys[0]              # Step 2: XOR block with Key 0 (Pre-Whitening)
    
    state = sub_state(state, SBOX)       # Step 3: Round 1 Confusion
    state = shift_rows(state)            # Step 4: Round 1 Diffusion
    state = mix_columns(state)           # Step 5: Round 1 Deep Math Diffusion
    state = state ^ keys[1]              # Step 6: XOR with Key 1
    
    state = sub_state(state, SBOX)       # Step 7: Round 2 Confusion
    state = shift_rows(state)            # Step 8: Round 2 Diffusion (No mix columns in final round)
    return state ^ keys[2]               # Step 9: XOR with Final Key 2

def saes_decrypt(block, key):
    # Running the recipe in reverse
    keys = key_expansion(key)
    state = block ^ keys[2]              
    state = shift_rows(state)            
    state = sub_state(state, INV_SBOX)   # Uses the inverse S-BOX
    state = state ^ keys[1]
    state = inv_mix_columns(state)       
    state = shift_rows(state)
    state = sub_state(state, INV_SBOX)
    return state ^ keys[0]

# 6. XTS Mode Operations (The Extra Security Protocol)
# Basic AES is bad if encrypting disk drives. If you encrypt the word "AAAA", you get "XZQZ".
# If you encrypt "AAAA" again, you get "XZQZ" again. Hackers can see the repeated "XZQZ" pattern visually.
# XTS fixes this by adding a "Tweak". A random shifting string mixed in BEFORE and AFTER encryption.

def mult_alpha_16(t):
    # Because S-AES blocks are 16-bits, we update the Tweak using GF(2^16) instead of GF(2^4).
    # This polynomial 0x002D maps to x^16 + x^5 + x^3 + x^2 + 1 
    shifted = (t << 1) & 0xFFFF 
    return shifted ^ 0x002D if (t & 0x8000) else shifted

def xts_encrypt(plaintext_blocks, key1, key2, tweak):
    ciphertext_blocks = []
    # XTS requires TWO distinct keys. Key 2 strictly encrypts the Tweak to protect it.
    T = saes_encrypt(tweak, key2)
    
    for block in plaintext_blocks:
        pp = block ^ T                    # Pre-Whitening: Block XOR Tweak (Secures it BEFORE encryption)
        cc = saes_encrypt(pp, key1)       # Encrypt normally with Key 1
        c = cc ^ T                        # Post-Whitening: Ciphertext XOR Tweak (Secures it AFTER encryption)
        
        ciphertext_blocks.append(c)       # Save the final safely encrypted block
        T = mult_alpha_16(T)              # Change the Tweak so the NEXT block gets a totally different scramble logic!
        
    return ciphertext_blocks

def xts_decrypt(ciphertext_blocks, key1, key2, tweak):
    # Exact reverse of xts_encrypt logic
    plaintext_blocks = []
    # Recompute initial Tweak exactly like encryption
    T = saes_encrypt(tweak, key2)
    
    for block in ciphertext_blocks:
        cc = block ^ T                    # Undo Post-Whitening: remove tweak from ciphertext
        pp = saes_decrypt(cc, key1)       # Decrypt with Key 1 (reverse of encryption step)
        p = pp ^ T                        # Undo Pre-Whitening: remove tweak from decrypted block to get original plaintext
        plaintext_blocks.append(p)        # Save the decrypted block
        T = mult_alpha_16(T)              # Update Tweak for the next block (same as encryption to stay in sync)
        
    return plaintext_blocks

# 7. Utilities (Helpful code to make string formats compatible with math)
def string_to_blocks(text):
    # Computers don't encrypt English letters, they encrypt numbers.
    # This chunks our string into 2-byte (16 bit) blocks. Example: "Hi" -> [0x4869]
    if len(text) % 2 != 0: text += " "
    blocks = []
    for i in range(0, len(text), 2):
        blocks.append((ord(text[i]) << 8) | ord(text[i+1])) # ord() converts char to ASCII number. We shift the first char left by 8 bits and OR it with the second char to glue them into a single 16-bit block.
    return blocks

def blocks_to_string(blocks):
    # Glues 16-bit blocks back into readable english characters 
    return "".join(chr(b >> 8) + chr(b & 0xFF) for b in blocks).rstrip()

# 8. Brute Force Cryptanalysis (The Hacking Module)
def brute_force_xts(target_ciphertext, known_plaintext, tweak):
    print("\n[+] Starting Brute-Force Attack on XTS Mode...")
    print("Targeting K1. Assuming K2 is fixed/known for demonstration purposes to keep demo within < 5 seconds.")
    
    actual_k2 = 0xABCD # We fake knowing K2 here so we don't have to wait 10 hours for a 32-bit loop to finish in python
    known_blocks = string_to_blocks(known_plaintext)
    
    start_time = time.time()
    
    # K1 is 16-bits. A 16-bit binary limit translates to exactly 65,536 limit. 
    # (0xFFFF in hex is 65535 in decimal). We loop every possible number and guess
    for potential_k1 in range(0xFFFF + 1):
        
        # PRUNING (SPEED HACK):
        # Instead of decrypting the whole paragraph
        # We exclusively extract and decrypt the VERY FIRST BLOCK ONLY natively:
        T = saes_encrypt(tweak, actual_k2)
        cc = target_ciphertext[0] ^ T       # Grabbing block 0 and stripping the Tweak
        pp = saes_decrypt(cc, potential_k1) # Trial-Decrypting using the loop's 'guess key'
        p = pp ^ T                          # Finishing the reverse sequence
        
        # Does the deciphered block 'p' match our Known Plaintext block?
        if p == known_blocks[0]: 
            # If yes, 99.9% chance we found the key. Let's do a full deep-check to be 100% sure.
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
    
    # Set our secret Keys
    K1_base = 0x1234
    K2_base = 0xABCD
    sector_tweak = 0x0001
    
    # Set the data we want to protect
    plaintext = "Secret Data!"
    print(f"Original Plaintext : '{plaintext}'")
    
    # Data to Math blocks
    pt_blocks = string_to_blocks(plaintext)
    
    # 1. ENCRYPT IT
    ct_blocks = xts_encrypt(pt_blocks, K1_base, K2_base, sector_tweak)
    print(f"Ciphertext (blocks): {[hex(b) for b in ct_blocks]}")
    
    # 2. DECRYPT IT
    decrypted_blocks = xts_decrypt(ct_blocks, K1_base, K2_base, sector_tweak)
    decrypted_text = blocks_to_string(decrypted_blocks)
    print(f"Decrypted Text     : '{decrypted_text}'")
    
    # Did it work?
    assert plaintext == decrypted_text, "Decryption failed to match original plaintext!"
    print("\n[+] Encryption/Decryption Validation Passed!")
    
    # 3. HACK IT
    brute_force_xts(ct_blocks, plaintext, sector_tweak)

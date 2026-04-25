# Cryptography Project Report: SAES with XTS Mode

Charbel Maroun 60346

## Step 1: Research on S-AES and XTS Mode

### Simplified AES (S-AES)
Simplified AES (S-AES) is an educational cipher designed to exhibit the same structural properties as the Advanced Encryption Standard (AES) but scaled down to facilitate easier manual computation and analytical understanding. Where standard AES operates on a 128-bit block size with 128/192/256-bit keys, S-AES operates strictly on a 16-bit block size with a 16-bit key. It retains the core operations providing fundamental confusion and diffusion properties:
- **Key Expansion:** Expanding the original 16-bit master key into three distinct 16-bit round keys (K0, K1, K2).
- **Add Round Key:** XORing the current state against the corresponding subkey.
- **Nibble Substitution (S-Boxes):** Applying non-linearity via a predefined 4x4 matrix.
- **Shift Rows:** Transposing the second row of the state matrix.
- **Mix Columns:** Applying a mathematically rigorous matrix multiplication across Galois Field GF(2^4) using the primitive polynomial x^4 + x + 1 (binary 10011 -> 0x13).

### XEX-based Tweaked CodeBook Mode (XTS)
XTS is a dominant block cipher mode of operation designed specifically to counteract identical plaintext-block pattern vulnerabilities during disk encryption. By introducing a cryptographic `tweak` based on a sector or location number, XTS ensures the same ciphertext is never generated twice. XTS operates using two distinct keys:
- **K1** is utilized to encrypt the plaintext block payload.
- **K2** is utilized to uniquely encrypt the static tweak string.

The operation formula for generating a ciphertext block in XTS is:
`C = E_K1(P XOR T) XOR T`
Where `T = E_K2(tweak) * alpha^i` processed through the native Galois Field. Since S-AES dictates a 16-bit state, this structure inherently scales the alpha multiplication over the larger GF(2^16).

### Brute Force Cryptanalysis Theory
Due to its intentionally compressed architecture, S-AES has a 16-bit key dimension, meaning the entire key space spans only 65,536 (2^16) possibilities. This makes brute-force attacks trivial when leveraging a Known-Plaintext Attack (KPA). If an attacker possesses even a minor snippet of the corresponding plaintext and ciphertext blocks, they can loop through the key options and systematically evaluate the correct decryption.

---

## Step 2: Implementation of SAES-XTS
The source code provided in `SAES-XTS.py` is programmed natively in Python 3, adhering to the assignment constraint forbidding Python's built-in block ciphers and libraries.

- **Fundamental Arithmetic:** The state manipulates 16-bit integers natively rather than strings or array matrices. Essential bitwise operations (masks `&`, shifts `<<`, and XORs `^`) pull out the active 4-bit "nibbles" representing the state matrix dynamically.
- **GF(2^4) Calculations:** A dedicated `gf_mult(a, b)` modulo arithmetic operation functions as the backbone of the MixColumns computation.
- **XTS Mode Logic:** The wrapper method chunks pure string payloads into contiguous arrays of 16-bit integers (`blocks`). The algorithm defines a Tweak derived from $K2$, then recursively modifies it per block iteration by multiplying `alpha` in GF(2^16) mapping to the irreducible polynomial $x^{16} + x^5 + x^3 + x^2 + 1$ (`0x002D`).

---

## Step 3: Brute Force Cryptanalysis Methodology
Utilizing vulnerabilities established during Step 1, a brute-force module is implemented at the final execution block of the script as a high-speed Known-Plaintext Attack validation.

1. **Context Extraction:** Given the known plaintext string "Secret Data!", the matched XTS ciphertext is fed into the process. 
2. **Sequential Iteration:** The system loops potential $K1$ keys sequentially from `0x0000` to `0xFFFF`. (In the practical demonstration, $K2$ is held constant as a test vector; otherwise, a nested $2^{32}$ loop is mandated).
3. **Execution Optimization (Pruning):** Instead of fully deciphering the multi-block string per loop, the function selectively strips the *first 16-bit ciphertext block* only. Decrypting block '0' alone instantly eliminates >99% of false keys, expediting computation remarkably.
4. **Result Validation:** Only upon a successful validation against block '0' does the script evaluate subsequent text blocks. If exactly verified, the loop halts. Output captures the exact keys and execution profiling metrics. Generally, the brute force attack concludes in under a tenth of a second, effectively compromising the scaled cipher.

---

## Step 4: Deliverables
- `SAES-XTS.py`: The natively programmed codebase.
- `README.md`: Instruction manual containing launch execution syntax.
- `Report.md`: This assignment methodology doc outlining the research architecture and implementation logic.
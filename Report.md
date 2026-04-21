# Cryptography Project Report: SAES with XTS Mode

## Step 1: Research on S-AES and XTS Mode
Simplified AES (S-AES) was developed to provide an educational tool that mimics the architecture of AES but scales down the computational complexity. While standard AES operates on a 128-bit block size with 128/192/256-bit keys, S-AES operates on a 16-bit block size with a 16-bit key. It features the same structural operations:
- Key Expansion
- Add Round Key
- Nibble Substitution (S-Boxes)
- Shift Rows
- Mix Columns

XTS (XEX-based Tweaked CodeBook Mode) is predominantly used for disk encryption. The XTS mode operates using two keys: K1 (to encrypt the data blocks) and K2 (to encrypt the tweak).
The formula for a ciphertext block in XTS is defined as:
C = E_K1(P XOR T) XOR T 
Where T = E_K2(tweak) * alpha^i in the Galois Field.

For cryptanalysis, S-AES has a 16-bit key size resulting in 65,536 possible key combinations. Brute-force attacks against S-AES are trivially fast utilizing known-plaintext attacks, where the attacker compares the output of possible decryption iterations to a known plaintext string.

## Step 2: Implementation of SAES-XTS
The Python implementation, provided in SAES-XTS.py, fulfills the requirement of building the encryption protocol from scratch without external libraries.
- The state operates as a 16-bit integer, and bitwise operations manipulate 4-bit nibbles.
- GF(2^4) is used for MixColumns (polynomial x^4 + x + 1).
- XTS mode iterates over string chunks. Since it operates in blocks of 16-bits, our tweaks represent sequential blocks. The Galois Field multiplication for the XTS tweak was mapped to GF(2^16) (polynomial x^16 + x^5 + x^3 + x^2 + 1).

## Step 3: Brute Force Cryptanalysis Methodology
Using the vulnerabilities discovered via research, I created a brute-force module in the script. The operation works as a Known-Plaintext Attack:
1. Obtain the known plaintext string and the matched XTS block ciphertext.
2. Iterate K1 from 0x0000 to 0xFFFF.
3. Decrypt the *first block* only. Comparing block 1 instantly eliminates virtually all false positives while massively speeding up Python's brute force execution time.
4. If the decrypted block matches the known plaintext block, check the remainder of the ciphertext to confirm a 100% block match.
5. Exit loop and print recovered keys.

## Deliverables
- SAES-XTS.py code uploaded.
- README.md containing Python running instructions included.
- Report.md documentation synthesized.
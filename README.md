# SAES-XTS — XEX-based Tweaked CodeBook Mode

## Project Overview
This project implements the **Simplified Advanced Encryption Standard (S-AES)** using the **XTS (XEX-based Tweaked CodeBook)** operation mode. It allows for the encryption and decryption of plaintext data.

Additionally, this repository contains a brute-force cryptanalysis attack simulation capable of recovering the key given a known plaintext-ciphertext pair.

## Files
- SAES-XTS.py: The core Python script containing the entire S-AES and XTS implementation, as well as the Brute-Force cryptanalysis attack.
- README.md: This documentation file.
- Report.md: Full assignment report detailing the research, implementation methodologies, and cryptanalysis mechanisms.

## Dependencies
- Standard Python 3.x only. 
- No predefined DES or AES libraries were used.

## Running the Code
To run the S-AES encryption, decryption, and the brute-force demonstration, simply execute:
python SAES-XTS.py

### What happens when you run it?
1. The script will take a sample plaintext, chunk it into 16-bit blocks, and define initial test keys, alongside a sector tweak.
2. It will encrypt the payload using S-AES in XTS mode and output the Ciphertext blocks.
3. It validates the output by immediately decrypting the cipherblocks and asserting if the resulting string matches the original plain text.
4. Finally, it executes a known-plaintext brute-force attack to deduce the utilized keys.
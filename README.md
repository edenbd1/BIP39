# Bitcoin BIP39 Wallet Generator

A Python implementation of the BIP39 mnemonic code for generating deterministic Bitcoin wallets.

## Description

This project implements the BIP39 standard for generating mnemonic phrases that can be used to create deterministic wallets. It includes functionality for:
- Generating secure random entropy
- Converting entropy to mnemonic phrases
- Deriving master private keys and chain codes
- Supporting BIP39 seed generation with optional passphrases

## Requirements

- Python 3.6+
- No external dependencies required (uses only Python standard library)

## Installation

1. Clone the repository
2. Ensure both files are in the same directory:
   - `TD2_BIP39.py`
   - `wordlist.txt`

## Usage

Run the script:

```bash
python TD2_BIP39.py
```
## Description of the result

The program will output:
1. Generated entropy (hex)
2. Complete binary string with 11-bit chunks
3. Mnemonic phrase (12 words)
4. Seed (hex)
5. Master Private Key and Chain Code

## Verification

You can verify the generated mnemonic phrases and keys using:
https://iancoleman.io/bip39/

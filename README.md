# Padding Oracle Demo

This repository demonstrates a classic **padding oracle attack** against **AES-CBC encryption with PKCS#7 padding**.

The purpose of this project is educational: to understand how leaking padding validity during decryption can allow an attacker to recover plaintext **without knowing the encryption key**.

---

## What is a Padding Oracle?

A padding oracle is a system that tells an attacker whether the padding of a decrypted ciphertext is valid or invalid.

In CBC mode, if a server reveals this information, an attacker can modify ciphertext blocks and use the server's responses to recover the plaintext one byte at a time.

---

## Why is this dangerous?

In CBC decryption:

P_i = D_K(C_i) XOR C_{i-1}

If an attacker modifies the previous ciphertext block, they can control the resulting plaintext block after decryption.

When the application leaks whether the padding is valid, this becomes enough to recover the plaintext.

---

## Files

- `oracle.py`  
  Implements:
  - AES-CBC encryption
  - PKCS#7 padding/unpadding
  - a vulnerable oracle that only reveals whether padding is valid

- `attack.py`  
  Implements the padding oracle attack to recover plaintext block by block

- `requirements.txt`  
  Contains the Python dependency for this project

---

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt

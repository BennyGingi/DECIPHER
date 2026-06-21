# ◈ DECIPHER

**Universal Decode / Decrypt Multitool**

A pure Python desktop tool with a cyber-themed CustomTkinter GUI for decoding, decrypting, and analyzing any encoded or encrypted text.

## Features

### Auto-Detect Mode
Paste any blob of text → DECIPHER tries every method and ranks results by confidence.

### Encodings (16)
Base64, Base32, Base58, Base85, Hex, URL, HTML Entities, Binary, Octal, Decimal, Morse Code, Punycode, Quoted-Printable, Unicode Escape, UUencode, JWT

### Ciphers (10)
Caesar Brute Force (all 25 shifts), ROT13, ROT47, Atbash, Vigenère (with key), Rail Fence (configurable rails), XOR Brute Force, XOR with key, Reverse Text, Reverse Words

### Analysis (2)
Hash Identification (MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, NTLM, etc.), Frequency Analysis (for substitution cipher cracking)

### Encode Mode
One click encodes your input into ALL formats simultaneously.

### Chaining
Swap button (⇅) sends output → input for pipeline decoding (e.g., Base64 → URL Decode → ROT13).

## Install & Run

```bash
pip install -r requirements.txt
python decipher.py
```

## Font

For the best look, install [JetBrains Mono](https://www.jetbrains.com/lp/mono/). Falls back to system monospace if not available.

## Author

Benny Golan

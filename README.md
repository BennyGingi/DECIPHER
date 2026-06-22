# ◈ DECIPHER v4.0

**Universal Decode / Decrypt / Brute Force Multitool**

A pure Python desktop tool with a cyber-themed CustomTkinter GUI that can decode, decrypt, analyze, and brute-force any encoded or encrypted text.

---

## ⚡ ULTRA BRUTE Mode

The flagship feature. Paste any encrypted or encoded blob, hit **⚡ ULTRA BRUTE**, and the tool automatically runs through 8 attack phases in a background thread with a live progress bar:

1. **Encoding Detection** — Base64, Hex, URL, HTML, Binary, Morse, Base32, Unicode, JWT
2. **Classic Cipher Brute Force** — Caesar (all 25 shifts, auto-scored for English), ROT13, ROT47, Atbash, Reverse
3. **XOR Multi-byte Brute** — Single-byte (256 keys) + 2-byte (65K combinations)
4. **Vigenère Auto-crack** — Kasiski examination → key length estimation → frequency analysis → automatic key recovery
5. **Multi-layer Chain Detection** — Automatically detects double-encoding (Base64→Base64, Base64→Hex, Base64→ROT13)
6. **Dictionary Attack: AES** — Tries 100+ passwords × multiple key derivations (raw, MD5, SHA-256) × ECB + CBC modes × common IVs
7. **Dictionary Attack: DES/3DES** — Same dictionary approach for legacy encryption
8. **Dictionary Attack: RC4** — Stream cipher with full password dictionary

All results are ranked by **English language scoring** (word frequency, letter distribution, printable ratio) and displayed with confidence bars.

---

## Supported Operations (40+)

### Encodings (17)
Base64, Base64URL, Base32, Base58, Base85, Hex, URL, HTML Entities, Binary, Octal, Decimal, Morse Code, Punycode, Quoted-Printable, Unicode Escape, UUencode, JWT

### Classic Ciphers (10)
Caesar Brute Force, ROT13, ROT47, Atbash, Vigenère (with key), Rail Fence, XOR Brute Force, XOR (with key), Reverse Text, Reverse Words

### Symmetric Encryption (6)
AES (ECB/CBC/CTR/GCM), DES / 3DES, RC4, Blowfish, ChaCha20, Fernet

### Compression (3)
Gzip, Zlib, Bzip2

### Binary Analysis (5)
File Type ID (45+ magic byte signatures), Pickle Inspector (safe opcode disassembly), Hex Dump, Strings Extraction, Entropy Analysis

### Analysis (3)
Hash Identification (MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, NTLM, etc.), Hash Generation (10+ algorithms), Frequency Analysis

---

## Smart Features

- **Auto-Detect Mode** — Paste anything, the tool identifies the encoding and decodes it
- **Smart Binary Detection** — When decoded bytes aren't text, automatically identifies file type, runs entropy analysis, extracts strings, and shows hex dump
- **Pickle Payload Inspector** — Safely disassembles Python pickle payloads without executing them, highlights dangerous functions (eval, exec, os.system)
- **Gzip/Zlib/Bzip2 Auto-decompress** — Detects compressed data inside Base64/Hex and auto-decompresses
- **Hash Priority Logic** — Pure hex strings matching known hash lengths (32, 40, 64, 128 chars) are correctly identified as hashes instead of being decoded as Base64
- **English Language Scoring** — Brute force results scored by word frequency, letter distribution, and printable ratio
- **Swap Button (⇅)** — Send output back to input for chaining decode steps
- **Encode Mode** — One click encodes input into ALL formats simultaneously

---

## Custom Wordlist

DECIPHER loads passwords from `wordlist.txt` on startup. Add your own passwords anytime — one per line, lines starting with `#` are ignored.

```
# Add investigation passwords
Company2025
S0cAnalyst!
Winter_Is_Coming
Mobileye123
```

The tool merges your custom passwords with the built-in dictionary. You can paste entire wordlists from SecLists, rockyou, or any breach database.

---

## Install & Run

```bash
pip install -r requirements.txt
python main.py
```

### Requirements
- Python 3.10+
- customtkinter
- pycryptodome (for AES/DES/RC4/Blowfish/ChaCha20)
- cryptography (for Fernet)

### Optional
- Install [JetBrains Mono](https://www.jetbrains.com/lp/mono/) font for the best look

---

## Project Structure

```
decyfher/
├── main.py           # Entry point
├── gui.py            # CustomTkinter GUI with ULTRA mode + progress bar
├── engine.py         # All 40+ decode/decrypt operations
├── bruteforce.py     # ULTRA brute force engine (threaded)
├── utils.py          # Magic bytes, hex dump, entropy, English scoring
├── theme.py          # Design constants (neon cyber palette)
├── wordlist.txt      # Custom password dictionary (editable)
└── requirements.txt
```

---

## Author

**Benny Golan**
GitHub: [github.com/BennyGingi](https://github.com/BennyGingi)

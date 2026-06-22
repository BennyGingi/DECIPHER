# decipher/utils.py — Utilities, Magic Bytes, Scoring, Smart Decode

import io
import math
import pickletools
import re
import gzip
import zlib
import bz2
from collections import Counter
from typing import Optional, List

# ──────────────────────────────────────────────
# MAGIC BYTES DATABASE
# ──────────────────────────────────────────────

MAGIC_SIGNATURES = [
    (b'\x80\x05\x95',               "Python Pickle (protocol 5)"),
    (b'\x80\x04\x95',               "Python Pickle (protocol 4)"),
    (b'\x80\x03',                    "Python Pickle (protocol 3)"),
    (b'\x80\x02',                    "Python Pickle (protocol 2)"),
    (b'\x1f\x8b',                    "Gzip compressed data"),
    (b'x\x9c',                       "Zlib compressed data (default)"),
    (b'x\x01',                       "Zlib compressed data (no compression)"),
    (b'x\xda',                       "Zlib compressed data (best)"),
    (b'BZ',                          "Bzip2 compressed data"),
    (b'PK\x03\x04',                 "ZIP archive (or DOCX/XLSX/JAR/APK)"),
    (b'\x89PNG\r\n\x1a\n',          "PNG image"),
    (b'\xff\xd8\xff',               "JPEG image"),
    (b'GIF87a',                      "GIF image (87a)"),
    (b'GIF89a',                      "GIF image (89a)"),
    (b'%PDF',                        "PDF document"),
    (b'\x7fELF',                     "ELF executable (Linux)"),
    (b'MZ',                          "PE executable (Windows EXE/DLL)"),
    (b'\xd0\xcf\x11\xe0',           "MS Office legacy (DOC/XLS/PPT)"),
    (b'Rar!\x1a\x07',               "RAR archive"),
    (b'\xfd7zXZ\x00',               "XZ compressed data"),
    (b'7z\xbc\xaf\x27\x1c',        "7-Zip archive"),
    (b'RIFF',                        "RIFF container (AVI/WAV/WEBP)"),
    (b'OggS',                        "Ogg container"),
    (b'fLaC',                        "FLAC audio"),
    (b'ID3',                         "MP3 audio (ID3 tag)"),
    (b'SQLite format 3',            "SQLite database"),
    (b'-----BEGIN',                  "PEM encoded (cert/key)"),
    (b'\x00asm',                     "WebAssembly binary"),
    (b'\x28\xb5\x2f\xfd',           "Zstandard compressed data"),
    (b'BM',                          "BMP image"),
]


# ──────────────────────────────────────────────
# ENGLISH SCORING — for brute force result ranking
# ──────────────────────────────────────────────

# Top 200 English words for scoring decoded text
COMMON_WORDS = set(
    "the be to of and a in that have i it for not on with he as you do at this "
    "but his by from they we say her she or an will my one all would there their "
    "what so up out if about who get which go me when make can like time no just "
    "him know take people into year your good some could them see other than then "
    "now look only come its over think also back after use two how our work first "
    "well way even new want because any these give day most us is are was were been "
    "has had did get got let may might must shall should will would need open close "
    "file read write data key flag password secret admin user root login system "
    "server host port http https error code access denied found hello world test "
    "the this that with from have been will".split()
)

# English letter frequency (approximate)
ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
    's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
    'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
    'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07,
}


def english_score(text: str) -> float:
    """Score text for likelihood of being English (0.0 - 1.0).
    Uses: printable ratio, common word matches, letter frequency similarity.
    """
    if not text or len(text) < 2:
        return 0.0

    score = 0.0

    # 1. Printable ratio (0-0.3)
    pr = printable_ratio(text)
    score += pr * 0.3

    # 2. Common word matches (0-0.4)
    words = re.findall(r'[a-zA-Z]+', text.lower())
    if words:
        common_count = sum(1 for w in words if w in COMMON_WORDS)
        word_score = min(common_count / max(len(words), 1), 1.0)
        score += word_score * 0.4

    # 3. Letter frequency similarity (0-0.2)
    alpha = [c.lower() for c in text if c.isalpha()]
    if len(alpha) > 10:
        freq = Counter(alpha)
        total = len(alpha)
        chi_sq = 0.0
        for letter, expected_pct in ENGLISH_FREQ.items():
            observed = freq.get(letter, 0) / total * 100
            chi_sq += (observed - expected_pct) ** 2 / max(expected_pct, 0.01)
        # Lower chi-squared = more English-like; normalize to 0-1
        freq_score = max(0, 1.0 - chi_sq / 500)
        score += freq_score * 0.2

    # 4. Space ratio bonus (0-0.1) — English has spaces roughly every 5 chars
    space_ratio = text.count(' ') / max(len(text), 1)
    if 0.1 < space_ratio < 0.3:
        score += 0.1
    elif 0.05 < space_ratio < 0.4:
        score += 0.05

    return min(score, 1.0)


# ──────────────────────────────────────────────
# COMMON PASSWORDS / KEYS for dictionary attack
# ──────────────────────────────────────────────

COMMON_PASSWORDS = [
    # Classic defaults
    "password", "password123", "123456", "12345678", "123456789",
    "admin", "administrator", "root", "toor", "guest", "default",
    "letmein", "welcome", "monkey", "dragon", "master", "qwerty",
    "abc123", "login", "passw0rd", "shadow", "sunshine", "trustno1",
    # Security/CTF common
    "secret", "supersecret", "changeme", "test", "test123",
    "flag", "ctf", "hack", "hacker", "security", "encrypted",
    "decrypted", "hidden", "key", "mykey", "thekey", "secretkey",
    "aes", "aeskey", "crypto", "cipher", "decipher",
    # Common phrases
    "iloveyou", "football", "baseball", "soccer", "hockey",
    "batman", "superman", "starwars", "hello", "world",
    # Patterns
    "aaaa", "aaaaaa", "aaaaaaaa", "aaaaaaaaaaaaaaaa",
    "0000", "000000", "00000000", "0000000000000000",
    "1111", "111111", "11111111", "1111111111111111",
    "1234", "12345678", "1234567890123456",
    "abcd", "abcdef", "abcdefgh", "abcdefghijklmnop",
    "AAAA", "AAAAAA", "AAAAAAAA", "AAAAAAAAAAAAAAAA",
    "dead", "deadbeef", "deadbeefdeadbeef",
    "cafe", "cafebabe", "cafebabecafebabe",
    "beef", "beefbeef", "beefbeefbeefbeef",
    "face", "faceface", "facefacefaceface",
    "ffff", "ffffffff", "ffffffffffffffff",
    # Null
    "\x00" * 8, "\x00" * 16, "\x00" * 24, "\x00" * 32,
]


def _load_external_wordlist():
    """Load additional passwords from wordlist.txt (same directory as this script)."""
    import os
    wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")
    if not os.path.exists(wordlist_path):
        return []
    passwords = []
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    passwords.append(line)
    except Exception:
        pass
    return passwords


# Merge built-in + external wordlist (deduped, external first for priority)
_external = _load_external_wordlist()
if _external:
    _seen = set()
    _merged = []
    for pw in _external + COMMON_PASSWORDS:
        if pw not in _seen:
            _seen.add(pw)
            _merged.append(pw)
    COMMON_PASSWORDS = _merged


def derive_keys_from_password(password: str) -> List[bytes]:
    """Generate multiple key formats from a password string for brute force."""
    import hashlib
    keys = []
    raw = password.encode('utf-8')

    # Raw bytes (truncated/padded to common sizes)
    for size in (8, 16, 24, 32):
        padded = (raw * ((size // len(raw)) + 1))[:size] if raw else b'\x00' * size
        keys.append(padded)

    # MD5 hash = 16 bytes (AES-128)
    keys.append(hashlib.md5(raw).digest())

    # SHA-256 hash = 32 bytes (AES-256)
    keys.append(hashlib.sha256(raw).digest())

    # SHA-256 first 16 bytes (AES-128)
    keys.append(hashlib.sha256(raw).digest()[:16])

    # SHA-256 first 24 bytes (AES-192)
    keys.append(hashlib.sha256(raw).digest()[:24])

    # If password looks like hex, try as raw hex bytes
    if re.match(r'^[a-fA-F0-9]+$', password) and len(password) % 2 == 0:
        try:
            hex_bytes = bytes.fromhex(password)
            keys.append(hex_bytes)
        except ValueError:
            pass

    # Deduplicate
    seen = set()
    unique = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            unique.append(k)
    return unique


# ──────────────────────────────────────────────
# COMMON IVs for brute force
# ──────────────────────────────────────────────

COMMON_IVS = [
    bytes(16),                                          # all zeros
    bytes(8),                                           # all zeros (DES)
    bytes(range(16)),                                   # 00 01 02 ... 0f
    bytes(range(8)),                                    # 00 01 02 ... 07
    b'\xff' * 16,                                       # all FF
    b'\xff' * 8,
    bytes.fromhex("00112233445566778899aabbccddeeff"),
    bytes.fromhex("aabbccddeeff00112233445566778899"),
    bytes.fromhex("0123456789abcdef0123456789abcdef"),
    bytes.fromhex("fedcba9876543210fedcba9876543210"),
    bytes.fromhex("1234567890abcdef"),                  # DES
    bytes.fromhex("0123456789abcdef"),                  # DES
]


# ──────────────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────────────

def identify_magic(data: bytes) -> Optional[str]:
    for sig, name in MAGIC_SIGNATURES:
        if data[:len(sig)] == sig:
            return name
    if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:64]):
        return "ASCII / UTF-8 text"
    return None


def hex_dump(data: bytes, width: int = 16, max_lines: int = 64) -> str:
    lines = []
    for i in range(0, min(len(data), width * max_lines), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    if len(data) > width * max_lines:
        lines.append(f"  ... ({len(data)} bytes total)")
    return '\n'.join(lines)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def entropy_verdict(ent: float) -> str:
    if ent < 1.0:
        return "Very low — repetitive/padding"
    elif ent < 3.5:
        return "Low — plaintext / structured"
    elif ent < 5.0:
        return "Moderate — encoded or light compression"
    elif ent < 7.0:
        return "High — compressed or obfuscated"
    elif ent < 7.9:
        return "Very high — encrypted or heavily compressed"
    return "Near-maximum — strong encryption or random"


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    return [m.group().decode('ascii') for m in pattern.finditer(data)]


def safe_pickle_dis(data: bytes) -> str:
    try:
        buf = io.StringIO()
        pickletools.dis(io.BytesIO(data), out=buf, annotate=1)
        return buf.getvalue()
    except Exception as e:
        return f"Pickle disassembly failed: {e}"


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)


def smart_decode_result(raw_bytes: bytes) -> str:
    """Given raw bytes, produce the best human-readable output."""
    try:
        text = raw_bytes.decode('utf-8')
        if printable_ratio(text) > 0.85:
            return text
    except UnicodeDecodeError:
        pass

    sections = []
    file_type = identify_magic(raw_bytes)
    sections.append("── BINARY DATA DETECTED ──\n")
    sections.append(f"  Size     : {len(raw_bytes)} bytes")
    if file_type:
        sections.append(f"  Type     : {file_type}")

    ent = shannon_entropy(raw_bytes)
    sections.append(f"  Entropy  : {ent:.4f} bits/byte")
    sections.append(f"  Verdict  : {entropy_verdict(ent)}")

    if file_type and "Pickle" in file_type:
        sections.append("\n── PICKLE DISASSEMBLY (safe — no code executed) ──\n")
        sections.append(safe_pickle_dis(raw_bytes))
    elif file_type and "Gzip" in file_type:
        try:
            decompressed = gzip.decompress(raw_bytes)
            sections.append(f"\n── GZIP DECOMPRESSED ({len(decompressed)} bytes) ──\n")
            try:
                text = decompressed.decode('utf-8')
                sections.append(text if printable_ratio(text) > 0.85 else hex_dump(decompressed))
            except UnicodeDecodeError:
                sections.append(hex_dump(decompressed))
        except Exception as e:
            sections.append(f"\n  Gzip decompress failed: {e}")
    elif file_type and "Zlib" in file_type:
        try:
            decompressed = zlib.decompress(raw_bytes)
            sections.append(f"\n── ZLIB DECOMPRESSED ({len(decompressed)} bytes) ──\n")
            try:
                text = decompressed.decode('utf-8')
                sections.append(text if printable_ratio(text) > 0.85 else hex_dump(decompressed))
            except UnicodeDecodeError:
                sections.append(hex_dump(decompressed))
        except Exception as e:
            sections.append(f"\n  Zlib decompress failed: {e}")
    elif file_type and "Bzip2" in file_type:
        try:
            decompressed = bz2.decompress(raw_bytes)
            sections.append(f"\n── BZIP2 DECOMPRESSED ({len(decompressed)} bytes) ──\n")
            try:
                text = decompressed.decode('utf-8')
                sections.append(text if printable_ratio(text) > 0.85 else hex_dump(decompressed))
            except UnicodeDecodeError:
                sections.append(hex_dump(decompressed))
        except Exception as e:
            sections.append(f"\n  Bzip2 decompress failed: {e}")

    strings = extract_strings(raw_bytes)
    if strings:
        sections.append(f"\n── EXTRACTED STRINGS ({len(strings)} found) ──\n")
        for s in strings[:30]:
            sections.append(f'  "{s}"')

    sections.append("\n── HEX DUMP ──\n")
    sections.append(hex_dump(raw_bytes))
    return '\n'.join(sections)


def try_binary_input(text: str) -> bytes:
    """Try to interpret input as hex or base64 to get raw bytes."""
    import base64
    stripped = text.strip()
    cleaned = re.sub(r'[\s:x\\]', '', stripped)
    if cleaned.lower().startswith('0x'):
        cleaned = cleaned[2:]
    if re.match(r'^[a-fA-F0-9]+$', cleaned) and len(cleaned) % 2 == 0:
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass
    try:
        return base64.b64decode(stripped)
    except Exception:
        pass
    return stripped.encode('latin-1')

"""
██████╗ ███████╗ ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗
██╔══██╗██╔════╝██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
██║  ██║█████╗  ██║     ██║██████╔╝███████║█████╗  ██████╔╝
██║  ██║██╔══╝  ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
██████╔╝███████╗╚██████╗██║██║     ██║  ██║███████╗██║  ██║
╚═════╝ ╚══════╝ ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

Universal Decode / Decrypt Multitool  v2.0
Author: Benny Golan
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import base64
import binascii
import codecs
import gzip
import zlib
import bz2
import hashlib
import html
import io
import json
import math
import pickletools
import re
import string
import struct
import urllib.parse
from collections import Counter
from typing import Optional, Tuple, List
import itertools


# ──────────────────────────────────────────────
# THEME & DESIGN CONSTANTS
# ──────────────────────────────────────────────

BG_DARK        = "#0a0a0f"
BG_PANEL       = "#111119"
BG_INPUT       = "#14141f"
BG_CARD        = "#16161f"
BORDER_DIM     = "#1e1e2e"
BORDER_GLOW    = "#00e5ff"
ACCENT_CYAN    = "#00e5ff"
ACCENT_PURPLE  = "#b44aff"
ACCENT_GREEN   = "#00ff88"
ACCENT_RED     = "#ff3366"
ACCENT_ORANGE  = "#ff8c00"
ACCENT_YELLOW  = "#ffd700"
TEXT_PRIMARY    = "#e8e8f0"
TEXT_SECONDARY  = "#7a7a8e"
TEXT_DIM        = "#4a4a5e"
FONT_MONO      = ("JetBrains Mono", 12)
FONT_MONO_SM   = ("JetBrains Mono", 10)
FONT_MONO_LG   = ("JetBrains Mono", 14)
FONT_TITLE     = ("JetBrains Mono", 22, "bold")
FONT_HEADING   = ("JetBrains Mono", 13, "bold")
FONT_LABEL     = ("JetBrains Mono", 11)
FONT_SMALL     = ("JetBrains Mono", 9)


# ──────────────────────────────────────────────
# MORSE CODE TABLES
# ──────────────────────────────────────────────

MORSE_TO_CHAR = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
    '.-.-.-': '.', '--..--': ',', '..--..': '?', '.----.': "'",
    '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')',
    '.-...': '&', '---...': ':', '-.-.-.': ';', '-...-': '=',
    '.-.-.': '+', '-....-': '-', '..--.-': '_', '.-..-.': '"',
    '...-..-': '$', '.--.-.': '@',
}
CHAR_TO_MORSE = {v: k for k, v in MORSE_TO_CHAR.items()}


# ──────────────────────────────────────────────
# MAGIC BYTES DATABASE
# ──────────────────────────────────────────────

MAGIC_SIGNATURES = [
    (b'\x80\x04\x95',               "Python Pickle (protocol 4)"),
    (b'\x80\x05\x95',               "Python Pickle (protocol 5)"),
    (b'\x80\x03',                    "Python Pickle (protocol 3)"),
    (b'\x80\x02',                    "Python Pickle (protocol 2)"),
    (b'\x1f\x8b',                    "Gzip compressed data"),
    (b'x\x9c',                       "Zlib compressed data (default)"),
    (b'x\x01',                       "Zlib compressed data (no compression)"),
    (b'x\xda',                       "Zlib compressed data (best)"),
    (b'BZ',                          "Bzip2 compressed data"),
    (b'PK\x03\x04',                 "ZIP archive (or DOCX/XLSX/PPTX/JAR/APK)"),
    (b'PK\x05\x06',                 "ZIP archive (empty)"),
    (b'\x89PNG\r\n\x1a\n',          "PNG image"),
    (b'\xff\xd8\xff',               "JPEG image"),
    (b'GIF87a',                      "GIF image (87a)"),
    (b'GIF89a',                      "GIF image (89a)"),
    (b'%PDF',                        "PDF document"),
    (b'\x7fELF',                     "ELF executable (Linux)"),
    (b'MZ',                          "PE executable (Windows EXE/DLL)"),
    (b'\xca\xfe\xba\xbe',           "Mach-O / Java class file"),
    (b'\xfe\xed\xfa\xce',           "Mach-O 32-bit"),
    (b'\xfe\xed\xfa\xcf',           "Mach-O 64-bit"),
    (b'\xd0\xcf\x11\xe0',           "MS Office legacy (DOC/XLS/PPT)"),
    (b'Rar!\x1a\x07',               "RAR archive"),
    (b'\xfd7zXZ\x00',               "XZ compressed data"),
    (b'7z\xbc\xaf\x27\x1c',        "7-Zip archive"),
    (b'\x1f\x9d',                    "LZW compressed (compress)"),
    (b'\x1f\xa0',                    "LZH compressed"),
    (b'RIFF',                        "RIFF container (AVI/WAV/WEBP)"),
    (b'OggS',                        "Ogg container (Vorbis/Opus)"),
    (b'fLaC',                        "FLAC audio"),
    (b'ID3',                         "MP3 audio (ID3 tag)"),
    (b'\xff\xfb',                    "MP3 audio"),
    (b'\x00\x00\x00\x1cftyp',       "MP4/M4A video"),
    (b'\x00\x00\x00\x20ftyp',       "MP4 video"),
    (b'\x1a\x45\xdf\xa3',           "MKV/WebM video (Matroska)"),
    (b'SQLite format 3',            "SQLite database"),
    (b'-----BEGIN',                  "PEM encoded (cert/key)"),
    (b'\x00asm',                     "WebAssembly binary"),
    (b'dex\n',                       "Android DEX"),
    (b'\xce\xfa\xed\xfe',           "Mach-O reverse byte order"),
    (b'LZIP',                        "Lzip compressed data"),
    (b'\x28\xb5\x2f\xfd',           "Zstandard compressed data"),
    (b'\x04\x22\x4d\x18',           "LZ4 compressed data"),
    (b'\x42\x4c\x45\x4e\x44\x45\x52', "Blender file"),
    (b'\x49\x49\x2a\x00',           "TIFF image (little-endian)"),
    (b'\x4d\x4d\x00\x2a',           "TIFF image (big-endian)"),
    (b'BM',                          "BMP image"),
    (b'\x00\x00\x01\x00',           "ICO icon"),
    (b'IHDR',                        "PNG IHDR chunk"),
]


# ──────────────────────────────────────────────
# UTILITY FUNCTIONS
# ──────────────────────────────────────────────

def identify_magic(data: bytes) -> Optional[str]:
    """Identify file type from magic bytes."""
    for sig, name in MAGIC_SIGNATURES:
        if data[:len(sig)] == sig:
            return name
    # Fallback — check if starts with printable ASCII
    if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:64]):
        return "ASCII / UTF-8 text"
    return None


def hex_dump(data: bytes, width: int = 16, max_lines: int = 64) -> str:
    """Produce a formatted hex dump like xxd."""
    lines = []
    for i in range(0, min(len(data), width * max_lines), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    if len(data) > width * max_lines:
        lines.append(f"  ... ({len(data)} bytes total, showing first {width * max_lines})")
    return '\n'.join(lines)


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0-8 bits)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def entropy_verdict(ent: float) -> str:
    """Human-readable entropy assessment."""
    if ent < 1.0:
        return "Very low — likely repetitive/padding"
    elif ent < 3.5:
        return "Low — plaintext / structured data"
    elif ent < 5.0:
        return "Moderate — encoded text or light compression"
    elif ent < 7.0:
        return "High — compressed or obfuscated data"
    elif ent < 7.9:
        return "Very high — encrypted or heavily compressed"
    else:
        return "Near-maximum — strong encryption or random data"


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract printable ASCII strings from binary data (like Unix `strings`)."""
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    return [m.group().decode('ascii') for m in pattern.finditer(data)]


def safe_pickle_dis(data: bytes) -> str:
    """Safely disassemble pickle opcodes without executing."""
    try:
        buf = io.StringIO()
        pickletools.dis(io.BytesIO(data), out=buf, annotate=1)
        return buf.getvalue()
    except Exception as e:
        return f"Pickle disassembly failed: {e}"


def printable_ratio(text: str) -> float:
    """Fraction of characters that are printable."""
    if not text:
        return 0.0
    return sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)


def smart_decode_result(raw_bytes: bytes) -> str:
    """Given raw decoded bytes, produce the best human-readable output.

    If the bytes are printable text → return as string.
    If the bytes match a known magic → identify + hex dump + deeper analysis.
    Otherwise → hex dump with entropy analysis.
    """
    # Try plain text first
    try:
        text = raw_bytes.decode('utf-8')
        if printable_ratio(text) > 0.85:
            return text
    except UnicodeDecodeError:
        pass

    sections = []
    file_type = identify_magic(raw_bytes)

    # ── Header
    sections.append("── BINARY DATA DETECTED ──\n")
    sections.append(f"  Size     : {len(raw_bytes)} bytes")
    if file_type:
        sections.append(f"  Type     : {file_type}")

    # ── Entropy
    ent = shannon_entropy(raw_bytes)
    sections.append(f"  Entropy  : {ent:.4f} bits/byte")
    sections.append(f"  Verdict  : {entropy_verdict(ent)}")

    # ── Deeper analysis based on type
    if file_type and "Pickle" in file_type:
        sections.append("\n── PICKLE DISASSEMBLY (safe — no code executed) ──\n")
        sections.append(safe_pickle_dis(raw_bytes))
    elif file_type and "Gzip" in file_type:
        try:
            decompressed = gzip.decompress(raw_bytes)
            sections.append(f"\n── GZIP DECOMPRESSED ({len(decompressed)} bytes) ──\n")
            try:
                text = decompressed.decode('utf-8')
                if printable_ratio(text) > 0.85:
                    sections.append(text)
                else:
                    sections.append(hex_dump(decompressed))
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
                if printable_ratio(text) > 0.85:
                    sections.append(text)
                else:
                    sections.append(hex_dump(decompressed))
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
                if printable_ratio(text) > 0.85:
                    sections.append(text)
                else:
                    sections.append(hex_dump(decompressed))
            except UnicodeDecodeError:
                sections.append(hex_dump(decompressed))
        except Exception as e:
            sections.append(f"\n  Bzip2 decompress failed: {e}")

    # ── Extracted strings
    strings = extract_strings(raw_bytes)
    if strings:
        sections.append(f"\n── EXTRACTED STRINGS ({len(strings)} found) ──\n")
        for s in strings[:30]:
            sections.append(f"  \"{s}\"")
        if len(strings) > 30:
            sections.append(f"  ... and {len(strings) - 30} more")

    # ── Hex dump
    sections.append("\n── HEX DUMP ──\n")
    sections.append(hex_dump(raw_bytes))

    return '\n'.join(sections)


# ──────────────────────────────────────────────
# DECODE / DECRYPT ENGINE
# ──────────────────────────────────────────────

class DecipherEngine:
    """Core engine handling all decode/decrypt operations."""

    # ── ENCODINGS (raw bytes variants for smart detection) ──

    @staticmethod
    def _base64_raw(text: str) -> bytes:
        return base64.b64decode(text.strip())

    @staticmethod
    def _base64url_raw(text: str) -> bytes:
        s = text.strip()
        s += '=' * (4 - len(s) % 4) if len(s) % 4 else ''
        return base64.urlsafe_b64decode(s)

    @staticmethod
    def _base32_raw(text: str) -> bytes:
        padded = text.strip().upper()
        pad_len = (8 - len(padded) % 8) % 8
        padded += "=" * pad_len
        return base64.b32decode(padded)

    @staticmethod
    def _hex_raw(text: str) -> bytes:
        cleaned = re.sub(r'[\s:x\\]', '', text.strip())
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        return bytes.fromhex(cleaned)

    @staticmethod
    def _base85_raw(text: str) -> bytes:
        return base64.b85decode(text.strip())

    # ── ENCODINGS (text-level wrappers using smart_decode_result) ──

    @staticmethod
    def base64_decode(text: str) -> str:
        raw = DecipherEngine._base64_raw(text)
        return smart_decode_result(raw)

    @staticmethod
    def base64_encode(text: str) -> str:
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def base64url_decode(text: str) -> str:
        raw = DecipherEngine._base64url_raw(text)
        return smart_decode_result(raw)

    @staticmethod
    def base64url_encode(text: str) -> str:
        return base64.urlsafe_b64encode(text.encode('utf-8')).decode('utf-8').rstrip('=')

    @staticmethod
    def base32_decode(text: str) -> str:
        raw = DecipherEngine._base32_raw(text)
        return smart_decode_result(raw)

    @staticmethod
    def base32_encode(text: str) -> str:
        return base64.b32encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def hex_decode(text: str) -> str:
        raw = DecipherEngine._hex_raw(text)
        return smart_decode_result(raw)

    @staticmethod
    def hex_encode(text: str) -> str:
        return text.encode('utf-8').hex()

    @staticmethod
    def base85_decode(text: str) -> str:
        raw = DecipherEngine._base85_raw(text)
        return smart_decode_result(raw)

    @staticmethod
    def base85_encode(text: str) -> str:
        return base64.b85encode(text.encode('utf-8')).decode('ascii')

    @staticmethod
    def url_decode(text: str) -> str:
        return urllib.parse.unquote(text.strip())

    @staticmethod
    def url_encode(text: str) -> str:
        return urllib.parse.quote(text, safe='')

    @staticmethod
    def html_decode(text: str) -> str:
        return html.unescape(text.strip())

    @staticmethod
    def html_encode(text: str) -> str:
        return html.escape(text)

    @staticmethod
    def binary_decode(text: str) -> str:
        cleaned = re.sub(r'[^01\s]', '', text.strip())
        chunks = cleaned.split()
        if not chunks or len(chunks) == 1:
            cleaned_no_space = re.sub(r'\s', '', cleaned)
            chunks = [cleaned_no_space[i:i+8] for i in range(0, len(cleaned_no_space), 8)]
        return ''.join(chr(int(b, 2)) for b in chunks if len(b) == 8)

    @staticmethod
    def binary_encode(text: str) -> str:
        return ' '.join(format(ord(c), '08b') for c in text)

    @staticmethod
    def octal_decode(text: str) -> str:
        parts = text.strip().split()
        return ''.join(chr(int(p, 8)) for p in parts)

    @staticmethod
    def octal_encode(text: str) -> str:
        return ' '.join(format(ord(c), 'o') for c in text)

    @staticmethod
    def decimal_decode(text: str) -> str:
        parts = re.split(r'[\s,;]+', text.strip())
        return ''.join(chr(int(p)) for p in parts if p.isdigit())

    @staticmethod
    def decimal_encode(text: str) -> str:
        return ' '.join(str(ord(c)) for c in text)

    @staticmethod
    def morse_decode(text: str) -> str:
        words = text.strip().split('   ')
        decoded_words = []
        for word in words:
            chars = word.split(' ')
            decoded_words.append(''.join(MORSE_TO_CHAR.get(c, '?') for c in chars if c))
        return ' '.join(decoded_words)

    @staticmethod
    def morse_encode(text: str) -> str:
        result = []
        for char in text.upper():
            if char == ' ':
                result.append('  ')
            elif char in CHAR_TO_MORSE:
                result.append(CHAR_TO_MORSE[char])
        return ' '.join(result)

    @staticmethod
    def punycode_decode(text: str) -> str:
        parts = text.strip().split('.')
        decoded = []
        for part in parts:
            if part.startswith('xn--'):
                decoded.append(part[4:].encode('ascii').decode('punycode'))
            else:
                decoded.append(part)
        return '.'.join(decoded)

    @staticmethod
    def quoted_printable_decode(text: str) -> str:
        return codecs.decode(text.strip().encode('ascii'), 'quopri').decode('utf-8', errors='replace')

    @staticmethod
    def quoted_printable_encode(text: str) -> str:
        return codecs.encode(text.encode('utf-8'), 'quopri').decode('ascii')

    @staticmethod
    def unicode_escape_decode(text: str) -> str:
        return text.encode('ascii', errors='replace').decode('unicode_escape', errors='replace')

    @staticmethod
    def unicode_escape_encode(text: str) -> str:
        return text.encode('unicode_escape').decode('ascii')

    @staticmethod
    def jwt_decode(text: str) -> str:
        parts = text.strip().split('.')
        if len(parts) not in (2, 3):
            raise ValueError("Invalid JWT format")
        result = {}
        labels = ["HEADER", "PAYLOAD", "SIGNATURE"]
        for i, part in enumerate(parts):
            if i < 2:
                padded = part + '=' * (4 - len(part) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
                try:
                    result[labels[i]] = json.dumps(json.loads(decoded), indent=2)
                except json.JSONDecodeError:
                    result[labels[i]] = decoded
            else:
                result[labels[i]] = part
        return '\n'.join(f"── {k} ──\n{v}" for k, v in result.items())

    @staticmethod
    def base58_decode(text: str) -> str:
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        num = 0
        for char in text.strip():
            num = num * 58 + alphabet.index(char)
        result = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
        pad = len(text.strip()) - len(text.strip().lstrip('1'))
        raw = b'\x00' * pad + result
        return smart_decode_result(raw)

    @staticmethod
    def uuencode_decode(text: str) -> str:
        import uu
        infile = io.BytesIO(text.strip().encode('ascii'))
        outfile = io.BytesIO()
        try:
            uu.decode(infile, outfile, quiet=True)
        except Exception:
            raise ValueError("Invalid UUEncoded data")
        return smart_decode_result(outfile.getvalue())

    # ── COMPRESSION ──

    @staticmethod
    def gzip_decompress(text: str) -> str:
        """Accepts hex or base64 encoded gzip data."""
        raw = DecipherEngine._try_binary_input(text)
        decompressed = gzip.decompress(raw)
        return smart_decode_result(decompressed)

    @staticmethod
    def zlib_decompress(text: str) -> str:
        raw = DecipherEngine._try_binary_input(text)
        decompressed = zlib.decompress(raw)
        return smart_decode_result(decompressed)

    @staticmethod
    def bzip2_decompress(text: str) -> str:
        raw = DecipherEngine._try_binary_input(text)
        decompressed = bz2.decompress(raw)
        return smart_decode_result(decompressed)

    @staticmethod
    def _try_binary_input(text: str) -> bytes:
        """Try to interpret input as hex or base64 to get raw bytes."""
        stripped = text.strip()
        # Try hex
        cleaned = re.sub(r'[\s:x\\]', '', stripped)
        if cleaned.lower().startswith('0x'):
            cleaned = cleaned[2:]
        if re.match(r'^[a-fA-F0-9]+$', cleaned) and len(cleaned) % 2 == 0:
            try:
                return bytes.fromhex(cleaned)
            except ValueError:
                pass
        # Try base64
        try:
            return base64.b64decode(stripped)
        except Exception:
            pass
        # Raw bytes
        return stripped.encode('latin-1')

    # ── CIPHERS ──

    @staticmethod
    def caesar_decrypt(text: str, shift: int = 0) -> str:
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base - shift) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def caesar_brute(text: str) -> str:
        lines = []
        for shift in range(1, 26):
            decoded = DecipherEngine.caesar_decrypt(text, shift)
            lines.append(f"ROT-{shift:02d} │ {decoded}")
        return '\n'.join(lines)

    @staticmethod
    def rot13(text: str) -> str:
        return codecs.decode(text, 'rot_13')

    @staticmethod
    def rot47(text: str) -> str:
        result = []
        for c in text:
            o = ord(c)
            if 33 <= o <= 126:
                result.append(chr(33 + (o - 33 + 47) % 94))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def atbash(text: str) -> str:
        result = []
        for c in text:
            if c.isalpha():
                if c.isupper():
                    result.append(chr(ord('Z') - (ord(c) - ord('A'))))
                else:
                    result.append(chr(ord('z') - (ord(c) - ord('a'))))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def vigenere_decrypt(text: str, key: str = "KEY") -> str:
        key = key.upper()
        result, ki = [], 0
        for c in text:
            if c.isalpha():
                shift = ord(key[ki % len(key)]) - ord('A')
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base - shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def vigenere_encrypt(text: str, key: str = "KEY") -> str:
        key = key.upper()
        result, ki = [], 0
        for c in text:
            if c.isalpha():
                shift = ord(key[ki % len(key)]) - ord('A')
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def rail_fence_decrypt(text: str, rails: int = 3) -> str:
        if rails < 2:
            return text
        n = len(text)
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        indices = [[] for _ in range(rails)]
        for i in range(n):
            indices[pattern[i % len(pattern)]].append(i)
        result = [''] * n
        pos = 0
        for rail_indices in indices:
            for idx in rail_indices:
                result[idx] = text[pos]
                pos += 1
        return ''.join(result)

    @staticmethod
    def rail_fence_encrypt(text: str, rails: int = 3) -> str:
        if rails < 2:
            return text
        fence = [[] for _ in range(rails)]
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        for i, c in enumerate(text):
            fence[pattern[i % len(pattern)]].append(c)
        return ''.join(''.join(rail) for rail in fence)

    @staticmethod
    def xor_brute(text: str) -> str:
        try:
            data = bytes.fromhex(re.sub(r'\s', '', text.strip()))
        except ValueError:
            data = text.encode('utf-8')
        lines = []
        for key in range(1, 256):
            decoded = ''.join(chr(b ^ key) for b in data)
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded):
                pr = sum(1 for c in decoded if c in string.printable) / len(decoded)
                if pr > 0.85:
                    lines.append(f"KEY 0x{key:02x} │ {decoded}")
        return '\n'.join(lines) if lines else "No printable XOR results found."

    @staticmethod
    def xor_decrypt(text: str, key: str = "FF") -> str:
        try:
            data = bytes.fromhex(re.sub(r'\s', '', text.strip()))
        except ValueError:
            data = text.encode('utf-8')
        key_bytes = bytes.fromhex(re.sub(r'\s', '', key.strip()))
        decrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        return smart_decode_result(decrypted)

    @staticmethod
    def reverse_text(text: str) -> str:
        return text[::-1]

    @staticmethod
    def reverse_words(text: str) -> str:
        return ' '.join(text.split()[::-1])

    # ── ANALYSIS ──

    @staticmethod
    def identify_hash(text: str) -> str:
        text = text.strip()
        results = []
        hash_patterns = [
            (r'^[a-fA-F0-9]{32}$', ["MD5", "NTLM", "MD4"]),
            (r'^[a-fA-F0-9]{40}$', ["SHA-1", "RIPEMD-160"]),
            (r'^[a-fA-F0-9]{56}$', ["SHA-224", "SHA3-224"]),
            (r'^[a-fA-F0-9]{64}$', ["SHA-256", "SHA3-256", "BLAKE2s"]),
            (r'^[a-fA-F0-9]{96}$', ["SHA-384", "SHA3-384"]),
            (r'^[a-fA-F0-9]{128}$', ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"]),
            (r'^\$2[aby]?\$\d{2}\$.{53}$', ["bcrypt"]),
            (r'^\$6\$', ["SHA-512 Crypt (Unix)"]),
            (r'^\$5\$', ["SHA-256 Crypt (Unix)"]),
            (r'^\$1\$', ["MD5 Crypt (Unix)"]),
            (r'^\$apr1\$', ["Apache MD5"]),
            (r'^\$argon2(i|d|id)\$', ["Argon2"]),
            (r'^[a-fA-F0-9]{16}$', ["MySQL (old)", "DES(Unix)", "Half MD5"]),
            (r'^pbkdf2', ["PBKDF2"]),
            (r'^scrypt\$', ["scrypt"]),
        ]
        for pattern, names in hash_patterns:
            if re.match(pattern, text):
                results.extend(names)
        if not results:
            return f"Unknown hash format (length: {len(text)} chars)"
        lines = ["── POSSIBLE HASH TYPES ──", ""]
        for name in results:
            lines.append(f"  ◆ {name}")
        lines.append(f"\n  Length: {len(text)} characters")
        return '\n'.join(lines)

    @staticmethod
    def substitution_freq_analysis(text: str) -> str:
        alpha_only = [c.upper() for c in text if c.isalpha()]
        total = len(alpha_only)
        if total == 0:
            return "No alphabetic characters found."
        freq = Counter(alpha_only)
        english_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
        lines = ["── FREQUENCY ANALYSIS ──", ""]
        lines.append("Char │ Count │  Freq  │ Bar")
        lines.append("─────┼───────┼────────┼" + "─" * 30)
        for char, count in freq.most_common():
            pct = (count / total) * 100
            bar = "█" * int(pct)
            lines.append(f"  {char}  │  {count:4d} │ {pct:5.1f}% │ {bar}")
        lines.append("")
        lines.append("── SUGGESTED MAPPING (by frequency) ──")
        sorted_chars = [c for c, _ in freq.most_common()]
        for i, sc in enumerate(sorted_chars):
            if i < len(english_freq):
                lines.append(f"  {sc} → {english_freq[i]}")
        return '\n'.join(lines)

    @staticmethod
    def entropy_analysis(text: str) -> str:
        """Full entropy analysis of input."""
        raw = text.encode('utf-8')
        ent = shannon_entropy(raw)
        lines = ["── ENTROPY ANALYSIS ──", ""]
        lines.append(f"  Input length : {len(raw)} bytes")
        lines.append(f"  Unique bytes : {len(set(raw))} / 256")
        lines.append(f"  Entropy      : {ent:.4f} bits/byte (max 8.0)")
        lines.append(f"  Randomness   : {ent / 8 * 100:.1f}%")
        lines.append(f"  Assessment   : {entropy_verdict(ent)}")
        lines.append("")

        # Byte distribution histogram
        freq = Counter(raw)
        lines.append("── BYTE FREQUENCY (top 20) ──")
        lines.append("")
        for byte_val, count in freq.most_common(20):
            pct = count / len(raw) * 100
            bar = "█" * max(1, int(pct * 2))
            char_repr = chr(byte_val) if 32 <= byte_val < 127 else '.'
            lines.append(f"  0x{byte_val:02x} '{char_repr}' │ {count:5d} │ {pct:5.1f}% │ {bar}")

        return '\n'.join(lines)

    @staticmethod
    def strings_extract(text: str) -> str:
        """Extract printable strings from input (treats as binary)."""
        raw = text.encode('latin-1', errors='replace')
        strings = extract_strings(raw, min_length=4)
        if not strings:
            return "No printable strings found (min length: 4)."
        lines = [f"── EXTRACTED STRINGS ({len(strings)} found) ──", ""]
        for i, s in enumerate(strings[:100], 1):
            lines.append(f"  {i:4d} │ \"{s}\"")
        if len(strings) > 100:
            lines.append(f"\n  ... and {len(strings) - 100} more")
        return '\n'.join(lines)

    @staticmethod
    def hex_dump_mode(text: str) -> str:
        """Raw hex dump of input."""
        raw = text.encode('utf-8')
        lines = [f"── HEX DUMP ({len(raw)} bytes) ──", ""]
        lines.append(hex_dump(raw, max_lines=128))
        return '\n'.join(lines)

    @staticmethod
    def magic_identify(text: str) -> str:
        """Try to identify input format via magic bytes."""
        raw = DecipherEngine._try_binary_input(text)
        file_type = identify_magic(raw)
        ent = shannon_entropy(raw)

        lines = ["── FILE / DATA IDENTIFICATION ──", ""]
        lines.append(f"  Size      : {len(raw)} bytes")
        lines.append(f"  Type      : {file_type or 'Unknown'}")
        lines.append(f"  Entropy   : {ent:.4f} bits/byte ({entropy_verdict(ent)})")
        lines.append("")

        # Show first 64 bytes hex
        lines.append("── HEADER BYTES ──")
        lines.append("")
        lines.append(hex_dump(raw[:64], max_lines=4))

        strings = extract_strings(raw, min_length=4)
        if strings:
            lines.append(f"\n── EMBEDDED STRINGS ({len(strings)}) ──")
            for s in strings[:15]:
                lines.append(f"  \"{s}\"")

        return '\n'.join(lines)

    @staticmethod
    def pickle_inspect(text: str) -> str:
        """Safely disassemble a pickle payload."""
        raw = DecipherEngine._try_binary_input(text)
        ft = identify_magic(raw)
        if ft and "Pickle" not in ft:
            return f"WARNING: Data appears to be {ft}, not Pickle.\n\nAttempting disassembly anyway...\n\n" + safe_pickle_dis(raw)
        if not ft:
            return "WARNING: No Pickle magic bytes detected.\n\nAttempting disassembly anyway...\n\n" + safe_pickle_dis(raw)

        lines = ["── PICKLE PAYLOAD ANALYSIS ──", ""]
        lines.append(f"  Type: {ft}")
        lines.append(f"  Size: {len(raw)} bytes")

        strings = extract_strings(raw, min_length=3)
        if strings:
            lines.append(f"\n── SUSPICIOUS STRINGS ──\n")
            danger_keywords = ['eval', 'exec', 'import', 'os.', 'system', 'subprocess',
                             'open(', '__', 'builtins', 'globals', 'getattr', 'setattr',
                             'compile', 'popen', 'shell', '/bin/', 'cmd', 'powershell',
                             'nt.', 'posix.']
            for s in strings:
                is_sus = any(kw in s.lower() for kw in danger_keywords)
                marker = " ⚠ DANGEROUS" if is_sus else ""
                lines.append(f"  \"{s}\"{marker}")

        lines.append(f"\n── OPCODE DISASSEMBLY ──\n")
        lines.append(safe_pickle_dis(raw))

        return '\n'.join(lines)

    # ── AUTO-DETECT ──

    @staticmethod
    def auto_detect(text: str) -> List[Tuple[str, str, float]]:
        """Try to auto-detect encoding/cipher. Returns [(method, result, confidence)]."""
        results = []
        stripped = text.strip()

        # JWT
        if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', stripped):
            try:
                r = DecipherEngine.jwt_decode(stripped)
                results.append(("JWT Decode", r, 0.95))
            except Exception:
                pass

        # Base64 (now with smart binary handling)
        if re.match(r'^[A-Za-z0-9+/\n\r]+=*$', stripped) and len(stripped) >= 4:
            try:
                raw = DecipherEngine._base64_raw(stripped)
                decoded = smart_decode_result(raw)
                ft = identify_magic(raw)
                if ft:
                    results.append((f"Base64 → {ft}", decoded, 0.95))
                elif printable_ratio(decoded) > 0.8:
                    results.append(("Base64", decoded, 0.85 * printable_ratio(decoded)))
                else:
                    results.append(("Base64 (binary)", decoded, 0.60))
            except Exception:
                pass

        # Base64URL
        if re.match(r'^[A-Za-z0-9_-]+=*$', stripped) and len(stripped) >= 4:
            try:
                raw = DecipherEngine._base64url_raw(stripped)
                decoded = smart_decode_result(raw)
                pr = printable_ratio(decoded)
                if pr > 0.8:
                    results.append(("Base64URL", decoded, 0.80 * pr))
            except Exception:
                pass

        # Base32
        if re.match(r'^[A-Z2-7\n\r]+=*$', stripped.upper()) and len(stripped) >= 8:
            try:
                raw = DecipherEngine._base32_raw(stripped)
                decoded = smart_decode_result(raw)
                pr = printable_ratio(decoded)
                if pr > 0.8:
                    results.append(("Base32", decoded, 0.75 * pr))
            except Exception:
                pass

        # Hex
        cleaned_hex = re.sub(r'[\s:x\\]', '', stripped)
        if cleaned_hex.lower().startswith("0x"):
            cleaned_hex = cleaned_hex[2:]
        if re.match(r'^[a-fA-F0-9]+$', cleaned_hex) and len(cleaned_hex) >= 4 and len(cleaned_hex) % 2 == 0:
            try:
                raw = DecipherEngine._hex_raw(stripped)
                decoded = smart_decode_result(raw)
                ft = identify_magic(raw)
                if ft:
                    results.append((f"Hex → {ft}", decoded, 0.90))
                elif printable_ratio(decoded) > 0.7:
                    results.append(("Hex", decoded, 0.80 * printable_ratio(decoded)))
            except Exception:
                pass

        # URL encoded
        if '%' in stripped and re.search(r'%[0-9a-fA-F]{2}', stripped):
            try:
                r = DecipherEngine.url_decode(stripped)
                if r != stripped:
                    results.append(("URL Decode", r, 0.90))
            except Exception:
                pass

        # HTML entities
        if re.search(r'&[#\w]+;', stripped):
            try:
                r = DecipherEngine.html_decode(stripped)
                if r != stripped:
                    results.append(("HTML Decode", r, 0.90))
            except Exception:
                pass

        # Binary
        if re.match(r'^[01\s]+$', stripped) and len(stripped.replace(' ', '')) >= 8:
            try:
                r = DecipherEngine.binary_decode(stripped)
                if r and all(c.isprintable() or c in '\n\r\t' for c in r):
                    results.append(("Binary", r, 0.85))
            except Exception:
                pass

        # Morse
        if re.match(r'^[\.\-\s/]+$', stripped) and len(stripped) >= 3:
            try:
                r = DecipherEngine.morse_decode(stripped)
                if r and '?' not in r[:5]:
                    results.append(("Morse Code", r, 0.90))
            except Exception:
                pass

        # Octal
        if re.match(r'^[0-7]+(\s+[0-7]+)*$', stripped):
            try:
                r = DecipherEngine.octal_decode(stripped)
                if r and all(c.isprintable() for c in r):
                    results.append(("Octal", r, 0.70))
            except Exception:
                pass

        # Quoted-Printable
        if '=' in stripped and re.search(r'=[0-9A-Fa-f]{2}', stripped):
            try:
                r = DecipherEngine.quoted_printable_decode(stripped)
                if r != stripped:
                    results.append(("Quoted-Printable", r, 0.80))
            except Exception:
                pass

        # Unicode escape
        if re.search(r'\\u[0-9a-fA-F]{4}', stripped):
            try:
                r = DecipherEngine.unicode_escape_decode(stripped)
                if r != stripped:
                    results.append(("Unicode Escape", r, 0.90))
            except Exception:
                pass

        # Hash ID
        if re.match(r'^[\$a-fA-F0-9]+$', stripped) and len(stripped) >= 16:
            hash_result = DecipherEngine.identify_hash(stripped)
            if "Unknown" not in hash_result:
                results.append(("Hash ID", hash_result, 0.70))

        # ROT13 (always works, low confidence)
        if stripped.isascii() and any(c.isalpha() for c in stripped):
            r = DecipherEngine.rot13(stripped)
            results.append(("ROT13", r, 0.30))

        results.sort(key=lambda x: x[2], reverse=True)
        return results


# ──────────────────────────────────────────────
# GUI APPLICATION
# ──────────────────────────────────────────────

class DecipherApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DECIPHER")
        self.geometry("1200x820")
        self.minsize(1000, 700)
        self.configure(fg_color=BG_DARK)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.engine = DecipherEngine()
        self.history: List[Tuple[str, str, str]] = []
        self._build_ui()

    def _build_ui(self):
        self._build_topbar()
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        main.grid_columnconfigure(0, weight=0, minsize=260)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)
        self._build_sidebar(main)
        self._build_content(main)

    def _build_topbar(self):
        topbar = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=60)
        topbar.pack(fill="x", padx=0, pady=0)
        topbar.pack_propagate(False)
        logo_frame = ctk.CTkFrame(topbar, fg_color="transparent")
        logo_frame.pack(side="left", padx=20, pady=10)
        ctk.CTkLabel(logo_frame, text="◈", font=("JetBrains Mono", 28),
                     text_color=ACCENT_CYAN).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(logo_frame, text="DECIPHER", font=FONT_TITLE,
                     text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(logo_frame, text="v2.0", font=FONT_SMALL,
                     text_color=TEXT_DIM).pack(side="left", padx=(8, 0), pady=(8, 0))
        status_frame = ctk.CTkFrame(topbar, fg_color="transparent")
        status_frame.pack(side="right", padx=20, pady=10)
        self.status_label = ctk.CTkLabel(status_frame, text="● READY", font=FONT_SMALL,
                                          text_color=ACCENT_GREEN)
        self.status_label.pack(side="right")
        sep = ctk.CTkFrame(self, fg_color=ACCENT_CYAN, height=1, corner_radius=0)
        sep.pack(fill="x", padx=0, pady=0)

    def _build_sidebar(self, parent):
        sidebar = ctk.CTkScrollableFrame(parent, fg_color=BG_PANEL, corner_radius=12,
                                          width=240, border_width=1, border_color=BORDER_DIM)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)

        ctk.CTkLabel(sidebar, text="─── MODE ───", font=FONT_LABEL,
                     text_color=TEXT_DIM).pack(pady=(10, 6))
        self.mode_var = ctk.StringVar(value="auto")

        modes = [
            ("◈  AUTO DETECT", "auto", ACCENT_CYAN),
            ("⇄  ENCODE", "encode", ACCENT_PURPLE),
        ]
        for label, val, color in modes:
            ctk.CTkRadioButton(sidebar, text=label, variable=self.mode_var, value=val,
                               font=FONT_LABEL, text_color=TEXT_PRIMARY, fg_color=color,
                               hover_color=color, border_color=TEXT_DIM,
                               command=self._on_mode_change).pack(anchor="w", padx=12, pady=3)

        ctk.CTkFrame(sidebar, fg_color=BORDER_DIM, height=1).pack(fill="x", padx=10, pady=10)

        categories = {
            "ENCODINGS": [
                ("Base64", "base64"), ("Base64URL", "base64url"),
                ("Base32", "base32"), ("Base58", "base58"),
                ("Base85", "base85"), ("Hex", "hex"), ("URL", "url"),
                ("HTML Entities", "html"), ("Binary", "binary"),
                ("Octal", "octal"), ("Decimal", "decimal"),
                ("Morse Code", "morse"), ("Punycode", "punycode"),
                ("Quoted-Printable", "qp"), ("Unicode Escape", "unicode"),
                ("UUencode", "uuencode"), ("JWT", "jwt"),
            ],
            "CIPHERS": [
                ("Caesar Brute", "caesar_brute"), ("ROT13", "rot13"),
                ("ROT47", "rot47"), ("Atbash", "atbash"),
                ("Vigenère", "vigenere"), ("Rail Fence", "railfence"),
                ("XOR Brute", "xor_brute"), ("XOR (key)", "xor"),
                ("Reverse Text", "reverse"), ("Reverse Words", "reverse_words"),
            ],
            "COMPRESSION": [
                ("Gzip", "gzip"), ("Zlib", "zlib"), ("Bzip2", "bzip2"),
            ],
            "BINARY ANALYSIS": [
                ("File Type ID", "magic_id"), ("Pickle Inspect", "pickle"),
                ("Hex Dump", "hexdump"), ("Strings Extract", "strings"),
                ("Entropy", "entropy"),
            ],
            "ANALYSIS": [
                ("Hash Identify", "hash_id"), ("Freq Analysis", "freq"),
            ],
        }

        for cat_name, items in categories.items():
            ctk.CTkLabel(sidebar, text=f"─── {cat_name} ───", font=FONT_LABEL,
                         text_color=TEXT_DIM).pack(pady=(8, 4))
            for label, val in items:
                ctk.CTkRadioButton(sidebar, text=label, variable=self.mode_var, value=val,
                                   font=FONT_SMALL, text_color=TEXT_SECONDARY,
                                   fg_color=ACCENT_CYAN, hover_color=ACCENT_CYAN,
                                   border_color=TEXT_DIM,
                                   command=self._on_mode_change).pack(anchor="w", padx=16, pady=2)

    def _build_content(self, parent):
        content = ctk.CTkFrame(parent, fg_color="transparent")
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_rowconfigure(1, weight=1)
        content.grid_rowconfigure(3, weight=1)
        content.grid_columnconfigure(0, weight=1)

        # ── INPUT
        input_header = ctk.CTkFrame(content, fg_color="transparent")
        input_header.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        ctk.CTkLabel(input_header, text="INPUT", font=FONT_HEADING,
                     text_color=ACCENT_CYAN).pack(side="left")
        self.input_count = ctk.CTkLabel(input_header, text="0 chars", font=FONT_SMALL,
                                         text_color=TEXT_DIM)
        self.input_count.pack(side="right")
        ctk.CTkButton(input_header, text="PASTE", font=FONT_SMALL, width=60, height=24,
                      fg_color=BG_CARD, hover_color=BORDER_DIM, text_color=TEXT_SECONDARY,
                      border_width=1, border_color=BORDER_DIM,
                      command=self._paste_clipboard).pack(side="right", padx=8)
        ctk.CTkButton(input_header, text="CLEAR", font=FONT_SMALL, width=60, height=24,
                      fg_color=BG_CARD, hover_color=BORDER_DIM, text_color=TEXT_SECONDARY,
                      border_width=1, border_color=BORDER_DIM,
                      command=self._clear_all).pack(side="right", padx=(0, 4))

        self.input_box = ctk.CTkTextbox(content, font=FONT_MONO, fg_color=BG_INPUT,
                                         text_color=TEXT_PRIMARY, corner_radius=10,
                                         border_width=1, border_color=BORDER_DIM, wrap="word")
        self.input_box.grid(row=1, column=0, sticky="nsew", pady=(0, 8))
        self.input_box.bind("<KeyRelease>", self._update_input_count)

        # ── ACTION BAR
        action_bar = ctk.CTkFrame(content, fg_color="transparent", height=50)
        action_bar.grid(row=2, column=0, sticky="ew", pady=4)

        self.key_frame = ctk.CTkFrame(action_bar, fg_color="transparent")
        self.key_frame.pack(side="left")
        ctk.CTkLabel(self.key_frame, text="KEY:", font=FONT_SMALL,
                     text_color=TEXT_DIM).pack(side="left", padx=(0, 6))
        self.key_entry = ctk.CTkEntry(self.key_frame, font=FONT_MONO_SM, width=160, height=36,
                                       fg_color=BG_INPUT, text_color=ACCENT_YELLOW,
                                       border_color=BORDER_DIM, border_width=1,
                                       placeholder_text="encryption key...")
        self.key_entry.pack(side="left")

        self.rails_frame = ctk.CTkFrame(action_bar, fg_color="transparent")
        ctk.CTkLabel(self.rails_frame, text="RAILS:", font=FONT_SMALL,
                     text_color=TEXT_DIM).pack(side="left", padx=(10, 6))
        self.rails_entry = ctk.CTkEntry(self.rails_frame, font=FONT_MONO_SM, width=60, height=36,
                                         fg_color=BG_INPUT, text_color=ACCENT_YELLOW,
                                         border_color=BORDER_DIM, border_width=1,
                                         placeholder_text="3")
        self.rails_entry.pack(side="left")

        self.min_len_frame = ctk.CTkFrame(action_bar, fg_color="transparent")
        ctk.CTkLabel(self.min_len_frame, text="MIN LEN:", font=FONT_SMALL,
                     text_color=TEXT_DIM).pack(side="left", padx=(10, 6))
        self.min_len_entry = ctk.CTkEntry(self.min_len_frame, font=FONT_MONO_SM, width=60, height=36,
                                           fg_color=BG_INPUT, text_color=ACCENT_YELLOW,
                                           border_color=BORDER_DIM, border_width=1,
                                           placeholder_text="4")
        self.min_len_entry.pack(side="left")

        self.run_btn = ctk.CTkButton(action_bar, text="▶  DECIPHER", font=FONT_HEADING,
                                      width=180, height=42, fg_color=ACCENT_CYAN,
                                      hover_color="#00b8cc", text_color=BG_DARK,
                                      corner_radius=8, command=self._run)
        self.run_btn.pack(side="right")

        ctk.CTkButton(action_bar, text="⇅", font=("JetBrains Mono", 18), width=42, height=42,
                      fg_color=BG_CARD, hover_color=BORDER_DIM, text_color=ACCENT_PURPLE,
                      border_width=1, border_color=BORDER_DIM, corner_radius=8,
                      command=self._swap_io).pack(side="right", padx=8)

        # ── OUTPUT
        output_header = ctk.CTkFrame(content, fg_color="transparent")
        output_header.grid(row=3, column=0, sticky="new", pady=(4, 4))
        ctk.CTkLabel(output_header, text="OUTPUT", font=FONT_HEADING,
                     text_color=ACCENT_GREEN).pack(side="left")
        self.output_count = ctk.CTkLabel(output_header, text="0 chars", font=FONT_SMALL,
                                          text_color=TEXT_DIM)
        self.output_count.pack(side="right")
        ctk.CTkButton(output_header, text="COPY", font=FONT_SMALL, width=60, height=24,
                      fg_color=BG_CARD, hover_color=BORDER_DIM, text_color=TEXT_SECONDARY,
                      border_width=1, border_color=BORDER_DIM,
                      command=self._copy_output).pack(side="right", padx=8)
        self.method_label = ctk.CTkLabel(output_header, text="", font=FONT_SMALL,
                                          text_color=ACCENT_PURPLE)
        self.method_label.pack(side="right", padx=8)

        self.output_box = ctk.CTkTextbox(content, font=FONT_MONO, fg_color=BG_INPUT,
                                          text_color=ACCENT_GREEN, corner_radius=10,
                                          border_width=1, border_color=BORDER_DIM,
                                          wrap="word", state="disabled")
        self.output_box.grid(row=4, column=0, sticky="nsew", pady=(0, 0))
        content.grid_rowconfigure(4, weight=1)

        self._on_mode_change()

    # ── ACTIONS ──

    def _on_mode_change(self):
        mode = self.mode_var.get()
        needs_key = mode in ("vigenere", "xor")
        needs_rails = mode == "railfence"
        needs_min_len = mode == "strings"

        # Hide all param frames first
        self.key_frame.pack_forget()
        self.rails_frame.pack_forget()
        self.min_len_frame.pack_forget()

        if needs_key:
            self.key_frame.pack(side="left")
            if mode == "xor":
                self.key_entry.configure(placeholder_text="hex key (e.g. FF)")
            else:
                self.key_entry.configure(placeholder_text="encryption key...")
        if needs_rails:
            self.rails_frame.pack(side="left")
        if needs_min_len:
            self.min_len_frame.pack(side="left")

        if mode == "auto":
            self.run_btn.configure(text="▶  AUTO DETECT")
        elif mode == "encode":
            self.run_btn.configure(text="▶  ENCODE")
        else:
            self.run_btn.configure(text="▶  DECIPHER")

    def _run(self):
        text = self.input_box.get("1.0", "end-1c")
        if not text.strip():
            self._set_status("● NO INPUT", ACCENT_RED)
            return

        mode = self.mode_var.get()
        self._set_status("● PROCESSING...", ACCENT_ORANGE)
        self.update_idletasks()

        try:
            if mode == "auto":
                results = self.engine.auto_detect(text)
                if results:
                    best_method, best_result, confidence = results[0]
                    output_lines = [f"▸ Best Match: {best_method} (confidence: {confidence:.0%})\n"]
                    output_lines.append(best_result)
                    if len(results) > 1:
                        output_lines.append("\n\n── OTHER MATCHES ──")
                        for method, result, conf in results[1:6]:
                            preview = result[:120].replace('\n', ' ')
                            output_lines.append(f"\n▸ {method} ({conf:.0%}): {preview}...")
                    output = '\n'.join(output_lines)
                    self.method_label.configure(text=f"⟨ {best_method} ⟩")
                else:
                    output = "Could not auto-detect encoding/cipher."
                    self.method_label.configure(text="")
            elif mode == "encode":
                output = self._run_encode_menu(text)
            else:
                output = self._run_specific(mode, text)

            self._set_output(output)
            self._set_status("● DONE", ACCENT_GREEN)
            self.history.append((mode, text[:100], output[:100]))

        except Exception as e:
            self._set_output(f"ERROR: {str(e)}")
            self._set_status("● ERROR", ACCENT_RED)

    def _run_specific(self, mode: str, text: str) -> str:
        key = self.key_entry.get().strip()
        rails_str = self.rails_entry.get().strip()
        rails = int(rails_str) if rails_str.isdigit() else 3
        min_len_str = self.min_len_entry.get().strip()
        min_len = int(min_len_str) if min_len_str.isdigit() else 4

        dispatch = {
            "base64":       lambda: self.engine.base64_decode(text),
            "base64url":    lambda: self.engine.base64url_decode(text),
            "base32":       lambda: self.engine.base32_decode(text),
            "base58":       lambda: self.engine.base58_decode(text),
            "base85":       lambda: self.engine.base85_decode(text),
            "hex":          lambda: self.engine.hex_decode(text),
            "url":          lambda: self.engine.url_decode(text),
            "html":         lambda: self.engine.html_decode(text),
            "binary":       lambda: self.engine.binary_decode(text),
            "octal":        lambda: self.engine.octal_decode(text),
            "decimal":      lambda: self.engine.decimal_decode(text),
            "morse":        lambda: self.engine.morse_decode(text),
            "punycode":     lambda: self.engine.punycode_decode(text),
            "qp":           lambda: self.engine.quoted_printable_decode(text),
            "unicode":      lambda: self.engine.unicode_escape_decode(text),
            "uuencode":     lambda: self.engine.uuencode_decode(text),
            "jwt":          lambda: self.engine.jwt_decode(text),
            "caesar_brute": lambda: self.engine.caesar_brute(text),
            "rot13":        lambda: self.engine.rot13(text),
            "rot47":        lambda: self.engine.rot47(text),
            "atbash":       lambda: self.engine.atbash(text),
            "vigenere":     lambda: self.engine.vigenere_decrypt(text, key or "KEY"),
            "railfence":    lambda: self.engine.rail_fence_decrypt(text, rails),
            "xor_brute":    lambda: self.engine.xor_brute(text),
            "xor":          lambda: self.engine.xor_decrypt(text, key or "FF"),
            "reverse":      lambda: self.engine.reverse_text(text),
            "reverse_words": lambda: self.engine.reverse_words(text),
            "hash_id":      lambda: self.engine.identify_hash(text),
            "freq":         lambda: self.engine.substitution_freq_analysis(text),
            "gzip":         lambda: self.engine.gzip_decompress(text),
            "zlib":         lambda: self.engine.zlib_decompress(text),
            "bzip2":        lambda: self.engine.bzip2_decompress(text),
            "magic_id":     lambda: self.engine.magic_identify(text),
            "pickle":       lambda: self.engine.pickle_inspect(text),
            "hexdump":      lambda: self.engine.hex_dump_mode(text),
            "strings":      lambda: self.engine.strings_extract(text),
            "entropy":      lambda: self.engine.entropy_analysis(text),
        }

        method_name = mode.upper().replace("_", " ")
        self.method_label.configure(text=f"⟨ {method_name} ⟩")
        if mode in dispatch:
            return dispatch[mode]()
        return f"Unknown mode: {mode}"

    def _run_encode_menu(self, text: str) -> str:
        lines = ["── ENCODE RESULTS ──\n"]
        encodings = [
            ("Base64", self.engine.base64_encode),
            ("Base64URL", self.engine.base64url_encode),
            ("Base32", self.engine.base32_encode),
            ("Base85", self.engine.base85_encode),
            ("Hex", self.engine.hex_encode),
            ("URL", self.engine.url_encode),
            ("HTML", self.engine.html_encode),
            ("Binary", self.engine.binary_encode),
            ("Octal", self.engine.octal_encode),
            ("Decimal", self.engine.decimal_encode),
            ("Morse", self.engine.morse_encode),
            ("ROT13", self.engine.rot13),
            ("ROT47", self.engine.rot47),
            ("Atbash", self.engine.atbash),
            ("Unicode Esc", self.engine.unicode_escape_encode),
            ("QP", self.engine.quoted_printable_encode),
            ("Reverse", self.engine.reverse_text),
        ]
        for name, func in encodings:
            try:
                result = func(text)
                lines.append(f"▸ {name}:\n  {result}\n")
            except Exception as e:
                lines.append(f"▸ {name}: [error: {e}]\n")
        self.method_label.configure(text="⟨ ENCODE ALL ⟩")
        return '\n'.join(lines)

    # ── HELPERS ──

    def _set_output(self, text: str):
        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", text)
        self.output_box.configure(state="disabled")
        self.output_count.configure(text=f"{len(text)} chars")

    def _set_status(self, text: str, color: str):
        self.status_label.configure(text=text, text_color=color)

    def _update_input_count(self, event=None):
        text = self.input_box.get("1.0", "end-1c")
        self.input_count.configure(text=f"{len(text)} chars")

    def _paste_clipboard(self):
        try:
            text = self.clipboard_get()
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", text)
            self._update_input_count()
        except Exception:
            pass

    def _copy_output(self):
        self.output_box.configure(state="normal")
        text = self.output_box.get("1.0", "end-1c")
        self.output_box.configure(state="disabled")
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("● COPIED", ACCENT_PURPLE)

    def _clear_all(self):
        self.input_box.delete("1.0", "end")
        self._set_output("")
        self.method_label.configure(text="")
        self._update_input_count()
        self._set_status("● READY", ACCENT_GREEN)

    def _swap_io(self):
        self.output_box.configure(state="normal")
        output_text = self.output_box.get("1.0", "end-1c")
        input_text = self.input_box.get("1.0", "end-1c")
        self.output_box.configure(state="disabled")
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", output_text)
        self._set_output(input_text)
        self._update_input_count()
        self._set_status("● SWAPPED", ACCENT_PURPLE)


if __name__ == "__main__":
    app = DecipherApp()
    app.mainloop()
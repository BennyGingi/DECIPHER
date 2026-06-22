# decipher/engine.py — All decode/decrypt/analysis operations

import base64
import codecs
import hashlib
import html
import io
import json
import re
import string
import urllib.parse
from collections import Counter
from typing import List, Tuple

from utils import (
    smart_decode_result, try_binary_input, printable_ratio,
    identify_magic, hex_dump, shannon_entropy, entropy_verdict,
    extract_strings, safe_pickle_dis
)

# Crypto imports
try:
    from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4, ChaCha20
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from cryptography.fernet import Fernet
    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False

# Morse tables
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


class DecipherEngine:
    """All decode/decrypt operations."""

    # ── ENCODINGS ──

    @staticmethod
    def base64_decode(text): return smart_decode_result(base64.b64decode(text.strip()))
    @staticmethod
    def base64_encode(text): return base64.b64encode(text.encode('utf-8')).decode()
    @staticmethod
    def base64url_decode(text):
        s = text.strip()
        s += '=' * (4 - len(s) % 4) if len(s) % 4 else ''
        return smart_decode_result(base64.urlsafe_b64decode(s))
    @staticmethod
    def base64url_encode(text): return base64.urlsafe_b64encode(text.encode('utf-8')).decode().rstrip('=')

    @staticmethod
    def base32_decode(text):
        p = text.strip().upper()
        p += "=" * ((8 - len(p) % 8) % 8)
        return smart_decode_result(base64.b32decode(p))
    @staticmethod
    def base32_encode(text): return base64.b32encode(text.encode('utf-8')).decode()

    @staticmethod
    def hex_decode(text):
        c = re.sub(r'[\s:x\\]', '', text.strip())
        if c.lower().startswith("0x"): c = c[2:]
        return smart_decode_result(bytes.fromhex(c))
    @staticmethod
    def hex_encode(text): return text.encode('utf-8').hex()

    @staticmethod
    def base85_decode(text): return smart_decode_result(base64.b85decode(text.strip()))
    @staticmethod
    def base85_encode(text): return base64.b85encode(text.encode('utf-8')).decode()

    @staticmethod
    def base58_decode(text):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        num = 0
        for char in text.strip():
            num = num * 58 + alphabet.index(char)
        result = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
        pad = len(text.strip()) - len(text.strip().lstrip('1'))
        return smart_decode_result(b'\x00' * pad + result)

    @staticmethod
    def url_decode(text): return urllib.parse.unquote(text.strip())
    @staticmethod
    def url_encode(text): return urllib.parse.quote(text, safe='')
    @staticmethod
    def html_decode(text): return html.unescape(text.strip())
    @staticmethod
    def html_encode(text): return html.escape(text)

    @staticmethod
    def binary_decode(text):
        c = re.sub(r'[^01\s]', '', text.strip())
        chunks = c.split()
        if not chunks or len(chunks) == 1:
            c2 = c.replace(' ', '')
            chunks = [c2[i:i+8] for i in range(0, len(c2), 8)]
        return ''.join(chr(int(b, 2)) for b in chunks if len(b) == 8)
    @staticmethod
    def binary_encode(text): return ' '.join(format(ord(c), '08b') for c in text)

    @staticmethod
    def octal_decode(text): return ''.join(chr(int(p, 8)) for p in text.strip().split())
    @staticmethod
    def octal_encode(text): return ' '.join(format(ord(c), 'o') for c in text)

    @staticmethod
    def decimal_decode(text):
        parts = re.split(r'[\s,;]+', text.strip())
        return ''.join(chr(int(p)) for p in parts if p.isdigit())
    @staticmethod
    def decimal_encode(text): return ' '.join(str(ord(c)) for c in text)

    @staticmethod
    def morse_decode(text):
        words = text.strip().split('   ')
        return ' '.join(''.join(MORSE_TO_CHAR.get(c, '?') for c in w.split(' ') if c) for w in words)
    @staticmethod
    def morse_encode(text):
        r = []
        for c in text.upper():
            if c == ' ': r.append('  ')
            elif c in CHAR_TO_MORSE: r.append(CHAR_TO_MORSE[c])
        return ' '.join(r)

    @staticmethod
    def punycode_decode(text):
        return '.'.join(p[4:].encode('ascii').decode('punycode') if p.startswith('xn--') else p for p in text.strip().split('.'))

    @staticmethod
    def quoted_printable_decode(text): return codecs.decode(text.strip().encode('ascii'), 'quopri').decode('utf-8', errors='replace')
    @staticmethod
    def quoted_printable_encode(text): return codecs.encode(text.encode('utf-8'), 'quopri').decode('ascii')

    @staticmethod
    def unicode_escape_decode(text): return text.encode('ascii', errors='replace').decode('unicode_escape', errors='replace')
    @staticmethod
    def unicode_escape_encode(text): return text.encode('unicode_escape').decode('ascii')

    @staticmethod
    def jwt_decode(text):
        parts = text.strip().split('.')
        if len(parts) not in (2, 3): raise ValueError("Invalid JWT")
        result = {}
        labels = ["HEADER", "PAYLOAD", "SIGNATURE"]
        for i, part in enumerate(parts):
            if i < 2:
                padded = part + '=' * (4 - len(part) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
                try: result[labels[i]] = json.dumps(json.loads(decoded), indent=2)
                except: result[labels[i]] = decoded
            else: result[labels[i]] = part
        return '\n'.join(f"── {k} ──\n{v}" for k, v in result.items())

    @staticmethod
    def uuencode_decode(text):
        import uu
        infile = io.BytesIO(text.strip().encode('ascii'))
        outfile = io.BytesIO()
        uu.decode(infile, outfile, quiet=True)
        return smart_decode_result(outfile.getvalue())

    # ── COMPRESSION ──

    @staticmethod
    def gzip_decompress(text):
        import gzip
        return smart_decode_result(gzip.decompress(try_binary_input(text)))
    @staticmethod
    def zlib_decompress(text):
        import zlib
        return smart_decode_result(zlib.decompress(try_binary_input(text)))
    @staticmethod
    def bzip2_decompress(text):
        import bz2
        return smart_decode_result(bz2.decompress(try_binary_input(text)))

    # ── CIPHERS ──

    @staticmethod
    def caesar_decrypt(text, shift=0):
        return ''.join(chr((ord(c) - (ord('A') if c.isupper() else ord('a')) - shift) % 26 + (ord('A') if c.isupper() else ord('a'))) if c.isalpha() else c for c in text)
    @staticmethod
    def caesar_brute(text):
        return '\n'.join(f"ROT-{s:02d} │ {DecipherEngine.caesar_decrypt(text, s)}" for s in range(1, 26))
    @staticmethod
    def rot13(text): return codecs.decode(text, 'rot_13')
    @staticmethod
    def rot47(text):
        return ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)
    @staticmethod
    def atbash(text):
        return ''.join(chr(ord('Z') - (ord(c) - ord('A'))) if c.isupper() else chr(ord('z') - (ord(c) - ord('a'))) if c.islower() else c for c in text)

    @staticmethod
    def vigenere_decrypt(text, key="KEY"):
        key = key.upper(); result, ki = [], 0
        for c in text:
            if c.isalpha():
                s = ord(key[ki % len(key)]) - ord('A')
                b = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - b - s) % 26 + b)); ki += 1
            else: result.append(c)
        return ''.join(result)

    @staticmethod
    def vigenere_encrypt(text, key="KEY"):
        key = key.upper(); result, ki = [], 0
        for c in text:
            if c.isalpha():
                s = ord(key[ki % len(key)]) - ord('A')
                b = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - b + s) % 26 + b)); ki += 1
            else: result.append(c)
        return ''.join(result)

    @staticmethod
    def rail_fence_decrypt(text, rails=3):
        if rails < 2: return text
        n = len(text)
        pat = list(range(rails)) + list(range(rails - 2, 0, -1))
        idx = [[] for _ in range(rails)]
        for i in range(n): idx[pat[i % len(pat)]].append(i)
        result = [''] * n; pos = 0
        for ri in idx:
            for j in ri: result[j] = text[pos]; pos += 1
        return ''.join(result)

    @staticmethod
    def xor_brute(text):
        try: data = bytes.fromhex(re.sub(r'\s', '', text.strip()))
        except: data = text.encode('utf-8')
        lines = []
        for key in range(1, 256):
            d = ''.join(chr(b ^ key) for b in data)
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in d):
                pr = sum(1 for c in d if c in string.printable) / len(d)
                if pr > 0.85: lines.append(f"KEY 0x{key:02x} │ {d}")
        return '\n'.join(lines) if lines else "No printable XOR results found."

    @staticmethod
    def xor_decrypt(text, key="FF"):
        try: data = bytes.fromhex(re.sub(r'\s', '', text.strip()))
        except: data = text.encode('utf-8')
        kb = bytes.fromhex(re.sub(r'\s', '', key.strip()))
        return smart_decode_result(bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data)))

    @staticmethod
    def reverse_text(text): return text[::-1]
    @staticmethod
    def reverse_words(text): return ' '.join(text.split()[::-1])

    # ── SYMMETRIC ENCRYPTION ──

    @staticmethod
    def _parse_key(key_str):
        k = key_str.strip()
        if re.match(r'^[a-fA-F0-9]+$', k) and len(k) % 2 == 0:
            try: return bytes.fromhex(k)
            except: pass
        if re.match(r'^[A-Za-z0-9+/=]+$', k) and len(k) >= 4:
            try:
                d = base64.b64decode(k)
                if len(d) in (16, 24, 32, 8): return d
            except: pass
        return k.encode('utf-8')

    @staticmethod
    def _parse_iv(iv_str):
        iv = iv_str.strip()
        if not iv: return None
        if re.match(r'^[a-fA-F0-9]+$', iv) and len(iv) % 2 == 0:
            try: return bytes.fromhex(iv)
            except: pass
        try: return base64.b64decode(iv)
        except: return iv.encode('utf-8')

    @staticmethod
    def aes_decrypt(text, key_str, iv_str="", mode="CBC"):
        if not HAS_CRYPTO: return "ERROR: pip install pycryptodome"
        ct = try_binary_input(text); key = DecipherEngine._parse_key(key_str)
        if len(key) not in (16, 24, 32):
            return f"ERROR: AES key must be 16/24/32 bytes. Got {len(key)}."
        try:
            if mode == "ECB":
                return smart_decode_result(unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16))
            elif mode == "CBC":
                iv = DecipherEngine._parse_iv(iv_str)
                if not iv:
                    if len(ct) > 16: iv, ct = ct[:16], ct[16:]
                    else: return "ERROR: CBC requires IV."
                return smart_decode_result(unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16))
            elif mode == "CTR":
                iv = DecipherEngine._parse_iv(iv_str)
                if not iv:
                    if len(ct) > 8: nonce, ct = ct[:8], ct[8:]
                    else: return "ERROR: CTR requires nonce."
                else: nonce = iv[:8]
                return smart_decode_result(AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct))
            elif mode == "GCM":
                iv = DecipherEngine._parse_iv(iv_str)
                if not iv:
                    if len(ct) > 28: iv, tag, ct = ct[:12], ct[-16:], ct[12:-16]
                    else: return "ERROR: GCM requires nonce."
                else: tag, ct = ct[-16:], ct[:-16]
                return smart_decode_result(AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag))
        except Exception as e: return f"AES Error: {e}"

    @staticmethod
    def des_decrypt(text, key_str, iv_str="", mode="CBC"):
        if not HAS_CRYPTO: return "ERROR: pip install pycryptodome"
        ct = try_binary_input(text); key = DecipherEngine._parse_key(key_str)
        try:
            if len(key) == 8:
                if mode == "ECB": cipher = DES.new(key, DES.MODE_ECB)
                else:
                    iv = DecipherEngine._parse_iv(iv_str)
                    if not iv: iv, ct = ct[:8], ct[8:]
                    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
                return f"[DES {mode}]\n\n" + smart_decode_result(unpad(cipher.decrypt(ct), 8))
            elif len(key) in (16, 24):
                if mode == "ECB": cipher = DES3.new(key, DES3.MODE_ECB)
                else:
                    iv = DecipherEngine._parse_iv(iv_str)
                    if not iv: iv, ct = ct[:8], ct[8:]
                    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
                return f"[3DES {mode}]\n\n" + smart_decode_result(unpad(cipher.decrypt(ct), 8))
            return f"ERROR: DES key=8 bytes, 3DES=16/24 bytes. Got {len(key)}."
        except Exception as e: return f"DES Error: {e}"

    @staticmethod
    def rc4_decrypt(text, key_str):
        if not HAS_CRYPTO: return "ERROR: pip install pycryptodome"
        try: return smart_decode_result(ARC4.new(DecipherEngine._parse_key(key_str)).decrypt(try_binary_input(text)))
        except Exception as e: return f"RC4 Error: {e}"

    @staticmethod
    def blowfish_decrypt(text, key_str, iv_str="", mode="CBC"):
        if not HAS_CRYPTO: return "ERROR: pip install pycryptodome"
        ct = try_binary_input(text); key = DecipherEngine._parse_key(key_str)
        try:
            if mode == "ECB": cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            else:
                iv = DecipherEngine._parse_iv(iv_str)
                if not iv: iv, ct = ct[:8], ct[8:]
                cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
            return smart_decode_result(unpad(cipher.decrypt(ct), Blowfish.block_size))
        except Exception as e: return f"Blowfish Error: {e}"

    @staticmethod
    def chacha20_decrypt(text, key_str, iv_str=""):
        if not HAS_CRYPTO: return "ERROR: pip install pycryptodome"
        ct = try_binary_input(text); key = DecipherEngine._parse_key(key_str)
        if len(key) != 32: return f"ERROR: ChaCha20 key=32 bytes. Got {len(key)}."
        try:
            nonce = DecipherEngine._parse_iv(iv_str)
            if not nonce:
                if len(ct) > 12: nonce, ct = ct[:12], ct[12:]
                else: return "ERROR: ChaCha20 requires nonce."
            return smart_decode_result(ChaCha20.new(key=key, nonce=nonce).decrypt(ct))
        except Exception as e: return f"ChaCha20 Error: {e}"

    @staticmethod
    def fernet_decrypt(text, key_str):
        if not HAS_FERNET: return "ERROR: pip install cryptography"
        try:
            key = key_str.strip().encode('utf-8')
            return smart_decode_result(Fernet(key).decrypt(text.strip().encode('utf-8')))
        except Exception as e: return f"Fernet Error: {e}"

    # ── ANALYSIS ──

    @staticmethod
    def identify_hash(text):
        text = text.strip(); results = []
        for pat, names in [
            (r'^[a-fA-F0-9]{32}$', ["MD5","NTLM","MD4"]),
            (r'^[a-fA-F0-9]{40}$', ["SHA-1","RIPEMD-160"]),
            (r'^[a-fA-F0-9]{56}$', ["SHA-224","SHA3-224"]),
            (r'^[a-fA-F0-9]{64}$', ["SHA-256","SHA3-256","BLAKE2s"]),
            (r'^[a-fA-F0-9]{96}$', ["SHA-384","SHA3-384"]),
            (r'^[a-fA-F0-9]{128}$', ["SHA-512","SHA3-512","BLAKE2b","Whirlpool"]),
            (r'^\$2[aby]?\$\d{2}\$.{53}$', ["bcrypt"]),
            (r'^\$6\$', ["SHA-512 Crypt"]), (r'^\$5\$', ["SHA-256 Crypt"]),
            (r'^\$1\$', ["MD5 Crypt"]), (r'^\$argon2', ["Argon2"]),
        ]:
            if re.match(pat, text): results.extend(names)
        if not results: return f"Unknown hash format (length: {len(text)})"
        lines = ["── POSSIBLE HASH TYPES ──\n"]
        for n in results: lines.append(f"  ◆ {n}")
        lines.append(f"\n  Length: {len(text)} characters")
        return '\n'.join(lines)

    @staticmethod
    def hash_generate(text):
        raw = text.encode('utf-8')
        lines = ["── HASH GENERATION ──\n"]
        for name, h in [
            ("MD5", hashlib.md5(raw).hexdigest()), ("SHA-1", hashlib.sha1(raw).hexdigest()),
            ("SHA-256", hashlib.sha256(raw).hexdigest()), ("SHA-512", hashlib.sha512(raw).hexdigest()),
            ("SHA3-256", hashlib.sha3_256(raw).hexdigest()), ("SHA3-512", hashlib.sha3_512(raw).hexdigest()),
            ("BLAKE2b", hashlib.blake2b(raw).hexdigest()), ("BLAKE2s", hashlib.blake2s(raw).hexdigest()),
        ]:
            lines.append(f"  {name:<10} │ {h}")
        try: lines.append(f"  {'NTLM':<10} │ {hashlib.new('md4', text.encode('utf-16le')).hexdigest()}")
        except: pass
        return '\n'.join(lines)

    @staticmethod
    def freq_analysis(text):
        alpha = [c.upper() for c in text if c.isalpha()]
        if not alpha: return "No alphabetic characters."
        freq = Counter(alpha); total = len(alpha)
        lines = ["── FREQUENCY ANALYSIS ──\n", "Char │ Count │  Freq  │ Bar", "─────┼───────┼────────┼" + "─" * 30]
        for ch, cnt in freq.most_common():
            pct = cnt / total * 100
            lines.append(f"  {ch}  │  {cnt:4d} │ {pct:5.1f}% │ {'█' * int(pct)}")
        return '\n'.join(lines)

    @staticmethod
    def entropy_analysis(text):
        raw = text.encode('utf-8')
        ent = shannon_entropy(raw)
        return '\n'.join([
            "── ENTROPY ANALYSIS ──\n",
            f"  Input    : {len(raw)} bytes", f"  Unique   : {len(set(raw))} / 256",
            f"  Entropy  : {ent:.4f} bits/byte", f"  Random   : {ent/8*100:.1f}%",
            f"  Verdict  : {entropy_verdict(ent)}"
        ])

    @staticmethod
    def hex_dump_mode(text):
        return f"── HEX DUMP ({len(text.encode('utf-8'))} bytes) ──\n\n{hex_dump(text.encode('utf-8'), max_lines=128)}"

    @staticmethod
    def strings_extract(text):
        strings = extract_strings(text.encode('latin-1', errors='replace'), min_length=4)
        if not strings: return "No printable strings found."
        lines = [f"── EXTRACTED STRINGS ({len(strings)}) ──\n"]
        for i, s in enumerate(strings[:100], 1): lines.append(f'  {i:4d} │ "{s}"')
        return '\n'.join(lines)

    @staticmethod
    def magic_identify(text):
        raw = try_binary_input(text); ft = identify_magic(raw); ent = shannon_entropy(raw)
        lines = ["── FILE IDENTIFICATION ──\n", f"  Size    : {len(raw)} bytes",
                 f"  Type    : {ft or 'Unknown'}", f"  Entropy : {ent:.4f} ({entropy_verdict(ent)})",
                 "\n── HEADER ──\n", hex_dump(raw[:64], max_lines=4)]
        strings = extract_strings(raw, 4)
        if strings:
            lines.append(f"\n── STRINGS ({len(strings)}) ──")
            for s in strings[:15]: lines.append(f'  "{s}"')
        return '\n'.join(lines)

    @staticmethod
    def pickle_inspect(text):
        raw = try_binary_input(text); ft = identify_magic(raw)
        lines = ["── PICKLE ANALYSIS ──\n", f"  Type: {ft or 'Unknown'}", f"  Size: {len(raw)} bytes"]
        strings = extract_strings(raw, 3)
        if strings:
            danger = ['eval','exec','import','os.','system','subprocess','open(','__','builtins','popen','shell','/bin/','cmd']
            lines.append("\n── STRINGS ──\n")
            for s in strings:
                sus = " ⚠ DANGEROUS" if any(k in s.lower() for k in danger) else ""
                lines.append(f'  "{s}"{sus}')
        lines.append(f"\n── OPCODES ──\n{safe_pickle_dis(raw)}")
        return '\n'.join(lines)

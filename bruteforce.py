# decipher/bruteforce.py — ULTRA Brute Force Engine

import base64
import codecs
import hashlib
import re
import string
import threading
import time
from typing import Callable, List, Tuple, Optional
from collections import Counter

from utils import (
    english_score, printable_ratio, smart_decode_result, identify_magic,
    try_binary_input, COMMON_PASSWORDS, COMMON_IVS, derive_keys_from_password,
    extract_strings
)

# Optional crypto imports
try:
    from Crypto.Cipher import AES, DES, DES3, ARC4, Blowfish, ChaCha20
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# Type alias for results: (method_name, decoded_text, confidence, details)
BruteResult = Tuple[str, str, float, str]


class UltraBrute:
    """Threaded brute-force engine that tries everything to decode/decrypt input."""

    def __init__(self):
        self._stop = False
        self._results: List[BruteResult] = []
        self._lock = threading.Lock()

    def stop(self):
        self._stop = True

    def _add_result(self, method: str, text: str, confidence: float, details: str = ""):
        with self._lock:
            self._results.append((method, text, confidence, details))

    def run(self, text: str,
            progress_cb: Optional[Callable[[int, int, str], None]] = None,
            done_cb: Optional[Callable[[List[BruteResult]], None]] = None):
        """Run the full brute force pipeline in a background thread."""
        self._stop = False
        self._results = []

        def worker():
            steps = [
                ("Encodings",            self._try_encodings),
                ("Classic Ciphers",      self._try_classic_ciphers),
                ("XOR Multi-byte",       self._try_xor_multibyte),
                ("Vigenère Auto-crack",  self._try_vigenere_autocrack),
                ("Multi-layer Chain",    self._try_multilayer),
            ]
            # Add crypto dictionary attack if available
            if HAS_CRYPTO:
                steps.append(("Dictionary Attack (AES)", self._try_dict_aes))
                steps.append(("Dictionary Attack (DES)", self._try_dict_des))
                steps.append(("Dictionary Attack (RC4)", self._try_dict_rc4))

            total = len(steps)
            for i, (name, func) in enumerate(steps):
                if self._stop:
                    break
                if progress_cb:
                    progress_cb(i, total, name)
                try:
                    func(text)
                except Exception:
                    pass

            if progress_cb:
                progress_cb(total, total, "Done")

            # Sort by confidence
            with self._lock:
                self._results.sort(key=lambda x: x[2], reverse=True)

            if done_cb:
                done_cb(self._results)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return t

    # ── ENCODING DETECTION ──

    def _try_encodings(self, text: str):
        stripped = text.strip()

        # Base64
        if re.match(r'^[A-Za-z0-9+/\n\r]+=*$', stripped) and len(stripped) >= 4:
            try:
                raw = base64.b64decode(stripped)
                decoded = raw.decode('utf-8', errors='replace')
                pr = printable_ratio(decoded)
                if pr > 0.8:
                    es = english_score(decoded)
                    self._add_result("Base64", decoded, 0.5 + es * 0.5,
                                     f"printable={pr:.0%} english={es:.0%}")
                else:
                    ft = identify_magic(raw)
                    if ft:
                        self._add_result(f"Base64 → {ft}",
                                         smart_decode_result(raw), 0.90,
                                         f"Binary: {ft}")
            except Exception:
                pass

        # Hex
        cleaned = re.sub(r'[\s:x\\]', '', stripped)
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if re.match(r'^[a-fA-F0-9]+$', cleaned) and len(cleaned) >= 4 and len(cleaned) % 2 == 0:
            # Check hash first
            known_hash_lengths = {16, 32, 40, 56, 64, 96, 128}
            if len(cleaned) in known_hash_lengths:
                self._add_result("Hash ID", f"Possible hash ({len(cleaned)} chars hex)", 0.95,
                                 f"length={len(cleaned)}")
            try:
                raw = bytes.fromhex(cleaned)
                decoded = raw.decode('utf-8', errors='replace')
                pr = printable_ratio(decoded)
                if pr > 0.7:
                    es = english_score(decoded)
                    self._add_result("Hex", decoded, 0.4 + es * 0.5,
                                     f"printable={pr:.0%} english={es:.0%}")
            except Exception:
                pass

        # URL
        if '%' in stripped and re.search(r'%[0-9a-fA-F]{2}', stripped):
            try:
                from urllib.parse import unquote
                r = unquote(stripped)
                if r != stripped:
                    self._add_result("URL Decode", r, 0.90)
            except Exception:
                pass

        # HTML
        if re.search(r'&[#\w]+;', stripped):
            try:
                import html
                r = html.unescape(stripped)
                if r != stripped:
                    self._add_result("HTML Decode", r, 0.90)
            except Exception:
                pass

        # Binary
        if re.match(r'^[01\s]+$', stripped) and len(stripped.replace(' ', '')) >= 8:
            try:
                chunks = stripped.split()
                if not chunks or len(chunks) == 1:
                    c = stripped.replace(' ', '')
                    chunks = [c[i:i+8] for i in range(0, len(c), 8)]
                r = ''.join(chr(int(b, 2)) for b in chunks if len(b) == 8)
                if r and printable_ratio(r) > 0.8:
                    self._add_result("Binary", r, 0.85)
            except Exception:
                pass

        # Morse
        if re.match(r'^[\.\-\s/]+$', stripped) and len(stripped) >= 3:
            from engine import DecipherEngine
            try:
                r = DecipherEngine.morse_decode(stripped)
                if r and '?' not in r[:5]:
                    self._add_result("Morse Code", r, 0.90)
            except Exception:
                pass

        # Base32
        if re.match(r'^[A-Z2-7\s]+=*$', stripped.upper()) and len(stripped) >= 8:
            try:
                padded = stripped.strip().upper()
                pad_len = (8 - len(padded) % 8) % 8
                raw = base64.b32decode(padded + "=" * pad_len)
                decoded = raw.decode('utf-8', errors='replace')
                pr = printable_ratio(decoded)
                if pr > 0.8:
                    self._add_result("Base32", decoded, 0.75 * pr)
            except Exception:
                pass

        # Unicode escape
        if re.search(r'\\u[0-9a-fA-F]{4}', stripped):
            try:
                r = stripped.encode('ascii', errors='replace').decode('unicode_escape', errors='replace')
                if r != stripped:
                    self._add_result("Unicode Escape", r, 0.90)
            except Exception:
                pass

        # JWT
        if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', stripped):
            from engine import DecipherEngine
            try:
                r = DecipherEngine.jwt_decode(stripped)
                self._add_result("JWT Decode", r, 0.95)
            except Exception:
                pass

    # ── CLASSIC CIPHERS ──

    def _try_classic_ciphers(self, text: str):
        stripped = text.strip()
        if not stripped.isascii() or not any(c.isalpha() for c in stripped):
            return

        # Caesar brute (all 25 shifts, score each)
        best_shift = 0
        best_score = 0.0
        best_text = ""
        for shift in range(1, 26):
            result = []
            for c in stripped:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    result.append(chr((ord(c) - base - shift) % 26 + base))
                else:
                    result.append(c)
            decoded = ''.join(result)
            es = english_score(decoded)
            if es > best_score:
                best_score = es
                best_shift = shift
                best_text = decoded

        if best_score > 0.3:
            self._add_result(f"Caesar ROT-{best_shift}", best_text, best_score,
                             f"Best shift={best_shift} english={best_score:.0%}")

        # ROT13
        r13 = codecs.decode(stripped, 'rot_13')
        es13 = english_score(r13)
        if es13 > 0.3:
            self._add_result("ROT13", r13, es13, f"english={es13:.0%}")

        # ROT47
        r47 = ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in stripped)
        es47 = english_score(r47)
        if es47 > 0.3:
            self._add_result("ROT47", r47, es47, f"english={es47:.0%}")

        # Atbash
        atb = []
        for c in stripped:
            if c.isalpha():
                if c.isupper():
                    atb.append(chr(ord('Z') - (ord(c) - ord('A'))))
                else:
                    atb.append(chr(ord('z') - (ord(c) - ord('a'))))
            else:
                atb.append(c)
        atb_text = ''.join(atb)
        es_atb = english_score(atb_text)
        if es_atb > 0.3:
            self._add_result("Atbash", atb_text, es_atb, f"english={es_atb:.0%}")

        # Reverse
        rev = stripped[::-1]
        es_rev = english_score(rev)
        if es_rev > 0.3:
            self._add_result("Reverse", rev, es_rev, f"english={es_rev:.0%}")

    # ── XOR MULTI-BYTE BRUTE ──

    def _try_xor_multibyte(self, text: str):
        try:
            data = bytes.fromhex(re.sub(r'\s', '', text.strip()))
        except ValueError:
            data = text.encode('utf-8')

        if len(data) < 4:
            return

        # Single-byte XOR (fast)
        for key in range(1, 256):
            if self._stop:
                return
            decoded = bytes(b ^ key for b in data)
            try:
                text_decoded = decoded.decode('utf-8', errors='replace')
                pr = printable_ratio(text_decoded)
                if pr > 0.85:
                    es = english_score(text_decoded)
                    if es > 0.25:
                        self._add_result(f"XOR 0x{key:02x}", text_decoded, es,
                                         f"single-byte key=0x{key:02x}")
            except Exception:
                pass

        # 2-byte XOR (slower, only if input looks like it could be XOR'd text)
        if len(data) <= 512:
            for k1 in range(256):
                if self._stop:
                    return
                for k2 in range(256):
                    key_bytes = bytes([k1, k2])
                    decoded = bytes(b ^ key_bytes[i % 2] for i, b in enumerate(data))
                    try:
                        text_decoded = decoded.decode('utf-8', errors='replace')
                        es = english_score(text_decoded)
                        if es > 0.5:  # Higher threshold for 2-byte
                            self._add_result(
                                f"XOR 0x{k1:02x}{k2:02x}", text_decoded, es,
                                f"2-byte key=0x{k1:02x}{k2:02x}")
                            return  # Found good match, stop 2-byte search
                    except Exception:
                        pass

    # ── VIGENÈRE AUTO-CRACK ──

    def _try_vigenere_autocrack(self, text: str):
        stripped = text.strip()
        alpha_only = [c for c in stripped if c.isalpha()]
        if len(alpha_only) < 20:
            return

        # Kasiski examination — find repeated trigrams
        text_upper = ''.join(c.upper() for c in stripped if c.isalpha())
        distances = []
        for i in range(len(text_upper) - 2):
            trigram = text_upper[i:i+3]
            for j in range(i + 3, len(text_upper) - 2):
                if text_upper[j:j+3] == trigram:
                    distances.append(j - i)

        if not distances:
            return

        # Find most common GCD of distances → likely key length
        from math import gcd
        from functools import reduce
        freq = Counter()
        for d in distances:
            for kl in range(2, min(d + 1, 21)):
                if d % kl == 0:
                    freq[kl] += 1

        if not freq:
            return

        # Try top 5 key lengths
        for key_len, _ in freq.most_common(5):
            if self._stop:
                return
            if key_len < 2 or key_len > 20:
                continue

            # Frequency analysis per column to recover key
            key = []
            for col in range(key_len):
                column_chars = [text_upper[i] for i in range(col, len(text_upper), key_len)]
                if not column_chars:
                    key.append(0)
                    continue
                # Try each shift, score by chi-squared against English frequency
                best_shift = 0
                best_chi = float('inf')
                col_freq = Counter(column_chars)
                col_total = len(column_chars)
                eng_freq_list = [
                    ('E', 12.7), ('T', 9.1), ('A', 8.2), ('O', 7.5), ('I', 7.0),
                    ('N', 6.7), ('S', 6.3), ('H', 6.1), ('R', 6.0), ('D', 4.3),
                    ('L', 4.0), ('C', 2.8), ('U', 2.8), ('M', 2.4), ('W', 2.4),
                    ('F', 2.2), ('G', 2.0), ('Y', 2.0), ('P', 1.9), ('B', 1.5),
                    ('V', 1.0), ('K', 0.8), ('J', 0.15), ('X', 0.15),
                    ('Q', 0.10), ('Z', 0.07),
                ]
                for shift in range(26):
                    chi = 0.0
                    for letter, expected_pct in eng_freq_list:
                        shifted_letter = chr((ord(letter) - ord('A') + shift) % 26 + ord('A'))
                        observed = col_freq.get(shifted_letter, 0) / col_total * 100
                        chi += (observed - expected_pct) ** 2 / max(expected_pct, 0.01)
                    if chi < best_chi:
                        best_chi = chi
                        best_shift = shift
                key.append(best_shift)

            # Decrypt with recovered key
            key_str = ''.join(chr(s + ord('A')) for s in key)
            result = []
            ki = 0
            for c in stripped:
                if c.isalpha():
                    shift = key[ki % len(key)]
                    base = ord('A') if c.isupper() else ord('a')
                    result.append(chr((ord(c) - base - shift) % 26 + base))
                    ki += 1
                else:
                    result.append(c)
            decoded = ''.join(result)
            es = english_score(decoded)
            if es > 0.3:
                self._add_result(f"Vigenère (key=\"{key_str}\")", decoded, es,
                                 f"key_len={key_len} recovered_key={key_str}")

    # ── MULTI-LAYER CHAIN ──

    def _try_multilayer(self, text: str):
        """Try chaining: decode once, if result looks encoded, decode again."""
        stripped = text.strip()

        # Base64 → Base64 (double encoding)
        if re.match(r'^[A-Za-z0-9+/\n\r]+=*$', stripped):
            try:
                layer1 = base64.b64decode(stripped).decode('utf-8', errors='replace')
                if re.match(r'^[A-Za-z0-9+/\n\r]+=*$', layer1.strip()):
                    layer2_raw = base64.b64decode(layer1.strip())
                    layer2 = layer2_raw.decode('utf-8', errors='replace')
                    pr = printable_ratio(layer2)
                    if pr > 0.8:
                        es = english_score(layer2)
                        self._add_result("Base64 → Base64", layer2, 0.6 + es * 0.4,
                                         "Double base64 encoding")
            except Exception:
                pass

        # Base64 → Hex
        try:
            layer1 = base64.b64decode(stripped).decode('utf-8', errors='replace').strip()
            if re.match(r'^[a-fA-F0-9]+$', layer1) and len(layer1) % 2 == 0:
                layer2 = bytes.fromhex(layer1).decode('utf-8', errors='replace')
                if printable_ratio(layer2) > 0.8:
                    es = english_score(layer2)
                    if es > 0.2:
                        self._add_result("Base64 → Hex", layer2, 0.5 + es * 0.4,
                                         "Base64 wrapping hex data")
        except Exception:
            pass

        # Hex → Base64
        cleaned = re.sub(r'[\s:]', '', stripped)
        if re.match(r'^[a-fA-F0-9]+$', cleaned) and len(cleaned) % 2 == 0:
            try:
                raw = bytes.fromhex(cleaned)
                layer1 = raw.decode('utf-8', errors='replace').strip()
                if re.match(r'^[A-Za-z0-9+/]+=*$', layer1):
                    layer2 = base64.b64decode(layer1).decode('utf-8', errors='replace')
                    if printable_ratio(layer2) > 0.8:
                        es = english_score(layer2)
                        if es > 0.2:
                            self._add_result("Hex → Base64", layer2, 0.5 + es * 0.4,
                                             "Hex wrapping base64 data")
            except Exception:
                pass

        # Base64 → ROT13
        try:
            layer1 = base64.b64decode(stripped).decode('utf-8', errors='replace')
            layer2 = codecs.decode(layer1, 'rot_13')
            es = english_score(layer2)
            if es > 0.4:
                self._add_result("Base64 → ROT13", layer2, es, "Base64 wrapping ROT13")
        except Exception:
            pass

    # ── DICTIONARY ATTACK — AES ──

    def _try_dict_aes(self, text: str):
        if not HAS_CRYPTO:
            return

        ciphertext = try_binary_input(text)
        if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
            # Not valid AES block size — try with IV prepended
            if len(ciphertext) < 32:
                return

        for password in COMMON_PASSWORDS:
            if self._stop:
                return
            keys = derive_keys_from_password(password)
            for key in keys:
                if len(key) not in (16, 24, 32):
                    continue

                # Try ECB
                try:
                    cipher = AES.new(key, AES.MODE_ECB)
                    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    decoded = pt.decode('utf-8', errors='replace')
                    es = english_score(decoded)
                    if es > 0.3:
                        self._add_result(
                            f"AES-ECB (pw=\"{password}\")", decoded, es,
                            f"key={key.hex()} mode=ECB")
                        return
                except Exception:
                    pass

                # Try CBC with common IVs
                for iv in COMMON_IVS:
                    if len(iv) != 16:
                        continue
                    try:
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
                        decoded = pt.decode('utf-8', errors='replace')
                        es = english_score(decoded)
                        if es > 0.3:
                            self._add_result(
                                f"AES-CBC (pw=\"{password}\")", decoded, es,
                                f"key={key.hex()} iv={iv.hex()} mode=CBC")
                            return
                    except Exception:
                        pass

                # Try CBC with IV prepended in ciphertext
                if len(ciphertext) >= 32:
                    try:
                        iv = ciphertext[:16]
                        ct = ciphertext[16:]
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        pt = unpad(cipher.decrypt(ct), AES.block_size)
                        decoded = pt.decode('utf-8', errors='replace')
                        es = english_score(decoded)
                        if es > 0.3:
                            self._add_result(
                                f"AES-CBC (pw=\"{password}\", IV prepended)", decoded, es,
                                f"key={key.hex()} iv=first_16_bytes mode=CBC")
                            return
                    except Exception:
                        pass

    # ── DICTIONARY ATTACK — DES ──

    def _try_dict_des(self, text: str):
        if not HAS_CRYPTO:
            return

        ciphertext = try_binary_input(text)
        if len(ciphertext) < 8 or len(ciphertext) % 8 != 0:
            return

        for password in COMMON_PASSWORDS[:30]:  # Limit for speed
            if self._stop:
                return
            keys = derive_keys_from_password(password)
            for key in keys:
                # DES (8 bytes)
                if len(key) == 8:
                    try:
                        cipher = DES.new(key, DES.MODE_ECB)
                        pt = unpad(cipher.decrypt(ciphertext), 8)
                        decoded = pt.decode('utf-8', errors='replace')
                        es = english_score(decoded)
                        if es > 0.3:
                            self._add_result(
                                f"DES-ECB (pw=\"{password}\")", decoded, es,
                                f"key={key.hex()}")
                            return
                    except Exception:
                        pass

                    # CBC with IV prepended
                    if len(ciphertext) >= 16:
                        try:
                            iv = ciphertext[:8]
                            ct = ciphertext[8:]
                            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
                            pt = unpad(cipher.decrypt(ct), 8)
                            decoded = pt.decode('utf-8', errors='replace')
                            es = english_score(decoded)
                            if es > 0.3:
                                self._add_result(
                                    f"DES-CBC (pw=\"{password}\")", decoded, es,
                                    f"key={key.hex()} iv=prepended")
                                return
                        except Exception:
                            pass

                # 3DES (16 or 24 bytes)
                if len(key) in (16, 24):
                    try:
                        cipher = DES3.new(key, DES3.MODE_ECB)
                        pt = unpad(cipher.decrypt(ciphertext), 8)
                        decoded = pt.decode('utf-8', errors='replace')
                        es = english_score(decoded)
                        if es > 0.3:
                            self._add_result(
                                f"3DES-ECB (pw=\"{password}\")", decoded, es,
                                f"key={key.hex()}")
                            return
                    except Exception:
                        pass

    # ── DICTIONARY ATTACK — RC4 ──

    def _try_dict_rc4(self, text: str):
        if not HAS_CRYPTO:
            return

        ciphertext = try_binary_input(text)
        if len(ciphertext) < 4:
            return

        for password in COMMON_PASSWORDS:
            if self._stop:
                return
            keys = derive_keys_from_password(password)
            for key in keys:
                if len(key) < 1 or len(key) > 256:
                    continue
                try:
                    cipher = ARC4.new(key)
                    pt = cipher.decrypt(ciphertext)
                    decoded = pt.decode('utf-8', errors='replace')
                    es = english_score(decoded)
                    if es > 0.35:
                        self._add_result(
                            f"RC4 (pw=\"{password}\")", decoded, es,
                            f"key={key.hex()}")
                        return
                except Exception:
                    pass

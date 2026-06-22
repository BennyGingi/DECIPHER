# decipher/gui.py — CustomTkinter GUI with ULTRA brute force mode

import customtkinter as ctk
from theme import *
from engine import DecipherEngine
from bruteforce import UltraBrute
from typing import List, Tuple


class DecipherApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DECIPHER")
        self.geometry("1280x900")
        self.minsize(1050, 750)
        self.configure(fg_color=BG_DARK)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.engine = DecipherEngine()
        self.brute = UltraBrute()
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
        topbar.pack(fill="x"); topbar.pack_propagate(False)
        logo = ctk.CTkFrame(topbar, fg_color="transparent")
        logo.pack(side="left", padx=20, pady=10)
        ctk.CTkLabel(logo, text="◈", font=("JetBrains Mono", 28), text_color=ACCENT_CYAN).pack(side="left", padx=(0,10))
        ctk.CTkLabel(logo, text="DECIPHER", font=FONT_TITLE, text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(logo, text="v4.0", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left", padx=(8,0), pady=(8,0))
        sf = ctk.CTkFrame(topbar, fg_color="transparent")
        sf.pack(side="right", padx=20, pady=10)
        self.status_label = ctk.CTkLabel(sf, text="● READY", font=FONT_SMALL, text_color=ACCENT_GREEN)
        self.status_label.pack(side="right")
        ctk.CTkFrame(self, fg_color=ACCENT_CYAN, height=1, corner_radius=0).pack(fill="x")

    def _build_sidebar(self, parent):
        sb = ctk.CTkScrollableFrame(parent, fg_color=BG_PANEL, corner_radius=12, width=240,
                                     border_width=1, border_color=BORDER_DIM)
        sb.grid(row=0, column=0, sticky="nsew", padx=(0,10))

        ctk.CTkLabel(sb, text="─── MODE ───", font=FONT_LABEL, text_color=TEXT_DIM).pack(pady=(10,6))
        self.mode_var = ctk.StringVar(value="ultra")

        for label, val, color in [
            ("⚡ ULTRA BRUTE", "ultra", ACCENT_RED),
            ("◈  AUTO DETECT", "auto", ACCENT_CYAN),
            ("⇄  ENCODE", "encode", ACCENT_PURPLE),
        ]:
            ctk.CTkRadioButton(sb, text=label, variable=self.mode_var, value=val,
                               font=FONT_LABEL, text_color=TEXT_PRIMARY, fg_color=color,
                               hover_color=color, border_color=TEXT_DIM,
                               command=self._on_mode_change).pack(anchor="w", padx=12, pady=3)

        ctk.CTkFrame(sb, fg_color=BORDER_DIM, height=1).pack(fill="x", padx=10, pady=10)

        categories = {
            "ENCODINGS": [
                ("Base64","base64"),("Base64URL","base64url"),("Base32","base32"),
                ("Base58","base58"),("Base85","base85"),("Hex","hex"),("URL","url"),
                ("HTML","html"),("Binary","binary"),("Octal","octal"),("Decimal","decimal"),
                ("Morse","morse"),("Punycode","punycode"),("QP","qp"),
                ("Unicode Esc","unicode"),("UUencode","uuencode"),("JWT","jwt"),
            ],
            "CIPHERS": [
                ("Caesar Brute","caesar_brute"),("ROT13","rot13"),("ROT47","rot47"),
                ("Atbash","atbash"),("Vigenère","vigenere"),("Rail Fence","railfence"),
                ("XOR Brute","xor_brute"),("XOR (key)","xor"),
                ("Reverse","reverse"),("Reverse Words","reverse_words"),
            ],
            "ENCRYPTION": [
                ("AES","aes"),("DES / 3DES","des"),("RC4","rc4"),
                ("Blowfish","blowfish"),("ChaCha20","chacha20"),("Fernet","fernet"),
            ],
            "COMPRESSION": [("Gzip","gzip"),("Zlib","zlib"),("Bzip2","bzip2")],
            "BINARY ANALYSIS": [
                ("File Type ID","magic_id"),("Pickle Inspect","pickle"),
                ("Hex Dump","hexdump"),("Strings","strings"),("Entropy","entropy"),
            ],
            "ANALYSIS": [
                ("Hash Identify","hash_id"),("Hash Generate","hash_gen"),("Freq Analysis","freq"),
            ],
        }

        for cat, items in categories.items():
            ctk.CTkLabel(sb, text=f"─── {cat} ───", font=FONT_LABEL, text_color=TEXT_DIM).pack(pady=(8,4))
            for label, val in items:
                ctk.CTkRadioButton(sb, text=label, variable=self.mode_var, value=val,
                                   font=FONT_SMALL, text_color=TEXT_SECONDARY,
                                   fg_color=ACCENT_CYAN, hover_color=ACCENT_CYAN,
                                   border_color=TEXT_DIM,
                                   command=self._on_mode_change).pack(anchor="w", padx=16, pady=2)

    def _build_content(self, parent):
        c = ctk.CTkFrame(parent, fg_color="transparent")
        c.grid(row=0, column=1, sticky="nsew")
        c.grid_columnconfigure(0, weight=1)
        c.grid_rowconfigure(1, weight=1)
        c.grid_rowconfigure(4, weight=1)

        # Input header
        ih = ctk.CTkFrame(c, fg_color="transparent")
        ih.grid(row=0, column=0, sticky="ew", pady=(0,4))
        ctk.CTkLabel(ih, text="INPUT", font=FONT_HEADING, text_color=ACCENT_CYAN).pack(side="left")
        self.input_count = ctk.CTkLabel(ih, text="0 chars", font=FONT_SMALL, text_color=TEXT_DIM)
        self.input_count.pack(side="right")
        ctk.CTkButton(ih, text="PASTE", font=FONT_SMALL, width=60, height=24, fg_color=BG_CARD,
                      hover_color=BORDER_DIM, text_color=TEXT_SECONDARY, border_width=1,
                      border_color=BORDER_DIM, command=self._paste).pack(side="right", padx=8)
        ctk.CTkButton(ih, text="CLEAR", font=FONT_SMALL, width=60, height=24, fg_color=BG_CARD,
                      hover_color=BORDER_DIM, text_color=TEXT_SECONDARY, border_width=1,
                      border_color=BORDER_DIM, command=self._clear).pack(side="right", padx=(0,4))

        self.input_box = ctk.CTkTextbox(c, font=FONT_MONO, fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
                                         corner_radius=10, border_width=1, border_color=BORDER_DIM, wrap="word")
        self.input_box.grid(row=1, column=0, sticky="nsew", pady=(0,8))
        self.input_box.bind("<KeyRelease>", lambda e: self.input_count.configure(
            text=f"{len(self.input_box.get('1.0','end-1c'))} chars"))

        # Action bar
        ab = ctk.CTkFrame(c, fg_color="transparent", height=50)
        ab.grid(row=2, column=0, sticky="ew", pady=4)

        self.key_frame = ctk.CTkFrame(ab, fg_color="transparent")
        ctk.CTkLabel(self.key_frame, text="KEY:", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left", padx=(0,6))
        self.key_entry = ctk.CTkEntry(self.key_frame, font=FONT_MONO_SM, width=160, height=36,
                                       fg_color=BG_INPUT, text_color=ACCENT_YELLOW,
                                       border_color=BORDER_DIM, border_width=1, placeholder_text="key...")
        self.key_entry.pack(side="left")

        self.iv_frame = ctk.CTkFrame(ab, fg_color="transparent")
        ctk.CTkLabel(self.iv_frame, text="IV:", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left", padx=(10,6))
        self.iv_entry = ctk.CTkEntry(self.iv_frame, font=FONT_MONO_SM, width=200, height=36,
                                      fg_color=BG_INPUT, text_color=ACCENT_ORANGE,
                                      border_color=BORDER_DIM, border_width=1, placeholder_text="IV/nonce hex...")
        self.iv_entry.pack(side="left")

        self.mode_frame = ctk.CTkFrame(ab, fg_color="transparent")
        ctk.CTkLabel(self.mode_frame, text="MODE:", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left", padx=(10,6))
        self.cipher_mode_var = ctk.StringVar(value="CBC")
        self.cipher_mode_menu = ctk.CTkOptionMenu(self.mode_frame, variable=self.cipher_mode_var,
            values=["ECB","CBC","CTR","GCM"], font=FONT_SMALL, width=80, height=36,
            fg_color=BG_INPUT, button_color=ACCENT_PURPLE, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TEXT_PRIMARY)
        self.cipher_mode_menu.pack(side="left")

        self.rails_frame = ctk.CTkFrame(ab, fg_color="transparent")
        ctk.CTkLabel(self.rails_frame, text="RAILS:", font=FONT_SMALL, text_color=TEXT_DIM).pack(side="left", padx=(10,6))
        self.rails_entry = ctk.CTkEntry(self.rails_frame, font=FONT_MONO_SM, width=60, height=36,
                                         fg_color=BG_INPUT, text_color=ACCENT_YELLOW,
                                         border_color=BORDER_DIM, border_width=1, placeholder_text="3")
        self.rails_entry.pack(side="left")

        self.run_btn = ctk.CTkButton(ab, text="⚡ ULTRA BRUTE", font=FONT_HEADING, width=200, height=42,
                                      fg_color=ACCENT_RED, hover_color="#cc2952", text_color="#ffffff",
                                      corner_radius=8, command=self._run)
        self.run_btn.pack(side="right")

        ctk.CTkButton(ab, text="⇅", font=("JetBrains Mono", 18), width=42, height=42,
                      fg_color=BG_CARD, hover_color=BORDER_DIM, text_color=ACCENT_PURPLE,
                      border_width=1, border_color=BORDER_DIM, corner_radius=8,
                      command=self._swap).pack(side="right", padx=8)

        # Progress bar
        self.progress_frame = ctk.CTkFrame(c, fg_color="transparent", height=30)
        self.progress_frame.grid(row=3, column=0, sticky="ew", pady=(0,4))
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, fg_color=BG_CARD,
                                                progress_color=ACCENT_CYAN, height=8, corner_radius=4)
        self.progress_bar.pack(fill="x", side="left", expand=True, padx=(0,10))
        self.progress_bar.set(0)
        self.progress_label = ctk.CTkLabel(self.progress_frame, text="", font=FONT_SMALL, text_color=TEXT_DIM)
        self.progress_label.pack(side="right")
        self.progress_frame.grid_remove()  # hidden by default

        # Output header
        oh = ctk.CTkFrame(c, fg_color="transparent")
        oh.grid(row=4, column=0, sticky="new", pady=(4,4))
        ctk.CTkLabel(oh, text="OUTPUT", font=FONT_HEADING, text_color=ACCENT_GREEN).pack(side="left")
        self.output_count = ctk.CTkLabel(oh, text="0 chars", font=FONT_SMALL, text_color=TEXT_DIM)
        self.output_count.pack(side="right")
        ctk.CTkButton(oh, text="COPY", font=FONT_SMALL, width=60, height=24, fg_color=BG_CARD,
                      hover_color=BORDER_DIM, text_color=TEXT_SECONDARY, border_width=1,
                      border_color=BORDER_DIM, command=self._copy).pack(side="right", padx=8)
        self.method_label = ctk.CTkLabel(oh, text="", font=FONT_SMALL, text_color=ACCENT_PURPLE)
        self.method_label.pack(side="right", padx=8)

        self.output_box = ctk.CTkTextbox(c, font=FONT_MONO, fg_color=BG_INPUT, text_color=ACCENT_GREEN,
                                          corner_radius=10, border_width=1, border_color=BORDER_DIM,
                                          wrap="word", state="disabled")
        self.output_box.grid(row=5, column=0, sticky="nsew")
        c.grid_rowconfigure(5, weight=1)

        self._on_mode_change()

    # ── MODE CHANGE ──

    def _on_mode_change(self):
        m = self.mode_var.get()
        crypto_modes = {"aes","des","blowfish"}
        crypto_iv = {"aes","des","blowfish","chacha20"}
        crypto_key = crypto_modes | crypto_iv | {"rc4","fernet"}
        classic_key = {"vigenere","xor"}

        for f in (self.key_frame, self.iv_frame, self.mode_frame, self.rails_frame):
            f.pack_forget()

        if m in (crypto_key | classic_key):
            self.key_frame.pack(side="left")
            if m == "xor": self.key_entry.configure(placeholder_text="hex key")
            elif m == "fernet": self.key_entry.configure(placeholder_text="fernet base64 key")
            elif m in crypto_key: self.key_entry.configure(placeholder_text="hex key")
            else: self.key_entry.configure(placeholder_text="key...")
        if m in crypto_iv: self.iv_frame.pack(side="left")
        if m in crypto_modes: self.mode_frame.pack(side="left")
        if m == "railfence": self.rails_frame.pack(side="left")

        if m == "ultra":
            self.run_btn.configure(text="⚡ ULTRA BRUTE", fg_color=ACCENT_RED, hover_color="#cc2952")
        elif m == "auto":
            self.run_btn.configure(text="▶  AUTO DETECT", fg_color=ACCENT_CYAN, hover_color="#00b8cc")
        elif m == "encode":
            self.run_btn.configure(text="▶  ENCODE", fg_color=ACCENT_PURPLE, hover_color="#9933dd")
        elif m in crypto_key:
            self.run_btn.configure(text="▶  DECRYPT", fg_color=ACCENT_ORANGE, hover_color="#cc7000")
        else:
            self.run_btn.configure(text="▶  DECIPHER", fg_color=ACCENT_CYAN, hover_color="#00b8cc")

    # ── RUN ──

    def _run(self):
        text = self.input_box.get("1.0", "end-1c")
        if not text.strip():
            self._status("● NO INPUT", ACCENT_RED); return
        mode = self.mode_var.get()

        if mode == "ultra":
            self._run_ultra(text)
        elif mode == "auto":
            self._run_auto(text)
        elif mode == "encode":
            self._run_encode(text)
        else:
            self._run_specific(mode, text)

    def _run_ultra(self, text: str):
        """Launch threaded ULTRA brute force."""
        self.brute.stop()
        self.brute = UltraBrute()
        self._status("⚡ BRUTE FORCING...", ACCENT_RED)
        self.progress_frame.grid()
        self.progress_bar.set(0)
        self.progress_label.configure(text="Starting...")
        self.run_btn.configure(state="disabled")

        def on_progress(current, total, desc):
            self.after(0, lambda: self._update_progress(current, total, desc))

        def on_done(results):
            self.after(0, lambda: self._show_ultra_results(results))

        self.brute.run(text, progress_cb=on_progress, done_cb=on_done)

    def _update_progress(self, current, total, desc):
        if total > 0:
            self.progress_bar.set(current / total)
        self.progress_label.configure(text=f"{desc} ({current}/{total})")

    def _show_ultra_results(self, results):
        self.run_btn.configure(state="normal")
        self.progress_frame.grid_remove()

        if not results:
            self._set_output("No results found. The input may be encrypted with an unknown key.")
            self._status("● NO RESULTS", ACCENT_ORANGE)
            return

        lines = [f"⚡ ULTRA BRUTE FORCE — {len(results)} result(s) found\n"]
        lines.append("=" * 60 + "\n")

        for i, (method, decoded, confidence, details) in enumerate(results[:20], 1):
            # Confidence bar
            bar_len = int(confidence * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)

            lines.append(f"#{i}  [{bar}] {confidence:.0%}")
            lines.append(f"    Method:  {method}")
            if details:
                lines.append(f"    Details: {details}")
            # Truncate very long results
            preview = decoded[:300]
            if len(decoded) > 300:
                preview += "..."
            lines.append(f"    Result:  {preview}")
            lines.append("")

        output = '\n'.join(lines)
        self._set_output(output)
        best = results[0]
        self.method_label.configure(text=f"⟨ {best[0]} — {best[2]:.0%} ⟩")
        self._status(f"⚡ {len(results)} RESULTS", ACCENT_GREEN)

    def _run_auto(self, text: str):
        """Lightweight auto-detect (no dictionary attacks)."""
        self._status("● DETECTING...", ACCENT_ORANGE)
        self.update_idletasks()

        # Run the lightweight auto-detect from bruteforce (encodings + ciphers only)
        from bruteforce import UltraBrute
        brute = UltraBrute()
        brute._try_encodings(text)
        brute._try_classic_ciphers(text)

        results = sorted(brute._results, key=lambda x: x[2], reverse=True)
        if results:
            best = results[0]
            lines = [f"▸ Best Match: {best[0]} (confidence: {best[2]:.0%})\n", best[1]]
            if len(results) > 1:
                lines.append("\n\n── OTHER MATCHES ──")
                for m, r, c, d in results[1:6]:
                    lines.append(f"\n▸ {m} ({c:.0%}): {r[:120]}...")
            self._set_output('\n'.join(lines))
            self.method_label.configure(text=f"⟨ {best[0]} ⟩")
        else:
            self._set_output("Could not auto-detect.")
        self._status("● DONE", ACCENT_GREEN)

    def _run_encode(self, text: str):
        e = self.engine
        lines = ["── ENCODE RESULTS ──\n"]
        for name, func in [
            ("Base64", e.base64_encode), ("Base64URL", e.base64url_encode),
            ("Base32", e.base32_encode), ("Base85", e.base85_encode),
            ("Hex", e.hex_encode), ("URL", e.url_encode), ("HTML", e.html_encode),
            ("Binary", e.binary_encode), ("Octal", e.octal_encode),
            ("Decimal", e.decimal_encode), ("Morse", e.morse_encode),
            ("ROT13", e.rot13), ("ROT47", e.rot47), ("Atbash", e.atbash),
            ("Reverse", e.reverse_text),
        ]:
            try: lines.append(f"▸ {name}:\n  {func(text)}\n")
            except Exception as ex: lines.append(f"▸ {name}: [error]\n")
        self._set_output('\n'.join(lines))
        self.method_label.configure(text="⟨ ENCODE ALL ⟩")
        self._status("● DONE", ACCENT_GREEN)

    def _run_specific(self, mode: str, text: str):
        self._status("● PROCESSING...", ACCENT_ORANGE)
        self.update_idletasks()
        key = self.key_entry.get().strip()
        iv = self.iv_entry.get().strip()
        cm = self.cipher_mode_var.get()
        rails = int(self.rails_entry.get().strip() or "3") if self.rails_entry.get().strip().isdigit() else 3
        e = self.engine

        dispatch = {
            "base64": lambda: e.base64_decode(text), "base64url": lambda: e.base64url_decode(text),
            "base32": lambda: e.base32_decode(text), "base58": lambda: e.base58_decode(text),
            "base85": lambda: e.base85_decode(text), "hex": lambda: e.hex_decode(text),
            "url": lambda: e.url_decode(text), "html": lambda: e.html_decode(text),
            "binary": lambda: e.binary_decode(text), "octal": lambda: e.octal_decode(text),
            "decimal": lambda: e.decimal_decode(text), "morse": lambda: e.morse_decode(text),
            "punycode": lambda: e.punycode_decode(text), "qp": lambda: e.quoted_printable_decode(text),
            "unicode": lambda: e.unicode_escape_decode(text), "uuencode": lambda: e.uuencode_decode(text),
            "jwt": lambda: e.jwt_decode(text),
            "caesar_brute": lambda: e.caesar_brute(text), "rot13": lambda: e.rot13(text),
            "rot47": lambda: e.rot47(text), "atbash": lambda: e.atbash(text),
            "vigenere": lambda: e.vigenere_decrypt(text, key or "KEY"),
            "railfence": lambda: e.rail_fence_decrypt(text, rails),
            "xor_brute": lambda: e.xor_brute(text), "xor": lambda: e.xor_decrypt(text, key or "FF"),
            "reverse": lambda: e.reverse_text(text), "reverse_words": lambda: e.reverse_words(text),
            "aes": lambda: e.aes_decrypt(text, key, iv, cm),
            "des": lambda: e.des_decrypt(text, key, iv, cm),
            "rc4": lambda: e.rc4_decrypt(text, key),
            "blowfish": lambda: e.blowfish_decrypt(text, key, iv, cm),
            "chacha20": lambda: e.chacha20_decrypt(text, key, iv),
            "fernet": lambda: e.fernet_decrypt(text, key),
            "gzip": lambda: e.gzip_decompress(text), "zlib": lambda: e.zlib_decompress(text),
            "bzip2": lambda: e.bzip2_decompress(text),
            "magic_id": lambda: e.magic_identify(text), "pickle": lambda: e.pickle_inspect(text),
            "hexdump": lambda: e.hex_dump_mode(text), "strings": lambda: e.strings_extract(text),
            "entropy": lambda: e.entropy_analysis(text),
            "hash_id": lambda: e.identify_hash(text), "hash_gen": lambda: e.hash_generate(text),
            "freq": lambda: e.freq_analysis(text),
        }
        try:
            result = dispatch.get(mode, lambda: f"Unknown: {mode}")()
            self._set_output(result)
            self.method_label.configure(text=f"⟨ {mode.upper()} ⟩")
            self._status("● DONE", ACCENT_GREEN)
        except Exception as ex:
            self._set_output(f"ERROR: {ex}")
            self._status("● ERROR", ACCENT_RED)

    # ── HELPERS ──

    def _set_output(self, text):
        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", text)
        self.output_box.configure(state="disabled")
        self.output_count.configure(text=f"{len(text)} chars")

    def _status(self, text, color):
        self.status_label.configure(text=text, text_color=color)

    def _paste(self):
        try:
            t = self.clipboard_get()
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", t)
        except: pass

    def _copy(self):
        self.output_box.configure(state="normal")
        t = self.output_box.get("1.0", "end-1c")
        self.output_box.configure(state="disabled")
        self.clipboard_clear(); self.clipboard_append(t)
        self._status("● COPIED", ACCENT_PURPLE)

    def _clear(self):
        self.input_box.delete("1.0", "end")
        self._set_output(""); self.method_label.configure(text="")
        self._status("● READY", ACCENT_GREEN)

    def _swap(self):
        self.output_box.configure(state="normal")
        o = self.output_box.get("1.0", "end-1c")
        i = self.input_box.get("1.0", "end-1c")
        self.output_box.configure(state="disabled")
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", o)
        self._set_output(i)
        self._status("● SWAPPED", ACCENT_PURPLE)

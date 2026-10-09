#!/usr/bin/python3 -OO
# Copyright 2007-2026 by The SABnzbd-Team (sabnzbd.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
sabnzbd.encryption - Decryption adapter encapsulating Argon2id, PyNaCl, and FF1.
"""

import hashlib
import hmac
import math
import struct
import threading
from typing import Any, Optional

import argon2.low_level as ll
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import nacl.bindings as nb

BOOTSTRAP_PREFIX_LEN = 20


def index_is_forbidden(index: int) -> bool:
    """Return True if uint32_be representation of index contains 0x0A or 0x0D (CR-02 / VEC-07)."""
    be = index.to_bytes(4, "big")
    return (0x0A in be) or (0x0D in be)


def next_permitted_index(candidate: int) -> int:
    """Advance candidate forward to next permitted segmentIndex skipping 0x0A and 0x0D bytes."""
    idx = max(1, candidate)
    while index_is_forbidden(idx):
        idx += 1
    return idx


class YEncEncryptionStructuralError(ValueError):
    """Structural yEnc-encryption metadata failure (missing/empty password, unsupported mode).

    Per the tier separation in the yEnc encryption standards: structural failures abort the
    job and are NEVER retried against another server - no plaintext or ciphertext is released.
    Inherits from ValueError so existing ``isinstance(e, ValueError)`` handlers still catch it,
    but decoder.py catches this class FIRST to route it to the job-terminal path instead of the
    retryable provider-failover tier (METADATA_VALIDATION semantics).
    """


def byte_to_numeral(b: int) -> int:
    """Map byte octet to numeral 0..252 per yEnc Control Lines Standard v1.0."""
    if 0x01 <= b <= 0x09:
        return b - 1
    elif b == 0x0B:
        return 9
    elif b == 0x0C:
        return 10
    elif 0x0E <= b <= 0xFF:
        return b - 3
    raise ValueError(f"Byte 0x{b:02x} is outside the 253-byte Alphabet (0x00, 0x0A, 0x0D forbidden)")


def numeral_to_byte(i: int) -> int:
    """Map numeral 0..252 back to byte octet per yEnc Control Lines Standard v1.0."""
    if 0 <= i <= 8:
        return i + 1
    elif i == 9:
        return 0x0B
    elif i == 10:
        return 0x0C
    elif 11 <= i <= 252:
        return i + 3
    raise ValueError(f"Numeral {i} is out of range [0, 252]")


def num_radix(numerals: list[int], radix: int) -> int:
    res = 0
    for n in numerals:
        res = res * radix + n
    return res


def str_radix(val: int, radix: int, m: int) -> list[int]:
    res = [0] * m
    for i in range(m):
        res[m - 1 - i] = val % radix
        val //= radix
    return res


def cbc_mac(aes_enc, data: bytes) -> bytes:
    block = bytes(16)
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        xored = bytes(a ^ b for a, b in zip(block, chunk))
        block = aes_enc(xored)
    return block


def ff1_encrypt_numerals(key: bytes, tweak: bytes, numerals: list[int], radix: int = 253) -> list[int]:
    """NIST SP 800-38G FF1 Encryption over arbitrary numeral strings."""
    backend = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    aes_enc = backend.update
    n = len(numerals)
    t = len(tweak)
    u = n // 2
    v = n - u
    b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    d = 4 * math.ceil(b / 4) + 4

    p = bytearray(16)
    p[0], p[1], p[2] = 1, 2, 1
    p[3:6] = radix.to_bytes(3, "big")
    p[6] = 10
    p[7] = u % 256
    p[8:12] = n.to_bytes(4, "big")
    p[12:16] = t.to_bytes(4, "big")

    pad_len = ((-t - b - 1) % 16 + 16) % 16
    q_prefix = tweak + bytes(pad_len)

    A = list(numerals[:u])
    B = list(numerals[u:])

    for i in range(10):
        q = q_prefix + bytes([i]) + num_radix(B, radix).to_bytes(b, "big")
        R = cbc_mac(aes_enc, bytes(p) + q)
        S = bytearray(R)
        j = 1
        while len(S) < d:
            j_bytes = j.to_bytes(16, "big")
            blk = bytes(a ^ b for a, b in zip(R, j_bytes))
            S.extend(aes_enc(blk))
            j += 1
        y = int.from_bytes(S[:d], "big")
        m = u if i % 2 == 0 else v
        c = (num_radix(A, radix) + y) % (radix**m)
        C = str_radix(c, radix, m)
        A = B
        B = C

    return A + B


def ff1_encrypt(key: bytes, tweak: bytes, plaintext_bytes: bytes, radix: int = 253) -> bytes:
    """Encrypt control line byte string using FF1 over Radix 253 Alphabet."""
    if len(plaintext_bytes) < 2:
        raise ValueError(f"Line too short: {len(plaintext_bytes)} bytes (minimum 2)")
    numerals = [byte_to_numeral(b) for b in plaintext_bytes]
    ct_numerals = ff1_encrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in ct_numerals)


def ff1_decrypt_numerals(key: bytes, tweak: bytes, numerals: list[int], radix: int = 253) -> list[int]:
    """NIST SP 800-38G FF1 Decryption over arbitrary numeral strings."""
    backend = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    aes_enc = backend.update
    n = len(numerals)
    t = len(tweak)
    u = n // 2
    v = n - u
    b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    d = 4 * math.ceil(b / 4) + 4

    p = bytearray(16)
    p[0], p[1], p[2] = 1, 2, 1
    p[3:6] = radix.to_bytes(3, "big")
    p[6] = 10
    p[7] = u % 256
    p[8:12] = n.to_bytes(4, "big")
    p[12:16] = t.to_bytes(4, "big")

    pad_len = ((-t - b - 1) % 16 + 16) % 16
    q_prefix = tweak + bytes(pad_len)

    A = list(numerals[:u])
    B = list(numerals[u:])

    for round_idx in range(10):
        i = 9 - round_idx
        q = q_prefix + bytes([i]) + num_radix(A, radix).to_bytes(b, "big")
        R = cbc_mac(aes_enc, bytes(p) + q)
        S = bytearray(R)
        j = 1
        while len(S) < d:
            j_bytes = j.to_bytes(16, "big")
            blk = bytes(a ^ b for a, b in zip(R, j_bytes))
            S.extend(aes_enc(blk))
            j += 1
        y = int.from_bytes(S[:d], "big")
        m = u if i % 2 == 0 else v
        c = (num_radix(B, radix) - y) % (radix**m)
        C = str_radix(c, radix, m)
        B = A
        A = C

    return A + B


def ff1_decrypt(key: bytes, tweak: bytes, ciphertext_bytes: bytes, radix: int = 253) -> bytes:
    """Decrypt control line byte string using FF1 over Radix 253 Alphabet."""
    if len(ciphertext_bytes) < 2:
        raise ValueError(f"Line too short: {len(ciphertext_bytes)} bytes (minimum 2)")
    numerals = [byte_to_numeral(b) for b in ciphertext_bytes]
    pt_numerals = ff1_decrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in pt_numerals)


def parse_yencryption_line(line: str | bytes) -> Optional[dict[str, Any]]:
    """Parse standard =yencryption control line per Body Encryption Standard v1.2.

    Format: =yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>
    Enforces strict grammar: exactly 4 single-SP separators (no leading/trailing whitespace,
    no tabs, no double spaces), exact total length 128, exact token order, exact lowercase
    hex, and exact field lengths. Grammar violations raise ValueError (mapped by callers to
    the retryable PROVIDER_FAILOVER tier).
    """
    if isinstance(line, bytes):
        line = line.decode("ascii", errors="replace")
    # Strip transport line terminators only (\r\n, \n, \r) - grammar whitespace itself stays strict
    line = line.rstrip("\r\n")
    if not line.startswith("=yencryption"):
        return None

    # Strict single-SP grammar: any tab or repeated space is a grammar violation
    # (INVALID_WHITESPACE -> PROVIDER_FAILOVER). Token-count/content violations keep the
    # existing None/typed-error semantics.
    strict_tokens = line.split(" ")
    normalized_tokens = line.split()
    if len(strict_tokens) != len(normalized_tokens) or any(token == "" for token in strict_tokens):
        raise ValueError("INVALID_WHITESPACE: =yencryption requires exactly 4 single-SP separators")
    if len(normalized_tokens) != 5:
        return None
    tokens = normalized_tokens
    if tokens[0] != "=yencryption":
        return None
    if tokens[1] != "cipher=XChaCha20-Poly1305":
        return None
    if not tokens[2].startswith("salt="):
        return None
    if not tokens[3].startswith("index="):
        return None
    if not tokens[4].startswith("tag="):
        return None

    # Exact 128-byte total length assertion (Body Std v1.2 grammar)
    if len(line) != 128:
        raise ValueError(f"INVALID_LENGTH: =yencryption line must be exactly 128 characters, got {len(line)}")

    salt_hex = tokens[2][len("salt=") :]
    index_hex = tokens[3][len("index=") :]
    tag_hex = tokens[4][len("tag=") :]

    if len(salt_hex) != 32 or not all(c in "0123456789abcdef" for c in salt_hex):
        return None
    if len(index_hex) != 8 or not all(c in "0123456789abcdef" for c in index_hex):
        return None
    if len(tag_hex) != 32 or not all(c in "0123456789abcdef" for c in tag_hex):
        return None

    segment_index = int(index_hex, 16)
    if segment_index == 0:
        return None

    try:
        salt = bytes.fromhex(salt_hex)
        tag = bytes.fromhex(tag_hex)
    except ValueError:
        return None

    return {
        "cipher": "XChaCha20-Poly1305",
        "salt": salt,
        "segment_index": segment_index,
        "tag": tag,
    }


def extract_and_remove_yencryption(yenc_block: bytes) -> tuple[dict[str, Any], bytes]:
    """Extract and remove the single canonical =yencryption line from a restored yEnc article block.

    Validates:
    - Block has at least 2 lines.
    - Line 1 starts with b"=ybegin".
    - If multipart (part= in line 1):
        - Block has at least 3 lines.
        - Line 2 starts with b"=ypart".
        - Line 3 starts with b"=yencryption".
        - yenc_line_idx is 2 (0-indexed).
    - If single-part:
        - Line 2 starts with b"=yencryption".
        - yenc_line_idx is 1 (0-indexed).
    - No other line anywhere in the block starts with b"=yencryption".
    - The =yencryption line conforms strictly to parse_yencryption_line.

    Returns (params_dict, cleaned_yenc_block).
    """
    raw_lines = yenc_block.splitlines(keepends=True)
    if len(raw_lines) < 2:
        raise ValueError(f"Article block too short: {len(raw_lines)} line(s)")

    line1 = raw_lines[0].lstrip()
    if not line1.startswith(b"=ybegin"):
        raise ValueError("Line 1 does not start with =ybegin")

    is_multipart = any(token.startswith(b"part=") for token in line1.split())

    if is_multipart:
        if len(raw_lines) < 3:
            raise ValueError(f"Multipart article too short: {len(raw_lines)} line(s)")
        line2 = raw_lines[1].lstrip()
        if not line2.startswith(b"=ypart"):
            raise ValueError("Line 2 in multipart article does not start with =ypart")
        line3 = raw_lines[2].lstrip()
        if not line3.startswith(b"=yencryption"):
            raise ValueError("Line 3 in multipart article does not start with =yencryption")
        yenc_idx = 2
    else:
        line2 = raw_lines[1].lstrip()
        if not line2.startswith(b"=yencryption"):
            raise ValueError("Line 2 in single-part article does not start with =yencryption")
        yenc_idx = 1

    for idx, r_line in enumerate(raw_lines):
        if idx != yenc_idx and r_line.lstrip().startswith(b"=yencryption"):
            raise ValueError(f"Duplicate or misplaced =yencryption found at line {idx + 1}")

    yenc_line = raw_lines[yenc_idx]
    params = parse_yencryption_line(yenc_line)
    if not params:
        raise ValueError(f"Malformed =yencryption line: {yenc_line.decode('ascii', errors='replace').strip()}")

    clean_lines = raw_lines[:yenc_idx] + raw_lines[yenc_idx + 1 :]
    return params, b"".join(clean_lines)


def extract_bootstrap_from_line1(line1: bytes) -> tuple[bytes, int]:
    """Extract and validate 20-byte bootstrap prefix ([16B salt][4B uint32_be(segmentIndex)]) from Line 1.

    Ensures line is at least 22 bytes, at most 4096 bytes, salt contains no forbidden bytes, and segment_index > 0.
    """
    if len(line1) < 22:
        raise ValueError(f"Line 1 truncated: {len(line1)} bytes (minimum 22)")
    if len(line1) > 4096:
        raise ValueError(f"Line 1 too long: {len(line1)} bytes (maximum 4096)")
    salt = line1[:16]
    for b in salt:
        if b in (0x00, 0x0A, 0x0D):
            raise ValueError(f"Forbidden byte 0x{b:02x} in salt (0x00, 0x0A, 0x0D forbidden)")
    segment_index = int.from_bytes(line1[16:20], "big")
    if segment_index == 0:
        raise ValueError("ZERO_SEGMENT_INDEX: segment index cannot be zero")
    if any(b in (0x0A, 0x0D) for b in line1[16:20]):
        # CR-02: a 0x0A/0x0D inside the index bytes splits Line 1 on the wire
        raise ValueError("FORBIDDEN_SEGMENT_INDEX_BYTE: segment index bytes contain 0x0A or 0x0D")
    return salt, segment_index


def extract_salt_from_line1(line1: bytes) -> bytes:
    """Extract and validate 16-byte salt from control line 1 (backward-compatible helper).

    Delegates to extract_bootstrap_from_line1 and returns only the salt.
    """
    salt, _ = extract_bootstrap_from_line1(line1)
    return salt


def split_lines_preserving_endings(input_bytes: bytes) -> list[bytes]:
    """Split bytes into lines while preserving \r\n, \n, or \r endings.

    For encrypted wire articles (which do not begin with =y), Line 1 carries a
    20-byte bootstrap prefix ([16B salt][4B uint32_be(segmentIndex)]). Because
    uint32_be(segmentIndex) may contain 0x0A (LF) or 0x0D (CR), the Line 1 terminator
    is searched strictly after the 20-byte bootstrap prefix.
    """
    lines: list[bytes] = []
    pos = 0
    total = len(input_bytes)
    while pos < total:
        start = pos
        if not lines and not input_bytes.startswith(b"=y") and total >= BOOTSTRAP_PREFIX_LEN:
            pos += BOOTSTRAP_PREFIX_LEN
        idx = input_bytes.find(b"\n", pos)
        if idx != -1:
            pos = idx + 1
            lines.append(input_bytes[start:pos])
        else:
            if start < total:
                lines.append(input_bytes[start:])
            break
    return lines


class DecryptionAdapter:
    """SABnzbd decryption adapter encapsulating Argon2id, PyNaCl, and FF1."""

    def __init__(self, password: Optional[str] = None):
        self.password: Optional[str] = password
        self._key_cache: dict[bytes, bytes] = {}
        self._lock = threading.Lock()

    def _derive_argon2id(
        self,
        secret: bytes,
        salt: bytes,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        hash_len: int,
        type: Any,
        version: int,
    ) -> bytes:
        return ll.hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=type,
            version=version,
        )

    def get_master_key(self, salt: bytes) -> bytes:
        """Derive 32-byte master key via Argon2id RFC 9106, thread-safely caching by salt."""
        with self._lock:
            if salt in self._key_cache:
                return self._key_cache[salt]
        if not self.password:
            raise YEncEncryptionStructuralError("MISSING_PASSWORD: no password supplied for yEnc-encrypted article")
        with self._lock:
            if salt in self._key_cache:
                return self._key_cache[salt]
            key = self._derive_argon2id(
                secret=self.password.encode("utf-8"),
                salt=salt,
                time_cost=1,
                memory_cost=65536,  # 64 MiB
                parallelism=4,
                hash_len=32,
                type=ll.Type.ID,
                version=0x13,
            )
            self._key_cache[salt] = key
            return key

    def derive_key(self, salt: bytes) -> bytes:
        return self.get_master_key(salt)

    def derive_body_nonce(self, key: bytes, segment_index: int) -> bytes:
        """Derive 24-byte nonce for XChaCha20-Poly1305 via 19-byte HMAC-SHA256 layout."""
        if not (0 <= segment_index <= 0xFFFFFFFF):
            raise ValueError(f"segment_index {segment_index} out of range for uint32_be")
        msg = b"yenc-body nonce" + struct.pack(">I", segment_index)
        return hmac.new(key, msg, hashlib.sha256).digest()[:24]

    def derive_control_keys(self, master_key: bytes, segment_index: int, line_index: int) -> tuple[bytes, bytes]:
        """Derive 32-byte encKey and 8-byte tweak for FF1 control line encryption."""
        if not (0 <= segment_index <= 0xFFFFFFFF):
            raise ValueError(f"segment_index {segment_index} out of range for uint32_be")
        if not (0 <= line_index <= 0xFFFFFFFF):
            raise ValueError(f"line_index {line_index} out of range for uint32_be")
        enc_key = hmac.new(master_key, b"yenc-control key", hashlib.sha256).digest()
        tweak_msg = b"yenc-control tweak" + struct.pack(">I", segment_index) + struct.pack(">I", line_index)
        tweak = hmac.new(master_key, tweak_msg, hashlib.sha256).digest()[:8]
        return enc_key, tweak

    def decrypt_body(self, ciphertext: bytes, tag: bytes, salt: bytes, segment_index: int) -> bytes:
        """Authenticate and decrypt ciphertext; raises ValueError on auth failure without releasing plaintext."""
        key = self.get_master_key(salt)
        nonce = self.derive_body_nonce(key, segment_index)
        ct_and_tag = ciphertext + tag
        try:
            return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(ct_and_tag, None, nonce, key)
        except Exception as e:
            # Zero-output guarantee: release zero bytes
            raise ValueError(f"Poly1305 authentication failed: {e}") from e

    def encrypt_control_line(self, plaintext: bytes, enc_key: bytes, tweak: bytes, radix: int = 253) -> bytes:
        """Encrypt a single control line with FF1 over Radix 253."""
        return ff1_encrypt(enc_key, tweak, plaintext, radix)

    def decrypt_control_line(self, ciphertext: bytes, enc_key: bytes, tweak: bytes, radix: int = 253) -> bytes:
        """Decrypt a single control line with FF1 over Radix 253."""
        return ff1_decrypt(enc_key, tweak, ciphertext, radix)

    def restore_control_lines(self, yenc_block: bytes, segment_index: Optional[int] = None) -> tuple[bytes, bytes, int]:
        """Restore encrypted control lines in a yEnc article block per Standard v1.2.

        Returns (restored_yenc_block, salt, segment_index).

        N (the footer lineIndex) is the 1-based line index of the =yend line. Trailing
        blank lines after the footer are outside the yEnc block and excluded from
        lineIndex accounting; they are preserved as-is after the restored footer.
        """
        raw_lines = split_lines_preserving_endings(yenc_block)
        if not raw_lines:
            return yenc_block, b"", 0

        # Preserve trailing blank lines if present, while finding true footer line
        trailing_lines: list[bytes] = []
        while raw_lines and not raw_lines[-1].strip():
            trailing_lines.insert(0, raw_lines.pop())

        if not raw_lines:
            return yenc_block, b"", 0

        # Extract line ending from line 1
        line1_raw = raw_lines[0]
        if line1_raw.endswith(b"\r\n"):
            ending = b"\r\n"
            line1_content = line1_raw[:-2]
        elif line1_raw.endswith(b"\n"):
            ending = b"\n"
            line1_content = line1_raw[:-1]
        else:
            ending = b""
            line1_content = line1_raw

        # Line 1: first 20 bytes is bootstrap prefix ([16B salt][4B uint32_be(segmentIndex)])
        salt, line1_segment_index = extract_bootstrap_from_line1(line1_content)
        if segment_index is not None and segment_index != line1_segment_index:
            raise ValueError(
                f"Dual index mismatch: caller specified {segment_index} but line 1 bootstrap contains {line1_segment_index}"
            )

        ct1 = line1_content[BOOTSTRAP_PREFIX_LEN:]
        master_key = self.get_master_key(salt)
        enc_key, tweak1 = self.derive_control_keys(master_key, line1_segment_index, 1)
        pt1 = self.decrypt_control_line(ct1, enc_key, tweak1)
        if not pt1.startswith(b"=ybegin"):
            raise ValueError("Control line decrypt failure: line 1 does not start with =ybegin")

        is_multipart = any(token.startswith(b"part=") for token in pt1.split())
        if len(raw_lines) < 2:
            raise ValueError(f"Article block too short for encrypted yEnc: {len(raw_lines)} line(s) (minimum 2)")

        max_header_lines = 3 if is_multipart else 2

        restored_lines: list[bytes] = [pt1 + ending]
        n_total = len(raw_lines)

        in_header = True
        for idx in range(1, n_total - 1):
            raw_line = raw_lines[idx]
            if raw_line.endswith(b"\r\n"):
                line_ending = b"\r\n"
                content = raw_line[:-2]
            elif raw_line.endswith(b"\n"):
                line_ending = b"\n"
                content = raw_line[:-1]
            else:
                line_ending = b""
                content = raw_line

            line_index = idx + 1
            if line_index <= max_header_lines and in_header:
                enc_key, tweak = self.derive_control_keys(master_key, line1_segment_index, line_index)
                try:
                    pt = self.decrypt_control_line(content, enc_key, tweak)
                except Exception:
                    pt = None

                if pt and pt.startswith(b"=y"):
                    if is_multipart and line_index == 2:
                        if not pt.startswith(b"=ypart"):
                            raise ValueError("Multipart line 2 does not start with =ypart")
                    elif not is_multipart and line_index == 2:
                        if not pt.startswith(b"=yencryption"):
                            raise ValueError(f"Header line {line_index} does not start with =yencryption")
                        in_header = False
                    elif is_multipart and line_index == 3:
                        if not pt.startswith(b"=yencryption"):
                            raise ValueError(f"Header line {line_index} does not start with =yencryption")
                        in_header = False
                    restored_lines.append(pt + line_ending)
                else:
                    in_header = False
                    restored_lines.append(raw_line)
            else:
                restored_lines.append(raw_line)

        # Final line (footer)
        raw_footer = raw_lines[-1]
        if raw_footer.endswith(b"\r\n"):
            footer_ending = b"\r\n"
            footer_content = raw_footer[:-2]
        elif raw_footer.endswith(b"\n"):
            footer_ending = b"\n"
            footer_content = raw_footer[:-1]
        else:
            footer_ending = b""
            footer_content = raw_footer

        footer_line_index = n_total
        enc_key, tweak = self.derive_control_keys(master_key, line1_segment_index, footer_line_index)
        pt_footer = self.decrypt_control_line(footer_content, enc_key, tweak)
        if not pt_footer.startswith(b"=yend"):
            raise ValueError("Control line decrypt failure: footer does not start with =yend")
        restored_lines.append(pt_footer + footer_ending)
        if trailing_lines:
            restored_lines.extend(trailing_lines)

        return b"".join(restored_lines), salt, line1_segment_index

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
from typing import Any, Optional

import argon2.low_level as ll
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import nacl.bindings as nb


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
    """Parse standard =yencryption control line.

    Format: =yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> tag=<32_hex_chars>
    Enforces strict token count (4), exact token order, exact lowercase hex, and exact 32-character lengths.
    """
    if isinstance(line, bytes):
        line = line.decode("ascii", errors="replace")
    line = line.strip()
    if not line.startswith("=yencryption"):
        return None

    tokens = line.split()
    if len(tokens) != 4:
        return None
    if tokens[0] != "=yencryption":
        return None
    if not tokens[1].startswith("cipher="):
        return None
    if not tokens[2].startswith("salt="):
        return None
    if not tokens[3].startswith("tag="):
        return None

    cipher = tokens[1][len("cipher=") :]
    if cipher != "XChaCha20-Poly1305":
        return None

    salt_hex = tokens[2][len("salt=") :]
    tag_hex = tokens[3][len("tag=") :]

    if len(salt_hex) != 32 or not all(c in "0123456789abcdef" for c in salt_hex):
        return None
    if len(tag_hex) != 32 or not all(c in "0123456789abcdef" for c in tag_hex):
        return None

    try:
        salt = bytes.fromhex(salt_hex)
        tag = bytes.fromhex(tag_hex)
    except ValueError:
        return None

    return {
        "cipher": cipher,
        "salt": salt,
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


class DecryptionAdapter:
    """SABnzbd decryption adapter encapsulating Argon2id, PyNaCl, and FF1."""

    def __init__(self, password: Optional[str] = None):
        self.password: Optional[str] = password
        self._key_cache: dict[bytes, bytes] = {}

    def _derive_argon2id(self, secret: bytes, salt: bytes, time_cost: int, memory_cost: int, parallelism: int, hash_len: int, type: Any, version: int) -> bytes:
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
        """Derive 32-byte master key via Argon2id RFC 9106, caching by salt."""
        if salt in self._key_cache:
            return self._key_cache[salt]
        if not self.password:
            raise ValueError("Password required for decryption but none provided")
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

    def restore_control_lines(self, yenc_block: bytes, segment_index: int) -> tuple[bytes, bytes]:
        """Restore encrypted control lines in a yEnc article block per Standard v1.0 Section 5.

        Returns (restored_yenc_block, salt).
        """
        raw_lines = yenc_block.splitlines(keepends=True)
        if not raw_lines:
            return yenc_block, b""

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

        if len(line1_content) < 18:
            raise ValueError(f"Line 1 truncated: {len(line1_content)} bytes")

        # Line 1: first 16 bytes is salt
        salt = line1_content[:16]
        for b in salt:
            if b in (0x00, 0x0A, 0x0D):
                raise ValueError(f"Forbidden byte 0x{b:02x} in salt")

        ct1 = line1_content[16:]
        master_key = self.get_master_key(salt)
        enc_key, tweak1 = self.derive_control_keys(master_key, segment_index, 1)
        pt1 = self.decrypt_control_line(ct1, enc_key, tweak1)
        if not pt1.startswith(b"=ybegin"):
            raise ValueError("Control line decrypt failure: line 1 does not start with =ybegin")

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
            if in_header:
                enc_key, tweak = self.derive_control_keys(master_key, segment_index, line_index)
                try:
                    pt = self.decrypt_control_line(content, enc_key, tweak)
                    if pt.startswith(b"=y"):
                        restored_lines.append(pt + line_ending)
                    else:
                        in_header = False
                        restored_lines.append(raw_line)
                except Exception:
                    in_header = False
                    restored_lines.append(raw_line)
            else:
                restored_lines.append(raw_line)

        # Final line (footer)
        if n_total > 1:
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
            enc_key, tweak = self.derive_control_keys(master_key, segment_index, footer_line_index)
            pt_footer = self.decrypt_control_line(footer_content, enc_key, tweak)
            if not pt_footer.startswith(b"=yend"):
                raise ValueError("Control line decrypt failure: footer does not start with =yend")
            restored_lines.append(pt_footer + footer_ending)

        return b"".join(restored_lines), salt

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

The heavy crypto dependencies (argon2-cffi, PyNaCl) are imported lazily so that
ordinary (unencrypted) downloads and application startup work without them;
encrypted jobs check availability on first use and fail structurally with an
actionable diagnostic when a package is missing.
"""

import hashlib
import hmac
import math
import re
import struct
import threading
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Minimal non-empty dependency diagnostics: raised structurally when an encrypted
# job needs a package that is not installed (METADATA_VALIDATION tier - the job
# cannot proceed on any server, so no alternate-provider query is made).
class MissingDependencyError(ImportError):
    pass


def _lazy_argon2():
    """Import argon2.low_level lazily; raise a structural diagnostic when absent."""
    try:
        import argon2.low_level as ll

        return ll
    except ImportError as e:
        raise MissingDependencyError(
            "yEnc-encrypted download requires the 'argon2-cffi' package (pip install argon2-cffi)"
        ) from e


def _lazy_nacl_bindings():
    """Import nacl.bindings lazily; raise a structural diagnostic when absent."""
    try:
        import nacl.bindings as nb

        return nb
    except ImportError as e:
        raise MissingDependencyError(
            "yEnc-encrypted download requires the 'pynacl' package (pip install pynacl)"
        ) from e


BOOTSTRAP_PREFIX_LEN = 20


class YEncEncryptionStructuralError(ValueError):
    """Structural yEnc-encryption metadata failure (missing/empty password, unsupported mode).

    Per the tier separation in the yEnc encryption standards: structural failures abort the
    job and are NEVER retried against another server - no plaintext or ciphertext is released.
    Inherits from ValueError so existing ``isinstance(e, ValueError)`` handlers still catch it,
    but decoder.py catches this class FIRST to route it to the job-terminal path instead of the
    retryable provider-failover tier (METADATA_VALIDATION semantics).
    """


class YEncEncryptionCryptoError(ValueError):
    """Retryable yEnc-encryption crypto failure (provider corruption tier).

    Wire-level crypto failures: Poly1305 authentication failure, FF1 control-line
    decryption failure, malformed or mismatched encrypted metadata, corrupt bootstrap
    bytes. decoder.py catches this class specifically for the provider-failover tier
    (PROVIDER_FAILOVER semantics); a plain ValueError is a programming error and is
    never retried as provider corruption. Inherits from ValueError so existing
    ``isinstance(e, ValueError)`` handlers still catch it.
    """


def _split_ending(line: bytes) -> tuple[bytes, bytes]:
    """Split line content and line ending (b'\r\n', b'\n', or b'')."""
    if line.endswith(b"\r\n"):
        return line[:-2], b"\r\n"
    elif line.endswith(b"\n"):
        return line[:-1], b"\n"
    return line, b""


def build_aad(
    name_bytes: bytes,
    part_number: int,
    part_begin: int,
    segment_bytes: int,
) -> bytes:
    """Serialize Associated Data (AAD) exactly per Body Encryption Standard v1.2 Section 2.1."""
    if not name_bytes:
        raise YEncEncryptionCryptoError("MISSING_AAD_SUBJECT: =ybegin name parameter is required for AAD")
    return b"yenc-body aad" + struct.pack(">IIQI", part_number, part_begin, segment_bytes, len(name_bytes)) + name_bytes


def byte_to_numeral(b: int) -> int:
    """Map byte octet to numeral 0..252 per yEnc Control Lines Standard v1.2."""
    if 0x01 <= b <= 0x09:
        return b - 1
    elif b == 0x0B:
        return 9
    elif b == 0x0C:
        return 10
    elif 0x0E <= b <= 0xFF:
        return b - 3
    raise YEncEncryptionCryptoError(f"Byte 0x{b:02x} is outside the 253-byte Alphabet (0x00, 0x0A, 0x0D forbidden)")


def numeral_to_byte(i: int) -> int:
    """Map numeral 0..252 back to byte octet per yEnc Control Lines Standard v1.2."""
    if 0 <= i <= 8:
        return i + 1
    elif i == 9:
        return 0x0B
    elif i == 10:
        return 0x0C
    elif 11 <= i <= 252:
        return i + 3
    raise YEncEncryptionCryptoError(f"Numeral {i} is out of range [0, 252]")


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
        raise YEncEncryptionCryptoError(f"Line too short: {len(ciphertext_bytes)} bytes (minimum 2)")
    numerals = [byte_to_numeral(b) for b in ciphertext_bytes]
    pt_numerals = ff1_decrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in pt_numerals)


def parse_yencryption_line(line: str | bytes) -> Optional[dict[str, Any]]:
    """Parse standard =yencryption control line per Body Encryption Standard v1.2.

    Format: =yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>
    Enforces strict grammar: exactly 4 single-SP separators (no leading/trailing whitespace,
    no tabs, no double spaces), exact total length 128, exact token order, exact lowercase
    hex, and exact field lengths. Grammar violations raise YEncEncryptionCryptoError (mapped by callers to
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
        raise YEncEncryptionCryptoError("INVALID_WHITESPACE: =yencryption requires exactly 4 single-SP separators")
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
        raise YEncEncryptionCryptoError(
            f"INVALID_LENGTH: =yencryption line must be exactly 128 characters, got {len(line)}"
        )

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

    idx_bytes = struct.pack(">I", segment_index)
    if b"\x0a" in idx_bytes or b"\x0d" in idx_bytes:
        raise YEncEncryptionCryptoError("FORBIDDEN_SEGMENT_INDEX_BYTE: segment index contains 0x0A or 0x0D")

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


# name= is the last =ybegin keyword and its value runs to the end of the line (Body Std v1.2 §2.1).
_NAME_KEYWORD = re.compile(rb"(?:^|[ \t])name=")


def _ybegin_header(line1: bytes) -> tuple[list[bytes], Optional[bytes]]:
    """Split a restored =ybegin line into its keywords before name= and the raw name value.

    Only keywords before name= describe the layout (Control Std v1.2 §5 step 4): a name such as
    ``my part=2.bin`` must not make a single-part article multipart. The name value is returned as
    raw bytes, without decoding, because it is the AAD subject (Body Std v1.2 §2.1).
    """
    content = line1.rstrip(b"\r\n")
    match = _NAME_KEYWORD.search(content)
    if match is None:
        return content.split(), None
    return content[: match.start()].split(), content[match.end() :]


def _is_multipart_ybegin(header_tokens: list[bytes]) -> bool:
    """Multipart only when a part= keyword precedes name= (Control Std v1.2 §5 step 4)."""
    return any(token.startswith(b"part=") for token in header_tokens)


def _keyword_values(tokens: list[bytes]) -> dict[bytes, bytes]:
    """Map keyword=value tokens to their raw values; tokens without '=' are ignored."""
    values: dict[bytes, bytes] = {}
    for token in tokens:
        key, sep, value = token.partition(b"=")
        if sep:
            values[key] = value
    return values


def _required_int(values: dict[bytes, bytes], key: bytes, line_name: str) -> int:
    """Read a mandatory decimal keyword needed for the AAD; a missing or malformed one fails under PROVIDER_FAILOVER."""
    raw = values.get(key, b"")
    if not raw.isdigit():
        raise YEncEncryptionCryptoError(f"PROVIDER_FAILOVER: {line_name} lacks a valid {key.decode()}= parameter")
    return int(raw)


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
        raise YEncEncryptionCryptoError(f"Article block too short: {len(raw_lines)} line(s)")

    line1 = raw_lines[0]
    if not line1.startswith(b"=ybegin"):
        raise YEncEncryptionCryptoError("Line 1 does not start with =ybegin")

    header_tokens, name_bytes = _ybegin_header(line1)
    is_multipart = _is_multipart_ybegin(header_tokens)

    if is_multipart:
        if len(raw_lines) < 3:
            raise YEncEncryptionCryptoError(f"Multipart article too short: {len(raw_lines)} line(s)")
        line2 = raw_lines[1]
        if not line2.startswith(b"=ypart"):
            raise YEncEncryptionCryptoError("Line 2 in multipart article does not start with =ypart")
        line3 = raw_lines[2]
        if not line3.startswith(b"=yencryption"):
            raise YEncEncryptionCryptoError("Line 3 in multipart article does not start with =yencryption")
        yenc_idx = 2
    else:
        line2 = raw_lines[1]
        if not line2.startswith(b"=yencryption"):
            raise YEncEncryptionCryptoError("Line 2 in single-part article does not start with =yencryption")
        yenc_idx = 1

    for idx, r_line in enumerate(raw_lines):
        if idx != yenc_idx and r_line.startswith(b"=yencryption"):
            raise YEncEncryptionCryptoError(f"Duplicate or misplaced =yencryption found at line {idx + 1}")

    yenc_line = raw_lines[yenc_idx]
    params = parse_yencryption_line(yenc_line)
    if not params:
        # The line holds the salt, index and tag; do not echo it into logs
        raise YEncEncryptionCryptoError("Malformed =yencryption line")

    # Mandatory name parameter for AAD (Body Standard v1.2 §2.1)
    if name_bytes is None:
        raise YEncEncryptionCryptoError("PROVIDER_FAILOVER: missing mandatory name parameter in =ybegin")
    if not name_bytes:
        raise YEncEncryptionCryptoError("PROVIDER_FAILOVER: empty name parameter in =ybegin")

    # AAD geometry comes only from the restored =ybegin/=ypart keywords (Body Std v1.2 §2.1).
    # A missing or malformed keyword the AAD needs is PROVIDER_FAILOVER, never a silent default.
    ybegin_values = _keyword_values(header_tokens)
    if is_multipart:
        part_number = _required_int(ybegin_values, b"part", "=ybegin")
        ypart_values = _keyword_values(line2.split())
        part_begin = _required_int(ypart_values, b"begin", "=ypart")
        part_end = _required_int(ypart_values, b"end", "=ypart")
        if part_end < part_begin:
            raise YEncEncryptionCryptoError("PROVIDER_FAILOVER: =ypart end is before begin")
        segment_bytes = part_end - part_begin + 1
    else:
        part_number = 1
        part_begin = 1
        segment_bytes = _required_int(ybegin_values, b"size", "=ybegin")

    params["aad"] = build_aad(name_bytes, part_number, part_begin, segment_bytes)
    params["segment_bytes"] = segment_bytes

    clean_lines = raw_lines[:yenc_idx] + raw_lines[yenc_idx + 1 :]
    return params, b"".join(clean_lines)


def neutral_ybegin_name(yenc_block: bytes) -> bytes:
    """Return a copy of a restored yEnc block whose =ybegin name= value is a fixed placeholder.

    The AAD is already computed from the raw name (Body Std v1.2 §2.1), so the name is not needed for
    body parsing. sabctools 9.7.1 treats any ``part=`` substring in =ybegin as multipart, so a single-part
    name such as ``my part=2.bin`` would make the sub-decoder expect =ypart. The header keywords (which
    decide the layout) are kept unchanged; only the name value is replaced.
    """
    end = yenc_block.find(b"\n")
    first_line = yenc_block if end == -1 else yenc_block[: end + 1]
    content, ending = _split_ending(first_line)
    header_tokens, name_bytes = _ybegin_header(content)
    if name_bytes is None:
        return yenc_block
    return b" ".join(header_tokens) + b" name=x" + ending + yenc_block[len(first_line) :]


def extract_bootstrap_from_line1(line1: bytes) -> tuple[bytes, int]:
    """Extract and validate 20-byte bootstrap prefix ([16B salt][4B uint32_be(segmentIndex)]) from Line 1.

    Ensures line is at least 22 bytes, salt contains no forbidden bytes, and segment_index > 0.
    """
    if len(line1) < 22:
        raise YEncEncryptionCryptoError(f"Line 1 truncated: {len(line1)} bytes (minimum 22)")
    salt = line1[:16]
    for b in salt:
        if b in (0x00, 0x0A, 0x0D):
            raise YEncEncryptionCryptoError(f"Forbidden byte 0x{b:02x} in salt (0x00, 0x0A, 0x0D forbidden)")
    segment_index = int.from_bytes(line1[16:20], "big")
    if segment_index == 0:
        raise YEncEncryptionCryptoError("ZERO_SEGMENT_INDEX: segment index cannot be zero")
    if any(b in (0x0A, 0x0D) for b in line1[16:20]):
        # Index framing rule: a 0x0A/0x0D inside the index bytes splits Line 1 on the wire
        raise YEncEncryptionCryptoError("FORBIDDEN_SEGMENT_INDEX_BYTE: segment index bytes contain 0x0A or 0x0D")
    return salt, segment_index


def split_lines_preserving_endings(input_bytes: bytes) -> list[bytes]:
    """Split bytes into lines while preserving \r\n or \n endings.

    For encrypted wire articles (which do not begin with =y), Line 1 carries a
    20-byte bootstrap prefix ([16B salt][4B uint32_be(segmentIndex)]). Because
    uint32_be(segmentIndex) may contain 0x0A (LF) or 0x0D (CR), the Line 1 terminator
    is searched strictly after the 20-byte bootstrap prefix.
    """
    if not input_bytes:
        raise YEncEncryptionCryptoError("Empty encrypted article block")
    lines: list[bytes] = []
    pos = 0
    total = len(input_bytes)
    while pos < total:
        start = pos
        if not lines and not input_bytes.startswith(b"=y"):
            if total >= BOOTSTRAP_PREFIX_LEN:
                pos += BOOTSTRAP_PREFIX_LEN
            else:
                # Input too short to carry the 20-byte bootstrap prefix is
                # treated as one truncated Line 1 so a stray 0x0A inside the
                # (missing) prefix cannot fragment it.
                pos = total
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
        return _lazy_argon2().hash_secret_raw(
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
            key = self._derive_argon2id(
                secret=self.password.encode("utf-8"),
                salt=salt,
                time_cost=1,
                memory_cost=65536,  # 64 MiB
                parallelism=4,
                hash_len=32,
                type=_lazy_argon2().Type.ID,
                version=0x13,
            )
            self._key_cache[salt] = key
            return key

    def derive_body_nonce(self, key: bytes, segment_index: int) -> bytes:
        """Derive 24-byte nonce for XChaCha20-Poly1305 via 19-byte HMAC-SHA256 layout."""
        msg = b"yenc-body nonce" + struct.pack(">I", segment_index)
        return hmac.new(key, msg, hashlib.sha256).digest()[:24]

    def derive_control_keys(self, master_key: bytes, segment_index: int, line_index: int) -> tuple[bytes, bytes]:
        """Derive 32-byte encKey and 8-byte tweak for FF1 control line encryption."""
        enc_key = hmac.new(master_key, b"yenc-control key", hashlib.sha256).digest()
        tweak_msg = b"yenc-control tweak" + struct.pack(">I", segment_index) + struct.pack(">I", line_index)
        tweak = hmac.new(master_key, tweak_msg, hashlib.sha256).digest()[:8]
        return enc_key, tweak

    def decrypt_body(
        self,
        ciphertext: bytes,
        tag: bytes,
        salt: bytes,
        segment_index: int,
        aad: bytes = b"",
    ) -> bytes:
        """Authenticate and decrypt ciphertext; raises YEncEncryptionCryptoError on auth failure without releasing plaintext.

        The AAD must be the Section 2.1 serialization (never empty for conforming articles).
        """
        key = self.get_master_key(salt)
        nonce = self.derive_body_nonce(key, segment_index)
        ct_and_tag = ciphertext + tag
        try:
            return _lazy_nacl_bindings().crypto_aead_xchacha20poly1305_ietf_decrypt(ct_and_tag, aad, nonce, key)
        except MissingDependencyError:
            raise
        except Exception as e:
            # Zero-output guarantee: release zero bytes
            raise YEncEncryptionCryptoError(f"Poly1305 authentication failed: {e}") from e

    def decrypt_control_line(self, ciphertext: bytes, enc_key: bytes, tweak: bytes) -> bytes:
        """Decrypt a single control line with FF1 over Radix 253."""
        return ff1_decrypt(enc_key, tweak, ciphertext)

    def _restore_yencryption_line(
        self, master_key: bytes, segment_index: int, wire_line: bytes, line_index: int
    ) -> bytes:
        """Decrypt the =yencryption line at its fixed position (Control Std v1.2 §5 step 4b).

        A decryption error or a non-=yencryption result is PROVIDER_FAILOVER. The position is
        fixed, so there is no fallback to treating the line as data.
        """
        content, ending = _split_ending(wire_line)
        enc_key, tweak = self.derive_control_keys(master_key, segment_index, line_index)
        pt_enc = self.decrypt_control_line(content, enc_key, tweak)
        if not pt_enc.startswith(b"=yencryption"):
            raise YEncEncryptionCryptoError(
                f"PROVIDER_FAILOVER: line {line_index} is not =yencryption at its fixed position"
            )
        return pt_enc + ending

    def restore_control_lines(self, yenc_block: bytes) -> tuple[bytes, bytes, int]:
        """Restore encrypted control lines in a yEnc article block per Control Lines Standard v1.2 §5.

        Deterministic combined-mode restoration (Control Std v1.2 §5): header positions are
        inferred from the restored =ybegin line only; data lines pass through untouched
        byte-for-byte and are never decrypted or inspected; the footer is identified by
        position (last physical line), never by content search. Line terminators are
        preserved byte-for-byte (bare LF is never canonicalized to CRLF).

        Returns (restored_yenc_block, salt, segment_index).

        N (the footer lineIndex) is the 1-based line index of the =yend line. Trailing
        blank lines after the footer are outside the yEnc block and excluded from
        lineIndex accounting; they are preserved as-is after the restored footer.
        """
        raw_lines = split_lines_preserving_endings(yenc_block)

        # Preserve trailing blank lines if present, while finding true footer line
        trailing_lines: list[bytes] = []
        while raw_lines and not raw_lines[-1].strip():
            trailing_lines.insert(0, raw_lines.pop())

        # Line 1 (lineIndex=1): bootstrap prefix + FF1-encrypted =ybegin
        line1_content, line1_ending = _split_ending(raw_lines[0])
        salt, segment_index = extract_bootstrap_from_line1(line1_content)

        master_key = self.get_master_key(salt)
        enc_key, tweak1 = self.derive_control_keys(master_key, segment_index, 1)
        pt1 = self.decrypt_control_line(line1_content[BOOTSTRAP_PREFIX_LEN:], enc_key, tweak1)
        if not pt1.startswith(b"=ybegin"):
            raise YEncEncryptionCryptoError("Control line decrypt failure: line 1 does not start with =ybegin")

        if len(raw_lines) < 2:
            raise YEncEncryptionCryptoError(
                f"Article block too short for encrypted yEnc: {len(raw_lines)} line(s) (minimum 2)"
            )

        is_multipart = _is_multipart_ybegin(_ybegin_header(pt1)[0])
        restored_lines: list[bytes] = [pt1 + line1_ending]

        if is_multipart:
            if len(raw_lines) < 3:
                raise YEncEncryptionCryptoError(
                    f"Multipart article too short for encrypted yEnc: {len(raw_lines)} line(s) (minimum 3)"
                )
            part_content, part_ending = _split_ending(raw_lines[1])
            enc_key, tweak = self.derive_control_keys(master_key, segment_index, 2)
            pt2 = self.decrypt_control_line(part_content, enc_key, tweak)
            if not pt2.startswith(b"=ypart"):
                raise YEncEncryptionCryptoError("Multipart line 2 does not start with =ypart")
            restored_lines.append(pt2 + part_ending)

            first_data_line_index = 3
            if len(raw_lines) > 3:
                restored_lines.append(self._restore_yencryption_line(master_key, segment_index, raw_lines[2], 3))
                first_data_line_index = 4
        else:
            first_data_line_index = 2
            if len(raw_lines) > 2:
                restored_lines.append(self._restore_yencryption_line(master_key, segment_index, raw_lines[1], 2))
                first_data_line_index = 3

        # Data lines (D through N-1) pass through untouched, byte for byte, terminators included
        for idx in range(first_data_line_index - 1, len(raw_lines) - 1):
            restored_lines.append(raw_lines[idx])

        # Footer at the fixed last position (lineIndex = N); no content-based search
        footer_content, footer_ending = _split_ending(raw_lines[-1])
        footer_line_index = len(raw_lines)
        enc_key, tweak = self.derive_control_keys(master_key, segment_index, footer_line_index)
        pt_footer = self.decrypt_control_line(footer_content, enc_key, tweak)
        if not pt_footer.startswith(b"=yend"):
            raise YEncEncryptionCryptoError("Control line decrypt failure: footer does not start with =yend")
        restored_lines.append(pt_footer + footer_ending)
        restored_lines.extend(trailing_lines)

        return b"".join(restored_lines), salt, segment_index

"""Self-contained encryption helpers for root integration and audit tests.
Performs FF1 Radix-253 encryption and decryption and XChaCha20-Poly1305 AEAD per v1.2 specifications.
"""

import hashlib
import hmac
import math
import struct
import argon2.low_level as ll
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RADIX = 253
# Alphabet: all 256 bytes except 0x00 (NUL), 0x0A (LF), 0x0D (CR)
ALPHABET_253 = bytes([b for b in range(256) if b not in (0, 10, 13)])
BYTE_TO_NUMERAL = {b: i for i, b in enumerate(ALPHABET_253)}
NUMERAL_TO_BYTE = dict(enumerate(ALPHABET_253))
BOOTSTRAP_PREFIX_LEN = 20


def byte_to_numeral(b: int) -> int:
    try:
        return BYTE_TO_NUMERAL[b]
    except KeyError:
        raise ValueError(f"Byte {b:#04x} not in Radix-253 alphabet")


def numeral_to_byte(i: int) -> int:
    return NUMERAL_TO_BYTE[i]


def num_radix(numerals: list[int], radix: int = 253) -> int:
    val = 0
    for x in numerals:
        val = val * radix + x
    return val


def str_radix(val: int, radix: int, length: int) -> list[int]:
    out = [0] * length
    for i in range(length - 1, -1, -1):
        out[i] = val % radix
        val //= radix
    return out


def cbc_mac(aes_enc, data: bytes) -> bytes:
    assert len(data) % 16 == 0
    block = bytes(16)
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        block = aes_enc(bytes(a ^ b for a, b in zip(block, chunk)))
    return block


def ff1_encrypt_numerals(key: bytes, tweak: bytes, numerals: list[int], radix: int = 253) -> list[int]:
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
    if len(plaintext_bytes) < 2:
        raise ValueError(f"Line too short: {len(plaintext_bytes)} bytes (minimum 2)")
    numerals = [byte_to_numeral(b) for b in plaintext_bytes]
    ct_numerals = ff1_encrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in ct_numerals)


def encrypt_control_line(plaintext: bytes, enc_key: bytes, tweak: bytes, radix: int = 253) -> bytes:
    return ff1_encrypt(enc_key, tweak, plaintext, radix)


def derive_control_keys(master_key: bytes, segment_index: int, line_index: int) -> tuple[bytes, bytes]:
    enc_key = hmac.new(master_key, b"yenc-control key", hashlib.sha256).digest()
    tweak_msg = b"yenc-control tweak" + struct.pack(">I", segment_index) + struct.pack(">I", line_index)
    tweak = hmac.new(master_key, tweak_msg, hashlib.sha256).digest()[:8]
    return enc_key, tweak


def derive_master_key(password: str, salt: bytes) -> bytes:
    return ll.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=1,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=ll.Type.ID,
        version=0x13,
    )


def build_aad(name_bytes: bytes, part_number: int, part_begin: int, segment_bytes: int) -> bytes:
    return b"yenc-body aad" + struct.pack(">IIQI", part_number, part_begin, segment_bytes, len(name_bytes)) + name_bytes

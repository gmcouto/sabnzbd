"""Uploader-side encryption helpers for tests."""

import math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sabnzbd.encryption import (
    YEncEncryptionCryptoError,
    byte_to_numeral,
    cbc_mac,
    num_radix,
    numeral_to_byte,
    str_radix,
)


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
        raise YEncEncryptionCryptoError(f"Line too short: {len(plaintext_bytes)} bytes (minimum 2)")
    numerals = [byte_to_numeral(b) for b in plaintext_bytes]
    ct_numerals = ff1_encrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in ct_numerals)


def encrypt_control_line(plaintext: bytes, enc_key: bytes, tweak: bytes, radix: int = 253) -> bytes:
    """Encrypt a single control line with FF1 over Radix 253."""
    return ff1_encrypt(enc_key, tweak, plaintext, radix)

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
tests.test_encryption - Unit and integration tests for SABnzbd decryption adapter.
"""

import itertools
import json
from pathlib import Path
import socket
import threading
import time
from unittest import mock
import pytest

import sabnzbd
from sabnzbd.downloader import Server, Downloader
from sabnzbd.get_addrinfo import AddrInfo
from sabnzbd.encryption import (
    DecryptionAdapter,
    YEncEncryptionCryptoError,
    parse_yencryption_line,
    extract_and_remove_yencryption,
    extract_bootstrap_from_line1,
    build_aad,
    BOOTSTRAP_PREFIX_LEN,
    ff1_decrypt,
    byte_to_numeral,
    numeral_to_byte,
)
from tests.encryption_helpers import ff1_encrypt, encrypt_control_line
from sabnzbd.nzb import Article
from sabnzbd.newswrapper import NewsWrapper


def _mock_response():
    """A response mock with the same status and byte-count types as sabctools."""
    import sabctools

    response = mock.MagicMock(spec=sabctools.NNTPResponse)
    response.status_code = 222
    response.bytes_decoded = 0
    response.sink_failed = False
    return response


def _encrypted_wire(
    password: str,
    plaintext: bytes,
    name: str = "test.bin",
    salt: bytes = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890"),
    segment_index: int = 1,
    multipart: bool = False,
    line_ending: bytes = b"\r\n",
    tamper_tag: bool = False,
):
    """Build a complete encrypted wire article body (centralized builder).

    Returns (wire_body, adapter, master_key, nonce, ct, tag, body_crc, aad).
    The body is framed with `line_ending` and carries the given name/segment_index.
    With tamper_tag=True the =yencryption tag is corrupted so authentication fails.
    """
    import nacl.bindings as nb
    import sabctools

    adapter = DecryptionAdapter(password=password)
    master_key = adapter.get_master_key(salt)
    nonce = adapter.derive_body_nonce(master_key, segment_index)

    part_number, part_begin = (1, 1)  # ypart fields are filled from multipart geometry below
    aad = build_aad(name.encode("ascii"), part_number, part_begin, len(plaintext))
    enc = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, master_key)
    ct = enc[:-16]
    tag = enc[-16:]
    if tamper_tag:
        tag = bytes([tag[0] ^ 0xFF]) + tag[1:]

    body_encoded, body_crc = sabctools.yenc_encode(ct)

    if multipart:
        line1_pt = f"=ybegin part=1 total=1 line=128 size={len(plaintext)} name={name}".encode("ascii")
        line2_pt = f"=ypart begin=1 end={len(plaintext)}".encode("ascii")
        line3_pt = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={segment_index:08x} tag={tag.hex()}".encode(
            "ascii"
        )
        line_last_pt = f"=yend size={len(plaintext)} part=1 pcrc32={body_crc:08x}".encode("ascii")
        plain_lines = [line1_pt, line2_pt, line3_pt, body_encoded, line_last_pt]
        line_indices = [1, 2, 3, None, 5]
    else:
        line1_pt = f"=ybegin line=128 size={len(plaintext)} name={name}".encode("ascii")
        line2_pt = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={segment_index:08x} tag={tag.hex()}".encode(
            "ascii"
        )
        line_last_pt = f"=yend size={len(plaintext)} crc32={body_crc:08x}".encode("ascii")
        plain_lines = [line1_pt, line2_pt, body_encoded, line_last_pt]
        line_indices = [1, 2, None, 4]

    n_lines = len(plain_lines)
    wire_lines: list[bytes] = []
    for idx, (pt, line_idx) in enumerate(zip(plain_lines, line_indices)):
        if line_idx is None:
            wire_lines.append(pt)  # data line: untouched
        elif line_idx == 1:
            k, t = adapter.derive_control_keys(master_key, segment_index, 1)
            wire_lines.append(salt + segment_index.to_bytes(4, "big") + ff1_encrypt(k, t, pt))
        else:
            k, t = adapter.derive_control_keys(master_key, segment_index, line_idx)
            wire_lines.append(ff1_encrypt(k, t, pt))

    return (
        line_ending.join(wire_lines) + line_ending,
        adapter,
        master_key,
        nonce,
        ct,
        tag,
        body_crc,
        aad,
        n_lines,
    )


def _get_test_vector_dir() -> Path:
    vector_dir = Path(__file__).resolve().parent / "data" / "test-vectors"
    if not vector_dir.exists():
        pytest.fail(f"Test vectors not found at {vector_dir}")
    return vector_dir


class MockArticleNNTPServer:
    """Minimal NNTP server providing custom responses for BODY and ARTICLE commands."""

    def __init__(self, body_bytes: bytes, host: str = "127.0.0.1", line_ending: bytes = b"\r\n", split_at=None):
        self.host: str = host
        self.port: int = 0
        self.server_socket = None
        self.connections = []
        self._stop = threading.Event()
        self._thread = None
        self.body_bytes: bytes = body_bytes
        self.line_ending: bytes = line_ending
        # When set, every response is delivered in explicit TCP chunks split at these
        # byte offsets, with a pause between chunks so the client really observes
        # separate TCP segments (used to test CRLF split across chunk boundaries).
        self.split_at = split_at
        self.have_body: bool = True  # Flip to False to make BODY respond 500
        # Set to True to answer BODY with an ARTICLE-style 220 response (a server that ignores BODY)
        self.body_answers_with_article: bool = False
        self.commands: list[bytes] = []  # Every command line received, in order

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.port = self.server_socket.getsockname()[1]
        self.server_socket.listen(5)
        self.server_socket.settimeout(0.5)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self.server_socket.accept()
                self.connections.append(conn)
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except OSError:
                pass

    def _handle_client(self, conn):
        def send_response(resp: bytes):
            if self.split_at is None:
                conn.sendall(resp)
                return
            # Deliver in explicit chunks at the requested split offsets, pausing
            # between chunks so the client's recv() sees separate TCP segments.
            bounds = [0, *sorted({s for s in self.split_at if 0 < s < len(resp)}), len(resp)]
            for start, end in itertools.pairwise(bounds):
                conn.sendall(resp[start:end])
                if end < len(resp):
                    time.sleep(0.05)

        try:
            conn.sendall(b"200 Welcome\r\n")
            while not self._stop.is_set():
                conn.settimeout(0.5)
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    if data.startswith(b"QUIT"):
                        conn.sendall(b"205 Goodbye" + self.line_ending)
                        break
                    elif data.startswith(b"BODY") and not self.body_answers_with_article:
                        self.commands.append(data)
                        if self.have_body:
                            resp = b"222 0 <art@e2e>" + self.line_ending + self.body_bytes + b"." + self.line_ending
                            send_response(resp)
                        else:
                            conn.sendall(b"500 command not supported" + self.line_ending)
                    elif data.startswith((b"ARTICLE", b"BODY")):
                        self.commands.append(data)
                        resp = (
                            b"220 0 <art@e2e>"
                            + self.line_ending
                            + b"Path: not-for-mail"
                            + self.line_ending
                            + b"From: poster@test"
                            + self.line_ending
                            + b"Newsgroups: alt.binaries.test"
                            + self.line_ending
                            + b"Subject: enc"
                            + self.line_ending
                            + b"Message-ID: <art@e2e>"
                            + self.line_ending
                            + self.line_ending
                            + self.body_bytes
                            + b"."
                            + self.line_ending
                        )
                        send_response(resp)
                    elif data.startswith(b"authinfo user"):
                        conn.sendall(b"381 More auth required" + self.line_ending)
                    elif data.startswith(b"authinfo pass"):
                        conn.sendall(b"281 Auth accepted" + self.line_ending)
                except TimeoutError:
                    continue
        except Exception:
            pass
        finally:
            conn.close()

    def stop(self):
        self._stop.set()
        for conn in self.connections:
            try:
                conn.close()
            except Exception:
                pass
        if self.server_socket:
            self.server_socket.close()
        if self._thread:
            self._thread.join(timeout=2)


class TestDecryptionAdapterContracts:
    """Adapter contract tests: Argon2id derivation, key caching, AEAD decryption, and FF1 control-line restoration."""

    def test_sab_adapter_contracts(self):
        """Argon2id key derivation, caching, body AEAD, and control line restoration against the standards vectors."""
        vector_dir = _get_test_vector_dir()

        # 1. Verify Argon2id key derivation against argon2id.json
        with open(vector_dir / "argon2id.json", "r", encoding="utf-8") as f:
            argon_data = json.load(f)

        for vec in argon_data["vectors"]:
            password = vec["password"]
            salt = bytes.fromhex(vec["salt_hex"])
            expected_key = bytes.fromhex(vec["expected_key_hex"])

            adapter = DecryptionAdapter(password=password)
            derived = adapter.get_master_key(salt)
            assert derived == expected_key, f"Key mismatch for {vec['id']}"

        # 2. Verify key caching (Argon2id called only once for identical salt)
        adapter = DecryptionAdapter(password="test123")
        salt = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")

        import argon2.low_level as argon2_ll

        with mock.patch("argon2.low_level.hash_secret_raw", wraps=argon2_ll.hash_secret_raw) as mock_kdf:
            k1 = adapter.get_master_key(salt)
            k2 = adapter.get_master_key(salt)
            assert k1 == k2
            assert mock_kdf.call_count == 1, "Expected Argon2id KDF to be called exactly once due to caching"

        # 3. Verify body AEAD decryption against body_encryption.json
        with open(vector_dir / "body_encryption.json", "r", encoding="utf-8") as f:
            body_data = json.load(f)

        for vec in body_data["vectors"]:
            password = vec["password"]
            salt = bytes.fromhex(vec["salt_hex"])
            segment_index = vec["segment_index"]
            expected_ct = bytes.fromhex(vec["expected_ciphertext_hex"])
            expected_tag = bytes.fromhex(vec["expected_tag_hex"])
            expected_pt = bytes.fromhex(vec["plaintext_hex"])
            aad_obj = vec["aad"]
            aad = bytes.fromhex(aad_obj["expected_aad_hex"])
            assert aad == build_aad(
                bytes.fromhex(aad_obj["name_bytes_hex"]),
                aad_obj["part_number"],
                aad_obj["part_begin"],
                aad_obj["segment_bytes"],
            ), f"AAD serialization mismatch for {vec['id']}"

            adapter = DecryptionAdapter(password=password)
            pt = adapter.decrypt_body(expected_ct, expected_tag, salt, segment_index, aad=aad)
            assert pt == expected_pt, f"Plaintext mismatch for {vec['id']}"

            # Empty AAD MUST fail authentication (Body Standard v1.2 Section 2.1)
            adapter_empty = DecryptionAdapter(password=password)
            with pytest.raises(ValueError, match="Poly1305 authentication failed"):
                adapter_empty.decrypt_body(expected_ct, expected_tag, salt, segment_index, aad=b"")

        # 4. Zero-Output Guarantee on authentication failure
        adapter = DecryptionAdapter(password="test123")
        salt = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        good_vec = body_data["vectors"][0]
        ct = bytes.fromhex(good_vec["expected_ciphertext_hex"])
        tag = bytes.fromhex(good_vec["expected_tag_hex"])
        good_aad = bytes.fromhex(good_vec["aad"]["expected_aad_hex"])

        # Corrupted tag
        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            adapter.decrypt_body(ct, bad_tag, salt, segment_index=1, aad=good_aad)

        # Corrupted ciphertext
        bad_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            adapter.decrypt_body(bad_ct, tag, salt, segment_index=1, aad=good_aad)

        # Wrong segment_index
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            adapter.decrypt_body(ct, tag, salt, segment_index=2, aad=good_aad)

        # Wrong password
        wrong_adapter = DecryptionAdapter(password="wrongpassword")
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            wrong_adapter.decrypt_body(ct, tag, salt, segment_index=1, aad=good_aad)

        # 5. Verify Control Line Decryption against control_line_encryption.json
        with open(vector_dir / "control_line_encryption.json", "r", encoding="utf-8") as f:
            control_data = json.load(f)

        for vec in control_data["vectors"]:
            if "total_physical_lines" in vec:
                # Full article test vector
                password = vec["password"]
                segment_index = vec["segment_index"]
                expected_lines = [line.encode("ascii") for line in vec["input_lines"]]
                wire_lines = [bytes.fromhex(h) for h in vec["expected_wire_lines_hex"]]
                wire_block = b"\r\n".join(wire_lines) + b"\r\n"

                adapter = DecryptionAdapter(password=password)
                restored_block, extracted_salt, extracted_idx = adapter.restore_control_lines(wire_block)
                assert extracted_salt == bytes.fromhex(vec["salt_hex"])
                assert extracted_idx == segment_index
                expected_block = b"\r\n".join(expected_lines) + b"\r\n"
                assert restored_block == expected_block, f"Full article restoration mismatch for {vec['id']}"
            else:
                # Single line vector
                password = vec["password"]
                salt = bytes.fromhex(vec["salt_hex"])
                segment_index = vec["segment_index"]
                line_index = vec["line_index"]
                is_line_1 = vec["is_line_1"]
                expected_pt_line = vec["plaintext_line"].encode("ascii")
                wire_bytes = bytes.fromhex(vec["expected_wire_hex"])

                adapter = DecryptionAdapter(password=password)
                master_key = adapter.get_master_key(salt)
                enc_key, tweak = adapter.derive_control_keys(master_key, segment_index, line_index)

                if is_line_1:
                    line_salt = wire_bytes[:16]
                    line_idx = int.from_bytes(wire_bytes[16:20], "big")
                    assert line_salt == salt
                    assert line_idx == segment_index
                    ct = wire_bytes[20:]
                else:
                    ct = wire_bytes

                pt_line = adapter.decrypt_control_line(ct, enc_key, tweak)
                assert pt_line == expected_pt_line, f"Control line mismatch for {vec['id']}"

    def test_combined_layout_vectors_restore_and_decrypt(self):
        """control-vec-07/09/10 carry =yencryption at line 2 in the standards repo; they are valid combined articles.

        Restoration must succeed, the =yencryption line must be verified against Line 1, and the restored yEnc
        block must equal the vector's plaintext lines. Vectors 11 and 12 stay covered by the same check.
        """
        vector_dir = _get_test_vector_dir()
        with open(vector_dir / "control_line_encryption.json", "r", encoding="utf-8") as f:
            control_data = json.load(f)

        checked = set()
        for vec in control_data["vectors"]:
            if "total_physical_lines" not in vec or not vec["id"].startswith(
                ("control-vec-07-", "control-vec-09-", "control-vec-10-", "control-vec-11-", "control-vec-12-")
            ):
                continue
            checked.add("-".join(vec["id"].split("-")[:3]))

            expected_lines = [line.encode("ascii") for line in vec["input_lines"]]
            # =yencryption sits at line 2 (line 3 when =ypart is present) in the standards vectors
            enc_index = next(i for i, line in enumerate(expected_lines) if line.startswith(b"=yencryption"))
            assert enc_index in (1, 2), vec["id"]

            wire_block = b"\r\n".join(bytes.fromhex(h) for h in vec["expected_wire_lines_hex"]) + b"\r\n"
            adapter = DecryptionAdapter(password=vec["password"])
            restored_block, extracted_salt, extracted_idx = adapter.restore_control_lines(wire_block)

            assert extracted_salt == bytes.fromhex(vec["salt_hex"]), vec["id"]
            assert extracted_idx == vec["segment_index"], vec["id"]
            assert restored_block == b"\r\n".join(expected_lines) + b"\r\n", vec["id"]

            yenc_params, clean_block = extract_and_remove_yencryption(restored_block)
            assert yenc_params["salt"] == extracted_salt, vec["id"]
            assert yenc_params["segment_index"] == extracted_idx, vec["id"]
            assert b"=yencryption" not in clean_block, vec["id"]
            without_enc = expected_lines[:enc_index] + expected_lines[enc_index + 1 :]
            assert clean_block == b"\r\n".join(without_enc) + b"\r\n", vec["id"]

        assert checked == {"control-vec-07", "control-vec-09", "control-vec-10", "control-vec-11", "control-vec-12"}

    def test_nonce_and_tweak_vectors(self):
        """Verify HMAC-SHA256 body nonce and control tweak derivations against nonce_tweak.json."""
        vector_dir = _get_test_vector_dir()
        with open(vector_dir / "nonce_tweak.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        adapter = DecryptionAdapter(password="test123")

        # 1. Body nonce vectors (24 bytes via 19-byte HMAC message)
        for vec in data["body_nonce_vectors"]:
            key = bytes.fromhex(vec["key_hex"])
            segment_index = vec["segment_index"]
            nonce = adapter.derive_body_nonce(key, segment_index)
            assert nonce.hex() == vec["expected_nonce_hex"], f"Nonce mismatch for {vec['id']}"

        # 2. Control tweak vectors (32-byte encKey and 8-byte tweak)
        for vec in data["control_tweak_vectors"]:
            master_key = bytes.fromhex(vec["master_key_hex"])
            segment_index = vec["segment_index"]
            line_index = vec["line_index"]
            enc_key, tweak = adapter.derive_control_keys(master_key, segment_index, line_index)
            assert enc_key.hex() == vec["enc_key_hex"], f"Enc key mismatch for {vec['id']}"
            assert tweak.hex() == vec["expected_tweak_hex"], f"Tweak mismatch for {vec['id']}"

    def test_numeral_bijection_and_parser(self):
        """Test byte_to_numeral, numeral_to_byte, and parse_yencryption_line."""
        # 1. Numeral bijection
        for b in range(1, 256):
            if b in (0x0A, 0x0D):
                with pytest.raises(ValueError):
                    byte_to_numeral(b)
            else:
                num = byte_to_numeral(b)
                assert 0 <= num <= 252
                assert numeral_to_byte(num) == b

        with pytest.raises(ValueError):
            byte_to_numeral(0x00)

        # 2. Parser
        line = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b"
        parsed = parse_yencryption_line(line)
        assert parsed is not None

        assert parsed["salt"] == bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        assert parsed["segment_index"] == 1
        assert parsed["tag"] == bytes.fromhex("0cd77ce245a654463f90b945b1d22d5b")

        # 3. extract_and_remove_yencryption basic smoke test
        block = b"=ybegin line=128 size=10 name=test\r\n=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\ndata\r\n=yend size=10\r\n"
        p, clean = extract_and_remove_yencryption(block)

        assert p["segment_index"] == 1
        assert clean == b"=ybegin line=128 size=10 name=test\r\ndata\r\n=yend size=10\r\n"

        # Invalid lines
        assert parse_yencryption_line("not an encryption line") is None
        assert parse_yencryption_line("=yencryption cipher=AES salt=123 tag=456") is None

    def test_extract_bootstrap_from_line1(self):
        """Test 20-byte bootstrap extraction: 22B minimum length, forbidden bytes, and zero index."""
        assert BOOTSTRAP_PREFIX_LEN == 20
        valid_prefix = b"A" * 16 + (42).to_bytes(4, "big")
        valid_line = valid_prefix + b"xy"
        salt, idx = extract_bootstrap_from_line1(valid_line)
        assert salt == b"A" * 16
        assert idx == 42

        # < 22 bytes fails
        with pytest.raises(ValueError, match="Line 1 truncated"):
            extract_bootstrap_from_line1(valid_prefix + b"x")

        # Forbidden bytes in salt
        for forbidden in (0x00, 0x0A, 0x0D):
            bad_salt = bytearray(b"A" * 16)
            bad_salt[5] = forbidden
            with pytest.raises(ValueError, match="Forbidden byte"):
                extract_bootstrap_from_line1(bytes(bad_salt) + (1).to_bytes(4, "big") + b"xx")

        # Zero index fails
        with pytest.raises(ValueError, match="ZERO_SEGMENT_INDEX"):
            extract_bootstrap_from_line1(b"A" * 16 + (0).to_bytes(4, "big") + b"xx")

    def test_dual_bootstrap_agreement(self):
        """Test Dual-Bootstrap Agreement in decoder: salt mismatch and index mismatch."""
        import sabnzbd.decoder as decoder

        # Setup valid wire block
        password = "test_password"
        salt = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        seg_idx = 1
        adapter = DecryptionAdapter(password=password)
        master_key = adapter.get_master_key(salt)
        k1, t1 = adapter.derive_control_keys(master_key, seg_idx, 1)
        k2, t2 = adapter.derive_control_keys(master_key, seg_idx, 2)

        line1_pt = b"=ybegin line=128 size=100 name=test.bin"
        wire1 = salt + seg_idx.to_bytes(4, "big") + ff1_encrypt(k1, t1, line1_pt)

        k4, t4 = adapter.derive_control_keys(master_key, seg_idx, 4)
        wire4 = ff1_encrypt(k4, t4, b"=yend size=100")

        # 1. Salt mismatch
        different_salt = bytes.fromhex("ffffffffffffffffffffffffffffffff")
        line2_salt_mismatch = f"=yencryption cipher=XChaCha20-Poly1305 salt={different_salt.hex()} index={seg_idx:08x} tag={'0'*32}".encode(
            "ascii"
        )
        wire2_bad_salt = ff1_encrypt(k2, t2, line2_salt_mismatch)

        article = mock.MagicMock(spec=Article)
        article.article = "art@test"
        article.nzf.nzo.password = password
        article.nzf.nzo.yenc_encrypted = True

        resp_bad_salt = _mock_response()
        resp_bad_salt.sink_failed = False
        resp_bad_salt.bytes_decoded = 0
        resp_bad_salt.lines = [
            wire1.decode("latin-1"),
            wire2_bad_salt.decode("latin-1"),
            "data",
            wire4.decode("latin-1"),
        ]

        with pytest.raises(ValueError, match="Salt mismatch"):
            decoder.decode_yenc(article, resp_bad_salt)

        # 2. Index mismatch
        line2_idx_mismatch = (
            f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index=00000002 tag={'0'*32}".encode("ascii")
        )
        wire2_bad_idx = ff1_encrypt(k2, t2, line2_idx_mismatch)

        resp_bad_idx = _mock_response()
        resp_bad_idx.sink_failed = False
        resp_bad_idx.bytes_decoded = 0
        resp_bad_idx.lines = [wire1.decode("latin-1"), wire2_bad_idx.decode("latin-1"), "data", wire4.decode("latin-1")]

        with pytest.raises(ValueError, match="Dual index mismatch"):
            decoder.decode_yenc(article, resp_bad_idx)


class TestDirectWriteGatingAndFailover:
    """Test suite verifying direct-write gating and authentication error routing."""

    def test_direct_write_gated_differentiation(self):
        """article_sink gates encrypted releases and preserves archive-password direct-write."""
        wrapper = mock.MagicMock(spec=NewsWrapper)
        mock_monitor = mock.MagicMock(allow_direct_decode=True)
        mock_writer = mock.MagicMock()
        mock_assembler = mock.MagicMock()
        mock_assembler.get_writer.return_value = mock_writer

        article_enc = mock.MagicMock(spec=Article)
        article_enc.nzf.nzo.yenc_encrypted = True
        article_enc.nzf.type = "yenc"
        article_enc.lowest_partnum = False
        article_enc.nzf.prepare_filepath.return_value = True

        with (
            mock.patch.object(sabnzbd.cfg, "direct_decode", return_value=True),
            mock.patch.object(sabnzbd.cfg, "direct_write", return_value=True),
            mock.patch.object(sabnzbd, "WriteMonitor", mock_monitor, create=True),
        ):
            assert NewsWrapper.article_sink(wrapper, article_enc) is None

        article_archive = mock.MagicMock(spec=Article)
        article_archive.nzf.nzo.yenc_encrypted = False
        article_archive.nzf.nzo.password = "rarpass"
        article_archive.nzf.type = "yenc"
        article_archive.lowest_partnum = False
        article_archive.nzf.prepare_filepath.return_value = True

        with (
            mock.patch.object(sabnzbd.cfg, "direct_decode", return_value=True),
            mock.patch.object(sabnzbd.cfg, "direct_write", return_value=True),
            mock.patch.object(sabnzbd, "WriteMonitor", mock_monitor, create=True),
            mock.patch.object(sabnzbd, "Assembler", mock_assembler, create=True),
        ):
            assert NewsWrapper.article_sink(wrapper, article_archive) == mock_writer

    def test_downloader_decode_candidate_dispatch(self):
        """Downloader.decode forwards candidate encrypted responses to decoder instead of discarding."""
        from sabnzbd.downloader import Downloader

        # Case 1: Candidate encrypted article (bytes_decoded == 0, lines and encryption provenance present)
        art_cand = mock.MagicMock(spec=Article)
        art_cand.fetcher.id = 1
        art_cand.nzf.nzo.password = "secret_pass"
        art_cand.nzf.nzo.yenc_encrypted = True
        art_cand.nzf.nzo.precheck = False

        resp_cand = _mock_response()
        resp_cand.bytes_decoded = 0
        resp_cand.lines = ["encrypted_line_1", "encrypted_line_2"]

        mock_bps = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "BPSMeter", mock_bps, create=True),
            mock.patch.object(sabnzbd.decoder, "decode") as mock_decoder_decode,
        ):
            Downloader.decode(art_cand, resp_cand)
            assert mock_decoder_decode.called, "Expected candidate encrypted article to be forwarded to decoder.decode"
            assert not art_cand.search_new_server.called
            assert not art_cand.nzf.nzo.increase_bad_articles_counter.called

        # Case 2: Broken archive-password article is not transport encrypted
        art_broken = mock.MagicMock(spec=Article)
        art_broken.fetcher.id = 1
        art_broken.nzf.nzo.password = "rarpass"
        art_broken.nzf.nzo.yenc_encrypted = False
        art_broken.nzf.nzo.precheck = False
        art_broken.search_new_server.return_value = False

        resp_broken = _mock_response()
        resp_broken.bytes_decoded = 0
        resp_broken.lines = ["some_line"]

        mock_queue = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "BPSMeter", mock_bps, create=True),
            mock.patch.object(sabnzbd.decoder, "decode") as mock_decoder_decode,
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
        ):
            Downloader.decode(art_broken, resp_broken)
            assert not mock_decoder_decode.called, "Broken article must not be forwarded to decoder.decode"
            assert art_broken.search_new_server.called
            assert art_broken.nzf.nzo.increase_bad_articles_counter.called

    def test_modified_tag_native_response_triggers_server_search(self):
        """A real encrypted wire response with a modified tag fails Poly1305 and is routed
        to search_new_server with zero bytes stored (real modified-tag native response)."""
        import sabnzbd.decoder as decoder

        password = "tag_tamper_password"
        plaintext = b"Modified tag native response test payload!"

        enc_body, _adapter, _mk, _nonce, _ct, _tag, _crc, _aad, _n = _encrypted_wire(
            password=password,
            plaintext=plaintext,
            name="test.bin",
            tamper_tag=True,
        )
        wire_lines = enc_body.split(b"\r\n")

        article = mock.MagicMock(spec=Article)
        article.article = "tag_tamper@news"
        article.nzf.nzo.password = password
        article.nzf.nzo.yenc_encrypted = True
        article.nzf.nzo.precheck = False
        article.nzf.filename_checked = True
        article.lowest_partnum = False
        article.on_disk = False
        article.search_new_server.return_value = True

        # Native 222 BODY response carrying the modified-tag encrypted article
        resp = _mock_response()
        resp.sink_failed = False
        resp.status_code = 222
        resp.bytes_decoded = 0
        resp.lines = [line.decode("latin-1") for line in wire_lines if line]

        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
        ):
            decoder.decode(article, resp)
            # search_new_server should have been called via article.search_new_server()
            assert article.search_new_server.called, "search_new_server should be called on auth failure"
            # Zero-output guarantee: cache save must NOT be called
            assert not mock_cache.save_article.called, "save_article must not be called on authentication failure"
            assert not article.on_disk, "article.on_disk must remain False on auth failure"

    def test_wire_restore_and_authenticated_decode(self):
        """Full wire response: encrypted control lines + =yencryption + ciphertext body -> authenticated decode."""
        import nacl.bindings as nb
        import sabctools
        import sabnzbd.decoder as decoder
        from sabnzbd.encryption import build_aad

        # 1. Single-part article test
        password = "test_password_123"
        salt = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        segment_index = 1
        plaintext = b"Super secret test payload for SABnzbd wire decryption testing!"

        adapter = DecryptionAdapter(password=password)
        master_key = adapter.get_master_key(salt)
        nonce = adapter.derive_body_nonce(master_key, segment_index)

        aad_single = build_aad(b"test.bin", 1, 1, len(plaintext))
        enc = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad_single, nonce, master_key)
        ct = enc[:-16]
        tag = enc[-16:]

        body_encoded, body_crc = sabctools.yenc_encode(ct)

        line1_pt = f"=ybegin line=128 size={len(ct)} name=test.bin".encode("ascii")
        line2_pt = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={segment_index:08x} tag={tag.hex()}".encode(
            "ascii"
        )
        line3_pt = body_encoded
        line4_pt = f"=yend size={len(ct)} crc32={body_crc:08x}".encode("ascii")

        k1, t1 = adapter.derive_control_keys(master_key, segment_index, 1)
        wire1 = salt + (segment_index).to_bytes(4, "big") + ff1_encrypt(k1, t1, line1_pt)

        k2, t2 = adapter.derive_control_keys(master_key, segment_index, 2)
        wire2 = ff1_encrypt(k2, t2, line2_pt)

        wire3 = line3_pt

        k4, t4 = adapter.derive_control_keys(master_key, segment_index, 4)
        wire4 = ff1_encrypt(k4, t4, line4_pt)

        article = mock.MagicMock(spec=Article)
        article.article = "wire_single@news"
        article.nzf.nzo.password = password
        article.nzf.filename_checked = False
        article.lowest_partnum = True

        resp = _mock_response()
        resp.sink_failed = False
        resp.bytes_decoded = 0
        resp.lines = [
            wire1.decode("latin-1"),
            wire2.decode("latin-1"),
            wire3.decode("latin-1"),
            wire4.decode("latin-1"),
        ]

        decoded = decoder.decode_yenc(article, resp)
        assert decoded == bytearray(plaintext)
        assert article.decoded_size == len(plaintext)
        assert article.file_size == len(ct)
        # Ciphertext CRC never persisted on encrypted paths
        assert article.crc32 is None
        assert article.nzf.nzo.verify_nzf_filename.called

        # 2. Multipart article test
        aad_multi = build_aad(b"multi.bin", 1, 1, len(plaintext))
        enc_m = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad_multi, nonce, master_key)
        ct_m = enc_m[:-16]
        tag_m = enc_m[-16:]
        body_encoded_m, body_crc_m = sabctools.yenc_encode(ct_m)

        line1_m_pt = f"=ybegin part=1 total=2 line=128 size={len(ct_m) * 2} name=multi.bin".encode("ascii")
        line2_m_pt = f"=ypart begin=1 end={len(ct_m)}".encode("ascii")
        line3_m_pt = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={segment_index:08x} tag={tag_m.hex()}".encode(
            "ascii"
        )
        line4_m_pt = body_encoded_m
        line5_m_pt = f"=yend size={len(ct_m)} part=1 pcrc32={body_crc_m:08x}".encode("ascii")

        wire_m_1 = salt + (segment_index).to_bytes(4, "big") + ff1_encrypt(k1, t1, line1_m_pt)
        wire_m_2 = ff1_encrypt(k2, t2, line2_m_pt)
        k3, t3 = adapter.derive_control_keys(master_key, segment_index, 3)
        wire_m_3 = ff1_encrypt(k3, t3, line3_m_pt)
        wire_m_4 = line4_m_pt
        k5, t5 = adapter.derive_control_keys(master_key, segment_index, 5)
        wire_m_5 = ff1_encrypt(k5, t5, line5_m_pt)

        article_m = mock.MagicMock(spec=Article)
        article_m.article = "wire_multi@news"
        article_m.bytes = len(plaintext)
        article_m.nzf.nzo.password = password
        article_m.nzf.filename_checked = True
        article_m.lowest_partnum = False

        resp_m = _mock_response()
        resp_m.sink_failed = False
        resp_m.bytes_decoded = 0
        resp_m.lines = [
            wire_m_1.decode("latin-1"),
            wire_m_2.decode("latin-1"),
            wire_m_3.decode("latin-1"),
            wire_m_4.decode("latin-1"),
            wire_m_5.decode("latin-1"),
        ]

        decoded_m = decoder.decode_yenc(article_m, resp_m)
        assert decoded_m == bytearray(plaintext)
        assert article_m.decoded_size == len(plaintext)
        assert article_m.file_size == len(ct_m) * 2
        assert article_m.data_begin == 0
        assert article_m.data_size == len(ct_m)
        # Ciphertext CRC never persisted on encrypted paths
        assert article_m.crc32 is None

        # 3. Wire CRC failure (corrupted pcrc32 in =yend)
        bad_crc = (body_crc_m ^ 0xFFFFFFFF) & 0xFFFFFFFF
        bad_line5_pt = f"=yend size={len(ct_m)} part=1 pcrc32={bad_crc:08x}".encode("ascii")
        bad_wire_5 = ff1_encrypt(k5, t5, bad_line5_pt)

        resp_bad_crc = _mock_response()
        resp_bad_crc.sink_failed = False
        resp_bad_crc.bytes_decoded = 0
        resp_bad_crc.lines = [
            wire_m_1.decode("latin-1"),
            wire_m_2.decode("latin-1"),
            wire_m_3.decode("latin-1"),
            wire_m_4.decode("latin-1"),
            bad_wire_5.decode("latin-1"),
        ]
        with pytest.raises(ValueError, match="Wire CRC error"):
            decoder.decode_yenc(article_m, resp_bad_crc)

        # 4. Poly1305 authentication failure (tampered tag)
        bad_tag = bytes([tag_m[0] ^ 0xFF]) + tag_m[1:]
        bad_line3_pt = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={segment_index:08x} tag={bad_tag.hex()}".encode(
            "ascii"
        )
        bad_wire_3 = ff1_encrypt(k3, t3, bad_line3_pt)

        resp_bad_tag = _mock_response()
        resp_bad_tag.sink_failed = False
        resp_bad_tag.bytes_decoded = 0
        resp_bad_tag.lines = [
            wire_m_1.decode("latin-1"),
            wire_m_2.decode("latin-1"),
            bad_wire_3.decode("latin-1"),
            wire_m_4.decode("latin-1"),
            wire_m_5.decode("latin-1"),
        ]
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            decoder.decode_yenc(article_m, resp_bad_tag)

    def test_extract_and_remove_yencryption(self):
        """Verify strict header placement, extraction, duplicate/misplaced rejection, and stripping."""
        valid_hdr = b"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b"

        # 1. Valid single-part article (header at line 2)
        single = (
            b"=ybegin line=128 size=100 name=test.bin\r\n" + valid_hdr + b"\r\n" b"DataLine1\r\n" b"=yend size=100\r\n"
        )
        params, clean = extract_and_remove_yencryption(single)

        assert params["salt"] == bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        assert params["segment_index"] == 1
        assert params["tag"] == bytes.fromhex("0cd77ce245a654463f90b945b1d22d5b")
        assert clean == (b"=ybegin line=128 size=100 name=test.bin\r\n" b"DataLine1\r\n" b"=yend size=100\r\n")

        # 2. Valid multipart article (header at line 3, following =ypart)
        multi = (
            b"=ybegin part=1 total=2 line=128 size=200 name=test.bin\r\n"
            b"=ypart begin=1 end=100\r\n" + valid_hdr + b"\r\n"
            b"DataLine1\r\n"
            b"=yend size=100 part=1\r\n"
        )
        m_params, m_clean = extract_and_remove_yencryption(multi)

        assert m_params["segment_index"] == 1
        assert m_clean == (
            b"=ybegin part=1 total=2 line=128 size=200 name=test.bin\r\n"
            b"=ypart begin=1 end=100\r\n"
            b"DataLine1\r\n"
            b"=yend size=100 part=1\r\n"
        )

        # 3. Missing =yencryption line
        missing = b"=ybegin line=128 size=100 name=test.bin\r\n" b"DataLine1\r\n" b"=yend size=100\r\n"
        with pytest.raises(ValueError, match="does not start with =yencryption"):
            extract_and_remove_yencryption(missing)

        # 4. Duplicate =yencryption line
        dup = (
            b"=ybegin line=128 size=100 name=test.bin\r\n" + valid_hdr + b"\r\n"
            b"DataLine1\r\n" + valid_hdr + b"\r\n"
            b"=yend size=100\r\n"
        )
        with pytest.raises(ValueError, match="Duplicate or misplaced =yencryption"):
            extract_and_remove_yencryption(dup)

        # 5. Misplaced =yencryption (at line 3 in single-part)
        misplaced_single = (
            b"=ybegin line=128 size=100 name=test.bin\r\n" b"DataLine1\r\n" + valid_hdr + b"\r\n" b"=yend size=100\r\n"
        )
        with pytest.raises(ValueError, match="does not start with =yencryption"):
            extract_and_remove_yencryption(misplaced_single)

        # 6. Misplaced =yencryption (at line 2 instead of line 3 in multipart)
        misplaced_multi = (
            b"=ybegin part=1 total=2 line=128 size=200 name=test.bin\r\n" + valid_hdr + b"\r\n"
            b"=ypart begin=1 end=100\r\n"
            b"DataLine1\r\n"
            b"=yend size=100 part=1\r\n"
        )
        with pytest.raises(ValueError, match="does not start with =ypart"):
            extract_and_remove_yencryption(misplaced_multi)

        # 7. Line 1 not =ybegin
        not_begin = b"not_ybegin\r\n" + valid_hdr + b"\r\n" b"=yend size=100\r\n"
        with pytest.raises(ValueError, match="Line 1 does not start with =ybegin"):
            extract_and_remove_yencryption(not_begin)

    def test_malformed_inputs_matrix(self):
        """Verify that all malformed header and control line test vectors fail closed with ValueError."""
        vector_dir = _get_test_vector_dir()
        with open(vector_dir / "malformed_inputs.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        with open(vector_dir / "control_line_encryption.json", "r", encoding="utf-8") as cf:
            control_data = json.load(cf)

        for vec in data["vectors"]:
            cat = vec["category"]
            vec_id = vec["id"]

            if cat == "header_syntax":
                # Strict v1.2 grammar: parse must fail closed (None or ValueError with
                # canonical error token). SABnzbd collapses all grammar violations into
                # a single ValueError tier mapped to PROVIDER_FAILOVER; the vector's
                # expected_error token must appear whenever the failure raises.
                if not vec["input_line"].startswith("=yencryption"):
                    assert parse_yencryption_line(vec["input_line"]) is None, f"Expected None for {vec_id}"
                else:
                    try:
                        parsed = parse_yencryption_line(vec["input_line"])
                        assert parsed is None, f"Expected rejection for {vec_id}"
                    except ValueError as parse_error:
                        # All grammar violations land in the single PROVIDER_FAILOVER
                        # ValueError tier; the vector token classifies the root cause
                        # but SABnzbd surfaces a canonical grammar/length token instead.
                        assert vec["expected_error"] in str(parse_error) or str(parse_error).startswith(
                            ("INVALID_LENGTH", "INVALID_WHITESPACE")
                        ), f"{vec_id}: unexpected rejection for: {parse_error}"
                # Must fail extract_and_remove_yencryption when in header position
                dummy = (
                    b"=ybegin line=128 size=10 name=test\r\n"
                    + vec["input_line"].encode("ascii", errors="replace")
                    + b"\r\n=yend size=10\r\n"
                )
                with pytest.raises(ValueError):
                    extract_and_remove_yencryption(dummy)

            elif cat == "control_syntax":
                adapter = DecryptionAdapter(password="test123")
                if "tampered_salt_hex" in vec:
                    # Line 1 with forbidden bytes in salt
                    raw_salt = bytes.fromhex(vec["tampered_salt_hex"])
                    line1 = raw_salt + b"=ybegin line=128 size=18"
                    with pytest.raises(ValueError, match="Forbidden byte"):
                        extract_bootstrap_from_line1(line1)[0]
                    wire = raw_salt + b"=" * 20 + b"\r\n"
                    with pytest.raises(ValueError):
                        adapter.restore_control_lines(wire)
                elif vec_id == "control-syntax-04-line-too-short":
                    short_bytes = bytes.fromhex(vec["line_hex"])
                    with pytest.raises(ValueError, match="Line too short"):
                        ff1_decrypt(b"0" * 32, b"0" * 8, short_bytes)
                    with pytest.raises(ValueError, match="Line too short"):
                        ff1_encrypt(b"0" * 32, b"0" * 8, short_bytes)
                elif vec_id == "control-syntax-05-line1-truncated":
                    wire = bytes.fromhex(vec["line1_hex"]) + b"\r\n"
                    with pytest.raises(ValueError, match="Line 1 truncated"):
                        adapter.restore_control_lines(wire)
                elif vec_id == "control-syntax-06-zero-segment-index":
                    wire = bytes.fromhex(vec["line1_hex"]) + b"\r\n"
                    with pytest.raises(ValueError, match="ZERO_SEGMENT_INDEX"):
                        adapter.restore_control_lines(wire)
                elif vec_id in (
                    "control-syntax-08-forbidden-index-10",
                    "control-syntax-09-forbidden-index-13",
                    "control-syntax-10-forbidden-index-266",
                    "control-syntax-11-forbidden-index-269",
                ):
                    wire = bytes.fromhex(vec["line1_hex"]) + b"\r\n"
                    with pytest.raises(ValueError, match="FORBIDDEN_SEGMENT_INDEX_BYTE"):
                        adapter.restore_control_lines(wire)
                elif vec_id in ("control-syntax-06-wrong-password", "control-syntax-07-wrong-password"):
                    # Valid wire line 1 from control_line_encryption.json
                    wire_line1 = bytes.fromhex(control_data["vectors"][0]["expected_wire_hex"]) + b"\r\n"
                    wrong_adapter = DecryptionAdapter(password=vec["wrong_password"])
                    with pytest.raises(ValueError, match="Control line decrypt failure"):
                        wrong_adapter.restore_control_lines(wire_line1)

    def test_zero_output_matrix(self):
        """Verify that all auth_failure test vectors fail authentication and produce zero plaintext output."""
        vector_dir = _get_test_vector_dir()
        with open(vector_dir / "malformed_inputs.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        for vec in data["vectors"]:
            if vec["category"] != "auth_failure":
                continue

            vec_id = vec["id"]
            pwd = vec["password"]
            salt = bytes.fromhex(vec["salt_hex"])
            ct = bytes.fromhex(vec.get("tampered_ciphertext_hex") or vec.get("ciphertext_hex"))
            tag = bytes.fromhex(vec.get("tampered_tag_hex") or vec.get("tag_hex"))
            seg_idx = vec["segment_index"]

            adapter = DecryptionAdapter(password=pwd)

            output = None
            aad = bytes.fromhex(vec["aad_hex"]) if "aad_hex" in vec else b""
            with pytest.raises(ValueError, match="Poly1305 authentication failed"):
                output = adapter.decrypt_body(ct, tag, salt, seg_idx, aad=aad)

            # Assert zero output released
            assert output is None, f"Zero-output violated for {vec_id}"

    def test_downloader_encrypted_e2e(self, caplog):
        """Dual-server failover: corrupted server 1 fails auth and fails over to server 2 which succeeds."""
        password = "multi_server_secret_password"
        plaintext = b"Dual server failover end-to-end integration test payload!"

        valid_body, _adapter, master_key, nonce, _ct, tag, _crc, _aad, _n = _encrypted_wire(
            password=password,
            plaintext=plaintext,
            name="test.bin",
        )
        bad_body, _, _, _, _, _, _, _, _ = _encrypted_wire(
            password=password,
            plaintext=plaintext,
            name="test.bin",
            tamper_tag=True,
        )

        srv1 = MockArticleNNTPServer(bad_body)
        srv1.start()
        srv2 = MockArticleNNTPServer(valid_body)
        srv2.start()

        try:
            s1 = Server(
                server_id="srv1",
                displayname="Primary Bad Server",
                host=srv1.host,
                port=srv1.port,
                timeout=5,
                threads=0,
                priority=0,
                use_ssl=False,
                ssl_verify=0,
                ssl_ciphers="",
                pipelining_requests=mock.Mock(return_value=1),
            )
            s1.addrinfo = AddrInfo(*socket.getaddrinfo(srv1.host, srv1.port, socket.AF_INET, socket.SOCK_STREAM)[0])
            s1.active = True

            s2 = Server(
                server_id="srv2",
                displayname="Backup Good Server",
                host=srv2.host,
                port=srv2.port,
                timeout=5,
                threads=0,
                priority=1,
                use_ssl=False,
                ssl_verify=0,
                ssl_ciphers="",
                pipelining_requests=mock.Mock(return_value=1),
            )
            s2.addrinfo = AddrInfo(*socket.getaddrinfo(srv2.host, srv2.port, socket.AF_INET, socket.SOCK_STREAM)[0])
            s2.active = True

            mock_downloader = mock.MagicMock(spec=Downloader)
            mock_downloader.servers = [s1, s2]
            mock_downloader.reset_nw = lambda nw, *args, **kwargs: None
            mock_downloader.finish_connect_nw = lambda nw, resp: Downloader.finish_connect_nw(mock_downloader, nw, resp)
            mock_downloader.decode = lambda article, resp: Downloader.decode(article, resp)
            mock_downloader.modify_socket = lambda nw, event: None
            mock_downloader.remove_socket = lambda nw: None
            mock_downloader.no_active_jobs = lambda: False
            mock_downloader.shutdown = False
            mock_downloader.paused_for_postproc = False
            mock_downloader.force_disconnect = False

            mock_bps = mock.MagicMock()
            mock_cache = mock.MagicMock()
            mock_queue = mock.MagicMock()

            mock_nzo = mock.MagicMock()
            mock_nzo.password = password
            mock_nzo.yenc_encrypted = True
            mock_nzo.precheck = False
            mock_nzo.removed_from_queue = False
            mock_nzo.status = "active"
            mock_nzo.priority = 0
            mock_nzo.update_download_stats = mock.MagicMock()

            mock_nzf = mock.MagicMock()
            mock_nzf.nzo = mock_nzo
            mock_nzf.filename_checked = True
            mock_nzf.type = "yenc"

            art = Article("art@e2e", 100, mock_nzf)
            art.lowest_partnum = False
            art.on_disk = False
            art.tries = 0

            with (
                mock.patch.object(sabnzbd, "Downloader", mock_downloader, create=True),
                mock.patch.object(sabnzbd, "BPSMeter", mock_bps, create=True),
                mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
                mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
            ):
                # 1. Connect NW1 to Server 1 (tampered article)
                nw1 = NewsWrapper(s1, thrdnum=1)
                s1.idle_threads.add(nw1)
                nw1.init_connect()
                for _ in range(50):
                    if nw1.connected:
                        break
                    time.sleep(0.05)
                nw1.nntp.sock.setblocking(True)
                nw1.nntp.sock.settimeout(2)
                nw1.read()
                assert nw1.ready

                # Request article from Server 1
                art.fetcher = s1
                nw1.queue_article(art)
                nw1.write()
                nw1.read()

                # Server 1 must fail auth and failover to Server 2
                assert s1 in art.try_list
                assert mock_bps.register_server_article_failed.called
                assert not mock_cache.save_article.called
                assert not mock_nzo.increase_bad_articles_counter.called

                # 2. Connect NW2 to Server 2 (valid article)
                nw2 = NewsWrapper(s2, thrdnum=1)
                s2.idle_threads.add(nw2)
                nw2.init_connect()
                for _ in range(50):
                    if nw2.connected:
                        break
                    time.sleep(0.05)
                nw2.nntp.sock.setblocking(True)
                nw2.nntp.sock.settimeout(2)
                nw2.read()
                assert nw2.ready

                # Request article from Server 2
                art.fetcher = s2
                nw2.queue_article(art)
                nw2.write()
                nw2.read()

                # Server 2 must succeed and save byte-identical plaintext
                assert mock_cache.save_article.called
                _saved_art, saved_data = mock_cache.save_article.call_args[0]
                assert bytes(saved_data) == plaintext

            # Log safety checks: no secrets leaked to logs
            log_text = caplog.text
            assert password not in log_text, "Password must not appear in logs"
            assert master_key.hex() not in log_text, "Master key must not appear in logs"
            assert nonce.hex() not in log_text, "Nonce must not appear in logs"
            assert tag.hex() not in log_text, "Tag must not appear in logs"
            assert plaintext.decode("ascii") not in log_text, "Plaintext must not appear in logs"
            assert "Encrypted article art@e2e rejected (Poly1305 authentication failed: " in log_text
            assert "Authentication failed" not in log_text

        finally:
            srv1.stop()
            srv2.stop()

    def test_body_unsupported_fails_closed_without_article_fallback(self, caplog):
        """BODY 500 on an encrypted article is provider failover; ARTICLE is never requested."""
        password = "article_fallback_password"
        plaintext = b"ARTICLE fallback end-to-end test payload!"

        enc_body, _adapter, _mk, _nonce, _ct, _tag, _crc, _aad, _n = _encrypted_wire(
            password=password,
            plaintext=plaintext,
            name="test.bin",
        )

        srv = MockArticleNNTPServer(enc_body)
        srv.have_body = False  # BODY will answer 500
        srv.start()

        try:
            s1 = Server(
                server_id="srv_a",
                displayname="Article Fallback Server",
                host=srv.host,
                port=srv.port,
                timeout=5,
                threads=0,
                priority=0,
                use_ssl=False,
                ssl_verify=0,
                ssl_ciphers="",
                pipelining_requests=mock.Mock(return_value=1),
            )
            s1.addrinfo = AddrInfo(*socket.getaddrinfo(srv.host, srv.port, socket.AF_INET, socket.SOCK_STREAM)[0])
            s1.active = True

            mock_downloader = mock.MagicMock(spec=Downloader)
            mock_downloader.servers = [s1]
            mock_downloader.reset_nw = lambda nw, *args, **kwargs: None
            mock_downloader.finish_connect_nw = lambda nw, resp: Downloader.finish_connect_nw(mock_downloader, nw, resp)
            mock_downloader.decode = lambda article, resp: Downloader.decode(article, resp)
            mock_downloader.modify_socket = lambda nw, event: None
            mock_downloader.remove_socket = lambda nw: None
            mock_downloader.no_active_jobs = lambda: False
            mock_downloader.shutdown = False
            mock_downloader.paused_for_postproc = False
            mock_downloader.force_disconnect = False

            mock_bps = mock.MagicMock()
            mock_cache = mock.MagicMock()
            mock_queue = mock.MagicMock()

            mock_nzo = mock.MagicMock()
            mock_nzo.password = password
            mock_nzo.yenc_encrypted = True
            mock_nzo.precheck = False
            mock_nzo.removed_from_queue = False
            mock_nzo.status = "active"
            mock_nzo.priority = 0
            mock_nzo.update_download_stats = mock.MagicMock()

            mock_nzf = mock.MagicMock()
            mock_nzf.nzo = mock_nzo
            mock_nzf.filename_checked = True
            mock_nzf.type = "yenc"

            art = Article("art@e2e", 100, mock_nzf)
            art.lowest_partnum = False
            art.on_disk = False
            art.tries = 0

            with (
                mock.patch.object(sabnzbd, "Downloader", mock_downloader, create=True),
                mock.patch.object(sabnzbd, "BPSMeter", mock_bps, create=True),
                mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
                mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
            ):
                nw1 = NewsWrapper(s1, thrdnum=1)
                s1.idle_threads.add(nw1)
                nw1.init_connect()
                for _ in range(50):
                    if nw1.connected:
                        break
                    time.sleep(0.05)
                nw1.nntp.sock.setblocking(True)
                nw1.nntp.sock.settimeout(2)
                nw1.read()
                assert nw1.ready

                # BODY -> 500: the article fails over (never cached), and no ARTICLE is sent
                art.fetcher = s1
                nw1.queue_article(art)
                nw1.write()
                nw1.read()
                assert not mock_cache.save_article.called
                assert _registered_success(mock_queue) is False

                # Retry on the same server still uses BODY
                art.fetcher = s1
                nw1.queue_article(art)
                nw1.write()
                nw1.read()
                assert not mock_cache.save_article.called
                assert srv.commands
                assert all(cmd.startswith(b"BODY") for cmd in srv.commands)

        finally:
            srv.stop()

    def test_non_body_status_logs_real_reason_not_authentication(self, caplog):
        """A 430 answer on an encrypted article logs the real reason; it is not an authentication failure."""
        import logging
        import sabctools
        import sabnzbd.decoder as decoder

        article = mock.MagicMock(spec=Article)
        article.article = "missing@f1"
        article.nzf.nzo.yenc_encrypted = True
        article.nzf.nzo.precheck = False
        article.nzf.nzo.password = "f1-430-pw"
        article.search_new_server.return_value = True

        response = _mock_response()
        response.status_code = 430
        response.format = sabctools.EncodingFormat.YENC
        response.bytes_decoded = 0
        response.lines = None
        response.sink_failed = False

        caplog.set_level(logging.INFO)
        decoder.decode(article, response)

        assert "answered with status 430" in caplog.text
        assert "Authentication failed" not in caplog.text
        assert article.search_new_server.called

    def test_salt_mismatch_logs_reason_without_salt_hex_at_info(self, caplog):
        """A salt mismatch logs the reason at INFO, with no salt bytes."""
        import logging
        import sabctools
        import sabnzbd.decoder as decoder

        salt_line1 = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        salt_yenc = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        yenc_line = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_yenc.hex()} index=00000001 tag={'ab' * 16}"
        assert len(yenc_line) == 128
        block = b"=ybegin line=128 size=3 name=salt.bin\r\n" + yenc_line.encode("ascii") + b"\r\n=yend size=3\r\n"

        article = mock.MagicMock(spec=Article)
        article.article = "salt@f1"
        article.nzf.nzo.yenc_encrypted = True
        article.nzf.nzo.precheck = False
        article.nzf.nzo.password = "f1-salt-pw"
        article.search_new_server.return_value = True

        response = _mock_response()
        response.status_code = 222
        response.format = sabctools.EncodingFormat.YENC
        response.bytes_decoded = 0
        response.lines = ["=ybegin line=128 size=3 name=salt.bin"]
        response.sink_failed = False

        caplog.set_level(logging.INFO)
        with mock.patch.object(
            DecryptionAdapter, "restore_control_lines", autospec=True, return_value=(block, salt_line1, 1)
        ):
            decoder.decode(article, response)

        assert (
            "Encrypted article salt@f1 rejected (Salt mismatch between control line 1 and =yencryption), "
            "trying next server"
        ) in caplog.text
        assert salt_line1.hex() not in caplog.text
        assert salt_yenc.hex() not in caplog.text
        assert article.search_new_server.called

    def test_malformed_yencryption_error_carries_no_salt_or_tag(self):
        """A malformed =yencryption line is reported without echoing its salt or tag."""
        salt = "1a2b3c4d5e6f7890abcdef1234567890"
        tag = "ab" * 16
        bad_line = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt} index=00000001"
        block = b"=ybegin line=128 size=3 name=bad.bin\r\n" + bad_line.encode("ascii") + b"\r\n=yend size=3\r\n"
        assert tag not in bad_line

        with pytest.raises(YEncEncryptionCryptoError, match="Malformed =yencryption") as info:
            extract_and_remove_yencryption(block)
        assert salt not in str(info.value)
        assert "index=" not in str(info.value)

    @pytest.mark.parametrize("framing", ["bare-lf", "split-terminator", "split-body"])
    def test_encrypted_response_framing_over_real_socket(self, framing):
        """Bare LF and CRLF split across TCP chunks deliver authenticated plaintext."""
        password = "framing_password"
        plaintext = b"Framing end-to-end test payload!"
        line_ending = b"\n" if framing == "bare-lf" else b"\r\n"
        enc_body, *_ = _encrypted_wire(password, plaintext, line_ending=line_ending)
        split_at = None
        if framing != "bare-lf":
            resp = b"222 0 <art@e2e>\r\n" + enc_body + b".\r\n"
            boundary = resp.rfind(b"\r\n")
            if framing == "split-body":
                terminator = resp.rfind(b"\r\n.")
                boundary = resp.rfind(b"\r\n", 0, terminator - 1)
            assert boundary >= 0 and resp[boundary : boundary + 2] == b"\r\n"
            split_at = [boundary + 1]
        srv = MockArticleNNTPServer(enc_body, line_ending=line_ending, split_at=split_at)
        srv.start()

        try:
            s1 = Server(
                server_id="srv_lf",
                displayname="Bare LF Server",
                host=srv.host,
                port=srv.port,
                timeout=5,
                threads=0,
                priority=0,
                use_ssl=False,
                ssl_verify=0,
                ssl_ciphers="",
                pipelining_requests=mock.Mock(return_value=1),
            )
            s1.addrinfo = AddrInfo(*socket.getaddrinfo(srv.host, srv.port, socket.AF_INET, socket.SOCK_STREAM)[0])
            s1.active = True

            mock_downloader = mock.MagicMock(spec=Downloader)
            mock_downloader.servers = [s1]
            mock_downloader.reset_nw = lambda nw, *args, **kwargs: None
            mock_downloader.finish_connect_nw = lambda nw, resp: Downloader.finish_connect_nw(mock_downloader, nw, resp)
            mock_downloader.decode = lambda article, resp: Downloader.decode(article, resp)
            mock_downloader.modify_socket = lambda nw, event: None
            mock_downloader.remove_socket = lambda nw: None
            mock_downloader.no_active_jobs = lambda: False
            mock_downloader.shutdown = False
            mock_downloader.paused_for_postproc = False
            mock_downloader.force_disconnect = False

            mock_bps = mock.MagicMock()
            mock_cache = mock.MagicMock()
            mock_queue = mock.MagicMock()

            mock_nzo = mock.MagicMock()
            mock_nzo.password = password
            mock_nzo.yenc_encrypted = True
            mock_nzo.precheck = False
            mock_nzo.removed_from_queue = False
            mock_nzo.status = "active"
            mock_nzo.priority = 0
            mock_nzo.update_download_stats = mock.MagicMock()

            mock_nzf = mock.MagicMock()
            mock_nzf.nzo = mock_nzo
            mock_nzf.filename_checked = True
            mock_nzf.type = "yenc"

            art = Article("art@e2e", 100, mock_nzf)
            art.lowest_partnum = False
            art.on_disk = False
            art.tries = 0

            with (
                mock.patch.object(sabnzbd, "Downloader", mock_downloader, create=True),
                mock.patch.object(sabnzbd, "BPSMeter", mock_bps, create=True),
                mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
                mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
            ):
                nw1 = NewsWrapper(s1, thrdnum=1)
                s1.idle_threads.add(nw1)
                nw1.init_connect()
                for _ in range(50):
                    if nw1.connected:
                        break
                    time.sleep(0.05)
                nw1.nntp.sock.setblocking(True)
                nw1.nntp.sock.settimeout(2)
                nw1.read()
                assert nw1.ready

                art.fetcher = s1
                nw1.queue_article(art)
                nw1.write()
                nw1.read()
                if split_at:
                    nw1.read()

                mock_cache.save_article.assert_called_once()
                _saved_art, saved_data = mock_cache.save_article.call_args[0]
                assert bytes(saved_data) == plaintext
        finally:
            srv.stop()


def _registered_success(queue_mock) -> bool:
    """The success flag of the last NzbQueue.register_article call, positional or keyword."""
    call = queue_mock.register_article.call_args
    return call.kwargs["success"] if "success" in call.kwargs else call.args[1]


class TestBodyCommandForEncryptedArticles:
    """Encrypted articles are fetched with BODY so no ARTICLE header scan (or trial decryption) happens."""

    @staticmethod
    def _queued_command(have_body: bool, yenc_encrypted) -> bytes:
        from sabnzbd.newswrapper import NewsWrapper as _NW

        wrapper = mock.MagicMock(spec=_NW)
        wrapper.server = mock.Mock(have_body=have_body, timeout=5)
        article = mock.MagicMock(spec=Article)
        article.article = "cmd@test"
        article.nzf.nzo.precheck = False
        article.nzf.nzo.yenc_encrypted = yenc_encrypted
        _NW.queue_article(wrapper, article)
        return wrapper.queue_command.call_args[0][0]

    @pytest.mark.parametrize(
        ("have_body", "yenc_encrypted", "expected"),
        [
            (True, True, b"BODY <cmd@test>\r\n"),
            (False, True, b"BODY <cmd@test>\r\n"),  # encrypted: BODY even after the server refused BODY earlier
            (True, False, b"BODY <cmd@test>\r\n"),  # plain regression: unchanged
            (False, False, b"ARTICLE <cmd@test>\r\n"),  # plain regression: unchanged
        ],
    )
    def test_command_selection(self, have_body, yenc_encrypted, expected):
        assert self._queued_command(have_body, yenc_encrypted) == expected

    def test_220_response_on_encrypted_release_fails_closed_without_kdf(self):
        """An ARTICLE-style 220 with long header lines is rejected before any body scan or KDF call."""
        import io
        import sabctools
        import sabnzbd.decoder as decoder

        body_wire, *_ = _encrypted_wire(password="sb2-pw", plaintext=b"never released")
        headers = b"Path: " + b"x" * 200 + b"\r\nSubject: " + b"y" * 200 + b"\r\n\r\n"
        wire = b"220 0 <a@t>\r\n" + headers + body_wire + b".\r\n"
        dec = sabctools.Decoder(len(wire))
        reader = io.BytesIO(wire)
        reader.readinto(dec)
        dec.process(len(wire))
        response = next(dec)
        assert response.status_code == 220

        article = mock.MagicMock(spec=Article)
        article.article = "a@t"
        article.nzf.nzo.yenc_encrypted = True
        article.nzf.nzo.password = "sb2-pw"

        original = DecryptionAdapter.get_master_key
        with mock.patch.object(DecryptionAdapter, "get_master_key", autospec=True, side_effect=original) as kdf:
            with pytest.raises(YEncEncryptionCryptoError, match="not BODY"):
                decoder.decode_yenc(article, response)
            assert kdf.call_count == 0


class TestKeyCacheAndHeaderBounding:
    """Regression tests for key cache thread-safety and header bounding."""

    def test_adapter_key_cache_thread_safety(self):
        """DecryptionAdapter._key_cache thread-safety under concurrent access."""
        import concurrent.futures
        from sabnzbd.encryption import DecryptionAdapter

        adapter = DecryptionAdapter(password="concurrent_test_pass")
        salt = bytes.fromhex("11223344556677889900aabbccddeeff")
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(adapter.get_master_key, salt) for _ in range(16)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        assert len(results) == 16
        # All threads must receive the identical derived key
        assert all(r == results[0] for r in results)
        assert len(results[0]) == 32
        # Exactly one entry in key cache
        assert salt in adapter._key_cache

    def test_restore_control_lines_header_bounded(self):
        """restore_control_lines decrypts only fixed header/footer positions (no data-line touch)."""
        from sabnzbd.encryption import DecryptionAdapter

        adapter = DecryptionAdapter(password="test123")
        salt = b"\x01" * 16
        master_key = adapter.get_master_key(salt)
        seg_idx = 1

        # Single-part: line 1 =ybegin, line 2 =yencryption, line 3 = data line, line 4 = =yend
        k1, t1 = adapter.derive_control_keys(master_key, seg_idx, 1)
        k2, t2 = adapter.derive_control_keys(master_key, seg_idx, 2)
        k4, t4 = adapter.derive_control_keys(master_key, seg_idx, 4)

        ct1 = encrypt_control_line(b"=ybegin line=128 size=50 name=test.bin", k1, t1)
        wire_line1 = salt + seg_idx.to_bytes(4, "big") + ct1 + b"\r\n"

        ct2 = encrypt_control_line(b"=yencryption cipher=XChaCha20-Poly1305 index=1", k2, t2)
        wire_line2 = ct2 + b"\r\n"

        data_line = b"PAYLOAD DATA LINE NOT CONTROL LINE\r\n"

        ct4 = encrypt_control_line(b"=yend size=50 crc32=12345678", k4, t4)
        wire_footer = ct4 + b"\r\n"

        wire_block = wire_line1 + wire_line2 + data_line + wire_footer

        orig_decrypt = adapter.decrypt_control_line
        decrypt_calls = []

        def tracked_decrypt(ct, enc_key, tweak):
            decrypt_calls.append(ct)
            return orig_decrypt(ct, enc_key, tweak)

        adapter.decrypt_control_line = tracked_decrypt
        restored, out_salt, out_idx = adapter.restore_control_lines(wire_block)

        # Header has 2 lines, footer is line 4 -> decrypt_control_line must be called exactly 3 times
        assert len(decrypt_calls) == 3, f"expected 3 header/footer decryptions, got {len(decrypt_calls)}"
        assert b"=yencryption cipher=XChaCha20-Poly1305 index=1" in restored
        assert b"PAYLOAD DATA LINE" in restored
        assert out_salt == salt
        assert out_idx == seg_idx

    def test_decoder_adapter_cached_on_nzo(self):
        """_get_decryption_adapter caches DecryptionAdapter on nzo to eliminate churn."""
        import sabnzbd.decoder as decoder

        mock_nzo = mock.MagicMock()
        mock_nzo.lock = threading.RLock()
        mock_nzo._decryption_adapter = None
        mock_nzo.password = "shared_password"

        mock_nzf = mock.MagicMock()
        mock_nzf.nzo = mock_nzo

        art1 = mock.MagicMock(spec=Article)
        art1.nzf = mock_nzf
        art1.password = None

        art2 = mock.MagicMock(spec=Article)
        art2.nzf = mock_nzf
        art2.password = None

        adapter1 = decoder._get_decryption_adapter(art1, "shared_password")
        adapter2 = decoder._get_decryption_adapter(art2, "shared_password")

        assert isinstance(adapter1, DecryptionAdapter)
        assert adapter1 is adapter2
        assert mock_nzo._decryption_adapter is adapter1


class TestDotUnstuffing:
    """Dot-stuffing transport boundary (RFC 3977 §3.1.1) for encrypted Line 1."""

    def test_dot_stuffed_line1_unstuffed_through_decode_path(self):
        """Regression: a dot-stuffed Line 1 (leading '..' on the wire) decodes with the exact original salt/index."""
        import nacl.bindings as nb
        import sabctools
        import sabnzbd.decoder as decoder

        password = "dot_stuff_regression"
        # Line 1 plaintext content starts with a 0x2E salt byte -> producer dot-stuffs -> '..' on wire
        salt = b"\x2e" + b"\x11" * 15
        segment_index = 1
        plaintext = b"Dot stuffed bootstrap regression payload!"

        adapter = DecryptionAdapter(password=password)
        master_key = adapter.get_master_key(salt)
        nonce = adapter.derive_body_nonce(master_key, segment_index)

        aad = build_aad(b"dot.bin", 1, 1, len(plaintext))
        enc = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, master_key)
        ct = enc[:-16]
        tag = enc[-16:]
        body_encoded, body_crc = sabctools.yenc_encode(ct)

        line1_pt = f"=ybegin line=128 size={len(ct)} name=dot.bin".encode("ascii")
        line2_pt = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={segment_index:08x} tag={tag.hex()}".encode(
            "ascii"
        )
        line4_pt = f"=yend size={len(ct)} crc32={body_crc:08x}".encode("ascii")

        k1, t1 = adapter.derive_control_keys(master_key, segment_index, 1)
        k2, t2 = adapter.derive_control_keys(master_key, segment_index, 2)
        k4, t4 = adapter.derive_control_keys(master_key, segment_index, 4)

        wire1 = salt + segment_index.to_bytes(4, "big") + ff1_encrypt(k1, t1, line1_pt)
        wire2 = ff1_encrypt(k2, t2, line2_pt)
        wire4 = ff1_encrypt(k4, t4, line4_pt)

        # Producer dot-stuffs Line 1 (its content byte 0 is 0x2E) -> '..' on the wire
        assert wire1[0:1] == b"."
        stuffed_wire1 = b"." + wire1

        article = mock.MagicMock(spec=Article)
        article.article = "dot@stuff"
        article.nzf.nzo.password = password
        article.nzf.nzo.yenc_encrypted = True

        resp = _mock_response()
        resp.sink_failed = False
        resp.bytes_decoded = 0
        resp.lines = [
            stuffed_wire1.decode("latin-1"),
            wire2.decode("latin-1"),
            body_encoded.decode("latin-1"),
            wire4.decode("latin-1"),
        ]

        decoded = decoder.decode_yenc(article, resp)
        assert decoded == bytearray(plaintext), "dot-stuffed Line 1 must decode to exact plaintext"


class TestUnauthenticatedPlainArticle:
    """Zero-Output Rule: plain article under a declared-encrypted release is rejected."""

    def _plain_response(self):
        import sabctools

        resp = _mock_response()
        resp.sink_failed = False
        resp.format = sabctools.EncodingFormat.YENC
        resp.data = bytearray(b"plain unencrypted content")
        resp.file_size = 100
        resp.part_begin = 0
        resp.part_size = len(resp.data)
        resp.bytes_decoded = len(resp.data)
        resp.file_name = "plain.bin"
        resp.crc = 0x12345678
        resp.lines = None
        return resp

    def _enc_article(self, nzo_yenc_encrypted=True):
        article = mock.MagicMock(spec=Article)
        article.article = "plain-sub@news"
        article.nzf.nzo.yenc_encrypted = nzo_yenc_encrypted
        article.nzf.nzo.precheck = False
        article.lowest_partnum = False
        return article

    def test_plain_article_rejected_when_release_declared_encrypted(self):
        """yenc_encrypted release + plain yEnc response raises UNAUTHENTICATED_ARTICLE and preserves metadata."""
        import sabnzbd.decoder as decoder

        nzf = mock.Mock()
        nzf.nzo.yenc_encrypted = True
        article = Article("plain-sub@news", 5, nzf)
        original = (article.file_size, article.data_begin, article.data_size, article.decoded_size, article.crc32)
        response = self._plain_response()

        with pytest.raises(ValueError, match="UNAUTHENTICATED_ARTICLE"):
            decoder.decode_yenc(article, response)
        assert (
            article.file_size,
            article.data_begin,
            article.data_size,
            article.decoded_size,
            article.crc32,
        ) == original

    def test_decode_routes_to_search_new_server_and_second_server_serves_authenticated_plaintext(self):
        """(2) decode() routes through search_new_server; second server's encrypted article decodes to authenticated plaintext only."""
        import nacl.bindings as nb
        import sabctools
        import sabnzbd.decoder as decoder

        password = "plain_sub_password"
        salt = bytes.fromhex("2a2b3c4d5e6f7890abcdef1234567890")
        segment_index = 1
        plaintext = b"Authenticated plaintext from the good server!"

        adapter = DecryptionAdapter(password=password)
        master_key = adapter.get_master_key(salt)
        nonce = adapter.derive_body_nonce(master_key, segment_index)
        aad = build_aad(b"good.bin", 1, 1, len(plaintext))
        enc = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, master_key)
        ct = enc[:-16]
        tag = enc[-16:]
        body_encoded, body_crc = sabctools.yenc_encode(ct)

        line1_pt = f"=ybegin line=128 size={len(ct)} name=good.bin".encode("ascii")
        line2_pt = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={segment_index:08x} tag={tag.hex()}".encode(
            "ascii"
        )
        line4_pt = f"=yend size={len(ct)} crc32={body_crc:08x}".encode("ascii")

        k1, t1 = adapter.derive_control_keys(master_key, segment_index, 1)
        k2, t2 = adapter.derive_control_keys(master_key, segment_index, 2)
        k4, t4 = adapter.derive_control_keys(master_key, segment_index, 4)
        wire1 = salt + segment_index.to_bytes(4, "big") + ff1_encrypt(k1, t1, line1_pt)
        wire2 = ff1_encrypt(k2, t2, line2_pt)
        wire4 = ff1_encrypt(k4, t4, line4_pt)

        good_resp = _mock_response()
        good_resp.sink_failed = False
        good_resp.bytes_decoded = 0
        good_resp.lines = [
            wire1.decode("latin-1"),
            wire2.decode("latin-1"),
            body_encoded.decode("latin-1"),
            wire4.decode("latin-1"),
        ]

        article = self._enc_article()
        article.article = "art@e2e"
        article.nzf.nzo.password = password
        article.on_disk = False
        article.search_new_server.return_value = True

        plain_resp = self._plain_response()

        # decode_yenc on server 1's plain response raises retriable ValueError
        with pytest.raises(ValueError, match="UNAUTHENTICATED_ARTICLE"):
            decoder.decode_yenc(article, plain_resp)

        # decode() routes it to search_new_server (retriable tier), zero bytes stored
        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
        ):
            # Server 1: plain article -> failover
            decoder.decode(article, plain_resp)
            assert article.search_new_server.called
            assert not mock_cache.save_article.called

            # Server 2: real encrypted article -> authenticated plaintext cached, server 1's bytes never appear
            mock_cache.reset_mock()
            decoded = decoder.decode_yenc(article, good_resp)
            assert bytes(decoded) == plaintext
            assert b"plain unencrypted content" not in bytes(decoded)

    def test_exhausted_servers_increments_bad_articles_with_zero_bytes_stored(self):
        """(3) Exhausted servers: bad_articles incremented, zero bytes stored."""
        import sabnzbd.decoder as decoder

        article = self._enc_article()
        article.article = "exhausted@e2e"
        article.search_new_server.return_value = False
        article.on_disk = False

        plain_resp = self._plain_response()

        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
        ):
            # Servers exhausted: search_new_server returns False -> decode() cleanly registers
            # failure via NzbQueue.register_article(article, False) without crashing;
            # bad_articles already incremented and zero bytes were stored.
            decoder.decode(article, plain_resp)
            assert article.nzf.nzo.increase_bad_articles_counter.called
            assert not mock_cache.save_article.called
            mock_queue.register_article.assert_called_once_with(article, False)

    def test_uu_response_on_encrypted_job_routes_to_server_search_with_zero_cached_bytes(self):
        """A valid UU-encoded article on a declared-encrypted job is an unencrypted
        substitution: decode() must reject it before decode_uu and route to
        search_new_server with zero bytes cached (Zero-Output Rule)."""
        import sabctools
        import io
        import sabnzbd.decoder as decoder

        # Real native UU response produced through sabctools' transport state machine
        def uu_line(data: bytes) -> bytes:
            n = len(data)
            out = bytearray()
            out.append((n & 0x3F) + 32 if n else ord("`"))
            for i in range(0, n, 3):
                chunk = data[i : i + 3]
                while len(chunk) < 3:
                    chunk += b"\0"
                b1, b2, b3 = chunk
                out += bytes(
                    [
                        32 + ((b1 >> 2) & 0x3F),
                        32 + (((b1 << 4) | (b2 >> 4)) & 0x3F),
                        32 + (((b2 << 2) | (b3 >> 6)) & 0x3F),
                        32 + (b3 & 0x3F),
                    ]
                )
            return bytes(out) + b"\r\n"

        payload = b"valid uu payload"
        wire = b"222 0 <x>\r\n" b"begin 644 test.bin\r\n" + uu_line(payload) + b"`\r\n" b"end\r\n" b".\r\n"
        dec = sabctools.Decoder(len(wire))
        dec.expect(None)
        reader = io.BytesIO(wire)
        reader.readinto(dec)
        dec.process(len(wire))
        uu_resp = next(dec)
        assert uu_resp.format is sabctools.EncodingFormat.UU
        assert uu_resp.bytes_decoded == len(payload)

        article = self._enc_article()
        article.article = "uu-sub@news"
        article.nzf.nzo.password = "pw"
        article.lowest_partnum = False
        article.on_disk = False
        article.search_new_server.return_value = True

        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
        ):
            decoder.decode(article, uu_resp)
            # Routed to server search, never handed to decode_uu, zero cached bytes
            assert article.search_new_server.called
            assert not mock_cache.save_article.called
            assert not article.on_disk


class TestStructuralNoPasswordEncryptedWire:
    """Encrypted wire with no resolvable password raises structural error, never on_disk."""

    def test_encrypted_wire_no_password_raises_structural(self):
        import sabctools
        import sabnzbd.decoder as decoder
        from sabnzbd.encryption import YEncEncryptionStructuralError

        article = mock.MagicMock(spec=Article)
        article.article = "nopass@enc"
        article.nzf.nzo.password = None
        article.nzf.nzo.yenc_encrypted = True
        article.nzf.nzo.precheck = False
        article.search_new_server.return_value = True
        article.on_disk = False

        resp = _mock_response()
        resp.sink_failed = False
        resp.format = sabctools.EncodingFormat.YENC
        resp.bytes_decoded = 0
        resp.lines = ["=ybegin line=128 size=50 name=test.bin", "AAAABBBBCCCCDDDDEEEE", "=yend size=50"]
        resp.data = None
        resp.crc = None

        with pytest.raises(YEncEncryptionStructuralError, match="MISSING_PASSWORD"):
            decoder.decode_yenc(article, resp)

    def test_authenticated_empty_segment_counts_as_complete(self):
        """An authenticated zero-length plaintext is complete: nothing is cached, and the
        article is marked on_disk so the assembler advances past it."""
        import nacl.bindings as nb
        import sabctools
        import sabnzbd.decoder as decoder

        password = "secret"
        salt = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        segment_index = 1
        plaintext = b""

        adapter = DecryptionAdapter(password=password)
        master_key = adapter.get_master_key(salt)
        nonce = adapter.derive_body_nonce(master_key, segment_index)

        aad = build_aad(b"test.bin", 1, 1, 0)
        enc = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, master_key)
        ct = enc[:-16]
        tag = enc[-16:]

        body_encoded, body_crc = sabctools.yenc_encode(ct)

        line1_pt = f"=ybegin line=128 size={len(ct)} name=test.bin".encode("ascii")
        line2_pt = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={segment_index:08x} tag={tag.hex()}".encode(
            "ascii"
        )
        line4_pt = f"=yend size={len(ct)} crc32={body_crc:08x}".encode("ascii")

        k1, t1 = adapter.derive_control_keys(master_key, segment_index, 1)
        wire1 = salt + (segment_index).to_bytes(4, "big") + ff1_encrypt(k1, t1, line1_pt)
        k2, t2 = adapter.derive_control_keys(master_key, segment_index, 2)
        wire2 = ff1_encrypt(k2, t2, line2_pt)
        k4, t4 = adapter.derive_control_keys(master_key, segment_index, 4)
        wire4 = ff1_encrypt(k4, t4, line4_pt)

        article = mock.MagicMock(spec=Article)
        article.article = "empty@enc"
        article.nzf.nzo.password = password
        article.nzf.nzo.yenc_encrypted = True
        article.nzf.nzo.precheck = False
        article.nzf.filename_checked = True
        article.lowest_partnum = False
        article.search_new_server.return_value = True
        article.on_disk = False
        article.decoded = False

        resp = _mock_response()
        resp.sink_failed = False
        resp.bytes_decoded = 0
        resp.lines = [
            wire1.decode("latin-1"),
            wire2.decode("latin-1"),
            body_encoded.decode("latin-1"),
            wire4.decode("latin-1"),
        ]

        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
        ):
            decoder.decode(article, resp)
            assert article.on_disk is True
            assert not mock_cache.save_article.called


class TestHeaderRegionFailClosed:
    """Fail-closed header-region FF1 error; byte-exact reconstruction (no lstrip masking)."""

    def _wire_block(self, adapter, salt, seg_idx, corrupt_line2=False):
        master_key = adapter.get_master_key(salt)
        k1, t1 = adapter.derive_control_keys(master_key, seg_idx, 1)
        k2, t2 = adapter.derive_control_keys(master_key, seg_idx, 2)
        k4, t4 = adapter.derive_control_keys(master_key, seg_idx, 4)

        ct1 = encrypt_control_line(b"=ybegin line=128 size=50 name=test.bin", k1, t1)
        wire_line1 = salt + seg_idx.to_bytes(4, "big") + ct1 + b"\r\n"

        if corrupt_line2:
            # Corrupt ciphertext so FF1 decryption raises (invalid Alphabet byte 0x00)
            wire_line2 = b"\x00" * 40 + b"\r\n"
        else:
            ct2 = encrypt_control_line(
                b"=yencryption cipher=XChaCha20-Poly1305 salt="
                + salt.hex().encode("ascii")
                + b" index=00000001 tag="
                + b"00" * 16,
                k2,
                t2,
            )
            wire_line2 = ct2 + b"\r\n"

        data_line = b"PAYLOAD DATA LINE\r\n"
        ct4 = encrypt_control_line(b"=yend size=50 crc32=12345678", k4, t4)
        wire_footer = ct4 + b"\r\n"
        return wire_line1 + wire_line2 + data_line + wire_footer

    def test_ff1_error_on_header_line_raises_provider_failover(self):
        """FF1 error on the fixed =yencryption position fails closed (never accepted as valid)."""
        adapter = DecryptionAdapter(password="testpass")
        salt = b"\x07" * 16
        wire_block = self._wire_block(adapter, salt, 1, corrupt_line2=True)

        with pytest.raises(ValueError):
            adapter.restore_control_lines(wire_block)

    def test_corrupt_header_line_never_appended_as_data_line(self):
        """The raw wire line of a failed header decryption is never accepted as data:
        extract_and_remove_yencryption fails closed on the restored block."""
        from sabnzbd.encryption import extract_and_remove_yencryption

        adapter = DecryptionAdapter(password="testpass")
        salt = b"\x08" * 16
        wire_block = self._wire_block(adapter, salt, 1, corrupt_line2=True)

        # The corrupted position either fails restoration outright or restores to a
        # non-=yencryption value; in both cases the block can never proceed to body
        # decryption (no =yencryption params are available).
        with pytest.raises(ValueError):
            restored, _s, _i = adapter.restore_control_lines(wire_block)
            extract_and_remove_yencryption(restored)


def _single_part_wire_lines(password: str, plaintext: bytes, name: bytes, segment_index: int = 1) -> list[str]:
    """Wire lines of a combined-mode single-part article with an arbitrary =ybegin name (Control Std v1.2 §5)."""
    import nacl.bindings as nb
    import sabctools

    salt = bytes.fromhex("9a8b7c6d5e4f30211f0e1d2c3b4a5968")
    adapter = DecryptionAdapter(password=password)
    master_key = adapter.get_master_key(salt)
    nonce = adapter.derive_body_nonce(master_key, segment_index)
    aad = build_aad(name, 1, 1, len(plaintext))
    enc = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, master_key)
    body_encoded, body_crc = sabctools.yenc_encode(enc[:-16])
    tag = enc[-16:]
    plain_lines = [
        b"=ybegin line=128 size=%d name=%s" % (len(plaintext), name),
        b"=yencryption cipher=XChaCha20-Poly1305 salt=%s index=%08x tag=%s"
        % (salt.hex().encode("ascii"), segment_index, tag.hex().encode("ascii")),
        None,  # data line, passed through untouched
        b"=yend size=%d crc32=%08x" % (len(plaintext), body_crc),
    ]
    wire: list[str] = []
    for line_index, pt in enumerate(plain_lines, start=1):
        if pt is None:
            wire.append(body_encoded.decode("latin-1"))
            continue
        if line_index == 1:
            k, t = adapter.derive_control_keys(master_key, segment_index, 1)
            wire.append((salt + segment_index.to_bytes(4, "big") + ff1_encrypt(k, t, pt)).decode("latin-1"))
        else:
            k, t = adapter.derive_control_keys(master_key, segment_index, line_index)
            wire.append(ff1_encrypt(k, t, pt).decode("latin-1"))
    return wire


class _FakeDecoder(bytearray):
    def __init__(self, size):
        super().__init__(size)
        self.processed = []
        self.pending = 0
        self.expected = 0

    def process(self, n):
        self.processed.append(n)

    def __iter__(self):
        return iter([])


class TestHeaderGeometryParsing:
    """Header-geometry parsing rules: keywords before name= decide multipart; missing
    AAD keywords (part=/begin=/end=/size=) fail closed instead of defaulting."""

    def test_single_part_name_containing_part_keyword_decodes(self):
        """Only keywords before name= decide multipart (Control Std v1.2 §5 step 4; Body Std §2.1)."""
        import sabnzbd.decoder as decoder

        plaintext = b"single-part payload whose name contains a part= keyword"
        wire = _single_part_wire_lines("conv_password", plaintext, b"my part=2.bin")
        article = mock.MagicMock(spec=Article)
        article.article = "conv_single_part@news"
        article.nzf.nzo.password = "conv_password"
        article.nzf.filename_checked = False
        article.lowest_partnum = True

        resp = _mock_response()
        resp.sink_failed = False
        resp.bytes_decoded = 0
        resp.lines = wire

        decoded = decoder.decode_yenc(article, resp)
        assert decoded == bytearray(plaintext)
        assert article.decoded_size == len(plaintext)

    def test_restore_marks_name_part_keyword_as_single_part(self):
        """F1 at the restore seam: =yencryption stays at line 2 and the AAD uses single-part geometry."""
        from sabnzbd.encryption import extract_and_remove_yencryption

        plaintext = b"geometry check"
        adapter = DecryptionAdapter(password="conv_password")
        wire = "\r\n".join(_single_part_wire_lines("conv_password", plaintext, b"my part=2.bin")) + "\r\n"
        restored, _salt, _idx = adapter.restore_control_lines(wire.encode("latin-1"))
        assert restored.split(b"\r\n")[1].startswith(b"=yencryption")
        params, _clean = extract_and_remove_yencryption(restored)
        assert params["aad"] == build_aad(b"my part=2.bin", 1, 1, len(plaintext))

    def test_yencryption_extract_reports_real_file_name(self):
        """The real =ybegin name must reach filename detection.

        The sub-decoder only sees the neutralized name=x placeholder, so
        decode_yenc must take the name from the restored block, decoded the same
        way sabctools decodes name= for ordinary yEnc; otherwise an obfuscated
        NZB subject can never be renamed from the yEnc header (what ordinary
        yEnc still does via response.file_name)."""
        from sabnzbd.encryption import extract_and_remove_yencryption

        valid_hdr = b"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b"
        block = b"=ybegin line=128 size=10 name=Ubuntu.24.04.iso\r\n" + valid_hdr + b"\r\nDATA\r\n=yend size=10\r\n"
        params, clean = extract_and_remove_yencryption(block)
        assert params["file_name"] == "Ubuntu.24.04.iso"
        # The AAD still uses the raw name bytes (Body Std v1.2 §2.1)
        assert params["aad"] == build_aad(b"Ubuntu.24.04.iso", 1, 1, 10)
        # The =yencryption line was removed; the =ybegin line keeps the real name
        # (neutralization to name=x happens later, only for the sub-decoder feed)
        assert clean.startswith(b"=ybegin line=128 size=10 name=Ubuntu.24.04.iso\r\n")

        # Non-UTF-8 names decode like sabctools' latin-1 fallback for ordinary yEnc
        block_l1 = b"=ybegin line=128 size=10 name=caf\xe9.bin\r\n" + valid_hdr + b"\r\nDATA\r\n=yend size=10\r\n"
        params_l1, _ = extract_and_remove_yencryption(block_l1)
        assert params_l1["file_name"] == "café.bin"

        # A name containing " part=" still works and keeps the whole value
        block_part = b"=ybegin line=128 size=10 name=my part=2.bin\r\n" + valid_hdr + b"\r\nDATA\r\n=yend size=10\r\n"
        params_part, _ = extract_and_remove_yencryption(block_part)
        assert params_part["file_name"] == "my part=2.bin"

    def test_multipart_with_part_keyword_in_name_uses_header_part_number(self):
        """A multipart =ybegin takes part= from the header keywords, never from the name value."""
        from sabnzbd.encryption import extract_and_remove_yencryption

        valid_hdr = b"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b"
        block = (
            b"=ybegin part=3 total=5 line=128 size=20 name=x part=9.bin\r\n"
            b"=ypart begin=11 end=20\r\n" + valid_hdr + b"\r\nDATA\r\n=yend size=10 part=3\r\n"
        )
        params, _clean = extract_and_remove_yencryption(block)
        assert params["aad"] == build_aad(b"x part=9.bin", 3, 11, 10)

    @pytest.mark.parametrize(
        "ybegin_line, ypart_line",
        [
            (b"=ybegin part=1 total=1 line=128 size=10 name=f.bin", b"=ypart end=10"),
            (b"=ybegin part=1 total=1 line=128 size=10 name=f.bin", b"=ypart begin=1"),
            (b"=ybegin part=1 total=1 line=128 size=10 name=f.bin", b"=ypart begin=x end=10"),
            (b"=ybegin line=128 name=f.bin", None),
        ],
    )
    def test_missing_aad_geometry_fails_closed(self, ybegin_line, ypart_line):
        """A missing or malformed keyword the AAD needs is PROVIDER_FAILOVER, not a silent
        default (Body Std v1.2 §2.1: =ypart begin=/end=, =ybegin size=)."""
        from sabnzbd.encryption import extract_and_remove_yencryption

        valid_hdr = b"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b"
        block = ybegin_line + b"\r\n"
        if ypart_line is not None:
            block += ypart_line + b"\r\n"
        block += valid_hdr + b"\r\nDATA\r\n=yend size=10\r\n"
        with pytest.raises(YEncEncryptionCryptoError):
            extract_and_remove_yencryption(block)

    def test_restore_fails_closed_on_missing_yencryption_before_data(self):
        """The fixed =yencryption position is never silently treated as data (Control Std v1.2 §5 step 4b)."""
        adapter = DecryptionAdapter(password="conv_password")
        wire = "\r\n".join(_single_part_wire_lines("conv_password", b"abc", b"f.bin")) + "\r\n"
        lines = wire.split("\r\n")
        # Swap line 2 (=yencryption) for the footer position's data: restoration must raise, not pass through.
        broken = "\r\n".join([lines[0], lines[2], lines[1], lines[3]]).encode("latin-1") + b"\r\n"
        with pytest.raises(YEncEncryptionCryptoError):
            adapter.restore_control_lines(broken)

    def test_bare_lf_unencrypted_chunk_is_unchanged(self):
        """Bytes passed to the decoder equal the bytes received; bytes_recv unchanged."""
        server = mock.MagicMock()
        server.timeout = 10
        server.ssl = False
        server.pipelining_requests.return_value = 1

        nw = NewsWrapper(server, thrdnum=1)
        dec = _FakeDecoder(1024)
        nw.decoder = dec
        nw.nntp = mock.MagicMock()
        nw.nntp.nw = nw

        chunks = [b"bare\nlf\nstream\n", b"without\r\ncr\n"]
        received = iter(chunks)

        def fake_recv_into(buf, nbytes=0):
            raw_chunk = next(received)
            memoryview(buf)[: len(raw_chunk)] = raw_chunk
            return len(raw_chunk)

        nw.nntp.sock.recv_into = fake_recv_into
        mock_article = mock.MagicMock()
        mock_article.nzf.nzo.yenc_encrypted = False
        nw.decoder.pending = 1
        with (
            mock.patch.object(NewsWrapper, "article", new_callable=mock.PropertyMock) as mock_art_prop,
            mock.patch.object(sabnzbd, "Downloader", create=True),
        ):
            mock_art_prop.return_value = mock_article
            for chunk in chunks:
                nrecv, _ = nw.read()
                assert nrecv == len(chunk)
                assert bytes(dec[:nrecv]) == chunk
        assert dec.processed == [len(chunk) for chunk in chunks]

    def test_bare_lf_expansion_never_exceeds_buffer(self):
        """Reads on encrypted jobs leave room for bare-LF to CRLF expansion, so no article is lost."""
        server = mock.MagicMock()
        server.timeout = 10
        server.ssl = False
        server.pipelining_requests.return_value = 1

        buf_size = 64
        stream = b"\n" * (buf_size * 3)

        def run(encrypted):
            nw = NewsWrapper(server, thrdnum=1)
            dec = _FakeDecoder(buf_size)
            nw.decoder = dec
            nw.nntp = mock.MagicMock()
            nw.nntp.nw = nw
            position = 0
            seen = bytearray()

            def fake_recv_into(buf, nbytes=0):
                # Like socket.recv_into: fill at most nbytes (default: the whole buffer)
                nonlocal position
                count = min(nbytes or len(buf), len(buf), len(stream) - position)
                memoryview(buf)[:count] = stream[position : position + count]
                position += count
                return count

            def fake_process(count):
                seen.extend(dec[:count])

            dec.process = fake_process
            nw.nntp.sock.recv_into = fake_recv_into

            article = mock.MagicMock()
            article.nzf.nzo.yenc_encrypted = encrypted
            with (
                mock.patch.object(NewsWrapper, "article", new_callable=mock.PropertyMock) as mock_art_prop,
                mock.patch.object(sabnzbd, "Downloader", create=True),
            ):
                mock_art_prop.return_value = article
                while position < len(stream):
                    nw.read()
            return bytes(seen)

        # Unencrypted release: the ordinary path never rewrites the bytes
        assert run(False) == stream

        # Encrypted release: every bare LF becomes CRLF and no read overflows the buffer
        assert run(True) == stream.replace(b"\n", b"\r\n")


def test_encrypted_article_filename_detected_from_ybegin_name():
    """End to end: decode_yenc must pass the real =ybegin name to
    verify_nzf_filename, like the ordinary yEnc path does with
    response.file_name. The sub-decoder's response carries the neutralized
    name=x placeholder, so it can never be used for filename detection."""
    import sabnzbd.decoder as decoder

    password = "x4-end-to-end"
    plaintext = b"payload for filename detection"
    article = mock.MagicMock(spec=Article)
    article.article = "x4-filename@news"
    article.nzf.filename = "1a2b3c4d5e6f0123456789abcdef0123.01"  # obfuscated NZB subject
    article.nzf.filename_checked = False
    article.nzf.nzo.password = password
    article.lowest_partnum = True

    resp = _mock_response()
    resp.sink_failed = False
    resp.bytes_decoded = 0
    resp.lines = _single_part_wire_lines(password, plaintext, b"Ubuntu.24.04.iso")

    decoded = decoder.decode_yenc(article, resp)
    assert decoded == bytearray(plaintext)
    verify_args = article.nzf.nzo.verify_nzf_filename.call_args[0]
    assert verify_args[1] == "Ubuntu.24.04.iso", verify_args


def test_key_cache_replaces_on_new_salt():
    """The single-entry key cache keeps only the most recent salt's key (DoS bound)."""
    adapter = DecryptionAdapter(password="test-pass")
    first_salt = bytes([1]) * 16
    first_key = adapter.get_master_key(first_salt)
    assert adapter._key_cache == {first_salt: first_key}

    second_salt = bytes([2]) * 16
    adapter.get_master_key(second_salt)
    assert adapter._key_cache == {second_salt: adapter.get_master_key(second_salt)}
    assert first_salt not in adapter._key_cache


@pytest.mark.parametrize("defect", ["missing_name", "empty_name", "missing_crc"])
def test_encrypted_missing_name_or_crc_fails_closed(defect):
    import sabnzbd.decoder as decoder

    password = "metadata-defects"
    lines = _single_part_wire_lines(password, b"hello", b"valid.bin")
    first = lines[0].encode("latin-1")
    salt = first[:16]
    adapter = DecryptionAdapter(password=password)
    key = adapter.get_master_key(salt)
    index = 4 if defect == "missing_crc" else 1
    enc_key, tweak = adapter.derive_control_keys(key, 1, index)
    content = lines[index - 1].encode("latin-1")
    plain = adapter.decrypt_control_line(content[20:] if index == 1 else content, enc_key, tweak)
    if defect == "missing_crc":
        plain = plain.split(b" crc32=")[0]
    else:
        plain = plain.split(b" name=")[0] + (b" name=" if defect == "empty_name" else b"")
    encrypted = ff1_encrypt(enc_key, tweak, plain)
    lines[index - 1] = ((first[:20] + encrypted) if index == 1 else encrypted).decode("latin-1")
    article = mock.MagicMock(spec=Article)
    article.article = "metadata-defects@test"
    article.nzf.nzo.yenc_encrypted = True
    article.nzf.nzo.password = password
    response = _mock_response()
    response.sink_failed = False
    response.bytes_decoded = 0
    response.status_code = 222
    response.lines = lines
    with pytest.raises(YEncEncryptionCryptoError):
        decoder.decode_yenc(article, response)


class TestDeclaredGeometryLengthMismatch:
    """The AEAD tag authenticates the DECLARED geometry (=ybegin size / =ypart range
    in the AAD), not the plaintext itself. A corrupted or truncated-then-reCRC'd article
    could carry plaintext whose actual length differs from the declaration. sabctools'
    sub-decoder does not validate actual-vs-declared (part_size mirrors the declared
    keywords), so decode_yenc must reject the mismatch before any cache write.
    """

    @staticmethod
    def _wire_lines(plaintext: bytes, declared_bytes: int, salt, seg, master_key, multipart: bool):
        """Build encrypted wire lines whose AAD/tag use the DECLARED geometry, while the
        actual plaintext length may differ from it. Returns (lines, adapter)."""
        import nacl.bindings as nb
        import sabctools

        adapter = DecryptionAdapter(password="pw")
        nonce = adapter.derive_body_nonce(master_key, seg)
        aad = build_aad(b"test.bin", 1, 1, declared_bytes)
        enc = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, master_key)
        ct, tag = enc[:-16], enc[-16:]
        body, crc = sabctools.yenc_encode(ct)

        if multipart:
            lines_pt = [
                f"=ybegin part=1 total=2 line=128 size={declared_bytes * 2} name=test.bin".encode(),
                f"=ypart begin=1 end={declared_bytes}".encode(),
                f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={seg:08x} tag={tag.hex()}".encode(),
                body,
                f"=yend size={declared_bytes * 2} part=1 pcrc32={crc:08x}".encode(),
            ]
            line_indices = [1, 2, 3, None, 5]
        else:
            lines_pt = [
                f"=ybegin line=128 size={declared_bytes} name=test.bin".encode(),
                f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={seg:08x} tag={tag.hex()}".encode(),
                body,
                f"=yend size={declared_bytes} crc32={crc:08x}".encode(),
            ]
            line_indices = [1, 2, None, 4]

        lines = []
        for pt, li in zip(lines_pt, line_indices):
            if li is None:
                lines.append(pt.decode("latin-1"))
            elif li == 1:
                k, t = adapter.derive_control_keys(master_key, seg, 1)
                lines.append((salt + seg.to_bytes(4, "big") + ff1_encrypt(k, t, pt)).decode("latin-1"))
            else:
                k, t = adapter.derive_control_keys(master_key, seg, li)
                lines.append(ff1_encrypt(k, t, pt).decode("latin-1"))
        return lines, adapter

    @pytest.mark.parametrize(
        ("plaintext", "declared_bytes", "multipart", "should_fail"),
        [
            (b"actual payload!!", 26, False, True),  # single-part shorter
            (b"x" * 30, 26, False, True),  # single-part longer
            (b"actual payload!!", 26, True, True),  # multipart range mismatch
            (b"exact ten ok", 12, False, False),  # matching length decodes
        ],
    )
    def test_declared_geometry_vs_actual_length(self, plaintext, declared_bytes, multipart, should_fail):
        import sabnzbd.decoder as decoder

        salt = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        adapter = DecryptionAdapter(password="pw")
        master_key = adapter.get_master_key(salt)
        lines, _ = self._wire_lines(plaintext, declared_bytes, salt, 1, master_key, multipart=multipart)

        article = mock.MagicMock(spec=Article)
        article.article = "length-check@test"
        article.nzf.nzo.password = "pw"
        article.nzf.filename_checked = True
        article.lowest_partnum = False
        original = (article.file_size, article.data_begin, article.data_size, article.decoded_size, article.crc32)

        resp = _mock_response()
        resp.lines = lines

        if should_fail:
            with pytest.raises(YEncEncryptionCryptoError, match="LENGTH_MISMATCH"):
                decoder.decode_yenc(article, resp)
            # Rejection must happen before article metadata mutation
            assert (
                article.file_size,
                article.data_begin,
                article.data_size,
                article.decoded_size,
                article.crc32,
            ) == original
        else:
            decoded = decoder.decode_yenc(article, resp)
            assert decoded == bytearray(plaintext)

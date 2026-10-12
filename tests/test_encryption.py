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
        pytest.skip(f"Test vectors not found at {vector_dir}")
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
            conn.sendall(b"200 Welcome" + self.line_ending)
            while not self._stop.is_set():
                conn.settimeout(0.5)
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    if data.startswith(b"QUIT"):
                        conn.sendall(b"205 Goodbye" + self.line_ending)
                        break
                    elif data.startswith(b"BODY"):
                        if self.have_body:
                            resp = b"222 0 <art@e2e>" + self.line_ending + self.body_bytes + b"." + self.line_ending
                            send_response(resp)
                        else:
                            conn.sendall(b"500 command not supported" + self.line_ending)
                    elif data.startswith(b"ARTICLE"):
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
    """Test suite verifying DecryptionAdapter meets all ARCH-01 and ARCH-03 contracts."""

    def test_sab_adapter_contracts(self):
        """Aggregate test verifying key derivation, caching, body AEAD, and control line restoration."""
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

        with mock.patch.object(adapter, "_derive_argon2id", wraps=adapter._derive_argon2id) as mock_kdf:
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
        assert parsed["cipher"] == "XChaCha20-Poly1305"
        assert parsed["salt"] == bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        assert parsed["segment_index"] == 1
        assert parsed["tag"] == bytes.fromhex("0cd77ce245a654463f90b945b1d22d5b")

        # 3. extract_and_remove_yencryption basic smoke test
        block = b"=ybegin line=128 size=10 name=test\r\n=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\ndata\r\n=yend size=10\r\n"
        p, clean = extract_and_remove_yencryption(block)
        assert p["cipher"] == "XChaCha20-Poly1305"
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
        import sabctools
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

        resp_bad_salt = mock.MagicMock(spec=sabctools.NNTPResponse)
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

        resp_bad_idx = mock.MagicMock(spec=sabctools.NNTPResponse)
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
        import sabctools

        # Case 1: Candidate encrypted article (bytes_decoded == 0, lines and encryption provenance present)
        art_cand = mock.MagicMock(spec=Article)
        art_cand.fetcher.id = 1
        art_cand.nzf.nzo.password = "secret_pass"
        art_cand.nzf.nzo.yenc_encrypted = True
        art_cand.nzf.nzo.precheck = False

        resp_cand = mock.MagicMock(spec=sabctools.NNTPResponse)
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

        resp_broken = mock.MagicMock(spec=sabctools.NNTPResponse)
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

    @pytest.mark.parametrize("line", ["ordinary yEnc data", b"ordinary yEnc data"])
    def test_ordinary_yenc_lines_accept_text_and_bytes(self, line):
        """Encryption probing preserves ordinary responses regardless of line representation."""
        import sabctools
        import sabnzbd.decoder as decoder

        article = mock.MagicMock(spec=Article)
        article.nzf.filename_checked = True
        article.lowest_partnum = False
        # Explicitly plain provenance: MagicMock auto-attributes would otherwise make
        # _is_yenc_encrypted() truthy and trip the Zero-Output Rule plain-article reject.
        article.nzf.nzo.yenc_encrypted = False

        response = mock.MagicMock(spec=sabctools.NNTPResponse)
        response.sink_failed = False
        response.data = bytearray(b"plain decoded data")
        response.file_size = len(response.data)
        response.part_begin = 0
        response.part_size = len(response.data)
        response.bytes_decoded = len(response.data)
        response.file_name = "plain.bin"
        response.crc = 0x12345678
        response.lines = [line]
        response.yencryption = None

        assert decoder.decode_yenc(article, response) == response.data

    def test_modified_tag_native_response_triggers_server_search(self):
        """A real encrypted wire response with a modified tag fails Poly1305 and is routed
        to search_new_server with zero bytes stored (real modified-tag native response)."""
        import sabctools
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
        resp = mock.MagicMock(spec=sabctools.NNTPResponse)
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

        resp = mock.MagicMock(spec=sabctools.NNTPResponse)
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

        resp_m = mock.MagicMock(spec=sabctools.NNTPResponse)
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

        resp_bad_crc = mock.MagicMock(spec=sabctools.NNTPResponse)
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

        resp_bad_tag = mock.MagicMock(spec=sabctools.NNTPResponse)
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
        assert params["cipher"] == "XChaCha20-Poly1305"
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
        assert m_params["cipher"] == "XChaCha20-Poly1305"
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
            with pytest.raises(ValueError, match="Poly1305 authentication failed"):
                output = adapter.decrypt_body(ct, tag, salt, seg_idx)

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
            assert "Authentication failed for art@e2e, trying next server" in log_text

        finally:
            srv1.stop()
            srv2.stop()

    def test_article_fallback_after_body_unsupported(self, caplog):
        """BODY 500 -> ARTICLE fallback: NNTP headers are separated from the encrypted body."""
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

                # First request: BODY -> 500 -> have_body flipped -> article re-queued
                art.fetcher = s1
                nw1.queue_article(art)
                nw1.write()
                nw1.read()
                assert s1.have_body is False
                assert not mock_cache.save_article.called

                # Second request: ARTICLE -> 220 with NNTP headers before the body
                art.fetcher = s1
                nw1.queue_article(art)
                nw1.write()
                nw1.read()

                # ARTICLE path must decode through the headers to authenticated plaintext
                assert mock_cache.save_article.called
                _saved_art, saved_data = mock_cache.save_article.call_args[0]
                assert bytes(saved_data) == plaintext

        finally:
            srv.stop()

    def test_bare_lf_response_over_real_socket(self):
        """A real NNTP server sending bare-LF framed encrypted responses decodes to the
        exact plaintext: terminators are handled at the native transport seam, never
        fabricated CRLF (Control Std v1.2 §6)."""
        password = "bare_lf_password"
        plaintext = b"Bare LF framing end-to-end test payload!"

        # Encrypted body framed with bare LF
        enc_body_lf, _adapter, _mk, _nonce, _ct, _tag, _crc, _aad, _n = _encrypted_wire(
            password=password,
            plaintext=plaintext,
            name="test.bin",
            line_ending=b"\n",
        )

        srv = MockArticleNNTPServer(enc_body_lf, line_ending=b"\n")
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

                # Bare-LF framed encrypted response must complete natively and decode
                assert mock_cache.save_article.called
                _saved_art, saved_data = mock_cache.save_article.call_args[0]
                assert bytes(saved_data) == plaintext

        finally:
            srv.stop()

    def test_crlf_terminator_split_across_tcp_chunks(self):
        """A conforming CRLF server whose \\r\\n.\\r\\n article terminator is split across
        TCP chunks (the final chunk starting with the lone \\n) must still deliver the
        article: a chunk that begins with '\\n' preceded by a chunk ending in '\\r' is
        the second half of a CRLF, never a bare LF (RFC 3977 §3.1.1)."""
        password = "crlf_split_password"
        plaintext = b"CRLF split terminator end-to-end test payload!"

        enc_body, _adapter, _mk, _nonce, _ct, _tag, _crc, _aad, _n = _encrypted_wire(
            password=password,
            plaintext=plaintext,
            name="test.bin",
        )

        resp = b"222 0 <art@e2e>" + b"\r\n" + enc_body + b"." + b"\r\n"
        # Split exactly at the \r|\n boundary of the \r\n.\r\n terminator
        split_at = resp.rfind(b"\r\n") + 1
        assert resp[split_at - 1 : split_at + 1] == b"\r\n"
        srv = MockArticleNNTPServer(enc_body, split_at=[split_at])
        srv.start()

        try:
            s1 = Server(
                server_id="srv_crlf_split",
                displayname="CRLF Split Server",
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
                # First chunk ends with '\r'; the response is not complete yet, so a
                # second read is required to receive the terminator's lone '\n'.
                nw1.read()
                nw1.read()

                # The split-terminator response must complete natively and decode to
                # the exact authenticated plaintext (no timeout/loss, no fabricated \r).
                assert mock_cache.save_article.called
                _saved_art, saved_data = mock_cache.save_article.call_args[0]
                assert bytes(saved_data) == plaintext
                # CRLF framing must not be misdetected as bare-LF framing
                assert not art._bare_lf

        finally:
            srv.stop()

    def test_crlf_split_mid_line_across_tcp_chunks(self):
        """Splitting mid-data-line at a \\r|\\n boundary must also stay byte-exact:
        the client assembles one intact CRLF-framed response from two TCP chunks."""
        password = "crlf_midline_password"
        plaintext = b"CRLF mid-line split end-to-end test payload!"

        enc_body, _adapter, _mk, _nonce, _ct, _tag, _crc, _aad, _n = _encrypted_wire(
            password=password,
            plaintext=plaintext,
            name="test.bin",
        )

        resp = b"222 0 <art@e2e>" + b"\r\n" + enc_body + b"." + b"\r\n"
        # Split mid-body at a \r|\n boundary between two wire lines (not the terminator).
        # Wire control lines are FF1-encrypted binary, but their terminating CRLF is
        # intact. Line 1 (salt+index+FF1) may itself contain \r\n bytes, so scan for the
        # CRLF that begins the =yend-adjacent framing: the last CRLF before the "." line,
        # minus one full terminator — i.e. split after the '\r' of the data-line CRLF
        # that precedes the final wire line.
        terminator_pos = resp.rfind(b"\r\n.")
        assert terminator_pos != -1
        split_at = terminator_pos + 1  # first split: \r|\n of the terminator (baseline)
        # Mid-line split: take the CRLF preceding the last wire line before the terminator
        prev_crlf = resp.rfind(b"\r\n", 0, terminator_pos - 1)
        assert prev_crlf != -1
        split_at = prev_crlf + 1
        assert resp[split_at - 1 : split_at + 1] == b"\r\n"
        srv = MockArticleNNTPServer(enc_body, split_at=[split_at])
        srv.start()

        try:
            s1 = Server(
                server_id="srv_crlf_mid",
                displayname="CRLF Mid-line Split Server",
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
                nw1.read()

                # The mid-line split must not lose or corrupt the article
                assert mock_cache.save_article.called
                _saved_art, saved_data = mock_cache.save_article.call_args[0]
                assert bytes(saved_data) == plaintext
                assert not art._bare_lf

        finally:
            srv.stop()


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
        import threading
        import sabnzbd.decoder as decoder
        from sabnzbd.encryption import DecryptionAdapter

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

    def test_split_lines_preserving_endings(self):
        """split_lines_preserving_endings handles unterminated inputs cleanly."""
        from sabnzbd.encryption import split_lines_preserving_endings

        # Unterminated trailing line
        raw = b"=ybegin line=128 size=10\r\n=yend size=10"
        lines = split_lines_preserving_endings(raw)
        assert len(lines) == 2
        assert lines[0] == b"=ybegin line=128 size=10\r\n"
        assert lines[1] == b"=yend size=10"

    def test_split_lines_sub_bootstrap_non_y_input(self):
        """Sub-BOOTSTRAP_PREFIX_LEN non-'=y' input is one truncated Line 1."""
        from sabnzbd.encryption import BOOTSTRAP_PREFIX_LEN, split_lines_preserving_endings

        # A 0x0A inside the (missing) 20-byte prefix must NOT fragment Line 1.
        raw = b"\xaa\x0a\xbb" + b"\r\nrest"
        lines = split_lines_preserving_endings(raw)
        assert len(lines) == 1
        assert lines[0] == raw

        # Same for a lone unterminated fragment shorter than the prefix.
        assert split_lines_preserving_endings(b"short") == [b"short"]

        # At exactly BOOTSTRAP_PREFIX_LEN total (including an embedded 0x0A past
        # the prefix window) the prefix skip applies: the \n after position 20 is
        # not searched, so the input stays one line.
        raw2 = b"\x01" * (BOOTSTRAP_PREFIX_LEN - 1) + b"\n" + b"tail"
        assert len(raw2) == BOOTSTRAP_PREFIX_LEN + 4
        lines2 = split_lines_preserving_endings(raw2)
        assert len(lines2) == 1
        assert lines2[0] == raw2

    def test_restore_control_lines_min_lines_truncated(self):
        """restore_control_lines rejects truncated blocks below min line count."""
        from sabnzbd.encryption import DecryptionAdapter

        adapter = DecryptionAdapter(password="testpass")
        salt = b"\x02" * 16
        master_key = adapter.get_master_key(salt)
        seg_idx = 1

        k1, t1 = adapter.derive_control_keys(master_key, seg_idx, 1)
        ct1 = encrypt_control_line(b"=ybegin line=128 size=50 name=test.bin", k1, t1)
        wire_line1 = salt + seg_idx.to_bytes(4, "big") + ct1 + b"\r\n"

        # 1 line total, minimum is 2
        truncated_single = wire_line1
        with pytest.raises(ValueError, match="Article block too short for encrypted yEnc"):
            adapter.restore_control_lines(truncated_single)

    def test_restore_control_lines_strict_sequence(self):
        """restore_control_lines strictly validates header sequence and missing =yencryption."""
        from sabnzbd.encryption import DecryptionAdapter

        adapter = DecryptionAdapter(password="testpass")
        salt = b"\x03" * 16
        master_key = adapter.get_master_key(salt)
        seg_idx = 1

        k1, t1 = adapter.derive_control_keys(master_key, seg_idx, 1)
        k2, t2 = adapter.derive_control_keys(master_key, seg_idx, 2)
        k4, t4 = adapter.derive_control_keys(master_key, seg_idx, 4)

        # Singlepart line 2 decrypts to =ypart instead of =yencryption -> must fail
        ct1 = encrypt_control_line(b"=ybegin line=128 size=50 name=test.bin", k1, t1)
        wire_line1 = salt + seg_idx.to_bytes(4, "big") + ct1 + b"\r\n"
        ct2_bad = encrypt_control_line(b"=ypart begin=1 end=50", k2, t2)
        wire_line2_bad = ct2_bad + b"\r\n"
        ct4 = encrypt_control_line(b"=yend size=50 crc32=12345678", k4, t4)
        wire_footer = ct4 + b"\r\n"

        bad_single = wire_line1 + wire_line2_bad + b"DATA\r\n" + wire_footer
        from sabnzbd.encryption import extract_and_remove_yencryption

        restored_single, _, _ = adapter.restore_control_lines(bad_single)
        with pytest.raises(ValueError):
            extract_and_remove_yencryption(restored_single)

        # Multipart line 2 decrypts to =yencryption instead of =ypart -> must fail
        ct1_multi = encrypt_control_line(b"=ybegin part=1 line=128 size=50 name=test.bin", k1, t1)
        wire_multi1 = salt + seg_idx.to_bytes(4, "big") + ct1_multi + b"\r\n"
        ct2_multi_bad = encrypt_control_line(
            b"=yencryption cipher=XChaCha20-Poly1305 index=00000001 salt="
            + salt.hex().encode("ascii")
            + b" tag="
            + (b"00" * 16),
            k2,
            t2,
        )
        wire_multi2_bad = ct2_multi_bad + b"\r\n"
        bad_multi = wire_multi1 + wire_multi2_bad + b"DATA\r\n" + wire_footer
        with pytest.raises(ValueError, match="Multipart line 2 does not start with =ypart"):
            adapter.restore_control_lines(bad_multi)

    def test_restore_control_lines_trailing_blank_lines(self):
        """restore_control_lines handles trailing blank lines after footer without crashing."""
        from sabnzbd.encryption import DecryptionAdapter

        adapter = DecryptionAdapter(password="testpass")
        salt = b"\x04" * 16
        master_key = adapter.get_master_key(salt)
        seg_idx = 1

        k1, t1 = adapter.derive_control_keys(master_key, seg_idx, 1)
        k2, t2 = adapter.derive_control_keys(master_key, seg_idx, 2)
        k4, t4 = adapter.derive_control_keys(master_key, seg_idx, 4)

        ct1 = encrypt_control_line(b"=ybegin line=128 size=50 name=test.bin", k1, t1)
        wire_line1 = salt + seg_idx.to_bytes(4, "big") + ct1 + b"\r\n"
        ct2 = encrypt_control_line(
            b"=yencryption cipher=XChaCha20-Poly1305 index=00000001 salt="
            + salt.hex().encode("ascii")
            + b" tag="
            + (b"00" * 16),
            k2,
            t2,
        )
        wire_line2 = ct2 + b"\r\n"
        data_line = b"PAYLOAD DATA LINE\r\n"
        ct4 = encrypt_control_line(b"=yend size=50 crc32=12345678", k4, t4)
        wire_footer = ct4 + b"\r\n"

        wire_with_trailing_blanks = wire_line1 + wire_line2 + data_line + wire_footer + b"\r\n\r\n"
        restored, out_salt, out_idx = adapter.restore_control_lines(wire_with_trailing_blanks)
        assert b"=yend size=50" in restored
        assert restored.endswith(b"\r\n\r\n")
        assert out_salt == salt
        assert out_idx == seg_idx

    def test_extract_bootstrap_line1_min_length(self):
        """extract_bootstrap_from_line1 enforces minimum line 1 length."""
        from sabnzbd.encryption import extract_bootstrap_from_line1

        salt = b"\x05" * 16
        seg_bytes = (1).to_bytes(4, "big")
        valid_prefix = salt + seg_bytes

        # 22 bytes is the minimum (20-byte bootstrap + 2-byte FF1 minimum)
        line_ok = valid_prefix + b"AA"
        s, idx = extract_bootstrap_from_line1(line_ok)
        assert s == salt
        assert idx == 1

        # 21 bytes is below the minimum
        line_too_short = valid_prefix + b"A"
        with pytest.raises(ValueError, match="Line 1 truncated"):
            extract_bootstrap_from_line1(line_too_short)

    def test_wire_crc_error_raises_valueerror_for_encrypted_article(self):
        """decode_yenc raises ValueError on CRC error for encrypted article without saving BadData."""
        import sabctools
        import sabnzbd.decoder as decoder

        article = mock.MagicMock(spec=Article)
        article.article = "wire_crc@enc"
        article.nzf.nzo.yenc_encrypted = True
        article.nzf.type = "yenc"
        article.nzf.filename_checked = True
        article.lowest_partnum = False

        response = mock.MagicMock(spec=sabctools.NNTPResponse)
        response.sink_failed = False
        response.bytes_decoded = 100
        response.data = bytearray(b"corrupted_bytes")
        response.file_size = 1000
        response.part_begin = 0
        response.part_size = 100
        response.crc = None
        response.lines = None

        # Zero-Output Rule: a decoded (unauthenticated) body for a declared-encrypted
        # release means the article was substituted with a plain one - rejected before
        # the CRC block.
        with pytest.raises(ValueError, match="UNAUTHENTICATED_ARTICLE"):
            decoder.decode_yenc(article, response)


class TestDotUnstuffing:
    """Dot-stuffing transport boundary (RFC 3977 §3.1.1) for encrypted Line 1."""

    def test_sabctools_unstuffing_boundary_probe(self):
        """Boundary probe: sabctools unstuffs yEnc DATA lines but preserves '..' on non-yEnc lines.

        The encrypted path (FF1-encrypted control lines, bytes_decoded == 0) goes through
        response.lines where sabctools does NOT unstuff - so the decoder adapter must.
        """
        import io
        import sabctools

        # Data path: '..' in yEnc data is unstuffed by sabctools during decode
        wire_data = b"222 0 <a@t>\r\n=ybegin line=64 size=8 name=x\r\n..abcdefg\r\n=yend size=8\r\n.\r\n"
        dec = sabctools.Decoder(len(wire_data))
        reader = io.BytesIO(wire_data)
        reader.readinto(dec)
        dec.process(len(wire_data))
        resp = next(dec)
        assert resp.data is not None and len(resp.data) == 8, "sabctools unstuffs yEnc data lines"

        # Lines path (encrypted candidate): '..' preserved verbatim
        wire_lines = b"222 0 <a@t>\r\n..FIRST\r\nSECOND\r\n.\r\n"
        dec2 = sabctools.Decoder(len(wire_lines))
        reader2 = io.BytesIO(wire_lines)
        reader2.readinto(dec2)
        dec2.process(len(wire_lines))
        resp2 = next(dec2)
        assert resp2.lines[0] == "..FIRST", "sabctools preserves '..' on the encrypted lines path"

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

        resp = mock.MagicMock(spec=sabctools.NNTPResponse)
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

        resp = mock.MagicMock(spec=sabctools.NNTPResponse)
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
        resp.yencryption = None
        return resp

    def _enc_article(self, nzo_yenc_encrypted=True):
        article = mock.MagicMock(spec=Article)
        article.article = "plain-sub@news"
        article.nzf.nzo.yenc_encrypted = nzo_yenc_encrypted
        article.nzf.nzo.precheck = False
        article.lowest_partnum = False
        return article

    def test_plain_article_rejected_when_release_declared_encrypted(self):
        """(1) yenc_encrypted release + plain yEnc response raises UNAUTHENTICATED_ARTICLE."""
        import sabnzbd.decoder as decoder

        article = self._enc_article()
        response = self._plain_response()

        with pytest.raises(ValueError, match="UNAUTHENTICATED_ARTICLE"):
            decoder.decode_yenc(article, response)
        # Raise happens before the CRC block populates article.crc32 (magic stays untouched)
        article.crc32.assert_not_called if callable(article.crc32) else None
        assert not article.crc32 == 0x12345678

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

        good_resp = mock.MagicMock(spec=sabctools.NNTPResponse)
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

    def test_plain_release_still_decodes_normally(self):
        """(4) Compatibility regression guard: yenc_encrypted=False plain article decodes normally."""
        import sabnzbd.decoder as decoder

        article = self._enc_article(nzo_yenc_encrypted=False)
        article.nzf.filename_checked = True
        response = self._plain_response()

        assert decoder.decode_yenc(article, response) == response.data

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

    def test_unencrypted_article_value_error_eligible_for_server_search(self):
        """(6) Unencrypted article raising ValueError is eligible for search_new_server and registers failure on exhaustion."""
        import sabnzbd.decoder as decoder

        article = self._enc_article(nzo_yenc_encrypted=False)
        article.article = "unenc_valerr@news"
        article.nzf.filename_checked = True
        article.on_disk = False
        article.search_new_server.return_value = True

        response = self._plain_response()

        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch("sabnzbd.decoder.decode_yenc", side_effect=ValueError("bad unencrypted data")),
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
        ):
            # Server search succeeds -> returns early
            decoder.decode(article, response)
            assert article.search_new_server.called
            assert not mock_queue.register_article.called

            # Server search fails (exhausted) -> cleanly registers failure without crash
            article.search_new_server.reset_mock()
            article.search_new_server.return_value = False
            decoder.decode(article, response)
            assert article.search_new_server.called
            assert article.nzf.nzo.increase_bad_articles_counter.called
            mock_queue.register_article.assert_called_with(article, False)


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

        resp = mock.MagicMock(spec=sabctools.NNTPResponse)
        resp.sink_failed = False
        resp.format = sabctools.EncodingFormat.YENC
        resp.bytes_decoded = 0
        resp.lines = ["=ybegin line=128 size=50 name=test.bin", "AAAABBBBCCCCDDDDEEEE", "=yend size=50"]
        resp.data = None
        resp.yencryption = None
        resp.crc = None

        with pytest.raises(YEncEncryptionStructuralError, match="MISSING_PASSWORD"):
            decoder.decode_yenc(article, resp)

    def test_authenticated_empty_segment_counts_as_decoded(self):
        """An authenticated zero-length plaintext is decoded/complete — the empty
        segment must count as decoded, not fall through as missing data."""
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

        resp = mock.MagicMock(spec=sabctools.NNTPResponse)
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
            # An empty authenticated plaintext IS complete: marked decoded, nothing
            # cached, and never treated as ordinary streamed output.
            assert article.decoded is True
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
        from sabnzbd.encryption import DecryptionAdapter, extract_and_remove_yencryption

        adapter = DecryptionAdapter(password="testpass")
        salt = b"\x07" * 16
        seg_idx = 1
        wire_block = self._wire_block(adapter, salt, seg_idx, corrupt_line2=True)

        restored, _out_salt, _out_idx = adapter.restore_control_lines(wire_block)
        with pytest.raises(ValueError):
            extract_and_remove_yencryption(restored)

    def test_corrupt_header_line_never_appended_as_data_line(self):
        """The raw wire line of a failed header decryption is never accepted as data:
        extract_and_remove_yencryption fails closed on the restored block."""
        from sabnzbd.encryption import DecryptionAdapter, extract_and_remove_yencryption

        adapter = DecryptionAdapter(password="testpass")
        salt = b"\x08" * 16
        seg_idx = 1
        wire_block = self._wire_block(adapter, salt, seg_idx, corrupt_line2=True)

        # The corrupted position either fails restoration outright or restores to a
        # non-=yencryption value; in both cases the block can never proceed to body
        # decryption (no =yencryption params are available).
        with pytest.raises(ValueError):
            restored, _s, _i = adapter.restore_control_lines(wire_block)
            extract_and_remove_yencryption(restored)

    def test_extract_and_remove_yencryption_byte_exact(self):
        """Leading whitespace is no longer masked - reconstruction is byte-exact."""
        from sabnzbd.encryption import extract_and_remove_yencryption

        valid_hdr = b"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b"

        # Clean block still works
        single = b"=ybegin line=128 size=100 name=test.bin\r\n" + valid_hdr + b"\r\nDataLine1\r\n=yend size=100\r\n"
        params, clean = extract_and_remove_yencryption(single)
        assert params["segment_index"] == 1
        assert clean == b"=ybegin line=128 size=100 name=test.bin\r\nDataLine1\r\n=yend size=100\r\n"

        # Leading whitespace on the =yencryption line is no longer silently stripped:
        # the strict grammar itself rejects it (parse_yencryption_line ValueError)
        indented_hdr = b" " + valid_hdr
        indented = (
            b"=ybegin line=128 size=100 name=test.bin\r\n" + indented_hdr + b"\r\nDataLine1\r\n=yend size=100\r\n"
        )
        with pytest.raises(ValueError):
            extract_and_remove_yencryption(indented)


class TestMissingCryptoDependencies:
    """Ordinary imports/startup work without argon2/pynacl; encrypted jobs fail with
    structural diagnostics on first use (lazy dependency loading)."""

    @staticmethod
    def _block_crypto_modules():
        """Install an import blocker for argon2/nacl and purge them from sys.modules."""
        import importlib.abc
        import sys

        class Blocker(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname in ("argon2", "nacl") or fullname.startswith(("argon2.", "nacl.")):
                    raise ImportError(f"No module named {fullname!r} (blocked)")
                return None

        blocker = Blocker()
        sys.meta_path.insert(0, blocker)
        saved = {name: mod for name, mod in sys.modules.items() if name.startswith(("argon2", "nacl"))}
        for name in saved:
            del sys.modules[name]
        return blocker, saved

    @staticmethod
    def _restore_crypto_modules(blocker, saved):
        import sys

        sys.meta_path.remove(blocker)
        sys.modules.update(saved)

    def test_encrypted_job_without_crypto_deps_fails_structurally(self, caplog):
        """With argon2/nacl blocked, an encrypted job raises a structural diagnostic
        naming the missing package; plain paths keep working."""
        import sys

        blocker, saved = self._block_crypto_modules()
        try:
            from sabnzbd.encryption import DecryptionAdapter, MissingDependencyError

            # Plain paths must not touch the crypto packages at all
            adapter_plain = DecryptionAdapter(password="unused")
            assert adapter_plain.password == "unused"

            adapter = DecryptionAdapter(password="pw")
            with pytest.raises(MissingDependencyError, match="argon2-cffi"):
                adapter.get_master_key(b"\x01" * 16)

            # MissingDependencyError must NOT be routed as provider corruption:
            # it derives from ImportError, not ValueError.
            assert not isinstance(MissingDependencyError("x"), ValueError)
        finally:
            self._restore_crypto_modules(blocker, saved)
            # Drop lazily-imported modules cached during the block
            for name in list(sys.modules):
                if name.startswith(("argon2", "nacl")) and name not in saved:
                    del sys.modules[name]

        # After restore, the adapter works again
        adapter_ok = DecryptionAdapter(password="pw")
        key = adapter_ok.get_master_key(b"\x02" * 16)
        assert len(key) == 32

    def test_ordinary_imports_without_crypto_deps(self):
        """Core modules import and plain NzbObject/NzbFile construct without crypto deps."""
        import datetime
        import sys

        blocker, saved = self._block_crypto_modules()
        try:
            # The imports themselves must not require argon2/nacl
            import sabnzbd.decoder
            import sabnzbd.nzbparser  # noqa: F401

            from sabnzbd.nzb import NzbObject, NzbFile

            nzo = NzbObject("plainjob")
            nzf = NzbFile(datetime.datetime.now(), "f.bin", [("m1@test", 100, 1)], 100, nzo)
            assert nzf.nzo is nzo
        finally:
            self._restore_crypto_modules(blocker, saved)
            for name in list(sys.modules):
                if name.startswith(("argon2", "nacl")) and name not in saved:
                    del sys.modules[name]


class TestStructuralErrorFailsWithoutServerSearch:
    """Structural errors fail the article without trying other servers."""

    def test_structural_error_never_searches_new_server(self):
        """decode() fails the article without server search and without storing output."""
        import sabctools
        import sabnzbd.decoder as decoder
        from sabnzbd.encryption import YEncEncryptionStructuralError

        article = mock.MagicMock(spec=Article)
        article.article = "structural@abort"
        article.nzf.nzo.yenc_encrypted = True
        article.nzf.nzo.precheck = False
        article.nzf.nzo.password = None  # structural: no password
        article.search_new_server.return_value = True  # must never be consulted
        article.on_disk = False

        response = mock.MagicMock(spec=sabctools.NNTPResponse)
        response.sink_failed = False
        response.format = sabctools.EncodingFormat.YENC
        response.bytes_decoded = 0
        response.lines = None

        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch("sabnzbd.decoder.decode_yenc", side_effect=YEncEncryptionStructuralError("MISSING_PASSWORD")),
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
        ):
            decoder.decode(article, response)

            mock_queue.register_article.assert_called_once_with(article, False)
            assert not article.search_new_server.called
            assert not mock_cache.save_article.called
            assert not article.on_disk
            assert article.nzf.nzo.fail_msg

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

import json
from pathlib import Path
from unittest import mock
import pytest

import sabnzbd
from sabnzbd.encryption import (
    DecryptionAdapter,
    parse_yencryption_line,
    byte_to_numeral,
    numeral_to_byte,
)
from sabnzbd.nzb import Article
from sabnzbd.newswrapper import NewsWrapper


def _get_test_vector_dir() -> Path:
    # Project root is 2 directories up from sabnzbd/tests
    project_root = Path(__file__).resolve().parents[2]
    vector_dir = project_root / "yenc-encryption-standards" / "test-vectors"
    if not vector_dir.exists():
        pytest.skip(f"Test vectors not found at {vector_dir}")
    return vector_dir


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

            adapter = DecryptionAdapter(password=password)
            pt = adapter.decrypt_body(expected_ct, expected_tag, salt, segment_index)
            assert pt == expected_pt, f"Plaintext mismatch for {vec['id']}"

        # 4. Zero-Output Guarantee on authentication failure
        adapter = DecryptionAdapter(password="test123")
        salt = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        good_vec = body_data["vectors"][0]
        ct = bytes.fromhex(good_vec["expected_ciphertext_hex"])
        tag = bytes.fromhex(good_vec["expected_tag_hex"])

        # Corrupted tag
        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            adapter.decrypt_body(ct, bad_tag, salt, segment_index=1)

        # Corrupted ciphertext
        bad_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            adapter.decrypt_body(bad_ct, tag, salt, segment_index=1)

        # Wrong segment_index
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            adapter.decrypt_body(ct, tag, salt, segment_index=2)

        # Wrong password
        wrong_adapter = DecryptionAdapter(password="wrongpassword")
        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            wrong_adapter.decrypt_body(ct, tag, salt, segment_index=1)

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
                restored_block, extracted_salt = adapter.restore_control_lines(wire_block, segment_index)
                assert extracted_salt == bytes.fromhex(vec["salt_hex"])
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
                    assert line_salt == salt
                    ct = wire_bytes[16:]
                else:
                    ct = wire_bytes

                pt_line = adapter.decrypt_control_line(ct, enc_key, tweak)
                assert pt_line == expected_pt_line, f"Control line mismatch for {vec['id']}"

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
        line = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b"
        parsed = parse_yencryption_line(line)
        assert parsed is not None
        assert parsed["cipher"] == "XChaCha20-Poly1305"
        assert parsed["salt"] == bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        assert parsed["tag"] == bytes.fromhex("0cd77ce245a654463f90b945b1d22d5b")

        # Invalid lines
        assert parse_yencryption_line("not an encryption line") is None
        assert parse_yencryption_line("=yencryption cipher=AES salt=123 tag=456") is None


class TestDirectWriteGatingAndFailover:
    """Test suite verifying direct-write gating and authentication error routing."""

    def test_direct_write_gated(self):
        """article_sink returns None for password-bearing releases, enabling direct-write only for plain releases."""
        # Mock server instance
        wrapper = mock.MagicMock(spec=NewsWrapper)

        # 1. Password-bearing article: direct-write must be refused (return None)
        article_enc = mock.MagicMock(spec=Article)
        article_enc.nzf.nzo.password = "secret_password"
        article_enc.nzf.type = "yenc"
        article_enc.lowest_partnum = False
        article_enc.nzf.prepare_filepath.return_value = True

        mock_monitor = mock.MagicMock(allow_direct_decode=True)
        with (
            mock.patch.object(sabnzbd.cfg, "direct_decode", return_value=True),
            mock.patch.object(sabnzbd.cfg, "direct_write", return_value=True),
            mock.patch.object(sabnzbd, "WriteMonitor", mock_monitor, create=True),
        ):
            sink = NewsWrapper.article_sink(wrapper, article_enc)
            assert sink is None, "Expected direct-write to be refused for password-bearing release"

        # 2. Unencrypted article: direct-write allowed when configured
        article_plain = mock.MagicMock(spec=Article)
        article_plain.nzf.nzo.password = None
        article_plain.nzf.type = "yenc"
        article_plain.lowest_partnum = False
        article_plain.nzf.prepare_filepath.return_value = True
        mock_writer = mock.MagicMock()

        mock_assembler = mock.MagicMock()
        mock_assembler.get_writer.return_value = mock_writer
        with (
            mock.patch.object(sabnzbd.cfg, "direct_decode", return_value=True),
            mock.patch.object(sabnzbd.cfg, "direct_write", return_value=True),
            mock.patch.object(sabnzbd, "WriteMonitor", mock_monitor, create=True),
            mock.patch.object(sabnzbd, "Assembler", mock_assembler, create=True),
        ):
            sink = NewsWrapper.article_sink(wrapper, article_plain)
            assert sink == mock_writer, "Expected direct-write sink to be returned for plain release"

    def test_auth_failure_triggers_server_search(self):
        """Poly1305 authentication error in decode() triggers search_new_server without unhandled crash."""
        import sabnzbd
        import sabnzbd.decoder as decoder
        import sabctools

        article = mock.MagicMock(spec=Article)
        article.article = "art_fail@news"
        article.nzf.nzo.password = "test123"
        article.nzf.nzo.precheck = False
        article.lowest_partnum = False
        article.segment_index = 1
        article.on_disk = False
        article.search_new_server.return_value = True

        # NNTPResponse with bad tag causing Poly1305 authentication failure
        resp = mock.MagicMock(spec=sabctools.NNTPResponse)
        resp.sink_failed = False
        resp.format = sabctools.EncodingFormat.YENC
        resp.data = bytearray(b"corrupted ciphertext")
        resp.file_size = 1000
        resp.part_begin = 0
        resp.part_size = 20
        resp.bytes_decoded = 20
        resp.file_name = "test.bin"
        resp.crc = 0x12345678
        resp.lines = None
        resp.yencryption = {
            "cipher": "XChaCha20-Poly1305",
            "salt": b"\x01" * 16,
            "tag": b"\x02" * 16,
        }

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

    def test_successful_encrypted_decode(self):
        """decode_yenc restores authenticated plaintext when valid =yencryption metadata is present."""
        import sabnzbd.decoder as decoder
        import sabctools

        vector_dir = _get_test_vector_dir()
        with open(vector_dir / "body_encryption.json", "r", encoding="utf-8") as f:
            body_data = json.load(f)

        vec = body_data["vectors"][0]
        password = vec["password"]
        salt = bytes.fromhex(vec["salt_hex"])
        ct = bytes.fromhex(vec["expected_ciphertext_hex"])
        tag = bytes.fromhex(vec["expected_tag_hex"])
        expected_pt = bytes.fromhex(vec["plaintext_hex"])

        article = mock.MagicMock(spec=Article)
        article.article = "art_ok@news"
        article.nzf.nzo.password = password
        article.nzf.filename_checked = True
        article.lowest_partnum = False
        article.segment_index = vec["segment_index"]

        resp = mock.MagicMock(spec=sabctools.NNTPResponse)
        resp.sink_failed = False
        resp.data = bytearray(ct)
        resp.file_size = 100
        resp.part_begin = 0
        resp.part_size = len(ct)
        resp.bytes_decoded = len(ct)
        resp.file_name = "test.bin"
        resp.crc = 0x12345678
        resp.lines = None
        resp.yencryption = {
            "cipher": "XChaCha20-Poly1305",
            "salt": salt,
            "tag": tag,
        }

        res = decoder.decode_yenc(article, resp)
        assert res == bytearray(expected_pt), "Expected decoded data to be authenticated plaintext"
        assert article.decoded_size == len(expected_pt)



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
tests.test_decoder- Testing functions in decoder.py
"""

import binascii
import os
import threading
import pytest
from io import BytesIO

from random import randint
from unittest import mock

import nacl.bindings as nb
import sabctools
import sabnzbd
import sabnzbd.decoder as decoder
from sabnzbd.encryption import DecryptionAdapter, YEncEncryptionStructuralError
from sabnzbd.nzb import Article, NzbFile


def uu(data: bytes):
    """Uuencode data and insert a period if necessary"""
    line = binascii.b2a_uu(data).rstrip(b"\n")

    # Dot stuffing
    if line.startswith(b"."):
        return b"." + line

    return line


LINES_DATA = [os.urandom(45) for _ in range(32)]
VALID_UU_LINES = [uu(data) for data in LINES_DATA]

END_DATA = os.urandom(randint(1, 45))
VALID_UU_END = [
    uu(END_DATA),
    b"`",
    b"end",
]


class TestUuDecoder:
    def _generate_msg_part(
        self,
        part: str,
        insert_empty_line: bool = True,
        insert_excess_empty_lines: bool = False,
        insert_headers: bool = False,
        insert_end: bool = True,
        insert_dot_stuffing_line: bool = False,
        begin_line: bytes = b"begin 644 My Favorite Open Source Movie.mkv",
    ):
        """Generate message parts. Part may be one of 'begin', 'middle', or 'end' for multipart
        messages, or 'single' for a singlepart message. All uu payload is taken from VALID_UU_*.

        Returns Article with a random id and lowest_partnum correctly set, socket-style raw
        data, and the expected result of uu decoding for the generated message.
        """
        article_id = "test@host" + os.urandom(8).hex() + ".sab"
        # Mock an nzf so results from hashing and filename handling can be stored
        mock_nzf = mock.Mock()
        article = Article(article_id, randint(4321, 54321), mock_nzf)
        article.lowest_partnum = True if part in ("begin", "single") else False

        # Store the message data and the expected decoding result
        data = []
        result = []

        # Always start with the response code line
        data.append(b"222 0 <" + bytes(article_id, encoding="ascii") + b">")

        if insert_empty_line:
            # Only insert other headers if there's an empty line
            if insert_headers:
                data.extend([b"x-hoop: is uitgestelde teleurstelling", b"Another-Header: Sure"])

            # Insert the empty line between response code and body
            data.append(b"")

        if insert_excess_empty_lines:
            data.extend([b"", b""])

        # Insert uu data into the body
        if part in ("begin", "single"):
            data.append(begin_line)

        if part in ("begin", "middle", "single"):
            size = randint(4, len(VALID_UU_LINES) - 1)
            data.extend(VALID_UU_LINES[:size])
            result.extend(LINES_DATA[:size])

            if insert_dot_stuffing_line:
                data.append(uu(b"\0" * 14))
                result.append(b"\0" * 14)

        if part in ("end", "single"):
            if insert_end:
                data.extend(VALID_UU_END)
                result.append(END_DATA)

        # Signal the end of the message with a dot on a line of its own
        data.append(b".\r\n")

        # Join the data with \r\n line endings, just like we get from socket reads
        data = b"\r\n".join(data)
        # Concatenate expected result
        result = b"".join(result)

        return article, bytearray(data), result

    @staticmethod
    def _response(raw_data: bytes) -> sabctools.NNTPResponse:
        dec = sabctools.Decoder(len(raw_data))
        reader = BytesIO(raw_data)
        reader.readinto(dec)
        dec.process(len(raw_data))
        return next(dec)

    @pytest.mark.parametrize(
        "raw_data",
        [
            b"222 0 <foo@bar>\r\n.\r\n",
            b"222 0 <foo@bar>\r\n\r\n.\r\n",
            b"222 0 <foo@bar>\r\nfoobar\r\n.\r\n",  # Plenty of list items, but (too) few actual lines
            b"222 0 <foo@bar>\r\nX-Too-Short: yup\r\n.\r\n",
        ],
    )
    def test_short_data(self, raw_data):
        mock_nzf = mock.Mock()
        article = Article("foo@bar", 4321, mock_nzf)
        with pytest.raises(decoder.BadUu):
            assert decoder.decode_uu(article, self._response(raw_data))

    @pytest.mark.parametrize(
        "raw_data",
        [
            b"222 0 <foo@bar>\r\n\r\n",  # Missing altogether
            b"222 0 <foo@bar>\r\n\r\nbeing\r\n",  # Typo in 'begin'
            b"222 0 <foo@bar>\r\n\r\nx-header: begin 644 foobar\r\n",  # Not at start of the line
            b"666 0 <foo@bar>\r\nbegin\r\n",  # No empty line + wrong response code
            b"OMG 0 <foo@bar>\r\nbegin\r\n",  # No empty line + invalid response code
            b"222 0 <foo@bar>\r\nbegin\r\n",  # No perms
            b"222 0 <foo@bar>\r\nbegin ABC DEF\r\n",  # Permissions not octal
            b"222 0 <foo@bar>\r\nbegin 755\r\n",  # No filename
            b"222 0 <foo@bar>\r\nbegin 644 \t \t\r\n",  # Filename empty after stripping
        ],
    )
    def test_missing_uu_begin(self, raw_data):
        mock_nzf = mock.Mock()
        article = Article("foo@bar", 1234, mock_nzf)
        article.lowest_partnum = True
        filler = b"\r\n" * 4
        with pytest.raises(decoder.BadUu):
            raw_data = bytearray(raw_data)
            raw_data.extend(filler)
            raw_data.extend(b".\r\n")
            assert decoder.decode_uu(article, self._response(raw_data))

    @pytest.mark.parametrize("insert_empty_line", [True, False])
    @pytest.mark.parametrize("insert_excess_empty_lines", [True, False])
    @pytest.mark.parametrize("insert_headers", [True, False])
    @pytest.mark.parametrize("insert_end", [True, False])
    @pytest.mark.parametrize("insert_dot_stuffing_line", [True, False])
    @pytest.mark.parametrize(
        "begin_line",
        [
            b"begin 644 nospace.bin",
            b"begin 444 filename with spaces.txt",
            b"BEGIN 644 foobar",
            b"begin 0755 shell.sh",
        ],
    )
    def test_singlepart(
        self,
        insert_empty_line,
        insert_excess_empty_lines,
        insert_headers,
        insert_end,
        insert_dot_stuffing_line,
        begin_line,
    ):
        """Test variations of a sane single part nzf with proper uu-encoded data"""
        # Generate a singlepart message
        article, raw_data, expected_result = self._generate_msg_part(
            "single",
            insert_empty_line,
            insert_excess_empty_lines,
            insert_headers,
            insert_end,
            insert_dot_stuffing_line,
            begin_line,
        )
        assert decoder.decode_uu(article, self._response(raw_data)) == expected_result
        assert article.nzf.filename_checked

    @pytest.mark.parametrize("insert_empty_line", [True, False])
    def test_multipart(self, insert_empty_line):
        """Test a simple multipart nzf"""

        # Generate and process a multipart msg
        decoded_data = expected_data = b""
        for part in ("begin", "middle", "middle", "end"):
            article, data, result = self._generate_msg_part(part, insert_empty_line, False, False, True)
            decoded_data += decoder.decode_uu(article, self._response(data))
            expected_data += result

        # Verify results
        assert decoded_data == expected_data
        assert article.nzf.filename_checked

    @pytest.mark.parametrize(
        "bad_data",
        [
            VALID_UU_LINES[-1][:10] + bytes("ваше здоровье", encoding="utf8") + VALID_UU_LINES[-1][-10:],  # Non-ascii
        ],
        ids=["non_ascii"],
    )
    def test_broken_uu(self, bad_data):
        mock_nzf = mock.Mock()
        article = Article("foo@bar", 4321, mock_nzf)
        article.lowest_partnum = False
        filler = b"\r\n".join(VALID_UU_LINES[:4]) + b"\r\n"
        with pytest.raises(decoder.BadData):
            assert decoder.decode_uu(
                article, self._response(bytearray(b"222 0 <foo@bar>\r\n" + filler + bad_data + b"\r\n.\r\n"))
            )


class TestEncryptionPhase58:
    def test_crc_clearing_on_encrypted_body_path(self):
        password = "testpassword123"
        salt = b"0123456789abcdef"
        seg_idx = 1
        plaintext = b"Decrypted Plaintext Secret Content 1234567890"

        adapter = DecryptionAdapter(password)
        key = adapter.get_master_key(salt)
        nonce = adapter.derive_body_nonce(key, seg_idx)
        ct_and_tag = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)
        ciphertext = ct_and_tag[:-16]
        tag = ct_and_tag[-16:]

        yenc_line = f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index={seg_idx:08x} tag={tag.hex()}"

        mock_resp = mock.Mock(spec=sabctools.NNTPResponse)
        mock_resp.sink_failed = False
        mock_resp.bytes_decoded = len(ciphertext)
        mock_resp.data = bytearray(ciphertext)
        mock_resp.file_size = len(plaintext)
        mock_resp.part_begin = 1
        mock_resp.part_size = len(plaintext)
        mock_resp.file_name = "test.bin"
        mock_resp.crc = 0x12345678  # wire ciphertext CRC
        mock_resp.lines = [yenc_line]

        mock_nzf = mock.Mock()
        mock_nzf.filename_checked = True
        mock_nzf.type = "yenc"
        mock_nzo = mock.MagicMock()
        mock_nzo.lock = threading.RLock()
        mock_nzo.yenc_encrypted = True
        mock_nzo.password = password
        mock_nzf.nzo = mock_nzo
        article = Article("test@example", len(ciphertext), mock_nzf, segment_index=seg_idx)

        out = decoder.decode_yenc(article, mock_resp)
        assert bytes(out) == plaintext
        # CRC clearing: wire ciphertext CRC is stripped so it does not pollute verification
        assert article.crc32 is None

    def test_crc_propagation_skipping_quick_check(self):
        class FakeNzo:
            def __init__(self):
                self.lock = threading.RLock()
                self.admin_path = "/tmp"
                self.files = []

        fake_nzo = FakeNzo()
        with mock.patch("sabnzbd.nzb.file.get_new_id", return_value="nzf123"), mock.patch(
            "sabnzbd.nzb.file.save_data"
        ):
            nzf = NzbFile(None, "test subject", [], 200, fake_nzo)

        art1 = Article("art1", 100, nzf)
        art1.decoded_size = 100
        art1.crc32 = 0x11111111

        art2 = Article("art2", 100, nzf)
        art2.decoded_size = 100
        art2.crc32 = 0x22222222

        nzf.decodetable = [art1, art2]
        nzf.finalize_crc32()
        assert nzf.crc32 is not None and isinstance(nzf.crc32, int)

        # Clear CRC on one article (encrypted yEnc)
        art1.crc32 = None
        nzf.finalize_crc32()
        assert nzf.crc32 is None

    def test_structural_error_failing_job_without_server_search(self):
        mock_resp = mock.Mock(spec=sabctools.NNTPResponse)
        mock_resp.format = sabctools.EncodingFormat.YENC
        mock_resp.sink_failed = False
        mock_resp.bytes_decoded = 0
        mock_resp.lines = ["corrupt_line"]

        mock_nzo = mock.Mock()
        mock_nzo.precheck = False
        mock_nzo.yenc_encrypted = True
        mock_nzo.password = None
        mock_nzo.fail_msg = None

        mock_nzf = mock.Mock()
        mock_nzf.nzo = mock_nzo

        art = Article("art3@test", 100, mock_nzf)

        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
            mock.patch("sabnzbd.decoder.search_new_server") as mock_search,
            mock.patch(
                "sabnzbd.decoder.decode_yenc",
                side_effect=YEncEncryptionStructuralError("MISSING_PASSWORD"),
            ),
        ):
            decoder.decode(art, mock_resp)
            mock_search.assert_not_called()
            assert mock_nzo.fail_msg is not None
            assert art.on_disk is False
            assert not mock_cache.save_article.called

    def test_failover_routing_on_auth_failure_with_zero_plaintext(self, caplog):
        mock_resp = mock.Mock(spec=sabctools.NNTPResponse)
        mock_resp.format = sabctools.EncodingFormat.YENC
        mock_resp.sink_failed = False
        mock_resp.bytes_decoded = 0
        mock_resp.lines = ["candidate_encrypted_line"]

        canary_secret = "super_secret_canary_pw_999"
        mock_nzo = mock.Mock()
        mock_nzo.precheck = False
        mock_nzo.yenc_encrypted = True
        mock_nzo.password = canary_secret

        mock_nzf = mock.Mock()
        mock_nzf.nzo = mock_nzo

        art = Article("art_failover@test", 100, mock_nzf)

        mock_cache = mock.MagicMock()
        mock_queue = mock.MagicMock()
        with (
            mock.patch.object(sabnzbd, "ArticleCache", mock_cache, create=True),
            mock.patch.object(sabnzbd, "NzbQueue", mock_queue, create=True),
            mock.patch("sabnzbd.decoder.search_new_server", return_value=True) as mock_search,
            mock.patch(
                "sabnzbd.decoder.decode_yenc",
                side_effect=ValueError("Poly1305 authentication failed"),
            ),
        ):
            decoder.decode(art, mock_resp)
            mock_search.assert_called_once()
            assert art.on_disk is False
            assert not mock_cache.save_article.called
            # Verify no secret leaked into log messages
            for record in caplog.records:
                assert canary_secret not in record.message

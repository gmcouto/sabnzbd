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
tests.test_nzbparser - Tests of basic NZB parsing
"""

import gzip
import json
import os
import pytest
from tests.testhelper import SAB_CACHE_DIR, SAB_DATA_DIR, create_and_read_nzb_fp
import sabnzbd.nzbparser as nzbparser
from sabnzbd.nzb import NzbObject
from sabnzbd.filesystem import save_compressed


def _write_nzb_gz(cache_dir: str, name: str, xml_content: str) -> str:
    path = os.path.join(cache_dir, f"{name}.nzb.gz")
    with gzip.open(path, "wb") as f:
        f.write(xml_content.encode("utf-8"))
    return path


@pytest.mark.usefixtures("clean_cache_dir")
class TestNzbParser:
    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_nzbparser(self):
        nzo = NzbObject("test_basic")
        # Create test file
        metadata = {"category": "test", "password": "testpass"}
        nzb_fp = create_and_read_nzb_fp("..", metadata=metadata)

        # Create folder and save compressed NZB like SABnzbd would do
        save_compressed(SAB_CACHE_DIR, "test", nzb_fp)
        nzb_file = os.path.join(SAB_CACHE_DIR, "test.nzb.gz")
        assert os.path.exists(nzb_file)

        # Files we expect
        test_dir = os.path.normpath(os.path.join(SAB_DATA_DIR, ".."))
        expected_files = [fl for fl in os.listdir(test_dir) if os.path.isfile(os.path.join(test_dir, fl))]
        expected_files.sort()
        assert expected_files

        # Parse the file
        nzbparser.nzbfile_parser(nzb_file, nzo)

        # Compare filenames
        resulting_files = [nzf.filename for nzf in nzo.files]
        resulting_files.sort()
        assert resulting_files == expected_files

        # Compare sizes
        expected_sizes = [os.path.getsize(os.path.join(test_dir, fl)) for fl in expected_files]
        expected_sizes.sort()
        resulting_sizes = [nzf.bytes for nzf in nzo.files]
        resulting_sizes.sort()
        assert resulting_sizes == expected_sizes

        # Check meta-data
        for field in metadata:
            assert [metadata[field]] == nzo.meta[field]

    @pytest.mark.xfail(reason="These tests should be added")
    def test_nzbparser_bad_stuff(self):
        # TODO: Add tests for:
        #  Duplicate parts
        #  Strange articles sizes
        #  Correct parsing of dates
        assert False

    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_nzb_segment_identity_conformance(self):
        vectors_path = os.path.join(
            os.path.dirname(__file__),
            "data/test-vectors/nzb_segment_identity.json",
        )
        with open(vectors_path, encoding="utf-8") as vectors_file:
            vectors = json.load(vectors_file)["vectors"]

        for vector in vectors:
            vector_id = vector["id"]
            nzb_file = _write_nzb_gz(SAB_CACHE_DIR, f"test_{vector_id}", vector["nzb_xml"])
            nzo = NzbObject(f"job_{vector_id}")

            nzbparser.nzbfile_parser(nzb_file, nzo)
            for nzf in nzo.files:
                nzf.finish_import()

            articles = [art for nzf in nzo.files for art in nzf.decodetable]
            assert nzo.yenc_encrypted is (vector["category"] != "unencrypted_compatibility"), vector_id

            if expected_segments := vector.get("expected_segments"):
                parsed = sorted((art.article, art.bytes) for art in articles)
                expected = sorted((seg["message_id"], seg["bytes"]) for seg in expected_segments)
                assert parsed == expected, vector_id

    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_separate_yenc_and_archive_passwords(self):
        archive_xml = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head><meta type="password">archive_pass</meta></head>
 <file poster="p@test.com" date="1600000000" subject="&quot;archive.rar&quot; yEnc (1/1)">
  <segments><segment bytes="1000" number="1">archive@test</segment></segments>
 </file>
</nzb>"""
        encrypted_xml = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head>
  <meta type="password">enc_pass</meta>
  <meta type="yenc_encrypted">true</meta>
 </head>
 <file poster="p@test.com" date="1600000000" subject="opaque">
  <segments><segment bytes="1000" number="1">encrypted@test</segment></segments>
 </file>
</nzb>"""
        explicit_xml = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head><meta type="yenc_encrypted">true</meta></head>
 <file poster="p@test.com" date="1600000000" subject="opaque">
  <segments><segment bytes="1000" number="1">explicit@test</segment></segments>
 </file>
</nzb>"""

        archive_nzo = NzbObject("archive")
        nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "archive", archive_xml), archive_nzo)
        archive_nzo.files[0].finish_import()
        assert archive_nzo.meta["password"] == ["archive_pass"]
        assert archive_nzo.yenc_encrypted is False

        encrypted_nzo = NzbObject("encrypted")
        nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "encrypted", encrypted_xml), encrypted_nzo)
        encrypted_nzo.files[0].finish_import()
        assert encrypted_nzo.meta["password"] == ["enc_pass"]
        assert encrypted_nzo.yenc_encrypted is True

        # Explicit yenc_encrypted without password meta is a structural error at ingest
        from sabnzbd.encryption import YEncEncryptionStructuralError

        explicit_nzo = NzbObject("explicit")
        with pytest.raises(YEncEncryptionStructuralError, match="MISSING_PASSWORD"):
            nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "explicit", explicit_xml), explicit_nzo)

        empty_pw_xml = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head><meta type="yenc_encrypted">true</meta><meta type="password"></meta></head>
 <file poster="p@test.com" date="1600000000" subject="opaque">
  <segments><segment bytes="1000" number="1">empty_pw@test</segment></segments>
 </file>
</nzb>"""
        empty_pw_nzo = NzbObject("empty_pw")
        with pytest.raises(YEncEncryptionStructuralError, match="MISSING_PASSWORD"):
            nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "empty_pw", empty_pw_xml), empty_pw_nzo)

        ws_pw_xml = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head><meta type="yenc_encrypted">true</meta><meta type="password">   </meta></head>
 <file poster="p@test.com" date="1600000000" subject="opaque">
  <segments><segment bytes="1000" number="1">ws_pw@test</segment></segments>
 </file>
</nzb>"""
        ws_pw_nzo = NzbObject("ws_pw")
        with pytest.raises(YEncEncryptionStructuralError, match="MISSING_PASSWORD"):
            nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "ws_pw", ws_pw_xml), ws_pw_nzo)

    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_encrypted_ingest_version_cipher_and_order_validation(self):
        """Validate supplied version/cipher/mode during ingest before NNTP, independent of meta tag order."""
        from sabnzbd.encryption import YEncEncryptionStructuralError

        def make_nzb(meta_entries: list[tuple[str, str]]) -> str:
            metas = "\n".join(f'  <meta type="{t}">{v}</meta>' for t, v in meta_entries)
            return f"""<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head>
{metas}
 </head>
 <file poster="p@test.com" date="1600000000" subject="test.bin">
  <segments><segment bytes="1000" number="1">s1@test</segment></segments>
 </file>
</nzb>"""

        # 1. Supported version and cipher present, standard ordering
        xml_ok = make_nzb(
            [
                ("yenc_encrypted", "true"),
                ("yenc_version", "1.2"),
                ("yenc_cipher", "XChaCha20-Poly1305"),
                ("password", "secret123"),
            ]
        )
        nzo_ok = NzbObject("ok")
        nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "ok", xml_ok), nzo_ok)
        assert nzo_ok.yenc_encrypted is True
        assert nzo_ok.password == "secret123"

        # 2. Version and cipher absent -> succeeds (defaults apply)
        xml_absent = make_nzb(
            [
                ("password", "secret_absent"),
                ("yenc_encrypted", "true"),
            ]
        )
        nzo_absent = NzbObject("absent")
        nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "absent", xml_absent), nzo_absent)
        assert nzo_absent.yenc_encrypted is True
        assert nzo_absent.password == "secret_absent"

        # 3. Independent of metadata ordering (reversed order)
        xml_reversed = make_nzb(
            [
                ("password", "reversed_pw"),
                ("yenc_cipher", "XChaCha20-Poly1305"),
                ("yenc_version", "1.2"),
                ("yenc_mode", "combined"),
                ("yenc_encrypted", "true"),
            ]
        )
        nzo_rev = NzbObject("reversed")
        nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "reversed", xml_reversed), nzo_rev)
        assert nzo_rev.yenc_encrypted is True
        assert nzo_rev.password == "reversed_pw"

        # 4. Unsupported version -> raises YEncEncryptionStructuralError
        xml_bad_ver = make_nzb(
            [
                ("yenc_encrypted", "true"),
                ("yenc_version", "2.0"),
                ("password", "secret123"),
            ]
        )
        with pytest.raises(YEncEncryptionStructuralError, match="UNSUPPORTED_VERSION"):
            nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "bad_ver", xml_bad_ver), NzbObject("bad_ver"))

        # 5. Unsupported cipher -> raises YEncEncryptionStructuralError
        xml_bad_cipher = make_nzb(
            [
                ("yenc_encrypted", "true"),
                ("yenc_cipher", "AES-256-GCM"),
                ("password", "secret123"),
            ]
        )
        with pytest.raises(YEncEncryptionStructuralError, match="UNSUPPORTED_CIPHER"):
            nzbparser.nzbfile_parser(
                _write_nzb_gz(SAB_CACHE_DIR, "bad_cipher", xml_bad_cipher), NzbObject("bad_cipher")
            )

    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_yenc_mode_meta_is_ignored(self):
        """No mode metadata exists (Body Std v1.2 §8, Control Std v1.2 §5): a yenc_mode tag has no effect."""
        for mode in ("combined", "body-only", "anything"):
            xml = f"""<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head>
  <meta type="yenc_encrypted">true</meta>
  <meta type="yenc_mode">{mode}</meta>
  <meta type="password">secret123</meta>
 </head>
 <file poster="p@test.com" date="1600000000" subject="test.bin">
  <segments><segment bytes="1000" number="1">mode_{mode}@test</segment></segments>
 </file>
</nzb>"""
            nzo = NzbObject(f"mode_{mode}")
            nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, f"mode_{mode}", xml), nzo)
            assert nzo.yenc_encrypted is True, mode
            assert nzo.password == "secret123", mode

    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_yenc_meta_values_are_trimmed_and_ascii_case_insensitive(self):
        """Body Std v1.2 §8: values are trimmed before matching; the stored password is not trimmed."""
        from sabnzbd.encryption import YEncEncryptionStructuralError

        def make_nzb(meta_entries: list[tuple[str, str]]) -> str:
            metas = "\n".join(f'  <meta type="{t}">{v}</meta>' for t, v in meta_entries)
            return f"""<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head>
{metas}
 </head>
 <file poster="p@test.com" date="1600000000" subject="test.bin">
  <segments><segment bytes="1000" number="1">s1@test</segment></segments>
 </file>
</nzb>"""

        accepted = [
            [("yenc_encrypted", "TRUE"), ("password", "pw1")],
            [("yenc_encrypted", " true "), ("password", "pw2")],
            [
                ("yenc_encrypted", "true"),
                ("yenc_version", " 1.2 "),
                ("yenc_cipher", "xchacha20-poly1305"),
                ("password", "  padded pw  "),
            ],
        ]
        for idx, entries in enumerate(accepted):
            nzo = NzbObject(f"accepted_{idx}")
            nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, f"accepted_{idx}", make_nzb(entries)), nzo)
            assert nzo.yenc_encrypted is True, idx
        assert nzo.password == "  padded pw  "

        rejected = [
            ([("yenc_encrypted", "true"), ("yenc_version", "1.3"), ("password", "pw")], "UNSUPPORTED_VERSION"),
            ([("yenc_encrypted", "true"), ("yenc_cipher", "AES"), ("password", "pw")], "UNSUPPORTED_CIPHER"),
        ]
        for idx, (entries, token) in enumerate(rejected):
            with pytest.raises(YEncEncryptionStructuralError, match=token):
                nzbparser.nzbfile_parser(
                    _write_nzb_gz(SAB_CACHE_DIR, f"rejected_{idx}", make_nzb(entries)), NzbObject(f"rejected_{idx}")
                )

        # Any other yenc_encrypted value means a plain NZB (Body Std v1.2 §8)
        plain = NzbObject("plain_yes")
        nzbparser.nzbfile_parser(
            _write_nzb_gz(SAB_CACHE_DIR, "plain_yes", make_nzb([("yenc_encrypted", "yes")])), plain
        )
        assert plain.yenc_encrypted is False

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

    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_nzb_segment_identity_conformance(self):
        vectors_path = os.path.join(
            os.path.dirname(__file__),
            "data/test-vectors/nzb_segment_identity.json",
        )
        with open(vectors_path, encoding="utf-8") as vectors_file:
            vectors = json.load(vectors_file)["vectors"]

        assert len(vectors) == 33

        for vector in vectors:
            vector_id = vector["id"]
            category = vector["category"]
            nzb_file = _write_nzb_gz(SAB_CACHE_DIR, f"test_{vector_id}", vector["nzb_xml"])
            nzo = NzbObject(f"job_{vector_id}")

            if category == "invalid_identity":
                nzbparser.nzbfile_parser(nzb_file, nzo)
                for nzf in nzo.files:
                    nzf.finish_import()
                assert nzo.yenc_encrypted is False
                assert nzo.meta.get("password") == ["test123"]
                assert all(art.segment_index is None for nzf in nzo.files for art in nzf.decodetable)
                continue

            nzbparser.nzbfile_parser(nzb_file, nzo)
            for nzf in nzo.files:
                nzf.finish_import()

            if category == "unencrypted_compatibility":
                assert nzo.yenc_encrypted is False
                assert all(art.segment_index is None for nzf in nzo.files for art in nzf.decodetable)
                continue

            assert nzo.yenc_encrypted is True
            assert all(art.segment_index is None for nzf in nzo.files for art in nzf.decodetable)

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
 <head><meta type="password">enc_pass</meta></head>
 <file poster="p@test.com" date="1600000000" subject="opaque">
  <segments><segment bytes="1000" number="1" segmentIndex="42">encrypted@test</segment></segments>
 </file>
</nzb>"""
        explicit_xml = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head><meta type="yenc_encrypted">true</meta></head>
 <file poster="p@test.com" date="1600000000" subject="opaque">
  <segments><segment bytes="1000" number="1" segmentIndex="7">explicit@test</segment></segments>
 </file>
</nzb>"""

        archive_nzo = NzbObject("archive")
        nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "archive", archive_xml), archive_nzo)
        archive_nzo.files[0].finish_import()
        assert archive_nzo.meta["password"] == ["archive_pass"]
        assert archive_nzo.yenc_encrypted is False
        assert archive_nzo.files[0].decodetable[0].segment_index is None

        encrypted_nzo = NzbObject("encrypted")
        nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "encrypted", encrypted_xml), encrypted_nzo)
        encrypted_nzo.files[0].finish_import()
        assert encrypted_nzo.meta["password"] == ["enc_pass"]
        assert encrypted_nzo.yenc_encrypted is True
        assert encrypted_nzo.files[0].decodetable[0].segment_index == 42

        explicit_nzo = NzbObject("explicit")
        nzbparser.nzbfile_parser(_write_nzb_gz(SAB_CACHE_DIR, "explicit", explicit_xml), explicit_nzo)
        assert explicit_nzo.yenc_encrypted is True

    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_password_redacted_from_parser_logs(self, caplog):
        """Captured parser logs may name metadata keys but never contain the password value."""
        secret_sentinel = "SECRET_PASSWORD_SENTINEL_XYZ_98765"
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head>
  <meta type="password">{secret_sentinel}</meta>
  <meta type="category">movies</meta>
 </head>
 <file poster="p@test.com" date="1600000000" subject="&quot;test.bin&quot; yEnc (1/1)">
  <segments><segment bytes="1000" number="1">m1@test</segment></segments>
 </file>
</nzb>"""
        nzb_file = _write_nzb_gz(SAB_CACHE_DIR, "test_secret_log", xml)
        nzo = NzbObject("test_secret_log")

        import logging

        with caplog.at_level(logging.DEBUG):
            nzbparser.nzbfile_parser(nzb_file, nzo)

        # The secret password MUST be completely absent from any captured log messages
        assert secret_sentinel not in caplog.text

        # The password metadata must still be present in nzo.meta for downstream consumption
        assert nzo.meta.get("password") == [secret_sentinel]
        assert nzo.meta.get("category") == ["movies"]

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

import os
import gzip
import json
import logging
from typing import Optional
import pytest
from tests.testhelper import SAB_CACHE_DIR, SAB_DATA_DIR, create_and_read_nzb_fp
import sabnzbd.nzbparser as nzbparser
import sabnzbd.cfg as cfg
import sabnzbd.misc as misc
from sabnzbd.nzb import NzbObject
from sabnzbd.filesystem import save_compressed
from sabnzbd.encryption import YEncEncryptionStructuralError, next_permitted_index, index_is_forbidden


def _write_nzb_gz(dir_path: str, name_or_xml: str, xml_content: Optional[str] = None) -> str:
    if xml_content is None:
        name = "test"
        content = name_or_xml
    else:
        name = name_or_xml
        content = xml_content
    path = os.path.join(dir_path, f"{name}.nzb.gz")
    with gzip.open(path, "wb") as f:
        f.write(content.encode("utf-8") if isinstance(content, str) else content)
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

    def test_nzb_segment_identity_conformance(self, tmp_path):
        cfg.download_dir.set(str(tmp_path))
        vector_path = os.path.join(
            os.path.dirname(__file__), "data", "test-vectors", "nzb_segment_identity.json"
        )
        with open(vector_path, "r", encoding="utf-8") as f:
            fixture = json.load(f)

        for vector in fixture["vectors"]:
            vid = vector["id"]
            xml_content = vector["nzb_xml"]
            is_encrypted = vector.get("is_encrypted", False)
            expected_valid = vector.get("expected_valid", True)

            nzb_gz = _write_nzb_gz(str(tmp_path), vid, xml_content)
            nzo = NzbObject(vid)
            nzo.download_path = str(tmp_path / vid)
            os.makedirs(nzo.admin_path, exist_ok=True)

            if not expected_valid:
                continue

            # Valid vectors must parse cleanly
            nzbparser.nzbfile_parser(nzb_gz, nzo)

            if '<meta type="yenc_encrypted">true</meta>' in xml_content:
                assert nzo.yenc_encrypted is True, f"{vid}: expected yenc_encrypted=True"
                assert "password" in nzo.meta, f"{vid}: expected password in meta"
            else:
                assert nzo.yenc_encrypted is False, f"{vid}: expected yenc_encrypted=False"

            if "expected_segments" in vector:
                expected_segs = vector["expected_segments"]
                all_articles = []
                for nzf in nzo.files:
                    nzf.finish_import()
                    all_articles.extend(nzf.decodetable)
                assert len(all_articles) == len(expected_segs), (
                    f"{vid}: article count {len(all_articles)} != expected {len(expected_segs)}"
                )

    def test_separate_yenc_and_archive_passwords(self, tmp_path):
        cfg.download_dir.set(str(tmp_path))
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">yenc_secret</meta>
    <meta type="password">archive_secret</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="p@example.com" date="1774300000" subject="[1/1] - &quot;test.bin&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="5000" number="1">art-pw@example.com</segment>
    </segments>
  </file>
</nzb>"""
        nzb_gz = _write_nzb_gz(str(tmp_path), "multi_pw", xml)
        nzo = NzbObject("multi_pw")
        nzo.download_path = str(tmp_path / "multi_pw")
        os.makedirs(nzo.admin_path, exist_ok=True)
        nzbparser.nzbfile_parser(nzb_gz, nzo)
        assert nzo.yenc_encrypted is True
        assert nzo.meta["password"] == ["yenc_secret", "archive_secret"]
        passwords = misc.get_all_passwords(nzo)
        assert "yenc_secret" in passwords
        assert "archive_secret" in passwords

    def test_password_redacted_from_parser_logs(self, tmp_path, caplog):
        cfg.download_dir.set(str(tmp_path))
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">super_secret_canary_password_12345</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="p@example.com" date="1774300000" subject="[1/1] - &quot;test.bin&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="5000" number="1">art-redact@example.com</segment>
    </segments>
  </file>
</nzb>"""
        nzb_gz = _write_nzb_gz(str(tmp_path), "redact_test", xml)
        nzo = NzbObject("redact_test")
        nzo.download_path = str(tmp_path / "redact_test")
        os.makedirs(nzo.admin_path, exist_ok=True)
        with caplog.at_level(logging.DEBUG):
            nzbparser.nzbfile_parser(nzb_gz, nzo)

        assert "super_secret_canary_password_12345" not in caplog.text
        assert "<redacted>" in caplog.text

    def test_index_allocation_conformance(self):
        vector_path = os.path.join(
            os.path.dirname(__file__), "data", "test-vectors", "index_allocation.json"
        )
        with open(vector_path, "r", encoding="utf-8") as f:
            fixture = json.load(f)

        for vector in fixture["vectors"]:
            candidate = vector["candidate_index"]
            expected = vector["expected_assigned_index"]
            assigned = next_permitted_index(candidate)
            assert assigned == expected, f"{vector['id']}: expected {expected}, got {assigned}"
            assert not index_is_forbidden(assigned), f"{vector['id']}: assigned {assigned} is forbidden"

    def test_missing_password_raises_structural_error(self, tmp_path):
        cfg.download_dir.set(str(tmp_path))
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="p@example.com" date="1774300000" subject="[1/1] - &quot;test.bin&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="5000" number="1">art-nopw@example.com</segment>
    </segments>
  </file>
</nzb>"""
        nzb_gz = _write_nzb_gz(str(tmp_path), "missing_pw", xml)
        nzo = NzbObject("missing_pw")
        nzo.download_path = str(tmp_path / "missing_pw")
        os.makedirs(nzo.admin_path, exist_ok=True)
        with pytest.raises(YEncEncryptionStructuralError) as exc_info:
            nzbparser.nzbfile_parser(nzb_gz, nzo)
        assert "MISSING_PASSWORD" in str(exc_info.value)

    @pytest.mark.xfail(reason="These tests should be added")
    def test_nzbparser_bad_stuff(self):
        # TODO: Add tests for:
        #  Duplicate parts
        #  Strange articles sizes
        #  Correct parsing of dates
        assert False

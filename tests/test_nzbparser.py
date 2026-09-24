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
    def test_reconstruct_identity_shuffled_files(self):
        """Shuffled XML files reconstruct indices by [N/M], not parse or nzo.files order."""
        xml = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <head>
  <meta type="password">secret123</meta>
 </head>
 <file poster="p@test.com" date="1600000000" subject="[2/2] - &quot;file2.bin&quot; yEnc (1/2)">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="1000" number="1">msg2_1@test</segment>
   <segment bytes="1000" number="2">msg2_2@test</segment>
  </segments>
 </file>
 <file poster="p@test.com" date="1600000000" subject="[1/2] - &quot;file1.bin&quot; yEnc (1/3)">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="1000" number="1">msg1_1@test</segment>
   <segment bytes="1000" number="2">msg1_2@test</segment>
   <segment bytes="1000" number="3">msg1_3@test</segment>
  </segments>
 </file>
</nzb>"""
        nzb_file = _write_nzb_gz(SAB_CACHE_DIR, "test_shuffled", xml)
        nzo = NzbObject("test_shuffled")
        nzbparser.nzbfile_parser(nzb_file, nzo)

        # Map by filename
        files_by_name = {f.filename: f for f in nzo.files}
        assert "file1.bin" in files_by_name
        assert "file2.bin" in files_by_name

        f1 = files_by_name["file1.bin"]
        f2 = files_by_name["file2.bin"]

        assert f1.file_ordinal == 1
        assert f1.total_files == 2
        assert f1.segment_index_base == 1

        assert f2.file_ordinal == 2
        assert f2.total_files == 2
        assert f2.segment_index_base == 4

        # Finish import to load all lazy articles
        f1.finish_import()
        f2.finish_import()

        # Check f1 articles: part 1 -> 1, part 2 -> 2, part 3 -> 3
        assert len(f1.decodetable) == 3
        assert f1.decodetable[0].part_number == 1
        assert f1.decodetable[0].segment_index == 1
        assert f1.decodetable[1].part_number == 2
        assert f1.decodetable[1].segment_index == 2
        assert f1.decodetable[2].part_number == 3
        assert f1.decodetable[2].segment_index == 3

        # Check f2 articles: part 1 -> 4, part 2 -> 5
        assert len(f2.decodetable) == 2
        assert f2.decodetable[0].part_number == 1
        assert f2.decodetable[0].segment_index == 4
        assert f2.decodetable[1].part_number == 2
        assert f2.decodetable[1].segment_index == 5

        # Also verify post-parse sort_nzfs does not affect attached identity
        nzo.sort_nzfs()
        assert f1.file_ordinal == 1
        assert f1.segment_index_base == 1
        assert f2.file_ordinal == 2
        assert f2.segment_index_base == 4

    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    def test_reconstruct_identity_rejects_inconsistent_or_missing(self):
        """Duplicate ordinals, gaps, zero, overflow, inconsistent totals, and missing prefixes leave identity None."""
        # Release with gap: [1/3] and [3/3] without [2/3]
        xml_gap = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <file poster="p@test.com" date="1600000000" subject="[1/3] - &quot;f1.bin&quot; yEnc (1/1)">
  <segments><segment bytes="1000" number="1">m1@test</segment></segments>
 </file>
 <file poster="p@test.com" date="1600000000" subject="[3/3] - &quot;f3.bin&quot; yEnc (1/1)">
  <segments><segment bytes="1000" number="1">m3@test</segment></segments>
 </file>
</nzb>"""
        nzb_file = _write_nzb_gz(SAB_CACHE_DIR, "test_gap", xml_gap)
        nzo = NzbObject("test_gap")
        nzbparser.nzbfile_parser(nzb_file, nzo)
        for f in nzo.files:
            f.finish_import()
            assert f.file_ordinal is None
            assert f.total_files is None
            assert f.segment_index_base is None
            for art in f.decodetable:
                assert art.segment_index is None
                assert art.part_number == 1  # declared part preserved!

        # Release with part gap: file has parts 1 and 3 (part 2 missing)
        xml_part_gap = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <file poster="p@test.com" date="1600000000" subject="[1/1] - &quot;f1.bin&quot; yEnc (1/3)">
  <segments>
   <segment bytes="1000" number="1">m1@test</segment>
   <segment bytes="1000" number="3">m3@test</segment>
  </segments>
 </file>
</nzb>"""
        nzb_file = _write_nzb_gz(SAB_CACHE_DIR, "test_part_gap", xml_part_gap)
        nzo = NzbObject("test_part_gap")
        nzbparser.nzbfile_parser(nzb_file, nzo)
        f = nzo.files[0]
        f.finish_import()
        assert f.file_ordinal is None
        assert f.segment_index_base is None
        assert len(f.decodetable) == 2
        # Declared parts MUST be preserved (1 and 3, not compacted into 1 and 2)
        assert f.decodetable[0].part_number == 1
        assert f.decodetable[1].part_number == 3
        assert f.decodetable[0].segment_index is None
        assert f.decodetable[1].segment_index is None

        # Ordinary NZB with no [N/M] prefix at all
        xml_ordinary = """<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
 <file poster="p@test.com" date="1600000000" subject="&quot;plain.bin&quot; yEnc (1/1)">
  <segments><segment bytes="1000" number="1">plain@test</segment></segments>
 </file>
</nzb>"""
        nzb_file = _write_nzb_gz(SAB_CACHE_DIR, "test_plain", xml_ordinary)
        nzo = NzbObject("test_plain")
        nzbparser.nzbfile_parser(nzb_file, nzo)
        f = nzo.files[0]
        f.finish_import()
        assert f.file_ordinal is None
        assert f.total_files is None
        assert f.segment_index_base is None
        assert f.decodetable[0].part_number == 1
        assert f.decodetable[0].segment_index is None

    @pytest.mark.xfail(reason="These tests should be added")
    def test_nzbparser_bad_stuff(self):
        # TODO: Add tests for:
        #  Duplicate parts
        #  Strange articles sizes
        #  Correct parsing of dates
        assert False

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
tests.test_nzbfile - Testing functions in nzb/file.py
"""

from datetime import datetime

import pytest

from sabnzbd.nzb import NzbFile, NzbObject
from tests.testhelper import SAB_CACHE_DIR


@pytest.mark.usefixtures("clean_cache_dir")
class TestNzbFile:
    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    @pytest.mark.parametrize(
        "filenames",
        [
            [
                "hello.world.par2",
                "hello.world.part01.rar",
                "hello.world.part02.rar",
                "hello.world.part03.rar",
                "hello.world.sample.mkv",
                "hello.world.sfv",
                "hello.world.nfo",
                "hello.world.vol000-001.par2",
                "hello.world.vol001-003.par2",
            ],
            [
                "a.s01e01.par2",
                "a.s01e01.vol000-001.par2",
                "a.s01e01.vol001-003.par2",
                "a.s01e02.par2",
                "a.s01e02.vol000-001.par2",
                "a.s01e02.rar",
                "a.s01e02.vol000-001.par2",
                "a.s01e03.rar",
                "a.s01e03.r00",
                "a.s01e01.rar",
                "a.s01e01.sfv",
                "a.s01e03.r01",
                "a.s01e02.r00",
                "a.s01e03.par2",
                "a.s01e01.sample.mkv",
                "a.s01e02.sample.mkv",
                "a.s01e03.sample.mkv",
            ],
        ],
    )
    def test_sort_is_consistent(self, filenames: list[str]):
        """Test sorting of nzb files is deterministic, this is that the order of input does not matter."""
        nzo = NzbObject("test")

        def make_nzf(filename: str):
            return NzbFile(
                date=datetime.now(),
                subject=filename,
                raw_article_db=[(filename, 0)],
                file_bytes=0,
                nzo=nzo,
            )

        files1 = [make_nzf(filename) for filename in filenames]
        files2 = [make_nzf(filename) for filename in reversed(filenames)]

        files1.sort()
        files2.sort()

        assert [f.filename for f in files1] == [f.filename for f in files2]

    def test_legacy_and_structured_lazy_tuples(self):
        nzo = NzbObject("test_tuples")
        nzf = NzbFile(datetime.now(), "test_file", [], 0, nzo)

        art2 = nzf.add_article(("art-2@example.com", 2000))
        assert art2.article == "art-2@example.com"
        assert art2.bytes == 2000
        assert art2.part_number is None
        assert art2.segment_index is None

        art3 = nzf.add_article(("art-3@example.com", 3000, 1))
        assert art3.article == "art-3@example.com"
        assert art3.bytes == 3000
        assert art3.part_number == 1
        assert art3.segment_index is None

        art4 = nzf.add_article(("art-4@example.com", 4000, 2, 42))
        assert art4.article == "art-4@example.com"
        assert art4.bytes == 4000
        assert art4.part_number == 2
        assert art4.segment_index == 42

    def test_missing_state_defaults_to_none(self):
        nzo = NzbObject("test_missing")
        nzf = NzbFile(datetime.now(), "test_file", [], 0, nzo)
        state = nzf.__getstate__()
        state.pop("file_ordinal", None)
        state.pop("total_files", None)
        state.pop("segment_index_base", None)

        unpickled_nzf = NzbFile.__new__(NzbFile)
        unpickled_nzf.__setstate__(state)
        assert unpickled_nzf.file_ordinal is None
        assert unpickled_nzf.total_files is None
        assert unpickled_nzf.segment_index_base is None

    def test_pickle_round_trip_preserves_identity_and_rebounds_locks(self):
        import pickle

        nzo = NzbObject("test_pickle")
        nzf = NzbFile(
            datetime.now(),
            "test_file",
            [],
            0,
            nzo,
            file_ordinal=2,
            total_files=5,
            segment_index_base=10,
        )
        nzf.add_article(("art-1@example.com", 1000, 1, 10))
        nzf.add_article(("art-2@example.com", 1000, 2, 11))

        data = pickle.dumps(nzf)
        restored: NzbFile = pickle.loads(data)

        assert restored.file_ordinal == 2
        assert restored.total_files == 5
        assert restored.segment_index_base == 10
        assert hasattr(restored, "lock") and restored.lock is not None

        for art in restored.decodetable:
            assert art.lock is restored.lock
            assert art.part_number in (1, 2)
            assert art.segment_index in (10, 11)

    def test_lazy_tuples_and_pickle_persistence(self):
        import pickle

        nzo = NzbObject("test_lazy")
        nzf = NzbFile(datetime.now(), "test_file", [("art-1@example.com", 1000, 1, 5)], 1000, nzo)
        assert nzf.decodetable[0].part_number == 1
        assert nzf.decodetable[0].segment_index == 5

        data = pickle.dumps(nzf)
        restored = pickle.loads(data)
        assert restored.decodetable[0].part_number == 1
        assert restored.decodetable[0].segment_index == 5

    def test_clean_nzb_tuples_with_none_segment_index(self):
        nzo = NzbObject("test_clean")
        nzf = NzbFile(datetime.now(), "test_file", [], 0, nzo)
        art = nzf.add_article(("art-clean@example.com", 5000, 3))
        assert art.part_number == 3
        assert art.segment_index is None

    def test_c2_06_nzbfile_and_article_unpickle_safe_none_and_lock_rebind(self):
        import pickle
        from sabnzbd.nzb import Article

        nzo = NzbObject("test_c2_06")
        nzf = NzbFile(datetime.now(), "test_file", [], 0, nzo)
        state = nzf.__getstate__()
        state["articles"] = None
        state["decodetable"] = None

        restored_nzf = NzbFile.__new__(NzbFile)
        restored_nzf.__setstate__(state)
        assert restored_nzf.articles == {}
        assert restored_nzf.decodetable == []
        assert restored_nzf.lock is not None

        art = Article("art@example.com", 100, None)
        restored_art: Article = pickle.loads(pickle.dumps(art))
        assert restored_art.lock is not None

    def test_c2_07_nzo_attribute_saver_preserves_yenc_encrypted(self, tmp_path):
        import os
        from sabnzbd.nzb.object import NzoAttributeSaver
        import sabnzbd.cfg as cfg

        assert "yenc_encrypted" in NzoAttributeSaver

        cfg.download_dir.set(str(tmp_path))

        nzo = NzbObject("test_c2_07")
        os.makedirs(nzo.admin_path, exist_ok=True)
        nzo.yenc_encrypted = True
        nzo.password = "canary_pw"

        nzo.save_attribs()

        nzo2 = NzbObject("test_c2_07")
        assert nzo2.yenc_encrypted is False
        nzo2.load_attribs()
        assert nzo2.yenc_encrypted is True
        assert nzo2.password == "canary_pw"

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

import pickle
import threading
from datetime import datetime
from unittest import mock

import pytest

from sabnzbd.nzb import NzbFile, NzbObject, Article
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

    def test_lazy_tuples_with_and_without_part_number(self):
        """add_article accepts both (id, size) and (id, size, part) tuples."""
        nzo = NzbObject("test_tuples")
        nzf = NzbFile(
            date=datetime.now(),
            subject="test.bin",
            raw_article_db=[],
            file_bytes=0,
            nzo=nzo,
            file_ordinal=1,
            total_files=1,
        )

        art_plain = nzf.add_article(("plain_msg@test", 500))
        assert art_plain.article == "plain_msg@test"
        assert art_plain.bytes == 500
        assert art_plain.part_number is None
        assert art_plain.segment_index is None

        art_structured = nzf.add_article(("struct_msg@test", 600, 3))
        assert art_structured.article == "struct_msg@test"
        assert art_structured.bytes == 600
        assert art_structured.part_number == 3
        assert art_structured.segment_index is None

    def test_missing_state_defaults_to_none(self):
        """__setstate__ missing new keys defaults identity fields to None."""
        # Test Article with old dict
        mock_nzf = mock.Mock()
        mock_nzf.lock = threading.RLock()
        art = Article("test_art", 100, mock_nzf)
        old_art_dict = art.__getstate__()
        del old_art_dict["part_number"]
        del old_art_dict["segment_index"]

        new_art = Article("tmp", 0, mock_nzf)
        new_art.__setstate__(old_art_dict)
        assert new_art.part_number is None
        assert new_art.segment_index is None

        # Test NzbFile with old dict
        nzo = NzbObject("test_old_nzf")
        nzf = NzbFile(
            date=datetime.now(),
            subject="test.bin",
            raw_article_db=[],
            file_bytes=0,
            nzo=nzo,
        )
        old_nzf_dict = nzf.__getstate__()
        del old_nzf_dict["file_ordinal"]
        del old_nzf_dict["total_files"]

        restored_nzf = NzbFile(
            date=datetime.now(),
            subject="tmp.bin",
            raw_article_db=[],
            file_bytes=0,
            nzo=nzo,
        )
        restored_nzf.__setstate__(old_nzf_dict)
        assert restored_nzf.file_ordinal is None
        assert restored_nzf.total_files is None

    def test_pickle_round_trip_preserves_identity_and_rebounds_locks(self):
        """Pickle/admin round trips retain file ordinal, declared part, and article segment cache.

        segment_index is a post-decode cache populated from the wire Line-1 bootstrap.
        """
        nzo = NzbObject("test_pickle")
        nzf = NzbFile(
            date=datetime.now(),
            subject="test.bin",
            raw_article_db=[],
            file_bytes=2000,
            nzo=nzo,
            file_ordinal=2,
            total_files=5,
        )
        art = nzf.add_article(("art1@test", 1000, 1))
        art2 = nzf.add_article(("art2@test", 1000, 2))
        # simulate art2 completed and removed from articles dict but still in decodetable
        nzf.remove_article(art2, success=True)

        # Article round trip
        art_pickled = pickle.dumps(art)
        art_restored: Article = pickle.loads(art_pickled)
        assert art_restored.article == "art1@test"
        assert art_restored.part_number == 1
        assert art_restored.segment_index is None

        # Post-decode cache field survives pickle when populated (bootstrap cache write path)
        art.segment_index = 10
        art_recached: Article = pickle.loads(pickle.dumps(art))
        assert art_recached.segment_index == 10

        # NzbFile round trip
        nzf_pickled = pickle.dumps(nzf)
        nzf_restored: NzbFile = pickle.loads(nzf_pickled)
        assert nzf_restored.file_ordinal == 2
        assert nzf_restored.total_files == 5
        assert len(nzf_restored.decodetable) == 2
        assert nzf_restored.decodetable[0].part_number == 1
        assert nzf_restored.decodetable[1].part_number == 2

        # Check lock rebinding on all articles
        for article in nzf_restored.decodetable:
            assert article.lock == nzf_restored.lock

    def test_lazy_tuples_and_pickle_persistence(self):
        """3-tuples (mid, size, part) survive disk save_data, load_data, and pickle round trips.

        Bootstrap-only identity (Standard v1.2): NZB tuples never carry a segment index;
        article.segment_index is only a post-decode cache.
        """
        nzo = NzbObject("test_pickle_identity")
        nzo.yenc_encrypted = True
        nzf = NzbFile(
            date=datetime.now(),
            subject="test.bin",
            raw_article_db=[
                ("mid1@test", 1000, 1),
                ("mid2@test", 1000, 2),
            ],
            file_bytes=2000,
            nzo=nzo,
        )
        assert nzf.decodetable[0].segment_index is None
        assert nzf.decodetable[0].part_number == 1
        assert not nzf.import_finished

        # Finish import to load remaining from admin disk
        nzf.finish_import()
        assert nzf.import_finished
        assert len(nzf.decodetable) == 2
        assert nzf.decodetable[1].segment_index is None
        assert nzf.decodetable[1].part_number == 2

        # Round trip Article
        art_restored: Article = pickle.loads(pickle.dumps(nzf.decodetable[0]))
        assert art_restored.article == "mid1@test"
        assert art_restored.part_number == 1
        assert art_restored.segment_index is None

        # Round trip NzbObject
        nzo_restored: NzbObject = pickle.loads(pickle.dumps(nzo))
        assert nzo_restored.yenc_encrypted is True

    def test_c2_06_nzbfile_and_article_unpickle_safe_none_and_lock_rebind(self):
        """NzbFile unpickling tolerates None for articles/decodetable and Article rebinds lock to nzf."""
        nzo = NzbObject("test_c2_06")
        nzf = NzbFile(
            date=datetime.now(),
            subject="c2_06.bin",
            raw_article_db=[("art1@test", 500, 1, 100)],
            file_bytes=500,
            nzo=nzo,
        )
        art = nzf.decodetable[0]

        # Article __setstate__ rebinds to nzf.lock
        art_pickled = pickle.dumps(art)
        art_restored: Article = pickle.loads(art_pickled)
        assert art_restored.lock == art_restored.nzf.lock

        # NzbFile __setstate__ with None articles and None decodetable
        nzf_dict = nzf.__getstate__()
        nzf_dict["articles"] = None
        nzf_dict["decodetable"] = None

        restored_nzf = NzbFile(
            date=datetime.now(),
            subject="tmp.bin",
            raw_article_db=[],
            file_bytes=0,
            nzo=nzo,
        )
        restored_nzf.__setstate__(nzf_dict)
        assert restored_nzf.articles == {}
        assert restored_nzf.decodetable == []

    def test_c2_07_nzo_attribute_saver_preserves_yenc_encrypted(self):
        """NzoAttributeSaver and load_attribs preserve yenc_encrypted across job retry."""
        from sabnzbd.nzb.object import NzoAttributeSaver

        assert "yenc_encrypted" in NzoAttributeSaver

        nzo = NzbObject("test_retry_enc")
        nzo.yenc_encrypted = True

        saved = {}

        def mock_save_data(data, filename, path, silent=True):
            saved.update(data)

        def mock_load_data(filename, path, remove=False):
            return dict(saved)

        with (
            mock.patch("sabnzbd.nzb.object.save_data", side_effect=mock_save_data),
            mock.patch("sabnzbd.nzb.object.load_data", side_effect=mock_load_data),
        ):
            nzo.save_attribs()
            assert saved.get("yenc_encrypted") is True

            nzo2 = NzbObject("test_retry_enc")
            assert nzo2.yenc_encrypted is False

            nzo2.load_attribs()
            assert nzo2.yenc_encrypted is True

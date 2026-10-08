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
sabnzbd.decoder - article decoder
"""

import logging
import hashlib
from typing import Optional

import sabnzbd
from sabnzbd.constants import SABCTOOLS_VERSION_REQUIRED
from sabnzbd.nzb import Article
from sabnzbd.misc import match_str
from sabnzbd.encryption import YEncEncryptionStructuralError

# Check for correct SABCTools version
SABCTOOLS_VERSION = None
SABCTOOLS_SIMD = None
SABCTOOLS_OPENSSL_LINKED = None
try:
    import sabctools

    SABCTOOLS_ENABLED = True
    SABCTOOLS_VERSION = sabctools.__version__
    SABCTOOLS_SIMD = sabctools.simd
    SABCTOOLS_OPENSSL_LINKED = sabctools.openssl_linked
    # Verify version to at least match minor version by splitting on "."
    if SABCTOOLS_VERSION.split(".")[:2] != SABCTOOLS_VERSION_REQUIRED.split(".")[:2]:
        raise ImportError
except Exception:
    SABCTOOLS_ENABLED = False


class BadData(Exception):
    def __init__(self, data: bytearray):
        super().__init__()
        self.data = data


class BadYenc(Exception):
    pass


class BadUu(Exception):
    pass


class SinkFailed(Exception):
    """A streamed article could not be written, so nothing was kept.

    Deliberately not a BadYenc: that handler inspects the response lines and can decide
    the article was fine after all, which would mark an article as successful when it
    is not on disk anywhere.
    """


def _is_yenc_encrypted(article: Article) -> bool:
    """Whether the article belongs to a yEnc-encrypted release (not merely password-protected)."""
    return (
        bool(getattr(getattr(getattr(article, "nzf", None), "nzo", None), "yenc_encrypted", False))
        or getattr(article, "segment_index", None) is not None
        or bool(getattr(article, "yenc_encrypted", False))
    )


def _get_decryption_adapter(article: Article, password: Optional[str]):
    """Retrieve cached DecryptionAdapter from the parent Nzo or create a new one."""
    from sabnzbd.encryption import DecryptionAdapter

    nzf = getattr(article, "nzf", None)
    nzo = getattr(nzf, "nzo", None)
    if nzo is not None:
        with nzo.lock:
            adapter = getattr(nzo, "_decryption_adapter", None)
            if adapter is not None and adapter.password == password:
                return adapter
            adapter = DecryptionAdapter(password=password)
            nzo._decryption_adapter = adapter
            return adapter
    return DecryptionAdapter(password=password)


def decode(article: Article, decoder: sabctools.NNTPResponse):
    decoded_data: Optional[bytearray] = None
    nzo = article.nzf.nzo
    art_id = article.article

    # Keeping track
    article_success = False

    try:
        if nzo.precheck:
            raise BadYenc

        if sabnzbd.LOG_ALL:
            logging.debug("Decoding %s", art_id)

        if decoder.format is sabctools.EncodingFormat.UU:
            decoded_data = decode_uu(article, decoder)
        else:
            decoded_data = decode_yenc(article, decoder)

        article_success = True

    except MemoryError:
        logging.warning(T("Decoder failure: Out of memory"))
        logging.info("Cache: %d, %d, %d", *sabnzbd.ArticleCache.cache_info())
        logging.info("Traceback: ", exc_info=True)
        sabnzbd.Downloader.pause()

        # This article should be fetched again
        article.allow_new_fetcher()
        return

    except BadData as error:
        # Continue to the next one if we found new server
        if search_new_server(article):
            return

        if _is_yenc_encrypted(article):
            logging.info("Discarding corrupt encrypted article data for %s (zero-output guarantee)", art_id)
            decoded_data = None
        else:
            # Store data, maybe par2 can still fix it
            decoded_data = error.data

    except BadUu:
        logging.info("Badly formed uu article in %s", art_id)

        # Try the next server
        if search_new_server(article):
            return

    except YEncEncryptionStructuralError:
        # Structural metadata failure (missing password, unsupported mode): abort the
        # job - never retried against another server. No plaintext or ciphertext was
        # released (zero-output guarantee), so nothing is stored.
        logging.error(T("Structural yEnc-encryption failure in %s: job aborted (not retryable)"), art_id)
        nzo.fail_msg = T("Structural yEnc-encryption failure: missing or invalid metadata")
        nzo.set_unpack_info("Download", nzo.fail_msg)
        decoded_data = None

    except ValueError:
        # Authentication failure on encrypted articles: log without secrets and
        # query next server (retryable provider corruption). Ordinary ValueErrors
        # keep develop behavior: re-raise so the caller classifies them.
        if _is_yenc_encrypted(article):
            logging.info("Authentication failed for %s, trying next server", art_id)
            if search_new_server(article):
                return
        raise

    except SinkFailed:
        # The file went away under the article, so it has to be fetched again. Any
        # part of it already written is overwritten at the same offsets next time.
        logging.info("Could not write %s to its file, fetching it again", art_id)

        if search_new_server(article):
            return

    except OSError as error:
        # The same response the assembler gives a failed write. Fetching the article
        # again cannot fix a full disk, and doing so would spend its retries and then
        # fail the job as incomplete - so pause instead and leave the article to be
        # picked up again once there is room.
        if sabnzbd.filesystem.out_of_space(error):
            logging.error(T("Disk full! Forcing Pause"))
        else:
            logging.error(T("Disk error on creating file %s"), error.filename)
        logging.info("Traceback: ", exc_info=True)
        sabnzbd.Downloader.pause()
        article.allow_new_fetcher()
        return

    except BadYenc:
        # Handles precheck and badly formed articles
        if nzo.precheck and decoder.status_code == 223:
            # STAT was used, so we only get a status code
            article_success = True
        else:
            # Examine the headers (for precheck) or body (for download).
            if lines := decoder.lines:
                for line in lines:
                    lline = line.lower()
                    if lline.startswith("message-id:"):
                        article_success = True
                    # Look for DMCA clues (while skipping "X-" headers)
                    if not lline.startswith("x-") and match_str(lline, ("dmca", "removed", "cancel", "blocked")):
                        article_success = False
                        logging.info("Article removed from server (%s)", art_id)
                        break

        # Pre-check, proper article found so just register
        if nzo.precheck and article_success and sabnzbd.LOG_ALL:
            logging.debug("Server %s has article %s", article.fetcher, art_id)
        elif not article_success:
            # If not pre-check, this must be a bad article
            if not nzo.precheck:
                logging.info("Badly formed yEnc article %s", art_id)

            # Continue to the next one if we found new server
            if search_new_server(article):
                return

    except Exception:
        logging.warning(T("Unknown Error while decoding %s"), art_id)
        logging.info("Traceback: ", exc_info=True)

        # Continue to the next one if we found new server
        if search_new_server(article):
            return

    if decoded_data:
        # If the data needs to be written to disk due to full cache, this will be slow
        # Causing the decoder-queue to fill up and delay the downloader
        sabnzbd.ArticleCache.save_article(article, decoded_data)
        article.decoded = True
    elif not nzo.precheck and (article_success or not _is_yenc_encrypted(article)):
        # Either there was nothing to save, or the decoder streamed it straight to the
        # file. Both are on disk as far as the rest of the pipeline is concerned; the
        # assembler advances past an on_disk article on its own when it next runs.
        article.on_disk = True

    sabnzbd.NzbQueue.register_article(article, article_success)


def decode_yenc(article: Article, response: sabctools.NNTPResponse) -> Optional[bytearray]:
    """Record what the decoder produced.

    data is None when the article was streamed straight to its file rather than
    decoded into memory. Everything the caller needs is still reported - sizes, offset,
    CRC - so the only difference is that there is nothing left to cache or assemble.
    """
    # The job was deleted while the article was arriving, or the write failed. The
    # decoder consumed the response anyway so the connection survives, but nothing was
    # kept, so this is a failed article rather than one on disk.
    if response.sink_failed:
        # A closed file means the job went away while the article was arriving, and it
        # only needs fetching again. Anything else is a real disk error - a full disk,
        # most often - and is re-raised as the OSError it came from so it gets the same
        # handling as a failed write from the assembler.
        if isinstance(response.sink_error, OSError):
            raise response.sink_error
        raise SinkFailed

    nzf = article.nzf

    password = None
    if hasattr(article, "nzf") and hasattr(article.nzf, "nzo"):
        password = getattr(article.nzf.nzo, "password", None)
    if not password and hasattr(article, "password"):
        password = article.password

    # Encrypted wire response: sabctools couldn't decode because control lines were FF1-encrypted
    if response.bytes_decoded == 0 and getattr(response, "lines", None) and password:
        import io
        import sabctools
        from sabnzbd.encryption import extract_and_remove_yencryption

        lines = [line.encode("latin-1") if isinstance(line, str) else line for line in response.lines]

        # Dot-unstuffing adapter (RFC 3977 §3.1.1 transport boundary). On the encrypted
        # path sabctools cannot recognize yEnc (the =ybegin line is FF1-encrypted), so
        # response.lines carry RAW presentation bytes with '..' intact - unlike the data
        # path, where sabctools unstuffs during yEnc decoding. Producers MUST dot-stuff
        # (a Line 1 salt byte can legitimately be 0x2E); consumers MUST unstuff before
        # line splitting/bootstrap extraction: '..' maps to content '.', and a lone
        # single '.' is the article terminator (already consumed by sabctools here).
        lines = [line[1:] if line.startswith(b"..") else line for line in lines]

        raw_wire = b"\r\n".join(lines) + b"\r\n"

        adapter = _get_decryption_adapter(article, password=password)
        restored_block, salt_line1, seg_idx_line1 = adapter.restore_control_lines(raw_wire)
        yenc_params, clean_yenc = extract_and_remove_yencryption(restored_block)

        # Bootstrap-only identity: a cached index from a prior decode of this article
        # must agree with the wire bootstrap; there is no XML-index preference.
        cached_index = getattr(article, "segment_index", None)
        if isinstance(cached_index, int) and cached_index != seg_idx_line1:
            raise ValueError(f"Dual index mismatch: cached segment_index {cached_index} != wire index {seg_idx_line1}")

        if yenc_params["salt"] != salt_line1:
            raise ValueError(
                f"Salt mismatch between control line 1 ({salt_line1.hex()}) and =yencryption ({yenc_params['salt'].hex()})"
            )

        if yenc_params["segment_index"] != seg_idx_line1:
            raise ValueError(
                f"Dual index mismatch between control line 1 ({seg_idx_line1}) and =yencryption ({yenc_params['segment_index']})"
            )

        art_id = getattr(article, "article", "enc")
        if isinstance(art_id, str):
            art_bytes = art_id.encode("ascii", "replace")
        else:
            art_bytes = b"enc"
        clean_wire = b"222 0 <" + art_bytes + b">\r\n" + clean_yenc
        if not clean_wire.endswith(b"\r\n"):
            clean_wire += b"\r\n"
        clean_wire += b".\r\n"

        dec = sabctools.Decoder(len(clean_wire))
        reader = io.BytesIO(clean_wire)
        reader.readinto(dec)
        dec.process(len(clean_wire))
        sub_resp = next(dec)

        if sub_resp.crc is None:
            raise ValueError(f"Wire CRC error in encrypted article {getattr(article, 'article', '')}")

        plaintext = adapter.decrypt_body(
            ciphertext=bytes(sub_resp.data),
            tag=yenc_params["tag"],
            salt=yenc_params["salt"],
            segment_index=seg_idx_line1,
        )

        decoded_data = bytearray(plaintext)
        if getattr(article, "segment_index", None) is None:
            article.segment_index = seg_idx_line1
        article.file_size = sub_resp.file_size
        article.data_begin = sub_resp.part_begin
        article.data_size = sub_resp.part_size
        article.decoded_size = len(decoded_data)
        # T4: never persist the ciphertext CRC into any verification path. The wire CRC
        # covers ciphertext, not plaintext; PAR2 verifies the authenticated plaintext.
        article.crc32 = None
        nzf.type = "yenc"

        if not nzf.filename_checked and (file_name := sub_resp.file_name):
            if article.lowest_partnum:
                nzf.md5of16k = hashlib.md5(memoryview(decoded_data)[:16384]).digest()
            nzf.nzo.verify_nzf_filename(nzf, file_name)

        return decoded_data

    # Let SABCTools do all the heavy lifting
    decoded_data = response.data
    article.file_size = response.file_size
    article.data_begin = response.part_begin
    article.data_size = response.part_size
    article.decoded_size = response.bytes_decoded

    # Assume it is yenc
    nzf.type = "yenc"

    # Check for encrypted body if =yencryption metadata is present
    yenc_info = getattr(response, "yencryption", None) or getattr(article, "yencryption", None)
    if not yenc_info and getattr(response, "lines", None):
        for line in response.lines:
            if (isinstance(line, str) and line.startswith("=yencryption")) or (
                isinstance(line, bytes) and line.startswith(b"=yencryption")
            ):
                yenc_info = line
                break

    parsed_enc = None
    if yenc_info:
        if isinstance(yenc_info, dict):
            parsed_enc = yenc_info
        elif isinstance(yenc_info, (str, bytes)):
            from sabnzbd.encryption import parse_yencryption_line

            parsed_enc = parse_yencryption_line(yenc_info)

    if parsed_enc:
        if decoded_data is None:
            raise SinkFailed("Direct-write occurred on encrypted article before authentication")

        if hasattr(article, "nzf") and hasattr(article.nzf, "nzo"):
            article.nzf.nzo.yenc_encrypted = True

        password = None
        if hasattr(article, "nzf") and hasattr(article.nzf, "nzo"):
            password = getattr(article.nzf.nzo, "password", None)
        if not password and hasattr(article, "password"):
            password = article.password

        adapter = _get_decryption_adapter(article, password=password)
        # Bootstrap-only identity: the wire =yencryption index field governs. Any cached
        # article.segment_index from a prior decode attempt of the same article must
        # agree; there is no XML-index preference anymore.
        segment_index = parsed_enc.get("segment_index")
        cached_index = getattr(article, "segment_index", None)
        if segment_index is None:
            raise ValueError(f"Missing explicit segment_index for encrypted article {getattr(article, 'article', '')}")
        if cached_index is not None and cached_index != segment_index:
            raise ValueError(f"Dual index mismatch: cached segment_index {cached_index} != wire index {segment_index}")

        plaintext = adapter.decrypt_body(
            ciphertext=bytes(decoded_data),
            tag=parsed_enc["tag"],
            salt=parsed_enc["salt"],
            segment_index=segment_index,
        )
        if getattr(article, "segment_index", None) is None:
            article.segment_index = segment_index
        decoded_data = bytearray(plaintext)
        article.decoded_size = len(decoded_data)
        # T4: ciphertext CRC must not flow into any verification path
        article.crc32 = None

    # Only set the name if it was found and not obfuscated. Streamed articles never
    # reach here: a sink is only handed out once the filename has been checked, exactly
    # because this needs the bytes.
    if decoded_data is not None and not nzf.filename_checked and (file_name := response.file_name):
        # Set the md5-of-16k if this is the first article
        if article.lowest_partnum:
            nzf.md5of16k = hashlib.md5(memoryview(decoded_data)[:16384]).digest()

        # Try the rename, even if it's not the first article
        # For example when the first article was missing
        nzf.nzo.verify_nzf_filename(nzf, file_name)

    # CRC check
    if (crc := response.crc) is None:
        logging.info("CRC Error in %s", article.article)
        is_enc = (
            bool(parsed_enc)
            or getattr(getattr(getattr(article, "nzf", None), "nzo", None), "yenc_encrypted", False)
            or getattr(article, "segment_index", None) is not None
            or getattr(article, "yenc_encrypted", False)
        )
        if is_enc:
            raise ValueError(f"Wire CRC error in encrypted article {article.article}")
        # A streamed article is already on disk, so there is nothing to hand back; the
        # bytes stay put either way, so par2 has the same chance of repairing it
        raise BadData(decoded_data)

    article.crc32 = None if parsed_enc else crc

    return decoded_data


def decode_uu(article: Article, response: sabctools.NNTPResponse) -> bytearray:
    """Process a uu-decoded response"""
    if not response.bytes_decoded:
        logging.debug("No data to decode")
        raise BadUu

    if response.baddata:
        raise BadData(response.data)

    decoded_data = response.data
    article.decoded_size = response.bytes_decoded
    nzf = article.nzf
    nzf.type = "uu"

    # Only set the name if it was found and not obfuscated
    if not nzf.filename_checked and (file_name := response.file_name):
        # Set the md5-of-16k if this is the first article
        if article.lowest_partnum:
            nzf.md5of16k = hashlib.md5(memoryview(decoded_data)[:16384]).digest()

        # Try the rename, even if it's not the first article
        # For example when the first article was missing
        nzf.nzo.verify_nzf_filename(nzf, file_name)

    article.crc32 = response.crc

    return decoded_data


def search_new_server(article: Article) -> bool:
    """Shorthand for searching new server or else increasing bad_articles"""
    # Continue to the next one if we found new server
    if not article.search_new_server():
        # Increase bad articles if no new server was found
        article.nzf.nzo.increase_bad_articles_counter("bad_articles")
        return False
    return True

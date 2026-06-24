"""Edge/error coverage for the TSCG-B binary protocol core."""
import struct

import pytest

from utf.tscg_b import core
from utf.tscg_b.core import (
    StreamDecoder,
    opcode_for_symbol,
    pack_text,
    unpack_frame,
)


def test_opcode_for_symbol():
    name = next(iter(core.ALL_SYMBOLS))
    assert isinstance(opcode_for_symbol(name), int)
    with pytest.raises(ValueError, match="Unknown symbol"):
        opcode_for_symbol("NOPE")


def test_roundtrip():
    frame = pack_text("hello")
    assert unpack_frame(frame)["text"] == "hello"


def test_frame_too_short():
    with pytest.raises(ValueError, match="too short"):
        unpack_frame(b"\x00")


def test_bad_magic():
    frame = bytearray(pack_text("hi"))
    frame[0] ^= 0xFF
    with pytest.raises(ValueError, match="magic"):
        unpack_frame(bytes(frame))


def test_bad_version():
    frame = bytearray(pack_text("hi"))
    frame[4] = 0xEE  # version byte after the 4-byte magic
    with pytest.raises(ValueError, match="version"):
        unpack_frame(bytes(frame))


def test_payload_length_overflow():
    data = (core.MAGIC + bytes([core.VERSION, 0]) + struct.pack("!H", 255)
            + b"\x00" * 36)
    with pytest.raises(ValueError, match="too short for payload"):
        unpack_frame(data)


def test_crc_mismatch():
    frame = bytearray(pack_text("hi"))
    crc_start = core.HEADER_SIZE + 2  # payload "hi" is 2 bytes
    frame[crc_start] ^= 0xFF
    with pytest.raises(ValueError, match="CRC32 mismatch"):
        unpack_frame(bytes(frame))


def test_sha_mismatch():
    frame = bytearray(pack_text("hi"))
    frame[-1] ^= 0xFF  # corrupt SHA (CRC does not cover the SHA region)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        unpack_frame(bytes(frame))


def test_no_verify_skips_checks():
    frame = bytearray(pack_text("hi"))
    frame[-1] ^= 0xFF
    # verify=False tolerates the corrupt SHA.
    assert unpack_frame(bytes(frame), verify=False)["text"] == "hi"


def test_stream_decoder_single_and_partial():
    dec = StreamDecoder()
    frame = pack_text("one")
    assert dec.feed(frame[:5]) == []  # partial → buffered
    rest = dec.feed(frame[5:])
    assert rest and rest[0]["text"] == "one"


def test_stream_decoder_resync_after_garbage():
    dec = StreamDecoder()
    frame = pack_text("sync")
    frames = dec.feed(b"\x01\x02\x03" + frame)
    assert frames and frames[0]["text"] == "sync"


def test_stream_decoder_discards_huge_garbage():
    dec = StreamDecoder()
    dec.feed(b"\x00" * 70000)  # no magic, >64KB → buffer cleared
    assert len(dec.buffer) == 0


def test_stream_decoder_corrupt_frame_skipped():
    dec = StreamDecoder()
    frame = bytearray(pack_text("x"))
    frame[-1] ^= 0xFF  # corrupt SHA → frame dropped
    assert dec.feed(bytes(frame)) == []

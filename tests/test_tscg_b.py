"""
Tests for TSCG-B (TSCG Binary Protocol)
Tests binary frame format, pack/unpack, CRC32, SHA-256, and StreamDecoder.
"""
import sys
import os
import struct
import hashlib
import zlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utf.tscg_b.core import (
    pack_text, unpack_frame, StreamDecoder,
    MAGIC, VERSION, HEADER_SIZE, MIN_FRAME_SIZE,
    FLAG_NONE, FLAG_EOF, FLAG_FRAGMENT,
    encode_text_to_opcodes, decode_opcodes_to_text,
    opcode_for_symbol, symbol_for_opcode
)


class TestOpcodes:
    """Test opcode mapping functions."""

    def test_opcode_for_symbol(self):
        assert opcode_for_symbol('COG') == 0x00
        assert opcode_for_symbol('DNT') == 0x01
        assert opcode_for_symbol('SAFE') == 0x10

    def test_symbol_for_opcode(self):
        assert symbol_for_opcode(0x00) == 'COG'
        assert symbol_for_opcode(0x10) == 'SAFE'

    def test_encode_decode_opcodes(self):
        original = "hello"
        opcodes = encode_text_to_opcodes(original)
        decoded = decode_opcodes_to_text(opcodes)
        assert decoded == original

    def test_encode_decode_empty(self):
        opcodes = encode_text_to_opcodes("")
        decoded = decode_opcodes_to_text(opcodes)
        assert decoded == ""


class TestPackUnpack:
    """Test binary frame packing and unpacking."""

    def test_pack_basic(self):
        frame = pack_text("hello")
        assert isinstance(frame, bytes)
        assert len(frame) > MIN_FRAME_SIZE
        # Check magic
        assert frame[:4] == MAGIC

    def test_pack_version(self):
        frame = pack_text("test")
        assert frame[4] == VERSION

    def test_pack_payload_length(self):
        text = "hello world"
        frame = pack_text(text)
        # Header: magic(4) + version(1) + flags(1) + payload_length(2) = 8 bytes
        payload_length = struct.unpack('!H', frame[6:8])[0]
        assert payload_length == len(text.encode('utf-8'))

    def test_pack_flags(self):
        frame = pack_text("test", flags=FLAG_EOF)
        assert frame[5] == FLAG_EOF

    def test_unpack_basic(self):
        text = "hello world"
        frame = pack_text(text)
        result = unpack_frame(frame)
        assert result['magic'] == MAGIC
        assert result['version'] == VERSION
        assert result['text'] == text

    def test_unpack_flags(self):
        frame = pack_text("test", flags=FLAG_FRAGMENT)
        result = unpack_frame(frame)
        assert result['flags'] == FLAG_FRAGMENT

    def test_roundtrip_simple(self):
        original = "Hello, Thirsty World!"
        frame = pack_text(original)
        result = unpack_frame(frame)
        assert result['text'] == original

    def test_roundtrip_unicode(self):
        original = "Thirsty 🧊 UTF Stack — Governance First"
        frame = pack_text(original)
        result = unpack_frame(frame)
        assert result['text'] == original

    def test_roundtrip_empty(self):
        original = ""
        frame = pack_text(original)
        result = unpack_frame(frame)
        assert result['text'] == original
        assert result['payload_length'] == 0

    def test_roundtrip_long_text(self):
        original = "A" * 1000
        frame = pack_text(original)
        result = unpack_frame(frame)
        assert result['text'] == original
        assert result['payload_length'] == 1000

    def test_crc32_verification(self):
        """CRC32 should be correctly computed and verified."""
        text = "verify me"
        frame = pack_text(text)
        result = unpack_frame(frame)
        # Recompute CRC32 to verify
        header = frame[:HEADER_SIZE]
        payload = frame[HEADER_SIZE:HEADER_SIZE + result['payload_length']]
        expected_crc32 = zlib.crc32(header + payload) & 0xFFFFFFFF
        assert result['crc32'] == expected_crc32

    def test_sha256_verification(self):
        """SHA-256 should be correctly computed and verified."""
        text = "sha256 check"
        frame = pack_text(text)
        result = unpack_frame(frame)
        # Recompute SHA-256 to verify
        payload_end = HEADER_SIZE + result['payload_length']
        crc32_end = payload_end + 4
        expected_sha256 = hashlib.sha256(
            frame[:payload_end + 4]
        ).digest()
        assert result['sha256'] == expected_sha256

    def test_unpack_verification_failure_tampered(self):
        """Tampered frame should raise ValueError."""
        frame = bytearray(pack_text("test"))
        # Corrupt a byte in the payload
        if len(frame) > HEADER_SIZE:
            frame[HEADER_SIZE] ^= 0xFF
        try:
            unpack_frame(bytes(frame))
            assert False, "Should have raised ValueError for tampered data"
        except ValueError:
            pass

    def test_unpack_short_frame(self):
        try:
            unpack_frame(b'\x00' * 10)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_unpack_bad_magic(self):
        frame = bytearray(pack_text("test"))
        frame[0:4] = b'BAD '
        try:
            unpack_frame(bytes(frame))
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


class TestStreamDecoder:
    """Test multi-frame stream decoding."""

    def test_decode_single_frame(self):
        decoder = StreamDecoder()
        frame = pack_text("stream test")
        frames = decoder.feed(frame)
        assert len(frames) == 1
        assert frames[0]['text'] == "stream test"

    def test_decode_multiple_frames(self):
        decoder = StreamDecoder()
        frame1 = pack_text("first")
        frame2 = pack_text("second")
        frame3 = pack_text("third")
        
        frames = decoder.feed(frame1 + frame2 + frame3)
        assert len(frames) == 3
        assert frames[0]['text'] == "first"
        assert frames[1]['text'] == "second"
        assert frames[2]['text'] == "third"

    def test_decode_partial_frame(self):
        decoder = StreamDecoder()
        frame = pack_text("partial")
        
        # Feed half the frame
        half = len(frame) // 2
        frames = decoder.feed(frame[:half])
        assert len(frames) == 0  # Not enough data
        
        # Feed the rest
        frames = decoder.feed(frame[half:])
        assert len(frames) == 1
        assert frames[0]['text'] == "partial"

    def test_decode_with_garbage_prefix(self):
        decoder = StreamDecoder()
        frame = pack_text("clean")
        
        # Feed garbage then a valid frame
        garbage = b'\x00\x01\x02\x03' * 10
        frames = decoder.feed(garbage + frame)
        # Decoder should resync to magic bytes
        assert len(frames) == 1
        assert frames[0]['text'] == "clean"

    def test_stream_decoder_count(self):
        decoder = StreamDecoder()
        assert decoder.frames_decoded == 0
        
        frame = pack_text("one")
        decoder.feed(frame)
        assert decoder.frames_decoded == 1
        
        frame2 = pack_text("two")
        decoder.feed(frame2)
        assert decoder.frames_decoded == 2

    def test_flush(self):
        decoder = StreamDecoder()
        frame = pack_text("flush test")
        decoder.feed(frame)
        remaining = decoder.flush()
        assert isinstance(remaining, list)
        assert decoder.buffered_bytes == 0

    def test_multi_frame_with_partial_last(self):
        decoder = StreamDecoder()
        frame1 = pack_text("frame1")
        frame2 = pack_text("frame2")
        
        # Feed complete frame1 + half of frame2
        half2 = len(frame2) // 2
        combined = frame1 + frame2[:half2]
        frames = decoder.feed(combined)
        assert len(frames) == 1  # Only frame1 complete
        assert frames[0]['text'] == "frame1"
        
        # Feed rest of frame2
        frames = decoder.feed(frame2[half2:])
        assert len(frames) == 1
        assert frames[0]['text'] == "frame2"


class TestE2E:
    """End-to-end TSCG-B tests."""

    def test_full_roundtrip(self):
        """Pack text, extract raw bytes, unpack, verify all fields."""
        original = "The quick brown fox jumps over the lazy dog"
        
        frame = pack_text(original)
        
        # Verify frame structure
        assert frame[:4] == MAGIC
        assert frame[4] == VERSION
        
        result = unpack_frame(frame)
        
        # Verify content
        assert result['text'] == original
        assert result['payload_length'] == len(original.encode('utf-8'))
        
        # Verify CRC32 is correct
        header = frame[:HEADER_SIZE]
        payload = frame[HEADER_SIZE:HEADER_SIZE + result['payload_length']]
        expected_crc32 = zlib.crc32(header + payload) & 0xFFFFFFFF
        assert result['crc32'] == expected_crc32
        
        # Verify SHA-256 is correct
        payload_end = HEADER_SIZE + result['payload_length']
        crc32_end = payload_end + 4
        expected_sha256 = hashlib.sha256(frame[:payload_end + 4]).digest()
        assert result['sha256'] == expected_sha256

    def test_stream_with_resync(self):
        """Test that the stream decoder can handle interleaved garbage."""
        decoder = StreamDecoder()
        
        valid_frames = []
        for i in range(5):
            frame = pack_text(f"message_{i}")
            valid_frames.append(frame)
        
        # Interleave with garbage
        stream = b''
        for i, f in enumerate(valid_frames):
            if i % 2 == 0:
                stream += b'\xDE\xAD\xBE\xEF' * 5 + f
            else:
                stream += f + b'\xCA\xFE\xBA\xBE' * 3
        
        frames = decoder.feed(stream)
        assert len(frames) == 5
        
        for i, f in enumerate(frames):
            assert f['text'] == f"message_{i}"


if __name__ == "__main__":
    for name in dir():
        obj = globals()[name]
        if isinstance(obj, type) and name.startswith("Test"):
            print(f"\n{'='*60}")
            print(f"Running {name}...")
            print('='*60)
            instance = obj()
            for attr in dir(instance):
                if attr.startswith("test_"):
                    try:
                        getattr(instance, attr)()
                        print(f"  ✓ {attr}")
                    except Exception as e:
                        print(f"  ✗ {attr}: {e}")
                        raise
    print("\n✅ All TSCG-B tests passed!")
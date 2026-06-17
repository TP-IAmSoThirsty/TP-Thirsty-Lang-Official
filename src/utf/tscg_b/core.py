"""
TSCG-B — TSCG Binary Protocol
Binary frame format with magic bytes, CRC32, SHA-256, and stream decoding.
"""
import hashlib
import struct
import zlib
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple

from utf.tscg.core import ALL_SYMBOLS, OPCODE_TO_SYMBOL

# Frame format constants
MAGIC = b'TSGB'
VERSION = 1
HEADER_SIZE = 8  # magic(4) + version(1) + flags(1) + payload_length(2)
CRC32_SIZE = 4
SHA256_SIZE = 32
MIN_FRAME_SIZE = HEADER_SIZE + CRC32_SIZE + SHA256_SIZE  # 44 bytes

# Flag bits
FLAG_NONE = 0x00
FLAG_EOF = 0x01
FLAG_FRAGMENT = 0x02


def opcode_for_symbol(symbol: str) -> int:
    """Get opcode for a TSCG symbol name."""
    if symbol in ALL_SYMBOLS:
        return ALL_SYMBOLS[symbol]
    raise ValueError(f"Unknown symbol: {symbol}")


def symbol_for_opcode(opcode: int) -> Optional[str]:
    """Get symbol name for an opcode."""
    return OPCODE_TO_SYMBOL.get(opcode)


def encode_text_to_opcodes(text: str) -> List[int]:
    """Encode text into reversible base-23 opcodes."""
    data = text.encode('utf-8')
    opcodes = []
    for byte in data:
        hi = byte // 23
        lo = byte % 23
        if hi > 0:
            opcodes.append(hi)
        opcodes.append(lo)
    return opcodes


def decode_opcodes_to_text(opcodes: List[int]) -> str:
    """Decode base-23 opcodes back to text (reversible)."""
    bytes_list = bytearray()
    i = 0
    while i < len(opcodes):
        op = opcodes[i]
        # If this op could be a high digit (0-11), try two-byte decode
        if op < 12 and i + 1 < len(opcodes):
            hi = op
            lo = opcodes[i + 1]
            byte_val = hi * 23 + lo
            if byte_val < 256:
                bytes_list.append(byte_val)
                i += 2
                continue
        # Single digit (byte < 23, or ambiguous low byte)
        bytes_list.append(op)
        i += 1
    return bytes(bytes_list).decode('utf-8', errors='replace')


def pack_text(text: str, flags: int = FLAG_NONE) -> bytes:
    """
    Encode text into TSCG-B binary frame.
    
    Frame layout:
    - magic: b'TSGB' (4 bytes)
    - version: 1 byte
    - flags: 1 byte
    - payload_length: 2 bytes big-endian
    - payload: N bytes
    - crc32: 4 bytes big-endian
    - sha256: 32 bytes
    """
    text_bytes = text.encode('utf-8')
    
    # Build header
    header = struct.pack('!4sBBH', MAGIC, VERSION, flags, len(text_bytes))
    
    # Payload is the raw text bytes
    payload = text_bytes
    
    # CRC32 of header + payload
    crc32_val = zlib.crc32(header + payload) & 0xFFFFFFFF
    crc32_bytes = struct.pack('!I', crc32_val)
    
    # SHA-256 of header + payload + crc32
    sha256_val = hashlib.sha256(header + payload + crc32_bytes).digest()
    
    return header + payload + crc32_bytes + sha256_val


def unpack_frame(data: bytes, verify: bool = True) -> Dict[str, Any]:
    """
    Unpack a TSCG-B binary frame.
    
    Returns dict with keys: magic, version, flags, payload_length, payload, crc32, sha256
    Raises ValueError on verification failure.
    """
    if len(data) < MIN_FRAME_SIZE:
        raise ValueError(f"Frame too short: {len(data)} bytes, minimum {MIN_FRAME_SIZE}")
    
    # Parse header
    magic, version, flags, payload_length = struct.unpack('!4sBBH', data[:HEADER_SIZE])
    
    if magic != MAGIC:
        raise ValueError(f"Invalid magic: {magic!r}, expected {MAGIC!r}")
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}, expected {VERSION}")
    
    # Extract payload
    payload_start = HEADER_SIZE
    payload_end = payload_start + payload_length
    if payload_end + CRC32_SIZE + SHA256_SIZE > len(data):
        raise ValueError(
            f"Frame too short for payload: need {payload_end + CRC32_SIZE + SHA256_SIZE}, "
            f"got {len(data)}"
        )
    
    payload = data[payload_start:payload_end]
    
    # Extract CRC32
    crc32_start = payload_end
    crc32_end = crc32_start + CRC32_SIZE
    stored_crc32 = struct.unpack('!I', data[crc32_start:crc32_end])[0]
    
    # Extract SHA-256
    sha256_start = crc32_end
    sha256_end = sha256_start + SHA256_SIZE
    stored_sha256 = data[sha256_start:sha256_end]
    
    if verify:
        # Verify CRC32
        computed_crc32 = zlib.crc32(data[:HEADER_SIZE] + payload) & 0xFFFFFFFF
        if computed_crc32 != stored_crc32:
            raise ValueError(
                f"CRC32 mismatch: computed {computed_crc32:#010x}, "
                f"stored {stored_crc32:#010x}"
            )
        
        # Verify SHA-256
        computed_sha256 = hashlib.sha256(
            data[:HEADER_SIZE] + payload + data[crc32_start:crc32_end]
        ).digest()
        if computed_sha256 != stored_sha256:
            raise ValueError(
                f"SHA-256 mismatch: computed {computed_sha256.hex()}, "
                f"stored {stored_sha256.hex()}"
            )
    
    text = payload.decode('utf-8', errors='replace')
    
    return {
        'magic': magic,
        'version': version,
        'flags': flags,
        'payload_length': payload_length,
        'payload': payload,
        'text': text,
        'crc32': stored_crc32,
        'sha256': stored_sha256,
        'crc32_hex': f'{stored_crc32:#010x}',
        'sha256_hex': stored_sha256.hex(),
    }


class StreamDecoder:
    """
    Buffered multi-frame TSCG-B decoder with magic-byte resynchronization.
    
    Handles streams where frames may be concatenated or interrupted.
    Maintains internal buffer and yields complete frames as they arrive.
    """
    
    def __init__(self):
        self.buffer = bytearray()
        self.frames_decoded = 0
    
    def feed(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Feed raw bytes into the decoder.
        Returns list of fully decoded frames found in the data.
        """
        self.buffer.extend(data)
        frames = []
        
        while True:
            frame = self._try_decode()
            if frame is None:
                break
            frames.append(frame)
            self.frames_decoded += 1
        
        return frames
    
    def _try_decode(self) -> Optional[Dict[str, Any]]:
        """Try to decode one frame from the buffer. Returns None if insufficient data."""
        if len(self.buffer) < MIN_FRAME_SIZE:
            return None
        
        # Find magic bytes
        magic_idx = self.buffer.find(MAGIC)
        if magic_idx == -1:
            # No magic found — discard buffer to prevent unbounded growth
            if len(self.buffer) > 65536:
                self.buffer.clear()
            return None
        
        if magic_idx > 0:
            # Discard bytes before magic (resynchronization)
            self.buffer = self.buffer[magic_idx:]
        
        # Need at least header to get payload_length
        if len(self.buffer) < HEADER_SIZE:
            return None
        
        try:
            _, _, _, payload_length = struct.unpack(
                '!4sBBH', bytes(self.buffer[:HEADER_SIZE])
            )
        except struct.error:
            # Corrupt header — resync by skipping first byte
            self.buffer = self.buffer[1:]
            return None
        
        frame_size = HEADER_SIZE + payload_length + CRC32_SIZE + SHA256_SIZE
        
        if len(self.buffer) < frame_size:
            return None
        
        frame_data = bytes(self.buffer[:frame_size])
        self.buffer = self.buffer[frame_size:]
        
        try:
            return unpack_frame(frame_data)
        except (ValueError, struct.error):
            # Corrupt frame — try next position
            return None
    
    def flush(self) -> List[Dict[str, Any]]:
        """Flush any remaining frames. Returns empty list (incomplete frames discarded)."""
        remaining = list(self.buffer)
        self.buffer.clear()
        return []
    
    @property
    def buffered_bytes(self) -> int:
        return len(self.buffer)
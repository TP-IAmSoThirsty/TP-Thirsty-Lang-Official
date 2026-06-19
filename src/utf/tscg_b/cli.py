"""
TSCG-B CLI — Command-line interface for TSCG Binary Protocol
encode/decode commands.
"""
import sys
import json

from utf.tscg_b.core import pack_text, unpack_frame, StreamDecoder


def cmd_encode(args: list):
    """Encode text into TSCG-B binary frame. Usage: tscg-b encode <text>"""
    if not args:
        text = sys.stdin.read().strip()
    else:
        text = ' '.join(args)

    frame = pack_text(text)
    sys.stdout.buffer.write(frame)


def cmd_decode(args: list):
    """Decode TSCG-B binary frame from stdin or hex string."""
    if args:
        data = bytes.fromhex(args[0])
    else:
        data = sys.stdin.buffer.read()

    result = unpack_frame(data)
    output = {
        'text': result['text'],
        'payload_length': result['payload_length'],
        'crc32': result['crc32_hex'],
        'sha256': result['sha256_hex'],
        'flags': result['flags'],
        'version': result['version'],
    }
    print(json.dumps(output, indent=2))


def cmd_stream(args: list):
    """Decode a stream of frames from stdin (hex or raw)."""
    if args:
        data = bytes.fromhex(args[0])
    else:
        data = sys.stdin.buffer.read()

    decoder = StreamDecoder()
    frames = decoder.feed(data)

    results = []
    for f in frames:
        results.append({
            'text': f['text'],
            'payload_length': f['payload_length'],
            'crc32': f['crc32_hex'],
            'sha256': f['sha256_hex'],
        })

    print(json.dumps(results, indent=2))


def main():
    if len(sys.argv) < 2:
        print("Usage: tscg-b <encode|decode|stream> [args...]")
        sys.exit(1)

    if sys.argv[1] in ('--help', '-h'):
        print("Usage: tscg-b <encode|decode|stream> [args...]")
        print("  encode [text...]  - Encode text into TSCG-B binary frame")
        print("  decode [hex]      - Decode TSCG-B binary frame from hex"
              " or stdin")
        print("  stream [hex]      - Decode a stream of TSCG-B frames")
        sys.exit(0)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        'encode': cmd_encode,
        'decode': cmd_decode,
        'stream': cmd_stream,
    }

    if cmd not in commands:
        print(f"Unknown command: {cmd}")
        print("Available: encode, decode, stream")
        sys.exit(1)

    try:
        commands[cmd](args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

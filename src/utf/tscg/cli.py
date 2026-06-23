"""
TSCG CLI — Parse, canonicalize, and checksum TSCG expressions.
"""
import argparse
import json
import sys

from utf.tscg.core import (
    ALL_SYMBOLS,
    EXTENDED_SYMBOLS,
    SYMBOLS,
    CombineExpr,
    PipelineExpr,
    SymbolExpr,
    canonical_form,
    checksum,
    parse,
    validate_symbols,
)


def _node_to_dict(n):
    if isinstance(n, SymbolExpr):
        return {'type': 'symbol', 'name': n.symbol_name, 'opcode': n.opcode}
    elif isinstance(n, PipelineExpr):
        return {'type': 'pipeline', 'left': _node_to_dict(n.left), 'right': _node_to_dict(n.right)}
    elif isinstance(n, CombineExpr):
        return {'type': 'combine', 'op': n.op, 'left': _node_to_dict(n.left), 'right': _node_to_dict(n.right)}
    return {}


def _node_to_str(n, indent=0):
    pad = '  ' * indent
    if isinstance(n, SymbolExpr):
        return f"{pad}${n.symbol_name} (0x{n.opcode:02X})"
    elif isinstance(n, PipelineExpr):
        return f"{pad}Pipeline(\n{_node_to_str(n.left, indent + 1)}\n{pad}  ->\n{_node_to_str(n.right, indent + 1)}\n{pad})"
    elif isinstance(n, CombineExpr):
        return f"{pad}Combine({n.op})(\n{_node_to_str(n.left, indent + 1)}\n{pad}  {n.op}\n{_node_to_str(n.right, indent + 1)}\n{pad})"
    return str(n)


def main():
    from utf.console import enable_utf8
    enable_utf8()
    parser = argparse.ArgumentParser(
        description="TSCG — Thirst's Symbolic Constitutional Grammar"
    )
    subparsers = parser.add_subparsers(dest='command', help='Sub-commands')

    # parse command
    parse_parser = subparsers.add_parser('parse', help='Parse and display a TSCG expression AST')
    parse_parser.add_argument('expression', help="TSCG expression (e.g. '$COG -> $DNT')")
    parse_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')

    # canonical command
    canon_parser = subparsers.add_parser('canonical', help='Output canonical normalized form')
    canon_parser.add_argument('expression', help='TSCG expression')

    # checksum command
    cs_parser = subparsers.add_parser('checksum', help='Output SHA-256 checksum')
    cs_parser.add_argument('expression', help='TSCG expression')

    # validate command
    val_parser = subparsers.add_parser('validate', help='Validate symbols in expression')
    val_parser.add_argument('expression', help='TSCG expression')

    # list command
    list_parser = subparsers.add_parser('list', help='List all recognized symbols')
    list_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == 'list':
        if args.json:
            print(json.dumps(ALL_SYMBOLS, indent=2))
        else:
            print("TSCG Symbols:")
            print(f"  {'Core (0x00-0x08):':<20}")
            for name, opcode in sorted(SYMBOLS.items(), key=lambda x: x[1]):
                print(f"    ${name:<15} 0x{opcode:02X} ({opcode})")
            print(f"  {'Extended (0x10-0x16):':<20}")
            for name, opcode in sorted(EXTENDED_SYMBOLS.items(), key=lambda x: x[1]):
                print(f"    ${name:<15} 0x{opcode:02X} ({opcode})")
        return

    if args.command == 'validate':
        errors = validate_symbols(args.expression)
        if errors:
            print(f"Validation errors ({len(errors)}):")
            for e in errors:
                print(f"  ✗ {e}")
        else:
            print("✓ All symbols recognized")
        return

    try:
        ast = parse(args.expression)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.command == 'parse':
        if args.json:
            print(json.dumps(_node_to_dict(ast), indent=2))
        else:
            print(_node_to_str(ast))

    elif args.command == 'canonical':
        print(canonical_form(ast))

    elif args.command == 'checksum':
        print(checksum(args.expression))


if __name__ == '__main__':
    main()

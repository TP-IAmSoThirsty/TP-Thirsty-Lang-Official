"""Thirst of Gods CLI — Command-line entry point for Tier 2 governance.

Subcommands:
  run <file>        — Interpret a .thirstofgods file
  check <file>      — Validate deity contract only
  transpile <file>
    --target thirsty|js  — Transpile to Thirsty-Lang or JavaScript
"""
import argparse
import json
import os
import sys


def run_file(file_path: str) -> None:
    """Interpret a .thirstofgods file through the Thirst of Gods interpreter.

    Args:
        file_path: Path to the .thirstofgods file.
    """
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser
    from utf.thirsty_lang.checker import check_ast
    from utf.thirsty_lang.diagnostics import DiagnosticBundle
    from utf.thirst_of_gods.core import interpret_gods, ThirstOfGodsError

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    with open(file_path, "r") as f:
        source = f.read()

    lexer = Lexer(source)
    tokens = lexer.lex()

    parser = Parser(tokens)
    ast = parser.parse()

    errors = list(lexer.errors)
    errors.extend(parser.errors)
    errors.extend(check_ast(ast))

    if errors:
        bundle = DiagnosticBundle(errors)
        print(bundle.format_all(), file=sys.stderr)
        sys.exit(1)

    try:
        result = interpret_gods(ast)
        if result is not None:
            print(result)
    except ThirstOfGodsError as e:
        print(f"Deity Contract Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Runtime Error: {e}", file=sys.stderr)
        sys.exit(1)


def check_file(file_path: str) -> None:
    """Validate deity contract compliance for a .thirstofgods file.

    Args:
        file_path: Path to the .thirstofgods file.
    """
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser
    from utf.thirst_of_gods.core import to_gods, validate_deity_contract

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    with open(file_path, "r") as f:
        source = f.read()

    lexer = Lexer(source)
    tokens = lexer.lex()

    parser = Parser(tokens)
    ast = parser.parse()

    errors = list(lexer.errors)
    errors.extend(parser.errors)

    if errors:
        for e in errors:
            msg = e.message if hasattr(e, 'message') else str(e)
            print(f"  {msg}", file=sys.stderr)
        sys.exit(1)

    # Run deity contract check
    contract = to_gods(ast)
    diagnostics = validate_deity_contract(ast)

    if diagnostics:
        print(f"Deity Contract: FAIL ({len(diagnostics)} violation(s))")
        for d in diagnostics:
            print(f"  [{d.code}] {d.severity}: {d.message}")
    else:
        print("Deity Contract: PASS")

    if contract.violations:
        print("\nDetails:")
        for v in contract.violations:
            print(f"  - {v}")

    if diagnostics:
        sys.exit(1)


def transpile_file(file_path: str, target: str = "thirsty") -> None:
    """Transpile a .thirstofgods file to Thirsty-Lang or JavaScript.

    Args:
        file_path: Path to the .thirstofgods file.
        target: Target language ("thirsty" or "js").
    """
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser
    from utf.thirsty_lang.checker import check_ast
    from utf.thirsty_lang.diagnostics import DiagnosticBundle

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    with open(file_path, "r") as f:
        source = f.read()

    lexer = Lexer(source)
    tokens = lexer.lex()

    parser = Parser(tokens)
    ast = parser.parse()

    errors = list(lexer.errors)
    errors.extend(parser.errors)
    errors.extend(check_ast(ast))

    if errors:
        bundle = DiagnosticBundle(errors)
        print(bundle.format_all(), file=sys.stderr)
        sys.exit(1)

    if target == "thirsty":
        from utf.thirsty_lang.formatter import format as format_ast
        output = format_ast(ast)
        output_path = os.path.splitext(file_path)[0] + ".thirsty"
        with open(output_path, "w") as f:
            f.write(output)
        print(f"Transpiled to Thirsty-Lang: {output_path}")
    elif target == "js":
        from utf.thirsty_lang.cli import _transpile_to_js
        js_code = _transpile_to_js(ast)
        output_path = os.path.splitext(file_path)[0] + ".js"
        with open(output_path, "w") as f:
            f.write(js_code)
        print(f"Transpiled to JavaScript: {output_path}")
    else:
        print(f"Error: Unknown target '{target}'. Use 'thirsty' or 'js'.", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point for the Thirst of Gods CLI."""
    parser = argparse.ArgumentParser(
        prog="thirst-of-gods",
        description="Thirst of Gods — Tier 2 governance enforcement CLI",
        epilog="See documentation for deity contract requirements"
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # run
    run_parser = subparsers.add_parser("run", help="Interpret a .thirstofgods file")
    run_parser.add_argument("file", help="Path to .thirstofgods file")

    # check
    check_parser = subparsers.add_parser("check", help="Validate deity contract compliance")
    check_parser.add_argument("file", help="Path to .thirstofgods file")

    # transpile
    transpile_parser = subparsers.add_parser("transpile", help="Transpile a .thirstofgods file")
    transpile_parser.add_argument("file", help="Path to .thirstofgods file")
    transpile_parser.add_argument("--target", choices=["thirsty", "js"], default="thirsty", help="Target language")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    try:
        if args.command == "run":
            run_file(args.file)
        elif args.command == "check":
            check_file(args.file)
        elif args.command == "transpile":
            transpile_file(args.file, target=args.target)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def run(file_path: str) -> None:
    """Entry point for delegation from the main Thirsty-Lang CLI.

    Args:
        file_path: Path to the .thirstofgods file.
    """
    run_file(file_path)


if __name__ == "__main__":
    main()
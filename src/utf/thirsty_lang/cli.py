"""
Thirsty-Lang CLI — Command-line interface with all subcommands.
"""
import argparse
import json
import os
import sys
import traceback

from utf.thirsty_lang.ast import (
    IntLiteral, FloatLiteral, StringLiteral, BoolLiteral, NoneLiteral, ErrorLiteral,
    Identifier, CallExpr, BinaryOp, UnaryOp, ExprStmt, ReturnStmt, BlockStmt,
    Program, FunctionDecl, VariableDecl,
)
from utf.thirsty_lang.token import TokenType


def main():
    """Main entry point for the Thirsty-Lang CLI."""
    parser = argparse.ArgumentParser(
        prog="thirsty",
        description="Thirsty-Lang: A governance-first programming language",
        epilog="For more information, see https://thirsty-lang.dev"
    )
    parser.add_argument("--version", action="version", version="Thirsty-Lang 1.0.0")

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # run
    run_parser = subparsers.add_parser("run", help="Run a .thirsty file")
    run_parser.add_argument("file", nargs="?", help="Path to .thirsty file")
    run_parser.add_argument("--trace", action="store_true", help="Enable execution tracing")
    run_parser.add_argument("--release", action="store_true", help="Suppress verbose error output, show user-friendly messages")
    run_parser.add_argument("--opt", type=int, choices=[0, 1, 2, 3], default=0, help="Optimization level (0-3)")
    run_parser.add_argument("--thirst-level", choices=["core", "governed"], default="core", help="Thirst mode")
    run_parser.add_argument("--authority", type=str, help="Authority tag for governed mode")
    run_parser.add_argument("--demo", action="store_true", help="Run demo program")

    # repl
    repl_parser = subparsers.add_parser("repl", help="Start interactive REPL")
    repl_parser.add_argument("--trace", action="store_true", help="Show stack traces on errors")
    repl_parser.add_argument("--opt", type=int, choices=[0, 1, 2, 3], default=0, help="Optimization level (0-3)")
    repl_parser.add_argument("--thirst-level", choices=["core", "governed"], default="core", help="Thirst mode")

    # fmt
    fmt_parser = subparsers.add_parser("fmt", help="Format .thirsty files")
    fmt_parser.add_argument("files", nargs="+", help="Files to format")
    fmt_parser.add_argument("--check", action="store_true", help="Check formatting without modifying")

    # new
    new_parser = subparsers.add_parser("new", help="Scaffold a new Thirsty-Lang project")
    new_parser.add_argument("name", help="Project name")
    new_parser.add_argument("--mode", choices=["core", "governed"], default="core", help="Default governance mode")

    # build
    build_parser = subparsers.add_parser("build", help="Build a .thirsty project")
    build_parser.add_argument("--target", choices=["llvm-ir", "llvm-obj", "llvm-exe", "llvm-asm", "llvm-jit", "js", "wasm-pyodide"], default="js", help="Build target")
    build_parser.add_argument("--emit-manifest", action="store_true", help="Emit governance manifest")
    build_parser.add_argument("file", nargs="?", help="Entry point .thirsty file")

    # govern
    govern_parser = subparsers.add_parser("govern", help="Governance operations")
    govern_parser.add_argument("file", nargs="?", help="Path to .thirsty file")
    govern_parser.add_argument("--report", action="store_true", help="Generate governance report")
    govern_parser.add_argument("--auto-tarl", action="store_true", help="Auto-generate T.A.R.L. policy")

    # add
    add_parser = subparsers.add_parser("add", help="Add a dependency")
    add_parser.add_argument("package", help="Package name with optional version (e.g., pkg@1.0)")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Audit dependencies for integrity")
    audit_parser.add_argument("--fix", action="store_true", help="Attempt to fix issues")

    # lock
    lock_parser = subparsers.add_parser("lock", help="Generate lockfile")
    lock_parser.add_argument("--update", action="store_true", help="Update existing lockfile")

    # doctor
    doctor_parser = subparsers.add_parser("doctor", help="Project health check")
    doctor_parser.add_argument("--fix", action="store_true", help="Attempt to fix issues")

    # lsp
    lsp_parser = subparsers.add_parser("lsp", help="Start LSP server")
    lsp_parser.add_argument("--stdio", action="store_true", help="Use stdio mode")
    lsp_parser.add_argument("--port", type=int, default=9898, help="TCP port")

    # docs
    docs_parser = subparsers.add_parser("docs", help="Generate documentation")
    docs_parser.add_argument("--output-dir", default="./docs", help="Output directory")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    try:
        if args.command == "run":
            cmd_run(args)
        elif args.command == "repl":
            cmd_repl(args)
        elif args.command == "fmt":
            cmd_fmt(args)
        elif args.command == "new":
            cmd_new(args)
        elif args.command == "build":
            cmd_build(args)
        elif args.command == "govern":
            cmd_govern(args)
        elif args.command == "add":
            cmd_add(args)
        elif args.command == "audit":
            cmd_audit(args)
        elif args.command == "lock":
            cmd_lock(args)
        elif args.command == "doctor":
            cmd_doctor(args)
        elif args.command == "lsp":
            cmd_lsp(args)
        elif args.command == "docs":
            cmd_docs(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if os.environ.get("THIRSTY_DEBUG"):
            traceback.print_exc()
        sys.exit(1)


def _lex_parse_check(file_path: str, mode: str = "core"):
    """Helper: lex, parse, and type-check a file. Returns (ast, errors, checker)."""
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser
    from utf.thirsty_lang.checker import check_ast

    with open(file_path, "r") as f:
        source = f.read()

    lexer = Lexer(source)
    tokens = lexer.lex()

    parser = Parser(tokens)
    ast = parser.parse()

    # Check for lexer/parser errors
    errors = list(lexer.errors)
    errors.extend(parser.errors)
    errors.extend(check_ast(ast))

    return ast, errors, source


def cmd_run(args):
    """Execute a .thirsty file."""
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser
    from utf.thirsty_lang.checker import check_ast
    from utf.thirsty_lang.interpreter import Interpreter
    from utf.thirsty_lang.diagnostics import DiagnosticBundle

    if args.demo:
        source = '''module hello: core

glass greet(name: String) {
    return "hello, " + name + "!"
}

drink main = "thirsty world"
drink result = greet(main)
pour result
'''
        file_path = "<demo>"
    else:
        file_path = args.file
        if file_path.endswith('.thirstofgods'):
            from utf.thirst_of_gods.cli import run as gods_run
            gods_run(file_path)
            return
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            sys.exit(1)
        with open(file_path, "r") as f:
            source = f.read()

    lexer = Lexer(source)
    tokens = lexer.lex()

    parser = Parser(tokens)
    ast = parser.parse()

    # Check errors
    errors = []
    errors.extend(lexer.errors)
    errors.extend(parser.errors)
    errors.extend(check_ast(ast))

    if errors:
        bundle = DiagnosticBundle(errors)
        print(bundle.format_all(), file=sys.stderr)
        sys.exit(1)

    interpreter = Interpreter(opt_level=args.opt, debug_mode=args.trace)
    try:
        result = interpreter.interpret(ast, mode=args.thirst_level)
        if result is not None:
            print(result)
    except Exception as e:
        if args.release:
            print(f"Error: {e}", file=sys.stderr)
        else:
            print(f"Runtime Error: {e}", file=sys.stderr)
        if args.trace:
            traceback.print_exc()
        sys.exit(1)


def cmd_repl(args):
    """Start an interactive REPL."""
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser
    from utf.thirsty_lang.checker import check_ast
    from utf.thirsty_lang.interpreter import Interpreter, Environment

    debug_enabled = args.trace or os.environ.get("THIRSTY_DEBUG") == "1"

    print(f"Thirsty-Lang REPL (mode: {args.thirst_level}, opt={args.opt})")
    print("Type 'exit' to quit, 'help' for commands, '.clear' to reset state.")
    print()

    interpreter = Interpreter(opt_level=args.opt, debug_mode=debug_enabled)
    source_buffer = ""
    pending = False

    while True:
        try:
            if not pending:
                line = input(">>> ")
            else:
                line = input("... ")

            if line.lower() in ("exit", "quit"):
                break
            if line.lower() == "help":
                print("Commands: exit, help, .clear")
                print("Thirsty-Lang expressions and statements")
                continue
            if line.strip() == ".clear":
                interpreter.env = Environment()
                interpreter._register_builtins()
                source_buffer = ""
                pending = False
                print("State cleared.")
                continue
            if line.strip() == "" and not pending:
                continue

            source_buffer += line + "\n"

            # Try to lex/parse the accumulated input
            lexer = Lexer(source_buffer)
            tokens = lexer.lex()
            parser = Parser(tokens)
            try:
                ast = parser.parse()
            except Exception:
                pending = True
                continue

            errors = []
            errors.extend(lexer.errors)
            errors.extend(parser.errors)
            errors.extend(check_ast(ast))

            if errors:
                needs_more = False
                for e in errors:
                    msg = str(e.message).lower() if hasattr(e, 'message') else str(e).lower()
                    if "unexpected end" in msg or "eof" in msg or "expect" in msg:
                        if not pending:
                            needs_more = True
                        break
                if needs_more:
                    pending = True
                    continue
                for e in errors:
                    print(f"  {e.code}: {e.message}")
                source_buffer = ""
                pending = False
                continue

            pending = False
            try:
                result = interpreter.interpret(ast, mode=args.thirst_level)
                if result is not None:
                    print(result)
            except Exception as e:
                print(f"Error: {e}")
                if debug_enabled:
                    import traceback
                    traceback.print_exc()
                source_buffer = ""

        except (EOFError, KeyboardInterrupt):
            print()
            break
        except Exception as e:
            print(f"Error: {e}")
            if debug_enabled:
                import traceback
                traceback.print_exc()
            source_buffer = ""
            pending = False

def cmd_fmt(args):
    """Format .thirsty files."""
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser
    from utf.thirsty_lang.formatter import format

    for file_path in args.files:
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            continue

        with open(file_path, "r") as f:
            source = f.read()

        lexer = Lexer(source)
        tokens = lexer.lex()
        parser = Parser(tokens)
        ast = parser.parse()

        formatted = format(ast)

        if args.check:
            if source.strip() != formatted.strip():
                print(f"{file_path}: would reformat")
                sys.exit(1)
        else:
            with open(file_path, "w") as f:
                f.write(formatted)
            print(f"Formatted: {file_path}")


def cmd_new(args):
    """Scaffold a new Thirsty-Lang project."""
    from utf.thirsty_lang.package_manager import create_thirsty_toml, create_thirsty_lock

    project_dir = os.path.join(os.getcwd(), args.name)
    if os.path.exists(project_dir):
        print(f"Error: Directory already exists: {project_dir}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(project_dir)
    os.makedirs(os.path.join(project_dir, "src"))
    os.makedirs(os.path.join(project_dir, "tests"))

    # Create main.thirsty
    main_path = os.path.join(project_dir, "src", "main.thirsty")
    with open(main_path, "w") as f:
        f.write(f'''module {args.name}: {args.mode}

glass greet(name: String) {{
    return "hello, " + name + "!"
}}

drink main = greet("thirsty world")
pour main
''')

    # Create thirsty.toml
    create_thirsty_toml(project_dir, args.name)

    # Create thirsty.lock
    create_thirsty_lock(project_dir)

    print(f"Created Thirsty-Lang project: {args.name}")
    print(f"  cd {project_dir}")
    print(f"  thirsty run src/main.thirsty")


def cmd_build(args):
    """Build a .thirsty project."""
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser
    from utf.thirsty_lang.formatter import format

    if not args.file:
        # Try to find main.thirsty
        main_path = os.path.join(os.getcwd(), "src", "main.thirsty")
        if os.path.exists(main_path):
            args.file = main_path
        else:
            print("Error: No file specified and no src/main.thirsty found", file=sys.stderr)
            sys.exit(1)

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    with open(args.file, "r") as f:
        source = f.read()

    lexer = Lexer(source)
    tokens = lexer.lex()

    parser = Parser(tokens)
    ast = parser.parse()

    target = args.target
    if target in ("llvm-ir", "llvm-obj", "llvm-exe", "llvm-asm", "llvm-jit"):
        print(f"LLVM backend not yet available for target: {target}")
        print("Falling back to JavaScript output.")
        target = "js"

    if target == "js":
        # Simple JavaScript transpilation
        js_code = _transpile_to_js(ast)
        output_path = os.path.splitext(args.file)[0] + ".js"
        with open(output_path, "w") as f:
            f.write(js_code)
        print(f"Built: {output_path}")

    elif target == "wasm-pyodide":
        print("Wasm/Pyodide target not yet implemented.")

    if args.emit_manifest:
        _emit_manifest(ast, args.file)


def _transpile_to_js(ast) -> str:
    """Simple transpilation of Thirsty-Lang AST to JavaScript."""
    from utf.thirsty_lang.formatter import format_expr, format_stmt

    lines = ['// Generated by Thirsty-Lang compiler', '']

    # Track function definitions
    for stmt in ast.stmts:
        if hasattr(stmt, 'name'):
            if hasattr(stmt, 'params') and hasattr(stmt, 'body'):
                # Function
                params = ", ".join(p[0] for p in stmt.params)
                lines.append(f"function {stmt.name}({params}) {{")
                _js_stmt_body(stmt.body, lines, indent=1)
                lines.append("}")
                lines.append("")

    # Track main expression
    main_expr = None
    for stmt in ast.stmts:
        if hasattr(stmt, 'name') and getattr(stmt, 'name', None) == 'main':
            if hasattr(stmt, 'init_expr') and stmt.init_expr:
                main_expr = stmt.init_expr
            break

    # Generate main execution
    for stmt in ast.stmts:
        if hasattr(stmt, 'name') and getattr(stmt, 'name', None) == 'main':
            continue
        if not (hasattr(stmt, 'params') and hasattr(stmt, 'body')):
            _js_stmt(stmt, lines, indent=0)
            lines.append("")

    if main_expr:
        js_expr = _js_expression(main_expr)
        lines.append(f"console.log({js_expr});")

    return "\n".join(lines)


def _js_expression(expr) -> str:
    """Convert a Thirsty-Lang expression to JS."""

    if isinstance(expr, IntLiteral):
        return str(expr.value)
    elif isinstance(expr, FloatLiteral):
        return str(expr.value)
    elif isinstance(expr, StringLiteral):
        return json.dumps(expr.value)
    elif isinstance(expr, BoolLiteral):
        return "true" if expr.value else "false"
    elif isinstance(expr, NoneLiteral):
        return "null"
    elif isinstance(expr, Identifier):
        return expr.name
    elif isinstance(expr, BinaryOp):
        op_map = {
            TokenType.PLUS: "+", TokenType.MINUS: "-",
            TokenType.STAR: "*", TokenType.SLASH: "/",
            TokenType.PERCENT: "%",
            TokenType.EQEQ: "===", TokenType.NE: "!==",
            TokenType.LT: "<", TokenType.GT: ">",
            TokenType.LE: "<=", TokenType.GE: ">=",
            TokenType.AND: "&&", TokenType.OR: "||",
        }
        js_op = op_map.get(expr.op, expr.op.name.lower())
        return f"({_js_expression(expr.left)} {js_op} {_js_expression(expr.right)})"
    elif isinstance(expr, UnaryOp):
        if expr.op == TokenType.MINUS:
            return f"(-{_js_expression(expr.operand)})"
        return f"(!{_js_expression(expr.operand)})"
    elif isinstance(expr, CallExpr):
        callee = _js_expression(expr.callee)
        args = ", ".join(_js_expression(a) for a in expr.args)
        return f"{callee}({args})"
    return "(null)"


def _js_stmt(stmt, lines, indent=0):
    """Convert a Thirsty-Lang statement to JS."""
    prefix = "  " * indent

    if isinstance(stmt, ExprStmt):
        lines.append(f"{prefix}{_js_expression(stmt.expr)};")
    elif isinstance(stmt, ReturnStmt):
        val = _js_expression(stmt.value) if stmt.value else ""
        lines.append(f"{prefix}return {val};")


def _js_stmt_body(stmt, lines, indent=0):
    """Convert a block statement body to JS."""
    if isinstance(stmt, BlockStmt):
        for s in stmt.statements:
            _js_stmt(s, lines, indent=indent)
    else:
        _js_stmt(stmt, lines, indent=indent)


def _emit_manifest(ast, file_path):
    """Emit governance manifest."""
    import json
    manifest = {
        "file": file_path,
        "mode": "core",
        "functions": [],
        "governance_policy": {
            "tarl": {},
            "shadow_thirst": {},
        }
    }
    if ast.header:
        manifest["mode"] = ast.header.mode
    for stmt in ast.stmts:
        if hasattr(stmt, 'name'):
            info = {"name": getattr(stmt, 'name', 'unknown')}
            if hasattr(stmt, 'requires_annotation'):
                info["requires"] = stmt.requires_annotation
            manifest["functions"].append(info)
    manifest_path = os.path.splitext(file_path)[0] + ".manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest: {manifest_path}")


def cmd_govern(args):
    """Governance operations."""
    import json

    if not args.file:
        # Scan for .thirsty files
        pattern = "*.thirsty"
        import glob
        files = glob.glob("**/*.thirsty", recursive=True)
        if not files:
            print("No .thirsty files found.", file=sys.stderr)
            sys.exit(1)
        args.file = files[0]

    ast, errors, source = _lex_parse_check(args.file)

    if args.report:
        print(f"Governance Report for: {args.file}")
        print(f"  Mode: {ast.header.mode if ast.header else 'core'}")
        print(f"  Functions: {sum(1 for s in ast.stmts if hasattr(s, 'name') and hasattr(s, 'params'))}")
        print(f"  Errors: {len(errors)}")
        for e in errors:
            print(f"    [{e.code}] {e.message}")

    if args.auto_tarl:
        # Auto-generate T.A.R.L. policy
        tarl_policy = "# Auto-generated T.A.R.L. Policy\n"
        for stmt in ast.stmts:
            if hasattr(stmt, 'name') and getattr(stmt, 'name', None):
                tarl_policy += f'\nwhen name == "{stmt.name}" => ALLOW\n'
        tarl_policy += "\nwhen true => DENY  # Default deny\n"

        tarl_path = os.path.splitext(args.file)[0] + ".tarl"
        with open(tarl_path, "w") as f:
            f.write(tarl_policy)
        print(f"T.A.R.L. policy: {tarl_path}")


def cmd_add(args):
    """Add a dependency."""
    from utf.thirsty_lang.package_manager import PackageManager

    pm = PackageManager()
    pm.parse_manifest()

    if "@" in args.package:
        name, version = args.package.split("@", 1)
    else:
        name = args.package
        version = "*"

    pm.add_dependency(name, version)
    pm.generate_lock()
    pm.write_lock()
    print(f"Added: {name}@{version}")


def cmd_audit(args):
    """Audit dependencies."""
    from utf.thirsty_lang.package_manager import PackageManager

    pm = PackageManager()
    issues = pm.audit_dependencies()

    if not issues:
        print("No dependency issues found.")
        return

    for issue in issues:
        print(f"  [{issue['type']}] {issue['message']}")

    if args.fix:
        pm.generate_lock()
        pm.write_lock()
        print("Lockfile regenerated.")


def cmd_lock(args):
    """Generate or update lockfile."""
    from utf.thirsty_lang.package_manager import PackageManager

    pm = PackageManager()
    pm.parse_manifest()
    pm.generate_lock()
    pm.write_lock()
    print("Lockfile generated: thirsty.lock")


def cmd_doctor(args):
    """Project health check."""
    checks_passed = 0
    checks_failed = 0

    print("Thirsty-Lang Doctor — Project Health Check")
    print()

    # Check thirsty.toml
    if os.path.exists("thirsty.toml"):
        print("✓ thirsty.toml found")
        checks_passed += 1
    else:
        print("✗ thirsty.toml missing")
        checks_failed += 1

    # Check thirsty.lock
    if os.path.exists("thirsty.lock"):
        print("✓ thirsty.lock found")
        checks_passed += 1
    else:
        print("✗ thirsty.lock missing")
        checks_failed += 1

    # Check source dir
    if os.path.isdir("src"):
        thirsty_files = []
        for root, dirs, files in os.walk("src"):
            for f in files:
                if f.endswith(".thirsty"):
                    thirsty_files.append(os.path.join(root, f))
        if thirsty_files:
            print(f"✓ {len(thirsty_files)} .thirsty source files found")
            checks_passed += 1
        else:
            print("✗ No .thirsty files in src/")
            checks_failed += 1
    else:
        print("✗ src/ directory missing")
        checks_failed += 1

    # Check Python environment
    if sys.version_info >= (3, 11):
        print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
        checks_passed += 1
    else:
        print(f"✗ Python {sys.version_info.major}.{sys.version_info.minor} (3.11+ required)")
        checks_failed += 1

    # Summary
    print()
    print(f"Passed: {checks_passed}, Failed: {checks_failed}")

    if args.fix and checks_failed > 0:
        from utf.thirsty_lang.package_manager import create_thirsty_toml, create_thirsty_lock
        if not os.path.exists("thirsty.toml"):
            create_thirsty_toml(".", "my-project")
            print("Created thirsty.toml")
        if not os.path.exists("thirsty.lock"):
            create_thirsty_lock(".")
            print("Created thirsty.lock")
        if not os.path.isdir("src"):
            os.makedirs("src")
            print("Created src/ directory")

    if checks_failed > 0:
        sys.exit(1)


def cmd_lsp(args):
    """Start LSP server."""
    if args.stdio:
        print("LSP stdio mode not yet fully implemented.")
        # Basic JSON-RPC loop
        import sys
        for line in sys.stdin:
            line = line.strip()
            if line:
                print('{"jsonrpc":"2.0","method":"textDocument/completion","params":[]}')
                sys.stdout.flush()
    else:
        import socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", args.port))
        server.listen(1)
        print(f"LSP server listening on port {args.port}")
        conn, addr = server.accept()
        print(f"Connection from {addr}")
        conn.close()


def cmd_docs(args):
    """Generate documentation."""
    import json

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    # Generate simple HTML docs
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Thirsty-Lang Documentation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #0a0e27; color: #e0e0e0; }
        h1, h2, h3 { color: #00d4aa; }
        code { background: #1a1f3a; padding: 2px 6px; border-radius: 3px; color: #ff79c6; }
        pre { background: #1a1f3a; padding: 16px; border-radius: 8px; overflow-x: auto; border: 1px solid #2a2f5a; }
        .keyword { color: #ff79c6; }
        .string { color: #f1fa8c; }
        .comment { color: #6272a4; }
        .type { color: #8be9fd; }
        nav { position: fixed; left: 20px; top: 20px; width: 200px; }
        nav a { display: block; color: #00d4aa; text-decoration: none; padding: 4px 0; }
        nav a:hover { color: #ff79c6; }
        @media (max-width: 1200px) { nav { position: static; width: 100%; } }
    </style>
</head>
<body>
    <h1>🌊 Thirsty-Lang Documentation</h1>
    <p>A governance-first programming language with water-metaphor syntax.</p>

    <h2>Quick Start</h2>
    <pre><code><span class="keyword">module</span> hello: core

<span class="keyword">glass</span> <span class="type">greet</span>(name: String) {
    <span class="keyword">return</span> <span class="string">"hello, "</span> + name + <span class="string">"!"</span>
}

<span class="keyword">drink</span> main = greet(<span class="string">"thirsty world"</span>)
<span class="keyword">pour</span> main</code></pre>

    <h2>Keywords</h2>
    <p>Core: drink, pour, sip, thirsty, hydrated, thirst, quench, refill, glass, reservoir, well, of, flood, drip, evaporate, condense, fountain, return, mut, empty</p>
    <p>Security: shield, sanitize, armor, morph, detect, defend</p>
    <p>Governance: cascade, spillage, cleanup, throw, policy, when, ALLOW, DENY, ESCALATE</p>
    <p>Shadow Thirst: mutation, validated_canonical, shadow, invariant, canonical, promote, reject</p>

    <h2>Types</h2>
    <p>Int, Float, Bool, String, Void, Any, Quenched&lt;T&gt;, Reservoir&lt;T&gt;, Task&lt;T&gt;, Result&lt;T,E&gt;, Governed&lt;T&gt;</p>

    <h2>CLI</h2>
    <p><code>thirsty run file.thirsty</code> — Execute a program</p>
    <p><code>thirsty repl</code> — Interactive REPL</p>
    <p><code>thirsty fmt file.thirsty</code> — Format source</p>
    <p><code>thirsty new project</code> — Scaffold project</p>

    <footer>
        <p>Thirsty-Lang v1.0.0 — The Universal Thirsty Family</p>
    </footer>
</body>
</html>"""

    index_path = os.path.join(output_dir, "index.html")
    with open(index_path, "w") as f:
        f.write(html)
    print(f"Documentation: {index_path}")


if __name__ == "__main__":
    main()
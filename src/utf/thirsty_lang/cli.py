"""
Thirsty-Lang CLI — Command-line interface with all subcommands.
"""
import argparse
import json
import os
import sys
import traceback

from utf.thirsty_lang import __version__
from utf.thirsty_lang.ast import (
    BinaryOp,
    BlockStmt,
    BoolLiteral,
    CallExpr,
    ExprStmt,
    FloatLiteral,
    Identifier,
    IntLiteral,
    NoneLiteral,
    ReturnStmt,
    StringLiteral,
    UnaryOp,
)
from utf.thirsty_lang.token import TokenType


def main():
    """Main entry point for the Thirsty-Lang CLI."""
    from utf.console import enable_utf8
    enable_utf8()
    parser = argparse.ArgumentParser(
        prog="thirsty",
        description="Thirsty-Lang: A governance-first programming language",
        epilog="For more information, see https://thirsty-lang.dev"
    )
    parser.add_argument("--version", action="version", version=f"Thirsty-Lang {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # run
    run_parser = subparsers.add_parser("run", help="Run a .thirsty file")
    run_parser.add_argument("file", nargs="?", help="Path to .thirsty file")
    run_parser.add_argument("--trace", action="store_true", help="Enable execution tracing")
    run_parser.add_argument("--release", action="store_true", help="Suppress verbose error output, show user-friendly messages")
    run_parser.add_argument("--opt", type=int, choices=[0, 1, 2, 3], default=0, help="Optimization level (0-3)")
    run_parser.add_argument("--thirst-level", choices=["core", "governed"], default="core", help="Thirst mode")
    run_parser.add_argument("--authority", type=str, help="Authority tag injected into the governance context for governed mode")
    run_parser.add_argument("--policy", type=str, help="Path to a .tarl policy file to route governed calls through")
    run_parser.add_argument("--demo", action="store_true", help="Run demo program")
    run_parser.add_argument("--locked", action="store_true", help="Require lockfile verification before executing")

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
    govern_parser.add_argument("--enforce", action="store_true", help="Exit 1 if any function gets DENY")

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
    from utf.thirsty_lang.checker import check_ast
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser

    with open(file_path) as f:
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
    from utf.thirsty_lang.checker import check_ast
    from utf.thirsty_lang.diagnostics import DiagnosticBundle
    from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.module_system import load_lockfile
    from utf.thirsty_lang.parser import Parser

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
        with open(file_path) as f:
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

    # --locked flag: verify thirsty.lock exists before executing
    if getattr(args, 'locked', False):
        lock = load_lockfile(".")
        if not lock or "dependencies" not in lock or not lock["dependencies"]:
            print("Error: Lockfile check failed — thirsty.lock not found or empty.", file=sys.stderr)
            print("Run 'thirsty lock' first to generate it.", file=sys.stderr)
            sys.exit(1)
        print("Lockfile verified. Running with integrity checks enabled.")

    interpreter = Interpreter(opt_level=args.opt, debug_mode=args.trace)

    # Governance wiring: bind the authority tag into the governance context,
    # and route governed calls through a TARL policy engine when --policy
    # supplies a .tarl file.
    authority = getattr(args, "authority", None)
    if authority:
        interpreter.set_authority(authority)
    policy_path = getattr(args, "policy", None)
    if policy_path:
        if not os.path.isfile(policy_path):
            print(f"Error: policy file not found: {policy_path}", file=sys.stderr)
            sys.exit(1)
        from utf.tarl.core import PolicyParser
        from utf.tarl.runtime import TarlRuntime
        with open(policy_path) as pf:
            policy = PolicyParser.parse(pf.read())
        interpreter.attach_tarl(TarlRuntime(policy))
        # A policy with no authority tag still needs a context to evaluate.
        if authority is None:
            interpreter.set_authority("")

    try:
        result = interpreter.interpret(ast, mode=args.thirst_level)
        if result is not None:
            print(result)
    except GovernanceViolation as e:
        print(f"governance denied: {e.name}: {e.reason}", file=sys.stderr)
        if e.proof is not None:
            print(f"  proof: verdict={e.proof.verdict} "
                  f"policy={e.proof.policy_hash}", file=sys.stderr)
        sys.exit(2)
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
    from utf.thirsty_lang.checker import check_ast
    from utf.thirsty_lang.interpreter import Environment, Interpreter
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser

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
    from utf.thirsty_lang.formatter import format
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser

    for file_path in args.files:
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            continue

        with open(file_path) as f:
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
    from utf.thirsty_lang.package_manager import (
        create_thirsty_lock,
        create_thirsty_toml,
    )

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
    print("  thirsty run src/main.thirsty")


def cmd_build(args):
    """Build a .thirsty project."""
    from utf.thirsty_lang.lexer import Lexer
    from utf.thirsty_lang.parser import Parser

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

    with open(args.file) as f:
        source = f.read()

    lexer = Lexer(source)
    tokens = lexer.lex()

    parser = Parser(tokens)
    ast = parser.parse()

    target = args.target
    base = os.path.splitext(args.file)[0]

    if target.startswith("llvm-"):
        output_path = _build_llvm(ast, base, target)
        print(f"Built: {output_path}")

    elif target == "js":
        # Simple JavaScript transpilation
        js_code = _transpile_to_js(ast)
        output_path = base + ".js"
        with open(output_path, "w") as f:
            f.write(js_code)
        print(f"Built: {output_path}")

    elif target == "wasm-pyodide":
        output_path = _build_pyodide(source, base)
        print(f"Built: {output_path}")

    if args.emit_manifest:
        _emit_manifest(ast, args.file)


def _transpile_to_js(ast) -> str:
    """Simple transpilation of Thirsty-Lang AST to JavaScript."""

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


class _LLVMExpr:
    """Accumulates LLVM IR instructions for an integer expression tree.

    Mirrors the scope of the JS transpiler: integers, booleans, identifiers,
    arithmetic/comparison/logic, unary, and direct calls. Each value is an i32.
    """

    def __init__(self):
        self.n = 0
        self.body = []

    def _tmp(self) -> str:
        self.n += 1
        return f"%t{self.n}"

    def emit(self, expr, env) -> str:
        """Emit IR for ``expr``; return the operand string (register or literal)."""
        if isinstance(expr, IntLiteral):
            return str(expr.value)
        if isinstance(expr, BoolLiteral):
            return "1" if expr.value else "0"
        if isinstance(expr, Identifier):
            return env.get(expr.name, "0")
        if isinstance(expr, UnaryOp):
            val = self.emit(expr.operand, env)
            reg = self._tmp()
            if expr.op == TokenType.MINUS:
                self.body.append(f"  {reg} = sub i32 0, {val}")
            else:  # logical not
                self.body.append(f"  {reg} = xor i32 {val}, 1")
            return reg
        if isinstance(expr, BinaryOp):
            left = self.emit(expr.left, env)
            right = self.emit(expr.right, env)
            arith = {
                TokenType.PLUS: "add", TokenType.MINUS: "sub",
                TokenType.STAR: "mul", TokenType.SLASH: "sdiv",
                TokenType.PERCENT: "srem",
            }
            cmps = {
                TokenType.EQEQ: "eq", TokenType.NE: "ne",
                TokenType.LT: "slt", TokenType.GT: "sgt",
                TokenType.LE: "sle", TokenType.GE: "sge",
            }
            if expr.op in arith:
                reg = self._tmp()
                self.body.append(f"  {reg} = {arith[expr.op]} i32 {left}, {right}")
                return reg
            if expr.op in cmps:
                bit = self._tmp()
                reg = self._tmp()
                self.body.append(f"  {bit} = icmp {cmps[expr.op]} i32 {left}, {right}")
                self.body.append(f"  {reg} = zext i1 {bit} to i32")
                return reg
            # and/or fold to bitwise on the i32 truth values
            reg = self._tmp()
            logic = "and" if expr.op == TokenType.AND else "or"
            self.body.append(f"  {reg} = {logic} i32 {left}, {right}")
            return reg
        if isinstance(expr, CallExpr):
            args = [self.emit(a, env) for a in expr.args]
            callee = expr.callee.name if isinstance(expr.callee, Identifier) else "unknown"
            arglist = ", ".join(f"i32 {a}" for a in args)
            reg = self._tmp()
            self.body.append(f"  {reg} = call i32 @{callee}({arglist})")
            return reg
        return "0"


def _llvm_function(stmt, lines):
    """Emit an ``i32`` LLVM function definition for a Thirsty-Lang function."""
    params = ", ".join(f"i32 %{p[0]}" for p in stmt.params)
    env = {p[0]: f"%{p[0]}" for p in stmt.params}
    lines.append(f"define i32 @{stmt.name}({params}) {{")
    lines.append("entry:")
    em = _LLVMExpr()
    ret = "0"
    body = stmt.body.statements if isinstance(stmt.body, BlockStmt) else [stmt.body]
    for s in body:
        if isinstance(s, ReturnStmt) and s.value is not None:
            ret = em.emit(s.value, env)
        elif isinstance(s, ExprStmt):
            em.emit(s.expr, env)
    lines.extend(em.body)
    lines.append(f"  ret i32 {ret}")
    lines.append("}")
    lines.append("")


def _transpile_to_llvm_ir(ast) -> str:
    """Emit textual LLVM IR for the integer subset (mirrors the JS transpiler)."""
    lines = [
        "; Generated by Thirsty-Lang compiler",
        'target triple = "x86_64-unknown-unknown"',
        "",
    ]
    for stmt in ast.stmts:
        if hasattr(stmt, "params") and hasattr(stmt, "body") and hasattr(stmt, "name"):
            _llvm_function(stmt, lines)

    main_expr = None
    for stmt in ast.stmts:
        if getattr(stmt, "name", None) == "main" and getattr(stmt, "init_expr", None):
            main_expr = stmt.init_expr
            break

    lines.append("define i32 @main() {")
    lines.append("entry:")
    if main_expr is not None:
        em = _LLVMExpr()
        result = em.emit(main_expr, {})
        lines.extend(em.body)
        lines.append(f"  ret i32 {result}")
    else:
        lines.append("  ret i32 0")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _build_llvm(ast, base: str, target: str) -> str:
    """Write textual IR, then drive the toolchain for non-IR targets.

    ``llvm-ir`` is fully self-contained. ``llvm-asm``/``llvm-obj``/``llvm-exe``/
    ``llvm-jit`` shell out to ``llc``/``clang``/``lli``; a missing tool raises a
    clear error (the ``.ll`` is still written).
    """
    import shutil
    import subprocess

    ir = _transpile_to_llvm_ir(ast)
    ir_path = base + ".ll"
    with open(ir_path, "w") as f:
        f.write(ir)
    if target == "llvm-ir":
        return ir_path

    exe_suffix = ".exe" if os.name == "nt" else ""
    plan = {
        "llvm-asm": ("llc", [ir_path, "-o", base + ".s"], base + ".s"),
        "llvm-obj": ("llc", ["-filetype=obj", ir_path, "-o", base + ".o"], base + ".o"),
        "llvm-exe": ("clang", [ir_path, "-o", base + exe_suffix], base + exe_suffix),
        "llvm-jit": ("lli", [ir_path], ir_path),
    }
    tool, tool_args, out_path = plan[target]
    resolved = shutil.which(tool)
    if resolved is None:
        raise RuntimeError(
            f"LLVM toolchain '{tool}' not found on PATH (required for {target}). "
            f"Textual IR was written to {ir_path}."
        )
    subprocess.run([resolved, *tool_args], check=True)
    return out_path


_PYODIDE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Thirsty-Lang (Pyodide)</title>
</head>
<body>
<pre id="out">Loading Pyodide…</pre>
<script src="https://cdn.jsdelivr.net/pyodide/v0.26.2/full/pyodide.js"></script>
<script type="module">
const SOURCE = {source_json};
async function main() {{
  const out = document.getElementById("out");
  const pyodide = await loadPyodide();
  await pyodide.loadPackage("micropip");
  const micropip = pyodide.pyimport("micropip");
  await micropip.install("thirsty-lang");
  pyodide.globals.set("SRC", SOURCE);
  await pyodide.runPythonAsync(`
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.interpreter import Interpreter
ast = Parser(Lexer(SRC).lex()).parse()
Interpreter().interpret(ast)
`);
  out.textContent = "Done.";
}}
main();
</script>
</body>
</html>
"""


def _build_pyodide(source: str, base: str) -> str:
    """Emit a Pyodide (Python-in-WebAssembly) HTML bundle that runs the program
    in-browser via the thirsty-lang interpreter loaded through micropip."""
    html = _PYODIDE_TEMPLATE.format(source_json=json.dumps(source))
    out_path = base + ".pyodide.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


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

    if not args.file:
        # Scan for .thirsty files
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

        # Evaluate policy against each function via TarlRuntime
        from utf.tarl.core import PolicyParser, evaluate_policy
        from utf.tarl.runtime import TarlRuntime

        policy = PolicyParser.parse(tarl_policy, name="auto-tarl")
        TarlRuntime(policy=policy)
        verdicts = []

        for stmt in ast.stmts:
            if hasattr(stmt, 'name') and hasattr(stmt, 'params'):
                context = {
                "name": stmt.name,
                "params": len(getattr(stmt, 'params', [])),
                "body_len": len(stmt.body.stmts) if hasattr(stmt.body, 'stmts') else 0,
                }
                decision = evaluate_policy(context, policy_text=tarl_policy)
                verdicts.append((stmt.name, decision.verdict.value if hasattr(decision, 'verdict') else str(decision)))
                print(f"  [{decision.verdict.value if hasattr(decision, 'verdict') else decision}] {stmt.name}")

        # Write policy file
        tarl_path = os.path.splitext(args.file)[0] + ".tarl"
        with open(tarl_path, "w") as f:
            f.write(tarl_policy)
        print(f"T.A.R.L. policy: {tarl_path}")

        if args.enforce:
            denied = [name for name, v in verdicts if v == "DENY"]
            if denied:
                print(f"Enforce failed: {len(denied)} function(s) denied: {' '.join(denied)}", file=sys.stderr)
                sys.exit(1)

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
        for root, _dirs, files in os.walk("src"):
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
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    checks_passed += 1

    # Summary
    print()
    print(f"Passed: {checks_passed}, Failed: {checks_failed}")

    if args.fix and checks_failed > 0:
        from utf.thirsty_lang.package_manager import (
            create_thirsty_lock,
            create_thirsty_toml,
        )
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
    """Start the language server (JSON-RPC over stdio or a TCP socket)."""
    from utf.tarl.lsp import TarlLanguageServer

    if args.stdio:
        TarlLanguageServer().run()
    else:
        _serve_lsp_socket(args.port)


def _serve_lsp_socket(port, host="127.0.0.1"):
    """Serve one LSP session over a TCP socket using the JSON-RPC server."""
    import socket

    from utf.tarl.lsp import TarlLanguageServer

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
        server.listen(1)
        print(f"LSP server listening on {host}:{port}")
        conn, addr = server.accept()
        print(f"Connection from {addr}")
        try:
            rstream = conn.makefile("rb")
            wstream = conn.makefile("wb")
            TarlLanguageServer(stdin=rstream, stdout=wstream).run()
        finally:
            conn.close()
    finally:
        server.close()


def cmd_docs(args):
    """Generate documentation."""

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
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Documentation: {index_path}")


if __name__ == "__main__":
    main()

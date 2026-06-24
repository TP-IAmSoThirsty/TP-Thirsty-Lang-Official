"""Broad parser coverage: every declaration, statement, and expression form."""
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def parse(src):
    p = Parser(Lexer(src).lex())
    ast = p.parse()
    return ast, p.errors


def ok(src):
    ast, errors = parse(f"module m: core\n{src}")
    assert not errors, f"unexpected parse errors: {errors}"
    return ast


def test_enum():
    ok("enum Color { Red, Green, Blue }")


def test_struct():
    ok("struct Point { x: int\n y: int }")


def test_interface():
    ok("interface Shape { area() -> int\n name() }")


def test_morph():
    ok("morph toInt(x: str) { return 0 }")


def test_defend():
    # defend actions are expressions, not statements.
    ok("defend guard(mypolicy) { alpha\n beta }")


def test_security_shield():
    ok("shield { drink x = 1 }")


def test_security_detect():
    ok("detect { drink y = 2 }")


def test_sanitize_armor():
    ok("drink a = sanitize(x)")
    ok("drink b = armor(y)")


def test_spillage_with_handlers():
    ok("spillage { drink x = 1 } error { drink y = 2 }")


def test_cleanup_finally():
    ok("cleanup { drink x = 1 } finally { drink y = 2 }")


def test_throw():
    ok("glass f() { throw 5 }")


def test_cascade():
    ok("glass f() { cascade g() }")


def test_new_expr():
    ok("fountain P { x: int }\ndrink obj = new P(1)")


def test_class_with_fields_and_methods():
    ok("fountain Counter {\n count: int\n glass inc() { return 1 }\n }")


def test_function_return_type():
    ok("glass add(a: int, b: int) -> int { return a + b }")


def test_governed_all_clauses():
    ok("glass w(a: int) -> int requires a > 0 ensures result > 0 "
       "invariant a < 100 { return a }")


def test_while_loop():
    ok("drink mut x = 0\nrefill (x < 3) { x = x + 1 }")


def test_guard_expr():
    ok("drink g = thirst a quench b")


def test_import_with_alias():
    ok('import "thirst::time" as t')


def test_arrays_and_member_access():
    ok("drink arr = [1, 2, 3]\ndrink m = arr.length")


def test_unary_and_binary_precedence():
    ok("drink v = -a + b * c - d / e % f")
    ok("drink w = not a and b or c")


def test_parse_error_recovery():
    # A malformed function still records errors without crashing.
    _ast, errors = parse("module m: core\nglass f( {")
    assert errors

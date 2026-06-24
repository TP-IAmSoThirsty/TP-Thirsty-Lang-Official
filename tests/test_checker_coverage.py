"""Broad checker/semantic-analysis coverage."""
from utf.thirsty_lang.checker import check_ast
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def check(src, mode="core"):
    ast = Parser(Lexer(f"module m: {mode}\n{src}").lex()).parse()
    return [e.code for e in check_ast(ast)]


# Run every declaration/statement form through the checker (covers the
# _check_stmt dispatch and per-construct check methods).
ALL_FORMS = """
enum Color { Red, Green, Blue }
struct Point { x: int\n y: int }
interface Shape { area() -> int }
morph toInt(x) { return 0 }
defend guard(pol) { alpha }
shield { drink s = 1 }
detect { drink d = 2 }
fountain Counter {
  count: int
  glass bump() { return 1 }
}
glass add(a, b) { return a + b }
glass w(a) requires a > 0 ensures result > 0 invariant a < 100 { return a }
drink xs = [1, 2, 3]
drink mut total = 0
refill (n in xs) { total = total + n }
refill (total < 100) { total = total + 1 }
thirsty (total > 0) { drink ok = 1 } hydrated { drink no = 1 }
spillage { drink a = 1 } error { drink b = 1 }
cleanup { drink a = 1 } finally { drink b = 1 }
drink obj = new Counter()
drink m = obj.count
drink san = sanitize(total)
drink arm = armor(total)
"""


def test_all_forms_check_runs():
    # Should complete without throwing; some diagnostics are acceptable.
    codes = check(ALL_FORMS)
    assert isinstance(codes, list)


def test_duplicate_variable():
    assert "E010" in check("drink x = 1\ndrink x = 2")


def test_duplicate_function():
    assert "E010" in check("glass f() { return 1 }\nglass f() { return 2 }")


def test_unknown_identifier():
    assert "E011" in check("drink y = undefined_thing")


def test_assign_immutable():
    assert "E020" in check("drink x = 1\nx = 2")


def test_type_mismatch_decl():
    assert "E021" in check("drink x: Bool = 5")


def test_governed_call_from_core():
    src = ("glass g(a) requires a > 0 { return a }\n"
           "drink r = g(1)")
    assert "E053" in check(src, mode="core")


def test_governed_call_allowed_in_governed():
    src = ("glass g(a) requires a > 0 { return a }\n"
           "drink r = g(1)")
    assert "E053" not in check(src, mode="governed")


def test_unknown_identifier_suggestion():
    # An identifier close to a known name exercises the edit-distance path.
    codes = check("drink total = 1\ndrink y = totl")
    assert "E011" in codes


def test_expressions_check():
    # Member access, calls, binary/unary, guards, pipelines, literals.
    src = ("glass f(a) { return a }\n"
           "drink v = f(1) + -2 * 3\n"
           "drink b = not true and false\n"
           "drink g = thirst v quench b\n"
           "drink arr = [1, 2]\n"
           "drink first = get(arr, 0)")
    assert isinstance(check(src), list)

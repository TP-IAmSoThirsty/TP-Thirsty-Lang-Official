"""Tests for the new language features added in 0.8.0:

* the ``times N { ... }`` repeat loop,
* the C-style ``refill(init; cond; step) { ... }`` for loop, and
* anonymous function expressions (lambdas): ``glass(params) { ... }``.
"""
from utf.thirsty_lang.checker import check_ast
from utf.thirsty_lang.formatter import format_stmt
from utf.thirsty_lang.interpreter import Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def _parse(src):
    parser = Parser(Lexer(src).lex())
    ast = parser.parse()
    assert not parser.errors, parser.errors
    return ast


def _check(src):
    return [e.code for e in check_ast(_parse(src))]


def _run(src, capsys):
    Interpreter().interpret(_parse(src))
    return capsys.readouterr().out.strip()


# --- times loop -----------------------------------------------------------

def test_times_basic(capsys):
    src = ("module m: core\n"
           "drink mut n = 0\n"
           "times 3 { n = n + 1 }\n"
           "pour n")
    assert _check(src) == []
    assert _run(src, capsys) == "3"


def test_times_zero_runs_body_never(capsys):
    src = ("module m: core\n"
           "drink mut n = 0\n"
           "times 0 { n = n + 1 }\n"
           "pour n")
    assert _run(src, capsys) == "0"


def test_times_count_from_expression(capsys):
    src = ("module m: core\n"
           "drink k = 2\n"
           "drink mut n = 0\n"
           "times k + 1 { n = n + 1 }\n"
           "pour n")
    assert _run(src, capsys) == "3"


# --- C-style refill -------------------------------------------------------

def test_cstyle_for_drink_init(capsys):
    src = ("module m: core\n"
           "drink mut sum = 0\n"
           "refill (drink i = 0; i < 5; i = i + 1) { sum = sum + i }\n"
           "pour sum")
    assert _check(src) == []
    assert _run(src, capsys) == "10"  # 0+1+2+3+4


def test_cstyle_for_counter_is_implicitly_mutable(capsys):
    # No `mut` keyword needed on the loop init.
    src = ("module m: core\n"
           "refill (drink x = 0; x < 3; x = x + 1) { pour x }")
    assert _run(src, capsys) == "0\n1\n2"


def test_cstyle_for_expression_init(capsys):
    src = ("module m: core\n"
           "drink mut i = 0\n"
           "drink mut sum = 0\n"
           "refill (i = 0; i < 4; i = i + 1) { sum = sum + i }\n"
           "pour sum")
    assert _run(src, capsys) == "6"  # 0+1+2+3


def test_while_and_foreach_refill_still_work(capsys):
    src = ("module m: core\n"
           "drink mut i = 0\n"
           "refill (i < 3) { i = i + 1 }\n"
           "pour i\n"
           "refill (x in [10, 20]) { pour x }")
    assert _run(src, capsys) == "3\n10\n20"


# --- lambdas --------------------------------------------------------------

def test_lambda_assigned_and_called(capsys):
    src = ("module m: core\n"
           "drink add = glass(a, b) { return a + b }\n"
           "pour add(3, 4)")
    assert _check(src) == []
    assert _run(src, capsys) == "7"


def test_lambda_as_higher_order_argument(capsys):
    src = ("module m: core\n"
           "import \"thirst::collections\" as col\n"
           "pour col.map(glass(n) { return n * 2 }, [1, 2, 3])")
    assert _run(src, capsys) == "[2, 4, 6]"


def test_lambda_closes_over_scope(capsys):
    src = ("module m: core\n"
           "glass make_mul(factor) {\n"
           "    return glass(n) { return n * factor }\n"
           "}\n"
           "drink triple = make_mul(3)\n"
           "pour triple(5)")
    assert _run(src, capsys) == "15"


# --- formatter round-trips ------------------------------------------------

def test_format_times_and_lambda():
    times_ast = _parse("module m: core\ntimes 3 { pour 1 }")
    times_stmt = times_ast.stmts[-1]
    assert "times 3 {" in format_stmt(times_stmt)

    lam_ast = _parse("module m: core\ndrink f = glass(x) { return x }")
    decl = lam_ast.stmts[-1]
    assert "glass(x)" in format_stmt(decl)

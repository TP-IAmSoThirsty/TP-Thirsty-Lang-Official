"""Regression tests for the 0.8.1 peer-review fixes.

F1 — subscript indexing (`xs[i]`) reads, bounds-checks, and assigns instead of
     silently misparsing.
F2 — un-annotated functions return Any (not Void), so their values flow into
     typed operators and self-recursion type-checks.
F3 — combine operators (`^`/`||`) require both operands bool, never coerce a
     mixed bool/non-bool (was a governance fail-open), and never silently drop
     an operand.
"""
import pytest

from utf.thirsty_lang.checker import check_ast
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def _parse(src):
    parser = Parser(Lexer(src).lex())
    ast = parser.parse()
    assert not parser.errors, parser.errors
    return ast


def _check(src):
    return [e.code for e in check_ast(_parse(src))]


def _run(src, capsys, mode="core"):
    Interpreter().interpret(_parse(src), mode=mode)
    return capsys.readouterr().out.strip()


# ── F1: subscript indexing ───────────────────────────────────────────────

def test_subscript_reads_element(capsys):
    src = "module p: core\ndrink xs = [10, 20, 30]\ndrink y = xs[1]\npour y"
    assert _check(src) == []
    assert _run(src, capsys) == "20"


def test_subscript_negative_index(capsys):
    assert _run("module p: core\npour [1, 2, 3][-1]", capsys) == "3"


def test_subscript_out_of_bounds_errors(capsys):
    with pytest.raises(IndexError):
        _run("module p: core\npour [1, 2, 3][9]", capsys)


def test_subscript_assignment_mutates(capsys):
    src = ("module p: core\ndrink xs = [10, 20, 30]\n"
           "xs[0] = 99\npour xs")
    assert _run(src, capsys) == "[99, 20, 30]"


def test_subscript_string_char(capsys):
    assert _run('module p: core\npour "thirsty"[0]', capsys) == "t"


def test_subscript_does_not_misparse(capsys):
    # The whole-list misparse bug bound y to the entire reservoir.
    src = "module p: core\ndrink xs = [10, 20, 30]\ndrink y = xs[2]\npour y"
    assert _run(src, capsys) == "30"


# ── F2: un-annotated return type is Any, not Void ─────────────────────────

def test_unannotated_value_used_arithmetically(capsys):
    src = ("module f: core\n"
           "glass helper(x: Int) { return x * 2 }\n"
           "glass main_calc(n: Int) { return helper(n) + 1 }\n"
           "pour main_calc(5)")
    assert "E022" not in _check(src)
    assert _run(src, capsys) == "11"


def test_unannotated_recursion(capsys):
    src = ("module f: core\n"
           "glass fact(n: Int) {\n"
           "    thirsty (n <= 1) { return 1 }\n"
           "    return n * fact(n - 1)\n"
           "}\n"
           "pour fact(5)")
    assert "E022" not in _check(src)
    assert _run(src, capsys) == "120"


# ── F3: combine operator soundness ────────────────────────────────────────

def test_combine_both_bool_truth_tables(capsys):
    src = ("module p: core\n"
           "pour true ^ false\n"      # AND -> False
           "pour true || false")      # OR  -> True
    assert _run(src, capsys) == "False\nTrue"


def test_combine_bool_with_nonbool_is_static_error():
    # bool ^ known-non-bool is a malformed predicate; the checker rejects it.
    assert "E022" in _check("module p: core\ndrink z = true ^ 5")


def test_combine_nonbool_raises_not_silent_drop(capsys):
    # `3 ^ 4` previously returned 4 (silent left-drop); now it errors.
    with pytest.raises(TypeError):
        _run("module p: core\npour 3 ^ 4", capsys)


def test_combine_dict_merge_and_list_concat_still_work(capsys):
    # Structured composition is unchanged.
    out = _run("module p: core\npour [1, 2] ^ [3, 4]", capsys)
    assert out == "[1, 2, 3, 4]"


def test_malformed_combine_predicate_fails_closed():
    # A `requires` whose combine mixes bool and non-bool must DENY, never
    # silently authorize (the original fail-open). Method contracts are
    # design-by-contract and enforced in core mode.
    src = ("module m: core\n"
           "fountain Gate {\n"
           "    glass bad(self, x) requires (x > 0) ^ x { return x }\n"
           "}\n"
           "drink g = new Gate()\n"
           "drink r = g.bad(50)")
    with pytest.raises(GovernanceViolation):
        Interpreter().interpret(_parse(src), mode="core")


def test_wellformed_combine_predicate_passes(capsys):
    # Positive control: a valid bool ^ bool predicate authorizes the call.
    src = ("module m: core\n"
           "fountain Gate {\n"
           "    glass ok(self, x) requires (x > 0) ^ (x < 100) { return x }\n"
           "}\n"
           "drink g = new Gate()\n"
           "pour g.ok(50)")
    assert _run(src, capsys) == "50"

"""
Regression tests for operator precedence and associativity.

These lock in the fix for the parser bug where the precedence table was dead
code: ``_get_precedence()`` was read *after* the operator was consumed, so it
saw the right operand (precedence 0) and every binary operator collapsed to one
right-associative level. The fatal consequence was that governed
``requires``/``ensures``/``invariant`` predicates did not mean what the author
wrote, so deny-by-default guards failed open (``balance - amount >= 0`` parsed
as ``balance - (amount >= 0)``).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def _eval(expr):
    """Evaluate a single Thirsty-Lang expression to a Python value."""
    interp = Interpreter()
    interp.interpret(Parser(Lexer(f"drink r = {expr}").lex()).parse())
    return interp.env.get("r")


# The exact rows from the audit reproduction — these were all WRONG before.
@pytest.mark.parametrize("expr,expected", [
    ("2 * 3 + 4", 10),       # was 14  (2 * (3 + 4))
    ("10 - 2 - 3", 5),       # was 11  (10 - (2 - 3))   left-assoc
    ("20 / 2 / 5", 2),       # was 50  (20 / (2 / 5))   left-assoc
    ("1 + 2 * 3 + 4", 11),   # was 15
    ("2 + 3 == 5", True),    # was 2   (== folded into the chain)
])
def test_audit_precedence_rows(expr, expected):
    assert _eval(expr) == expected


@pytest.mark.parametrize("expr,expected", [
    # multiplicative binds tighter than additive
    ("10 - 2 * 3", 4),
    ("1 + 2 * 3 - 4 / 2", 5),
    # comparison binds looser than arithmetic
    ("1 + 2 < 4", True),
    ("100 - 200 >= 0", False),   # the overdraft predicate, as written
    ("2 * 3 == 6", True),
    # logical binds loosest; and tighter than or
    ("1 < 2 and 3 < 4", True),
    ("1 < 2 and 3 > 4", False),
    ("1 > 2 or 3 < 4", True),
])
def test_mixed_precedence(expr, expected):
    assert _eval(expr) == expected


@pytest.mark.parametrize("expr,expected", [
    # unary minus binds tighter than every binary operator
    ("-2 + 3", 1),
    ("-2 * 3", -6),
    # logical not binds looser than comparison, tighter than and/or
    ("not 2 == 3", True),
    ("not 2 == 2", False),
    ("not 1 > 2 and 2 > 1", True),
])
def test_unary_binding(expr, expected):
    assert _eval(expr) == expected


def _run_governed(src):
    interp = Interpreter()
    interp.interpret(Parser(Lexer(src).lex()).parse(), mode="governed")
    return interp


_WITHDRAW = (
    "module bank: governed\n"
    "glass withdraw(balance, amount) requires balance - amount >= 0 "
    "{ return balance - amount }\n"
)


def test_overdraft_guard_denies():
    # The guard must now fail closed: 100 - 200 >= 0 is False → DENY.
    with pytest.raises(GovernanceViolation):
        _run_governed(_WITHDRAW + "drink r = withdraw(100, 200)\n")


def test_valid_withdraw_allows():
    interp = _run_governed(_WITHDRAW + "drink r = withdraw(100, 50)\n")
    assert interp.env.get("r") == 50

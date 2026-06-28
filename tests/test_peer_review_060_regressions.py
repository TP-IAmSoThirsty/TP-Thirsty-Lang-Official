import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.thirsty_lang.checker import check_ast
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def _program(src):
    return Parser(Lexer(src).lex()).parse()


def _eval(expr):
    interp = Interpreter()
    interp.interpret(_program(f"drink r = {expr}\nr"))
    return interp.env.get("r")


def _policy(text='policy p\nwhen action == "moveFunds" => ALLOW\nwhen true => DENY\n'):
    return TarlRuntime(PolicyParser.parse(text))


@pytest.mark.parametrize("expr,expected", [
    ("true || false", True),
    ("false ^ true", False),
    ("true ^ false", False),
    ("false || false", False),
])
def test_boolean_combine_uses_truth_table(expr, expected):
    assert _eval(expr) is expected


def test_symbol_statement_consumes_semicolon_and_registers_symbol():
    src = """module m: core
symbol Foo;
drink observed = Foo
"""
    interp = Interpreter()
    interp.interpret(_program(src))
    assert interp.env.get("Foo") == "Foo"
    assert interp.env.get("observed") == "Foo"


def test_governed_function_without_policy_denies_with_proof():
    src = """module m: governed
glass moveFunds(amt) requires amt > 0 { return amt }
drink z = moveFunds(1000000)
"""
    with pytest.raises(GovernanceViolation) as exc:
        Interpreter().interpret(_program(src))
    assert "policy engine and authority" in exc.value.reason
    assert exc.value.proof is not None
    assert exc.value.proof.verdict == TarlVerdict.DENY


def test_governed_function_with_policy_allows_contract_success():
    src = """module m: governed
glass moveFunds(amt) requires amt > 0 { return amt }
drink z = moveFunds(10)
"""
    interp = Interpreter()
    interp.attach_tarl(_policy())
    interp.set_authority("admin")
    interp.interpret(_program(src))
    assert interp.env.get("z") == 10


def test_assignment_in_call_argument_is_checker_error():
    src = """drink mut x = 0
glass id(v) { return v }
drink y = id(x = 7)
"""
    errors = check_ast(_program(src))
    assert any("Assignment cannot be used as an expression" in e.message
               for e in errors)


def test_assignment_in_call_argument_rejected_at_runtime():
    src = """drink mut x = 0
glass id(v) { return v }
drink y = id(x = 7)
"""
    with pytest.raises(RuntimeError, match="assignment cannot be used"):
        Interpreter().interpret(_program(src))

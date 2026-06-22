"""
Tests for real runtime governance enforcement in Thirsty-Lang.

Covers the layered, default-deny policy wired into the interpreter:
  1. In-language `requires` preconditions (allow on truthy, deny on falsy)
  2. Cross-mode guard (governed function denied when not in governed mode)
  3. Optional TARL policy routing (ALLOW permits, non-ALLOW denies + proof)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.ast import GovernedFunctionDecl
from utf.thirsty_lang.interpreter import Interpreter, GovernanceViolation


def _load(src, mode=None):
    """Parse + interpret a program, returning the interpreter."""
    prog = Parser(Lexer(src).lex()).parse()
    interp = Interpreter()
    if mode is None:
        interp.interpret(prog)          # header decides mode
    else:
        interp.interpret(prog, mode=mode)
    return interp


GOVERNED_SRC = """module bank: governed
glass withdraw(amt) requires amt > 0 {
    return amt * 2
}
"""

CORE_SRC = """module bank: core
glass withdraw(amt) requires amt > 0 {
    return amt * 2
}
"""


class TestParsing:
    def test_requires_produces_governed_decl(self):
        prog = Parser(Lexer(GOVERNED_SRC).lex()).parse()
        decls = [s for s in prog.stmts if isinstance(s, GovernedFunctionDecl)]
        assert len(decls) == 1
        assert decls[0].name == "withdraw"
        assert decls[0].requires_annotation == "amt > 0"
        assert decls[0].requires_expr is not None

    def test_plain_function_is_not_governed(self):
        src = "module m: core\nglass plain(x) { return x }\n"
        prog = Parser(Lexer(src).lex()).parse()
        assert not any(isinstance(s, GovernedFunctionDecl) for s in prog.stmts)


class TestPrecondition:
    def test_precondition_satisfied_runs(self):
        interp = _load(GOVERNED_SRC)
        assert interp.env.get("withdraw")(5) == 10

    def test_precondition_violation_denies(self):
        interp = _load(GOVERNED_SRC)
        with pytest.raises(GovernanceViolation) as exc:
            interp.env.get("withdraw")(-1)
        assert "precondition failed" in exc.value.reason
        assert exc.value.name == "withdraw"


class TestCrossModeGuard:
    def test_governed_call_from_core_mode_denied(self):
        interp = _load(CORE_SRC)            # header is core
        with pytest.raises(GovernanceViolation) as exc:
            interp.env.get("withdraw")(5)
        assert "governed mode" in exc.value.reason

    def test_governance_not_swallowed_by_spillage(self):
        # A governance denial inside a spillage block must propagate, not be
        # caught by user error handlers.
        src = """module bank: core
glass guarded(x) requires x > 0 {
    return x
}
glass attempt() {
    spillage {
        return guarded(1)
    } cleanup {
        return -999
    }
}
"""
        interp = _load(src)
        with pytest.raises(GovernanceViolation):
            interp.env.get("attempt")()


class TestTarlRouting:
    def _runtime(self, policy_text):
        from utf.tarl.core import PolicyParser
        from utf.tarl.runtime import TarlRuntime
        return TarlRuntime(PolicyParser.parse(policy_text))

    def test_allow_policy_permits_and_records_proof(self):
        prog = Parser(Lexer(GOVERNED_SRC).lex()).parse()
        interp = Interpreter()
        interp.attach_tarl(self._runtime(
            'policy p\nwhen authority == "admin" => ALLOW\n'))
        interp.set_authority("admin")
        interp.interpret(prog)
        assert interp.env.get("withdraw")(5) == 10
        assert interp._last_proof is not None
        assert str(interp._last_proof.verdict) == "ALLOW"

    def test_deny_policy_blocks_with_proof(self):
        prog = Parser(Lexer(GOVERNED_SRC).lex()).parse()
        interp = Interpreter()
        interp.attach_tarl(self._runtime(
            'policy p\nwhen authority == "admin" => DENY\n'))
        interp.set_authority("admin")
        interp.interpret(prog)
        with pytest.raises(GovernanceViolation) as exc:
            interp.env.get("withdraw")(5)
        assert exc.value.proof is not None

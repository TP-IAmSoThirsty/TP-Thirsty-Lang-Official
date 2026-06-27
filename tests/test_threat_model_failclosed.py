"""Fail-closed-under-failure tests (THREAT_MODEL C037-C038).

Resource exhaustion / evaluator errors must DENY, never fail open (C037), and
execution must fail closed when a required audit record cannot be persisted
(C038).
"""
import pytest

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser

ALLOW_WRITE = (
    'policy p\n'
    'when action == "write" => ALLOW\n'
    'when true => DENY\n'
)


class _ExplodingArchive:
    """Stands in for an audit sink under DoS / disk-full."""

    def store(self, *_args, **_kwargs):
        raise OSError("audit sink unavailable")


class _ExplodingRuntime(TarlRuntime):
    """A runtime whose evaluation raises, simulating resource exhaustion."""

    def evaluate_with_proof(self, *_args, **_kwargs):
        raise MemoryError("evaluation exhausted resources")


# ── C037: evaluator errors fail closed (DENY, not ALLOW) ──────────────────────

def test_rule_evaluation_exception_does_not_match_and_falls_to_default_deny():
    # A source provider that raises must not cause its rule to match.
    rt = TarlRuntime(PolicyParser.parse(
        'policy p\nwhen source:boom => ALLOW\nwhen true => DENY\n'
    ))
    rt.register_source("boom", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    assert rt.evaluate({"action": "write"}).verdict == TarlVerdict.DENY


def test_gate_converts_evaluation_error_into_fail_closed_denial(capsys):
    interp = Interpreter()
    interp.attach_tarl(_ExplodingRuntime(PolicyParser.parse(ALLOW_WRITE)))
    interp.set_authority("admin")
    ast = Parser(Lexer('module m: governed\npour "x"\n').lex()).parse()
    with pytest.raises(GovernanceViolation) as exc:
        interp.interpret(ast)
    assert exc.value.proof.verdict == TarlVerdict.DENY
    assert "x" not in capsys.readouterr().out


def test_evaluation_error_denial_is_not_swallowed_by_spillage(capsys):
    # The fail-closed denial must propagate through a spillage handler.
    src = (
        "module m: governed\n"
        "spillage {\n"
        '    pour "x"\n'
        "} catch {\n"
        '    pour "handled"\n'
        "}\n"
    )
    interp = Interpreter()
    interp.attach_tarl(_ExplodingRuntime(PolicyParser.parse(ALLOW_WRITE)))
    interp.set_authority("admin")
    ast = Parser(Lexer(src).lex()).parse()
    with pytest.raises(GovernanceViolation):
        interp.interpret(ast)
    out = capsys.readouterr().out
    assert "x" not in out and "handled" not in out


# ── C038: required audit that cannot persist fails closed ──────────────────────

def test_required_audit_persistence_failure_downgrades_to_deny():
    rt = TarlRuntime(PolicyParser.parse(ALLOW_WRITE))
    rt.set_archive(_ExplodingArchive())
    rt.set_require_audit(True)
    decision, proof = rt.evaluate_with_proof({"action": "write"})
    assert decision.verdict == TarlVerdict.DENY
    assert "audit" in decision.reason
    assert proof.verdict == TarlVerdict.DENY


def test_best_effort_audit_failure_does_not_change_verdict_by_default():
    # Without require_audit, a persistence failure is best-effort (compat).
    rt = TarlRuntime(PolicyParser.parse(ALLOW_WRITE))
    rt.set_archive(_ExplodingArchive())
    decision, _proof = rt.evaluate_with_proof({"action": "write"})
    assert decision.verdict == TarlVerdict.ALLOW


def test_required_audit_failure_denies_a_governed_capability(capsys):
    interp = Interpreter()
    rt = TarlRuntime(PolicyParser.parse(ALLOW_WRITE))
    rt.set_archive(_ExplodingArchive())
    rt.set_require_audit(True)
    interp.attach_tarl(rt)
    interp.set_authority("admin")
    ast = Parser(Lexer('module m: governed\npour "x"\n').lex()).parse()
    with pytest.raises(GovernanceViolation) as exc:
        interp.interpret(ast)
    assert exc.value.proof.verdict == TarlVerdict.DENY
    assert "x" not in capsys.readouterr().out

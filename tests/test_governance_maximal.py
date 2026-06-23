"""
Phase 1 — maximal governance:
  - ensures postconditions, invariants (entry + exit)
  - contracts on methods (design-by-contract, valid in any mode)
  - capability gates (imports, I/O) routed through TARL, with proofs
  - temporal policy windows governing a call
  - static parity: E053 (governed call from core), forward-reference hoisting
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.thirsty_lang.checker import check_ast
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def _prog(src):
    return Parser(Lexer(src).lex()).parse()


def _interp(src, policy_text=None, authority=None):
    it = Interpreter()
    if policy_text is not None:
        it.attach_tarl(TarlRuntime(PolicyParser.parse(policy_text)))
    if authority is not None:
        it.set_authority(authority)
    it.interpret(_prog(src))
    return it


def _diags(src):
    return [d.code for d in check_ast(_prog(src))]


# ── Contracts: ensures / invariant / methods ────────────────────────────────

class TestContracts:
    def test_ensures_pass(self):
        it = _interp(
            'module m: governed\n'
            'glass dbl(x) requires x > 0 ensures result == x * 2 '
            '{ return x * 2 }\n')
        assert it.env.get("dbl")(5) == 10

    def test_ensures_fail_denies(self):
        it = _interp(
            'module m: governed\n'
            'glass bad(x) ensures result > 100 { return x * 2 }\n')
        with pytest.raises(GovernanceViolation) as e:
            it.env.get("bad")(5)
        assert "postcondition" in e.value.reason

    def test_invariant_entry_and_exit(self):
        it = _interp(
            'module m: governed\n'
            'glass f(x) invariant x >= 0 { return x }\n')
        assert it.env.get("f")(3) == 3
        with pytest.raises(GovernanceViolation):
            it.env.get("f")(-1)

    def test_method_contract_any_mode(self):
        # Contracts on methods are design-by-contract: enforced even in core
        # mode (no cross-mode guard), via interpreted method dispatch.
        src = (
            'module m: core\n'
            'fountain Acc {\n'
            '    total: Int\n'
            '    glass init(self) { self.total = 0 }\n'
            '    glass add(self, n) requires n > 0 '
            '{ self.total = self.total + n\n        return self.total }\n'
            '}\n'
            'drink a = new Acc()\n')
        ok = Interpreter()
        ok.interpret(_prog(src + 'drink r = a.add(4)\nreturn r'))
        assert ok.env.get("r") == 4

        bad = Interpreter()
        with pytest.raises(GovernanceViolation) as e:
            bad.interpret(_prog(src + 'drink r = a.add(-1)\nreturn r'))
        assert "precondition" in e.value.reason


# ── Capability gates ────────────────────────────────────────────────────────

class TestCapabilityGates:
    def test_write_allowed(self):
        # pour (write) permitted by policy → runs without denial.
        _interp(
            'module m: governed\nglass g(){ pour "hi" }\ndrink _ = g()\n',
            policy_text='policy p\nwhen action == "write" => ALLOW\n',
            authority='admin')

    def test_write_denied_with_proof(self):
        with pytest.raises(GovernanceViolation) as e:
            _interp(
                'module m: governed\nglass g(){ pour "hi" }\ndrink _ = g()\n',
                policy_text='policy p\nwhen action == "read" => ALLOW\n',
                authority='admin')
        assert e.value.proof is not None

    def test_import_denied_before_resolve(self):
        # The gate fires before the import resolves, so a denied import never
        # touches the module loader.
        with pytest.raises(GovernanceViolation):
            _interp(
                "module m: governed\nimport 'thirst::crypto' as crypto\n",
                policy_text='policy p\nwhen action == "read" => ALLOW\n',
                authority='admin')

    def test_gate_inactive_without_policy(self):
        # No policy attached → capability gates are inert; pour runs.
        _interp('module m: governed\nglass g(){ pour "hi" }\ndrink _ = g()\n')


# ── Temporal windows ────────────────────────────────────────────────────────

class TestTemporal:
    def test_expired_window_denies(self):
        with pytest.raises(GovernanceViolation):
            _interp(
                'module m: governed\nglass g(){ pour "hi" }\ndrink _ = g()\n',
                policy_text=('policy p:\n  valid_until: 2026-01-01\n'
                             '  when action == "write" => ALLOW\n'),
                authority='admin')

    def test_active_window_allows(self):
        _interp(
            'module m: governed\nglass g(){ pour "hi" }\ndrink _ = g()\n',
            policy_text=('policy p:\n  valid_until: 2030-12-31\n'
                         '  when action == "write" => ALLOW\n'),
            authority='admin')


# ── Static parity ───────────────────────────────────────────────────────────

class TestStatic:
    def test_e053_governed_call_from_core(self):
        codes = _diags(
            'module m: core\n'
            'glass priv(x) requires x > 0 { return x }\n'
            'glass use() { return priv(5) }\n')
        assert "E053" in codes

    def test_no_e053_in_governed_mode(self):
        codes = _diags(
            'module m: governed\n'
            'glass priv(x) requires x > 0 { return x }\n'
            'glass use() { return priv(5) }\n')
        assert "E053" not in codes

    def test_forward_reference_resolves(self):
        # Caller declared before callee — hoisting makes this clean.
        codes = _diags(
            'module m: core\n'
            'glass a() { return b() }\n'
            'glass b() { return 1 }\n')
        assert "E011" not in codes

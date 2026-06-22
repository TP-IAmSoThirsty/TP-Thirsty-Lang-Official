"""
Phase 2 — layered semantic verifiers.

  - Convergence (Shadow Thirst): structural pre-check, Z3 symbolic proof, and
    execute-and-compare fallback, including counterexample reporting.
  - Determinism effect pass: non-determinism followed through aliases.
  - Thirst of Gods: a cascade is linked to an enclosing spillage handler, not
    merely co-present with one.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.ast import BlockStmt
from utf.shadow_thirst.core import (
    CanonicalConvergenceAnalyzer, DeterminismAnalyzer, ShadowModule,
    EffectAnalysis,
)
from utf.shadow_thirst import convergence as conv
from utf.thirst_of_gods.core import to_gods


def _block(code):
    program = Parser(Lexer("{\n" + code + "\n}").lex()).parse()
    return next(s for s in program.stmts if isinstance(s, BlockStmt))


def _converge(shadow, canonical):
    return CanonicalConvergenceAnalyzer().analyze(
        ShadowModule(name="t", shadow_code=shadow, canonical_code=canonical))


# ── Convergence: layered ─────────────────────────────────────────────────────

class TestConvergence:
    def test_structural_alpha_equivalent_promotes(self):
        # Layer 1: same shape up to variable naming.
        r = _converge("drink x = compute(input)\nreturn x",
                      "drink result = compute(input)\nreturn result")
        assert r.passed

    def test_semantically_equal_different_shape_promotes(self):
        # x + x and x * 2 are different ASTs but equal for all inputs — a layer
        # beyond structural (Z3 or execute-and-compare) must promote it.
        r = _converge("drink y = x + x\nreturn y", "return x * 2")
        assert r.passed
        assert "converge" in r.message.lower()

    def test_subtle_divergence_rejects_with_counterexample(self):
        r = _converge("return x + 1", "return x + 2")
        assert not r.passed
        assert "counterexample" in r.message.lower()

    def test_execute_and_compare_finds_diverging_input(self):
        v = conv.execute_and_compare(_block("return x + 1"),
                                     _block("return x + 2"))
        assert v.status == "diverge"
        assert v.counterexample is not None

    def test_execute_and_compare_abstains_on_effects(self):
        # Return-value comparison is unsound when a block has observable effects.
        v = conv.execute_and_compare(_block("pour x\nreturn x"),
                                     _block("return x"))
        assert v.status == "unsupported"


class TestConvergenceZ3:
    """The symbolic layer — only when thirsty-lang[analysis] (z3) is present."""

    def setup_method(self):
        pytest.importorskip("z3")

    def test_z3_proves_equivalence(self):
        v = conv.z3_equivalence(_block("drink y = x + x\nreturn y"),
                                _block("return x * 2"))
        assert v.status == "equivalent"

    def test_z3_finds_counterexample(self):
        v = conv.z3_equivalence(_block("return x + 1"),
                                _block("return x + 2"))
        assert v.status == "diverge"
        assert v.counterexample is not None

    def test_z3_abstains_outside_supported_subset(self):
        # Division is not faithfully modelled — the layer defers, it never lies.
        v = conv.z3_equivalence(_block("return x / 2"), _block("return x"))
        assert v.status == "unsupported"


# ── Determinism effect pass ──────────────────────────────────────────────────

class TestEffectPass:
    def test_direct_nondeterministic_call_flagged(self):
        assert not DeterminismAnalyzer().analyze(
            ShadowModule(name="t", shadow_code="drink x = now()")).passed

    def test_alias_indirection_flagged(self):
        # The evasion: alias `now` into a variable, then call the variable.
        r = DeterminismAnalyzer().analyze(ShadowModule(
            name="t", shadow_code="drink f = now\ndrink x = f()"))
        assert not r.passed

    def test_transitive_alias_chain_flagged(self):
        r = DeterminismAnalyzer().analyze(ShadowModule(
            name="t", shadow_code="drink f = now\ndrink g = f\ndrink x = g()"))
        assert not r.passed

    def test_taint_set_tracks_aliases(self):
        eff = EffectAnalysis().run(_block("drink f = now\ndrink g = f"))
        assert {"f", "g"} <= eff.tainted

    def test_clean_block_passes(self):
        assert DeterminismAnalyzer().analyze(
            ShadowModule(name="t", shadow_code="drink x = input + 1")).passed

    def test_variable_named_like_source_not_flagged(self):
        assert DeterminismAnalyzer().analyze(
            ShadowModule(name="t", shadow_code="drink nowhere = a + 1")).passed


# ── Thirst of Gods: cascade→spillage linking ─────────────────────────────────

def _ast(src):
    return Parser(Lexer(src).lex()).parse()


class TestCascadeLinking:
    def test_cascade_inside_spillage_is_guarded(self):
        src = """module m: core
glass w(items) {
    spillage {
        drink r = cascade fetch(items)
        return r
    } error {
        return none
    }
}
"""
        assert to_gods(_ast(src)).has_cascade_handler

    def test_cascade_outside_spillage_is_unguarded(self):
        src = """module m: core
glass w(items) {
    drink r = cascade fetch(items)
    spillage {
        return r
    } error {
        return none
    }
}
"""
        contract = to_gods(_ast(src))
        assert not contract.has_cascade_handler
        assert any("cascade" in v.lower() for v in contract.violations)

    def test_no_cascade_at_all_is_unsatisfied(self):
        src = """module m: core
glass w(x) {
    spillage {
        return x
    } error {
        return none
    }
}
"""
        assert not to_gods(_ast(src)).has_cascade_handler

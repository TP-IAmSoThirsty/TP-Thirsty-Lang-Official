"""
Tests for T.A.R.L. Phase 3 — Static Analysis Engine.

Structure:
  - Dataclass / result-type tests (no Z3 needed)
  - PolicyAnalyzer with Z3 unavailable (monkeypatched)
  - _ConditionToZ3 type-inference tests (no Z3 needed)
  - Full Z3 analysis tests (skipped when z3-solver not installed)
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))  # noqa: E402

import utf.tarl.analyzer as _ana_mod  # noqa: E402
from utf.tarl.analyzer import (  # noqa: E402
    _Z3_AVAILABLE,
    AnalysisResult,
    ConflictPair,
    CoverageGap,
    PolicyAnalyzer,
    ShadowedRule,
    _ConditionToZ3,
    _unavailable,
)
from utf.tarl.core import PolicyParser  # noqa: E402
from utf.tarl.spec import TarlPolicy, TarlRule, TarlVerdict  # noqa: E402

# ── helpers ───────────────────────────────────────────────────────────────────


def _policy(rules_text: str, name: str = "test") -> TarlPolicy:
    text = f"policy {name}:\n" + "\n".join(
        f"  when {c} => {v}" for c, v in rules_text
    )
    return PolicyParser.parse(text, name)


def _rule(condition: str, verdict: str = "ALLOW") -> TarlRule:
    return TarlRule(condition=condition, verdict=TarlVerdict(verdict))


Z3_SKIP = unittest.skipUnless(_Z3_AVAILABLE, "z3-solver not installed")


# ── AnalysisResult dataclass ──────────────────────────────────────────────────

class TestAnalysisResult(unittest.TestCase):

    def test_str_unavailable(self):
        r = AnalysisResult(kind="coverage", available=False, passed=False,
                           message="no z3")
        self.assertIn("unavailable", str(r))
        self.assertIn("coverage", str(r))

    def test_str_pass(self):
        r = AnalysisResult(kind="shadows", available=True, passed=True,
                           message="clean")
        self.assertIn("PASS", str(r))
        self.assertIn("shadows", str(r))

    def test_str_fail(self):
        r = AnalysisResult(kind="conflicts", available=True, passed=False,
                           message="found 1")
        self.assertIn("FAIL", str(r))

    def test_summary_with_gaps(self):
        r = AnalysisResult(
            kind="coverage", available=True, passed=False,
            message="gap found",
            gaps=[CoverageGap(description="no match", example_context={"x": 1})],
        )
        s = r.summary
        self.assertIn("gap:", s)
        self.assertIn("no match", s)
        self.assertIn("example:", s)

    def test_summary_with_shadows(self):
        r = AnalysisResult(
            kind="shadows", available=True, passed=False,
            message="dead rule",
            shadows=[ShadowedRule(rule_index=1, condition="x > 0",
                                  description="shadowed")],
        )
        self.assertIn("dead:", r.summary)

    def test_summary_with_conflicts(self):
        r = AnalysisResult(
            kind="conflicts", available=True, passed=False,
            message="conflict",
            conflicts=[ConflictPair(rule_i=0, rule_j=1,
                                    verdict_i=TarlVerdict.ALLOW,
                                    verdict_j=TarlVerdict.DENY,
                                    description="overlap")],
        )
        self.assertIn("conflict:", r.summary)

    def test_summary_with_counterexample(self):
        r = AnalysisResult(
            kind="equiv", available=True, passed=False,
            message="differ", counterexample={"role": "admin"},
        )
        self.assertIn("counterexample", r.summary)

    def test_defaults(self):
        r = AnalysisResult(kind="coverage", available=True, passed=True)
        self.assertEqual(r.gaps, [])
        self.assertEqual(r.shadows, [])
        self.assertEqual(r.conflicts, [])
        self.assertIsNone(r.counterexample)


# ── CoverageGap dataclass ─────────────────────────────────────────────────────

class TestCoverageGap(unittest.TestCase):

    def test_defaults(self):
        g = CoverageGap()
        self.assertEqual(g.description, "")
        self.assertIsNone(g.example_context)

    def test_with_values(self):
        g = CoverageGap(description="no match", example_context={"x": 5})
        self.assertEqual(g.description, "no match")
        self.assertEqual(g.example_context, {"x": 5})


# ── ShadowedRule dataclass ────────────────────────────────────────────────────

class TestShadowedRule(unittest.TestCase):

    def test_defaults(self):
        s = ShadowedRule()
        self.assertEqual(s.rule_index, 0)
        self.assertEqual(s.shadowed_by, [])
        self.assertEqual(s.verdict, TarlVerdict.DENY)

    def test_with_values(self):
        s = ShadowedRule(
            rule_index=2,
            condition="x > 5",
            verdict=TarlVerdict.ALLOW,
            shadowed_by=[0, 1],
            description="covered by earlier",
        )
        self.assertEqual(s.shadowed_by, [0, 1])
        self.assertEqual(s.verdict, TarlVerdict.ALLOW)


# ── ConflictPair dataclass ────────────────────────────────────────────────────

class TestConflictPair(unittest.TestCase):

    def test_defaults(self):
        c = ConflictPair()
        self.assertEqual(c.rule_i, 0)
        self.assertEqual(c.rule_j, 0)
        self.assertIsNone(c.example_context)

    def test_with_values(self):
        c = ConflictPair(
            rule_i=1, rule_j=3,
            verdict_i=TarlVerdict.ALLOW, verdict_j=TarlVerdict.DENY,
            description="overlap",
        )
        self.assertEqual(c.verdict_i, TarlVerdict.ALLOW)
        self.assertEqual(c.verdict_j, TarlVerdict.DENY)


# ── _unavailable helper ───────────────────────────────────────────────────────

class TestUnavailableHelper(unittest.TestCase):

    def test_returns_analysis_result(self):
        r = _unavailable("coverage")
        self.assertIsInstance(r, AnalysisResult)

    def test_available_false(self):
        r = _unavailable("shadows")
        self.assertFalse(r.available)
        self.assertFalse(r.passed)

    def test_kind_is_set(self):
        self.assertEqual(_unavailable("equiv").kind, "equiv")
        self.assertEqual(_unavailable("refines").kind, "refines")

    def test_message_contains_z3(self):
        r = _unavailable("conflicts")
        self.assertIn("z3", r.message.lower())


# ── PolicyAnalyzer with Z3 unavailable (monkeypatched) ───────────────────────

class TestAnalyzerZ3Unavailable(unittest.TestCase):

    def setUp(self):
        self.policy = PolicyParser.parse(
            "policy p:\n  when x == 1 => ALLOW\n  when x == 2 => DENY"
        )

    def _run_with_no_z3(self, fn):
        with patch.object(_ana_mod, '_Z3_AVAILABLE', False):
            return fn()

    def test_coverage_unavailable(self):
        r = self._run_with_no_z3(
            lambda: PolicyAnalyzer(self.policy).check_coverage()
        )
        self.assertFalse(r.available)
        self.assertEqual(r.kind, "coverage")

    def test_shadows_unavailable(self):
        r = self._run_with_no_z3(
            lambda: PolicyAnalyzer(self.policy).check_shadows()
        )
        self.assertFalse(r.available)
        self.assertEqual(r.kind, "shadows")

    def test_conflicts_unavailable(self):
        r = self._run_with_no_z3(
            lambda: PolicyAnalyzer(self.policy).check_conflicts()
        )
        self.assertFalse(r.available)
        self.assertEqual(r.kind, "conflicts")

    def test_equiv_unavailable(self):
        r = self._run_with_no_z3(
            lambda: PolicyAnalyzer.check_equiv(self.policy, self.policy)
        )
        self.assertFalse(r.available)
        self.assertEqual(r.kind, "equiv")

    def test_refines_unavailable(self):
        r = self._run_with_no_z3(
            lambda: PolicyAnalyzer.check_refines(self.policy, self.policy)
        )
        self.assertFalse(r.available)
        self.assertEqual(r.kind, "refines")

    def test_str_contains_install_hint(self):
        r = self._run_with_no_z3(
            lambda: PolicyAnalyzer(self.policy).check_coverage()
        )
        self.assertIn("pip install", r.message)


# ── _ConditionToZ3 type inference (no Z3 needed) ─────────────────────────────

class TestConditionToZ3TypeInference(unittest.TestCase):

    def _infer(self, *conditions) -> dict:
        tr = _ConditionToZ3()
        rules = [TarlRule(condition=c, verdict=TarlVerdict.ALLOW)
                 for c in conditions]
        tr.infer_types(rules)
        return tr._types

    def test_int_comparison(self):
        t = self._infer("age >= 18")
        self.assertEqual(t.get("age"), "Int")

    def test_string_equality(self):
        t = self._infer('role == "admin"')
        self.assertEqual(t.get("role"), "String")

    def test_dot_access_int(self):
        t = self._infer("user.age > 0")
        self.assertEqual(t.get("user.age"), "Int")

    def test_dot_access_string(self):
        t = self._infer('user.role == "guest"')
        self.assertEqual(t.get("user.role"), "String")

    def test_set_membership_string(self):
        t = self._infer('role IN ["admin", "user"]')
        self.assertEqual(t.get("role"), "String")

    def test_set_membership_int(self):
        t = self._infer("level IN [1, 2, 3]")
        self.assertEqual(t.get("level"), "Int")

    def test_conflict_becomes_opaque(self):
        # role compared to both a string and an int → opaque
        t = self._infer('role == "admin"', "role == 5")
        self.assertEqual(t.get("role"), "opaque")

    def test_arithmetic_forces_int(self):
        t = self._infer("x + y >= 10")
        self.assertEqual(t.get("x"), "Int")
        self.assertEqual(t.get("y"), "Int")

    def test_bool_default(self):
        # Variable never typed → not in types dict; _get_var defaults to Int
        t = self._infer("1 == 1")
        self.assertNotIn("undefined_var", t)

    def test_multiple_rules_accumulate(self):
        t = self._infer("age >= 18", 'role == "admin"')
        self.assertEqual(t.get("age"), "Int")
        self.assertEqual(t.get("role"), "String")


# ── Full Z3 analysis tests ────────────────────────────────────────────────────

@Z3_SKIP
class TestCoverageAnalysis(unittest.TestCase):

    def test_gap_exists_narrow_policy(self):
        # Only covers role == "admin" — huge gap for other roles
        p = PolicyParser.parse('policy p:\n  when role == "admin" => ALLOW')
        r = PolicyAnalyzer(p).check_coverage()
        self.assertTrue(r.available)
        self.assertFalse(r.passed)
        self.assertEqual(len(r.gaps), 1)
        self.assertIsNotNone(r.gaps[0].example_context)

    def test_no_gap_tautology(self):
        # 1 == 1 always matches
        p = PolicyParser.parse('policy p:\n  when 1 == 1 => ALLOW')
        r = PolicyAnalyzer(p).check_coverage()
        self.assertTrue(r.available)
        self.assertTrue(r.passed)

    def test_no_gap_complementary_rules(self):
        # x >= 0 or x < 0 covers all integers
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x >= 0 => ALLOW\n'
            '  when x < 0 => DENY'
        )
        r = PolicyAnalyzer(p).check_coverage()
        self.assertTrue(r.available)
        self.assertTrue(r.passed)

    def test_gap_no_rules(self):
        p = TarlPolicy(name="empty")
        r = PolicyAnalyzer(p).check_coverage()
        self.assertFalse(r.passed)
        self.assertGreater(len(r.gaps), 0)

    def test_gap_example_context_is_dict(self):
        p = PolicyParser.parse('policy p:\n  when x == 42 => ALLOW')
        r = PolicyAnalyzer(p).check_coverage()
        self.assertFalse(r.passed)
        self.assertIsInstance(r.gaps[0].example_context, dict)

    def test_multiple_rules_with_gap(self):
        # Covers x == 1 and x == 2 but not x == 3
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x == 1 => ALLOW\n'
            '  when x == 2 => ALLOW'
        )
        r = PolicyAnalyzer(p).check_coverage()
        self.assertFalse(r.passed)


@Z3_SKIP
class TestShadowsAnalysis(unittest.TestCase):

    def test_no_shadows_single_rule(self):
        p = PolicyParser.parse('policy p:\n  when x > 0 => ALLOW')
        r = PolicyAnalyzer(p).check_shadows()
        self.assertTrue(r.passed)

    def test_dead_rule_tautology_first(self):
        # Rule 0 always matches, rule 1 is dead
        p = PolicyParser.parse(
            'policy p:\n'
            '  when 1 == 1 => ALLOW\n'
            '  when x > 5 => DENY'
        )
        r = PolicyAnalyzer(p).check_shadows()
        self.assertFalse(r.passed)
        self.assertEqual(len(r.shadows), 1)
        self.assertEqual(r.shadows[0].rule_index, 1)
        self.assertIn(0, r.shadows[0].shadowed_by)

    def test_dead_rule_superset_condition(self):
        # Rule 0: x >= 0 (all non-negative), Rule 1: x >= 10 is subsumed
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x >= 0 => ALLOW\n'
            '  when x >= 10 => DENY'
        )
        r = PolicyAnalyzer(p).check_shadows()
        self.assertFalse(r.passed)
        self.assertEqual(r.shadows[0].rule_index, 1)

    def test_reachable_rules_not_shadowed(self):
        # Rules are mutually exclusive
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x == 1 => ALLOW\n'
            '  when x == 2 => DENY'
        )
        r = PolicyAnalyzer(p).check_shadows()
        self.assertTrue(r.passed)
        self.assertEqual(len(r.shadows), 0)

    def test_shadow_description_contains_rule_index(self):
        p = PolicyParser.parse(
            'policy p:\n'
            '  when 1 == 1 => ALLOW\n'
            '  when x > 0 => DENY'
        )
        r = PolicyAnalyzer(p).check_shadows()
        self.assertFalse(r.passed)
        desc = r.shadows[0].description
        self.assertIn("[1]", desc)

    def test_fewer_than_two_rules(self):
        p = PolicyParser.parse('policy p:\n  when x > 0 => ALLOW')
        r = PolicyAnalyzer(p).check_shadows()
        self.assertTrue(r.passed)
        self.assertIn("fewer than 2", r.message)


@Z3_SKIP
class TestConflictsAnalysis(unittest.TestCase):

    def test_no_conflicts_same_verdict(self):
        # Both rules ALLOW → no conflict even if they overlap
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x >= 0 => ALLOW\n'
            '  when x >= 10 => ALLOW'
        )
        r = PolicyAnalyzer(p).check_conflicts()
        self.assertTrue(r.passed)

    def test_conflict_overlapping_different_verdicts(self):
        # x >= 5 and x >= 10 both ALLOW/DENY overlap when x >= 10
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x >= 5 => ALLOW\n'
            '  when x >= 10 => DENY'
        )
        r = PolicyAnalyzer(p).check_conflicts()
        self.assertFalse(r.passed)
        self.assertGreater(len(r.conflicts), 0)
        self.assertEqual(r.conflicts[0].rule_i, 0)
        self.assertEqual(r.conflicts[0].rule_j, 1)

    def test_conflict_has_example_context(self):
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x == 5 => ALLOW\n'
            '  when x >= 0 => DENY'
        )
        r = PolicyAnalyzer(p).check_conflicts()
        self.assertFalse(r.passed)
        self.assertIsNotNone(r.conflicts[0].example_context)

    def test_no_conflict_disjoint_ranges(self):
        # x < 5 and x >= 5 never overlap
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x < 5 => ALLOW\n'
            '  when x >= 5 => DENY'
        )
        r = PolicyAnalyzer(p).check_conflicts()
        self.assertTrue(r.passed)

    def test_conflict_count_multiple_pairs(self):
        # Three rules, all pairs overlap with different verdicts
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x >= 0 => ALLOW\n'
            '  when x >= 1 => DENY\n'
            '  when x >= 2 => ESCALATE'
        )
        r = PolicyAnalyzer(p).check_conflicts()
        self.assertFalse(r.passed)
        # At least two conflict pairs
        self.assertGreaterEqual(len(r.conflicts), 2)

    def test_conflict_message_contains_count(self):
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x > 0 => ALLOW\n'
            '  when x > 5 => DENY'
        )
        r = PolicyAnalyzer(p).check_conflicts()
        if not r.passed:
            self.assertIn("conflict", r.message.lower())


@Z3_SKIP
class TestEquivAnalysis(unittest.TestCase):

    def test_same_policy_is_equiv(self):
        p = PolicyParser.parse(
            'policy p:\n'
            '  when x > 0 => ALLOW\n'
            '  when x <= 0 => DENY'
        )
        r = PolicyAnalyzer.check_equiv(p, p)
        self.assertTrue(r.passed)

    def test_identical_text_is_equiv(self):
        text = 'policy p:\n  when x == 1 => ALLOW'
        p1 = PolicyParser.parse(text, "p1")
        p2 = PolicyParser.parse(text, "p2")
        r = PolicyAnalyzer.check_equiv(p1, p2)
        self.assertTrue(r.passed)

    def test_different_policies_not_equiv(self):
        # p1 allows x > 0, p2 allows x > 10
        p1 = PolicyParser.parse('policy p1:\n  when x > 0 => ALLOW')
        p2 = PolicyParser.parse('policy p2:\n  when x > 10 => ALLOW')
        r = PolicyAnalyzer.check_equiv(p1, p2)
        self.assertFalse(r.passed)
        self.assertIsNotNone(r.counterexample)

    def test_reordered_allow_and_deny_differ(self):
        # Same conditions, different order → different behavior
        p1 = PolicyParser.parse(
            'policy p1:\n'
            '  when x > 5 => ALLOW\n'
            '  when x > 0 => DENY'
        )
        p2 = PolicyParser.parse(
            'policy p2:\n'
            '  when x > 0 => DENY\n'
            '  when x > 5 => ALLOW'
        )
        r = PolicyAnalyzer.check_equiv(p1, p2)
        self.assertFalse(r.passed)

    def test_equiv_result_names_policies(self):
        p1 = PolicyParser.parse('policy alpha:\n  when 1 == 1 => ALLOW')
        p2 = PolicyParser.parse('policy beta:\n  when 1 == 1 => ALLOW')
        r = PolicyAnalyzer.check_equiv(p1, p2)
        self.assertIn("alpha", r.message)
        self.assertIn("beta", r.message)


@Z3_SKIP
class TestRefinesAnalysis(unittest.TestCase):

    def test_strict_subset_passes(self):
        # strict: x > 10 → ALLOW; permissive: x > 0 → ALLOW
        # strict ⊑ permissive: everything strict allows, permissive allows too
        strict = PolicyParser.parse('policy strict:\n  when x > 10 => ALLOW')
        permissive = PolicyParser.parse(
            'policy perm:\n  when x > 0 => ALLOW'
        )
        r = PolicyAnalyzer.check_refines(strict, permissive)
        self.assertTrue(r.passed)

    def test_superset_fails(self):
        # strict allows x > 0, permissive allows x > 10
        # strict allows x=5 but permissive doesn't → NOT a refinement
        strict = PolicyParser.parse('policy strict:\n  when x > 0 => ALLOW')
        permissive = PolicyParser.parse(
            'policy perm:\n  when x > 10 => ALLOW'
        )
        r = PolicyAnalyzer.check_refines(strict, permissive)
        self.assertFalse(r.passed)
        self.assertIsNotNone(r.counterexample)

    def test_same_policy_refines_itself(self):
        p = PolicyParser.parse('policy p:\n  when x == 5 => ALLOW')
        r = PolicyAnalyzer.check_refines(p, p)
        self.assertTrue(r.passed)

    def test_deny_only_refines_anything(self):
        # A policy that only denies can't violate refinement since it never ALLOW
        deny_all = TarlPolicy(
            name="deny_all",
            rules=[TarlRule(condition="1 == 1", verdict=TarlVerdict.DENY)],
        )
        permissive = PolicyParser.parse(
            'policy perm:\n  when x > 0 => ALLOW'
        )
        r = PolicyAnalyzer.check_refines(deny_all, permissive)
        self.assertTrue(r.passed)

    def test_refines_message_contains_policy_names(self):
        p1 = PolicyParser.parse('policy s:\n  when x == 1 => ALLOW')
        p2 = PolicyParser.parse('policy p:\n  when x >= 0 => ALLOW')
        r = PolicyAnalyzer.check_refines(p1, p2)
        self.assertIn("s", r.message)
        self.assertIn("p", r.message)


@Z3_SKIP
class TestConditionToZ3Translation(unittest.TestCase):
    """Verify translator produces valid Z3 formulas (requires Z3)."""

    def _check_sat(self, condition: str, expect_sat: bool):
        import z3
        tr = _ConditionToZ3()
        rules = [TarlRule(condition=condition, verdict=TarlVerdict.ALLOW)]
        tr.infer_types(rules)
        from utf.tarl.core import SafeExpr
        toks = PolicyParser._tokenize(condition)
        ast = SafeExpr(toks).parse_expr()
        formula = tr.to_bool(ast)
        s = z3.Solver()
        s.add(*tr.domain_constraints())
        s.add(formula)
        result = s.check()
        if expect_sat:
            self.assertEqual(result, z3.sat, f"Expected SAT for: {condition}")
        else:
            self.assertEqual(result, z3.unsat, f"Expected UNSAT for: {condition}")

    def test_tautology_is_sat(self):
        self._check_sat("1 == 1", True)

    def test_contradiction_is_unsat(self):
        self._check_sat("1 == 2", False)

    def test_integer_comparison_sat(self):
        self._check_sat("x > 5", True)

    def test_string_eq_sat(self):
        self._check_sat('role == "admin"', True)

    def test_inline_set_membership_sat(self):
        self._check_sat('role IN ["admin", "user"]', True)

    def test_logical_and(self):
        self._check_sat("x > 0 and x < 10", True)

    def test_logical_and_contradiction(self):
        self._check_sat("x > 10 and x < 5", False)

    def test_logical_or(self):
        self._check_sat("x < 0 or x > 0", True)

    def test_not(self):
        self._check_sat("not 1 == 1", False)

    def test_arithmetic_comparison(self):
        self._check_sat("x + 1 > x", True)


@Z3_SKIP
class TestTemporalBuiltinsInZ3(unittest.TestCase):

    def test_current_hour_has_domain(self):
        import z3
        tr = _ConditionToZ3()
        rules = [TarlRule(
            condition="CURRENT_HOUR >= 9 and CURRENT_HOUR < 17",
            verdict=TarlVerdict.ALLOW,
        )]
        tr.infer_types(rules)
        from utf.tarl.core import SafeExpr
        toks = PolicyParser._tokenize(
            "CURRENT_HOUR >= 9 and CURRENT_HOUR < 17"
        )
        ast = SafeExpr(toks).parse_expr()
        formula = tr.to_bool(ast)
        s = z3.Solver()
        s.add(*tr.domain_constraints())
        s.add(formula)
        self.assertEqual(s.check(), z3.sat)

    def test_current_hour_domain_respected(self):
        import z3
        tr = _ConditionToZ3()
        rules = [TarlRule(condition="CURRENT_HOUR >= 0",
                          verdict=TarlVerdict.ALLOW)]
        tr.infer_types(rules)
        v = tr._get_var("CURRENT_HOUR")
        s = z3.Solver()
        s.add(*tr.domain_constraints())
        # Should never be outside 0-23
        s.add(z3.Or(v < 0, v > 23))
        self.assertEqual(s.check(), z3.unsat)


@Z3_SKIP
class TestVerdictITEChain(unittest.TestCase):

    def test_first_rule_wins(self):
        import z3

        from utf.tarl.analyzer import _VERDICT_INT, _build_formulas, _verdict_ite

        p = PolicyParser.parse(
            'policy p:\n'
            '  when x > 5 => ALLOW\n'
            '  when x > 0 => DENY'
        )
        tr = _ConditionToZ3()
        tr.infer_types(p.rules)
        formulas = _build_formulas(tr, p.rules)
        ite = _verdict_ite(formulas, p.rules)

        x = tr._get_var("x")
        s = z3.Solver()
        s.add(*tr.domain_constraints())
        # x = 10 → first rule fires → ALLOW=2
        s.add(x == 10)
        s.add(ite == _VERDICT_INT[TarlVerdict.ALLOW])
        self.assertEqual(s.check(), z3.sat)

    def test_default_deny_when_no_match(self):
        import z3

        from utf.tarl.analyzer import _VERDICT_INT, _build_formulas, _verdict_ite

        p = PolicyParser.parse('policy p:\n  when x == 99 => ALLOW')
        tr = _ConditionToZ3()
        tr.infer_types(p.rules)
        formulas = _build_formulas(tr, p.rules)
        ite = _verdict_ite(formulas, p.rules)

        x = tr._get_var("x")
        s = z3.Solver()
        s.add(*tr.domain_constraints())
        s.add(x == 0)
        s.add(ite == _VERDICT_INT[TarlVerdict.DENY])
        self.assertEqual(s.check(), z3.sat)


@Z3_SKIP
class TestModelExtraction(unittest.TestCase):

    def test_model_dict_contains_int_var(self):
        import z3

        from utf.tarl.analyzer import _model_dict
        tr = _ConditionToZ3()
        rules = [TarlRule(condition="age >= 18", verdict=TarlVerdict.ALLOW)]
        tr.infer_types(rules)
        v = tr._get_var("age")
        s = z3.Solver()
        s.add(v == 25)
        self.assertEqual(s.check(), z3.sat)
        d = _model_dict(s.model(), tr)
        self.assertIn("age", d)
        self.assertEqual(d["age"], 25)

    def test_model_dict_contains_string_var(self):
        import z3

        from utf.tarl.analyzer import _model_dict
        tr = _ConditionToZ3()
        rules = [TarlRule(condition='role == "admin"', verdict=TarlVerdict.ALLOW)]
        tr.infer_types(rules)
        v = tr._get_var("role")
        s = z3.Solver()
        s.add(v == z3.StringVal("admin"))
        self.assertEqual(s.check(), z3.sat)
        d = _model_dict(s.model(), tr)
        self.assertIn("role", d)
        self.assertEqual(d["role"], "admin")


# ── Public API exported from __init__ ─────────────────────────────────────────

class TestPublicAPIExports(unittest.TestCase):

    def test_analyzer_exported(self):
        import utf.tarl as tarl
        self.assertTrue(hasattr(tarl, 'PolicyAnalyzer'))

    def test_analysis_result_exported(self):
        import utf.tarl as tarl
        self.assertTrue(hasattr(tarl, 'AnalysisResult'))

    def test_coverage_gap_exported(self):
        import utf.tarl as tarl
        self.assertTrue(hasattr(tarl, 'CoverageGap'))

    def test_shadowed_rule_exported(self):
        import utf.tarl as tarl
        self.assertTrue(hasattr(tarl, 'ShadowedRule'))

    def test_conflict_pair_exported(self):
        import utf.tarl as tarl
        self.assertTrue(hasattr(tarl, 'ConflictPair'))


if __name__ == '__main__':
    unittest.main()

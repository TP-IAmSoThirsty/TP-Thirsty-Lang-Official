"""
T.A.R.L. Static Analysis Engine — Phase 3

Z3 SMT-backed analysis (optional: pip install thirsty-lang[analysis])

  coverage  — contexts that fall through to DEFAULT-DENY
  shadows   — dead rules that can never be reached
  conflicts — rule pairs with overlapping conditions but different verdicts
  equiv     — prove two policies produce identical verdicts for all contexts
  refines   — prove one policy is a strict subset of another
"""
from __future__ import annotations

import functools
import gc
import threading
from dataclasses import dataclass, field
from typing import Any

from utf.tarl.core import PolicyParser, SafeExpr
from utf.tarl.spec import TarlPolicy, TarlRule, TarlVerdict

# ── Z3 availability ───────────────────────────────────────────────────────────

# z3-solver ships no type stubs; the handle is annotated ``Any`` so the optional
# dependency does not produce a storm of "None has no attribute …" errors at
# every ``_z3.<symbol>`` use site. Import first (so the success path types as
# Any), falling back to None when the extra is not installed.
_z3: Any
try:
    import z3 as _z3  # type: ignore[no-redef,import-untyped,import-not-found]
    _Z3_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _z3 = None
    _Z3_AVAILABLE = False

_Z3_MSG = "static analysis requires z3-solver: pip install thirsty-lang[analysis]"


# ── Z3 thread-safety guard ────────────────────────────────────────────────────
#
# z3-solver's Python bindings share a single global context (z3.main_ctx()) whose
# reference counting is NOT thread-safe. The LSP runs coverage/shadow analysis in
# a daemon thread (see utf/tarl/lsp.py:_publish_diagnostics) while the main thread
# also drives z3, and z3 AST/model objects reaped by Python's cyclic garbage
# collector can call Z3_dec_ref from a thread other than the one using the solver.
# Concurrent deref against the shared context corrupts the z3 heap — observed as a
# Windows 0xC0000374 fatal exception / access violation inside Z3_model_dec_ref.
#
# _z3_serialized() confines every z3 entry point to a process-wide lock and forces
# gc.collect() *inside* the lock, after the wrapped frame's z3 locals are gone, so
# every Z3_dec_ref (immediate or deferred/cyclic) runs on a single thread with no
# concurrent context access. Results are plain dataclasses holding no z3 refs.
_Z3_LOCK = threading.RLock()


def _z3_serialized(fn):
    """Serialize z3 global-context access and collect z3 garbage under the lock."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _Z3_AVAILABLE:
            return fn(*args, **kwargs)
        with _Z3_LOCK:
            try:
                return fn(*args, **kwargs)
            finally:
                # The wrapped frame has returned, so its z3 locals are already
                # unreferenced; collect any cyclic z3 garbage here, on this
                # thread, before another thread can touch the global context.
                gc.collect()
    return wrapper

# Verdict integer encoding for ITE chains
_VERDICT_INT = {
    TarlVerdict.DENY: 0,
    TarlVerdict.ESCALATE: 1,
    TarlVerdict.ALLOW: 2,
}

# Temporal int domains: (lo, hi) inclusive
_TEMPORAL_INT_DOMAINS = {
    "CURRENT_HOUR": (0, 23),
    "CURRENT_DAY": (1, 31),
    "CURRENT_MONTH": (1, 12),
    "CURRENT_YEAR": (2020, 2100),
}
_TEMPORAL_STR_BUILTINS = frozenset({"CURRENT_WEEKDAY", "CURRENT_TIMESTAMP"})


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class CoverageGap:
    """A context region where all rules fail and DEFAULT-DENY applies."""
    description: str = ""
    example_context: dict[str, Any] | None = None


@dataclass
class ShadowedRule:
    """A rule that can never be reached because earlier rules always fire first."""
    rule_index: int = 0
    condition: str = ""
    verdict: TarlVerdict = TarlVerdict.DENY
    shadowed_by: list[int] = field(default_factory=list)
    description: str = ""


@dataclass
class ConflictPair:
    """Two rules with different verdicts that can simultaneously match."""
    rule_i: int = 0
    rule_j: int = 0
    verdict_i: TarlVerdict = TarlVerdict.DENY
    verdict_j: TarlVerdict = TarlVerdict.DENY
    example_context: dict[str, Any] | None = None
    description: str = ""


@dataclass
class AnalysisResult:
    """Result of a static analysis query."""
    kind: str
    available: bool
    passed: bool
    message: str = ""
    gaps: list[CoverageGap] = field(default_factory=list)
    shadows: list[ShadowedRule] = field(default_factory=list)
    conflicts: list[ConflictPair] = field(default_factory=list)
    counterexample: dict[str, Any] | None = None

    def __str__(self) -> str:
        if not self.available:
            return f"[{self.kind}] unavailable: {self.message}"
        status = "PASS" if self.passed else "FAIL"
        return f"[{self.kind}] {status}: {self.message}"

    @property
    def summary(self) -> str:
        lines = [str(self)]
        for g in self.gaps:
            lines.append(f"  gap: {g.description}")
            if g.example_context:
                lines.append(f"    example: {g.example_context}")
        for s in self.shadows:
            lines.append(f"  dead: {s.description}")
        for c in self.conflicts:
            lines.append(f"  conflict: {c.description}")
            if c.example_context:
                lines.append(f"    example: {c.example_context}")
        if self.counterexample:
            lines.append(f"  counterexample: {self.counterexample}")
        return "\n".join(lines)


def _unavailable(kind: str) -> AnalysisResult:
    return AnalysisResult(kind=kind, available=False, passed=False, message=_Z3_MSG)


# ── Condition → Z3 translator ─────────────────────────────────────────────────

class _ConditionToZ3:
    """
    Two-pass translator: type inference then AST → Z3 formula.

    Strategy
    - Numeric comparisons → Z3 Int (precise)
    - String equality / IN literal sets → Z3 String (precise)
    - Temporal builtins → Z3 Int with domain bounds
    - Everything else (regex, sources, quantifiers) → fresh opaque Bool
    """

    def __init__(self) -> None:
        self._vars: dict = {}
        self._types: dict = {}           # key -> "Int"|"String"|"Bool"|"opaque"
        self._domain: list = []
        self._opaque_n: int = 0

    # ── type inference ────────────────────────────────────────────────────────

    def infer_types(self, rules: list[TarlRule]) -> None:
        for rule in rules:
            try:
                toks = PolicyParser._tokenize(rule.condition)
                ast = SafeExpr(toks).parse_expr()
                self._collect(ast)
            except Exception:
                pass

    def _collect(self, node: object) -> None:
        if not isinstance(node, tuple):
            return
        tag = node[0]

        if tag == "compare":
            lk, rk = self._var_key(node[2]), self._var_key(node[3])
            lt, rt = self._lit_type(node[2]), self._lit_type(node[3])
            if lk and rt:
                self._merge(lk, rt)
            if rk and lt:
                self._merge(rk, lt)
            for side in (node[2], node[3]):
                if isinstance(side, tuple) and side[0] in (
                    "add", "sub", "mul", "div", "mod"
                ):
                    for k in self._arith_vars(side):
                        self._merge(k, "Int")

        elif tag in ("in", "not_in"):
            vk = self._var_key(node[1])
            if vk and isinstance(node[2], tuple) and node[2][0] == "set":
                for item in node[2][1]:
                    it = self._lit_type(item)
                    if it:
                        self._merge(vk, it)

        for child in node[1:]:
            if isinstance(child, tuple):
                self._collect(child)
            elif isinstance(child, list):
                for item in child:
                    if isinstance(item, tuple):
                        self._collect(item)

    def _arith_vars(self, node: object) -> list:
        if not isinstance(node, tuple):
            return []
        k = self._var_key(node)
        if k:
            return [k]
        keys: list = []
        for child in node[1:]:
            if isinstance(child, tuple):
                keys.extend(self._arith_vars(child))
        return keys

    def _merge(self, key: str, new_type: str) -> None:
        existing = self._types.get(key)
        if existing is None:
            self._types[key] = new_type
        elif existing != new_type:
            self._types[key] = "opaque"

    @staticmethod
    def _lit_type(node: object) -> str | None:
        if not isinstance(node, tuple):
            return None
        t = node[0]
        if t in ("int", "float"):
            return "Int"
        if t == "string":
            return "String"
        if t == "bool":
            return "Bool"
        return None

    @staticmethod
    def _var_key(node: object) -> str | None:
        if not isinstance(node, tuple):
            return None
        t = node[0]
        if t == "ident":
            return str(node[1])
        if t == "attr":
            return ".".join(node[1])
        return None

    # ── variable creation ─────────────────────────────────────────────────────

    def _get_var(self, key: str) -> Any:
        if key in self._vars:
            return self._vars[key]
        if key in _TEMPORAL_INT_DOMAINS:
            v = _z3.Int(key)
            lo, hi = _TEMPORAL_INT_DOMAINS[key]
            self._domain += [v >= lo, v <= hi]
            self._vars[key] = v
            return v
        if key in _TEMPORAL_STR_BUILTINS:
            v = _z3.String(key)
            if key == "CURRENT_WEEKDAY":
                days = [
                    "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY",
                    "FRIDAY", "SATURDAY", "SUNDAY",
                ]
                self._domain.append(_z3.Or([v == _z3.StringVal(d) for d in days]))
            self._vars[key] = v
            return v
        sort = self._types.get(key, "Int")
        safe = key.replace(".", "__")
        if sort == "String":
            v = _z3.String(safe)
        elif sort in ("Bool", "opaque"):
            v = _z3.Bool(safe + ("_op" if sort == "opaque" else ""))
        else:
            v = _z3.Int(safe)
        self._vars[key] = v
        return v

    def _fresh(self, hint: str = "") -> Any:
        name = f"_op{self._opaque_n}" + (f"_{hint[:16]}" if hint else "")
        self._opaque_n += 1
        return _z3.Bool(name)

    def domain_constraints(self) -> list[Any]:
        return list(self._domain)

    # ── translation ───────────────────────────────────────────────────────────

    def to_bool(self, node: object) -> Any:
        if not isinstance(node, tuple):
            return _z3.BoolVal(bool(node))
        tag = node[0]
        if tag == "bool":
            return _z3.BoolVal(node[1])
        if tag == "int":
            return _z3.BoolVal(node[1] != 0)
        if tag == "and":
            return _z3.And(self.to_bool(node[1]), self.to_bool(node[2]))
        if tag == "or":
            return _z3.Or(self.to_bool(node[1]), self.to_bool(node[2]))
        if tag == "not":
            return _z3.Not(self.to_bool(node[1]))
        if tag == "compare":
            return self._cmp(node)
        if tag == "in":
            return self._membership(node[1], node[2], negate=False)
        if tag == "not_in":
            return self._membership(node[1], node[2], negate=True)
        if tag == "ident":
            k = node[1]
            if self._types.get(k) == "Bool":
                return self._get_var(k)
            return self._fresh(f"ident_{k}")
        return self._fresh(tag)

    def to_val(self, node: object) -> Any:
        if not isinstance(node, tuple):
            return None
        tag = node[0]
        if tag == "int":
            return _z3.IntVal(node[1])
        if tag == "float":
            return _z3.RealVal(node[1])
        if tag == "string":
            return _z3.StringVal(node[1])
        if tag == "bool":
            return _z3.BoolVal(node[1])
        if tag == "ident":
            return self._get_var(node[1])
        if tag == "attr":
            return self._get_var(".".join(node[1]))
        if tag == "neg":
            v = self.to_val(node[1])
            try:
                return -v if v is not None else None
            except Exception:
                return None
        _arith_ops = {
            "add": "+", "sub": "-", "mul": "*", "div": "/", "mod": "%",
        }
        if tag in _arith_ops:
            return self._arith(node[1], node[2], _arith_ops[tag])
        return None

    def _arith(self, left: object, right: object, op: str) -> Any:
        lv, rv = self.to_val(left), self.to_val(right)
        if lv is None or rv is None:
            return None
        try:
            lv, rv = self._coerce(lv, rv)
            return {
                "+": lambda: lv + rv,
                "-": lambda: lv - rv,
                "*": lambda: lv * rv,
                "/": lambda: lv / rv,
                "%": lambda: lv % rv,
            }[op]()
        except Exception:
            return None

    @staticmethod
    def _coerce(lv: Any, rv: Any) -> tuple[Any, Any]:
        try:
            if lv.sort() == _z3.IntSort() and rv.sort() == _z3.RealSort():
                return _z3.ToReal(lv), rv
            if lv.sort() == _z3.RealSort() and rv.sort() == _z3.IntSort():
                return lv, _z3.ToReal(rv)
        except Exception:
            pass
        return lv, rv

    def _cmp(self, node: tuple[Any, ...]) -> Any:
        op, lv, rv = node[1], self.to_val(node[2]), self.to_val(node[3])
        if lv is None or rv is None:
            return self._fresh(f"cmp_{op}")
        try:
            lv, rv = self._coerce(lv, rv)
            return {
                "EQEQ": lambda: lv == rv,
                "NE":   lambda: lv != rv,
                "LT":   lambda: lv < rv,
                "GT":   lambda: lv > rv,
                "LE":   lambda: lv <= rv,
                "GE":   lambda: lv >= rv,
            }[op]()
        except Exception:
            return self._fresh(f"cmp_{op}")

    def _membership(
        self, val_node: object, col_node: object, negate: bool
    ) -> Any:
        if not isinstance(col_node, tuple):
            return self._fresh("in")
        if col_node[0] == "set":
            vz = self.to_val(val_node)
            if vz is None:
                return self._fresh("in_set")
            clauses = []
            for item in col_node[1]:
                iz = self.to_val(item)
                if iz is None:
                    continue
                try:
                    lz, rz = self._coerce(vz, iz)
                    clauses.append(lz == rz)
                except Exception:
                    pass
            if not clauses:
                return self._fresh("in_empty")
            result = _z3.Or(clauses) if len(clauses) > 1 else clauses[0]
            return _z3.Not(result) if negate else result
        return self._fresh("in_dyn")


# ── Module helpers ────────────────────────────────────────────────────────────

def _build_formulas(tr: _ConditionToZ3, rules: list[TarlRule]) -> list[Any]:
    out = []
    for rule in rules:
        try:
            toks = PolicyParser._tokenize(rule.condition)
            ast = SafeExpr(toks).parse_expr()
            out.append(tr.to_bool(ast))
        except Exception:
            out.append(tr._fresh("err"))
    return out


def _verdict_ite(formulas: list[Any], rules: list[TarlRule]) -> Any:
    """First-match-wins ITE chain: DENY=0, ESCALATE=1, ALLOW=2."""
    result = _z3.IntVal(0)  # DEFAULT-DENY
    for i in range(len(formulas) - 1, -1, -1):
        result = _z3.If(
            formulas[i],
            _z3.IntVal(_VERDICT_INT[rules[i].verdict]),
            result,
        )
    return result


def _model_dict(model: Any, tr: _ConditionToZ3) -> dict[str, Any]:
    """Extract variable assignments from a Z3 satisfying model."""
    ctx: dict[str, Any] = {}
    for key, var in tr._vars.items():
        try:
            val = model.eval(var, model_completion=True)
            if _z3.is_int_value(val):
                ctx[key] = val.as_long()
            elif _z3.is_true(val):
                ctx[key] = True
            elif _z3.is_false(val):
                ctx[key] = False
            elif hasattr(val, "as_string"):
                ctx[key] = val.as_string()
            else:
                ctx[key] = str(val)
        except Exception:
            pass
    return ctx


# ── PolicyAnalyzer ────────────────────────────────────────────────────────────

class PolicyAnalyzer:
    """
    Static analysis engine for a single T.A.R.L. policy.

    All methods return AnalysisResult.  When z3-solver is not installed every
    result has available=False and carries an installation hint.
    """

    def __init__(self, policy: TarlPolicy) -> None:
        self.policy = policy

    def _translate(self) -> tuple:
        tr = _ConditionToZ3()
        tr.infer_types(self.policy.rules)
        formulas = _build_formulas(tr, self.policy.rules)
        return tr, formulas

    # ── coverage ──────────────────────────────────────────────────────────────

    @_z3_serialized
    def check_coverage(self) -> AnalysisResult:
        """
        Gap(P) = SAT(¬φ₁ ∧ ... ∧ ¬φₙ)

        SAT  → coverage gap exists (DEFAULT-DENY reachable)
        UNSAT → full coverage (every context matches a rule)
        """
        if not _Z3_AVAILABLE:
            return _unavailable("coverage")
        if not self.policy.rules:
            return AnalysisResult(
                kind="coverage", available=True, passed=False,
                message="No rules — every context reaches DEFAULT-DENY",
                gaps=[CoverageGap(description="Policy has no rules")],
            )
        tr, formulas = self._translate()
        s = _z3.Solver()
        s.add(*tr.domain_constraints())
        s.add(*[_z3.Not(f) for f in formulas])
        r = s.check()
        if r == _z3.sat:
            return AnalysisResult(
                kind="coverage", available=True, passed=False,
                message=f"Coverage gap found ({len(self.policy.rules)} rule(s) checked)",
                gaps=[CoverageGap(
                    description="Context region that falls through to DEFAULT-DENY",
                    example_context=_model_dict(s.model(), tr),
                )],
            )
        if r == _z3.unsat:
            return AnalysisResult(
                kind="coverage", available=True, passed=True,
                message="Full coverage: every context matches at least one rule",
            )
        return AnalysisResult(
            kind="coverage", available=True, passed=False,
            message="Z3 returned unknown",
        )

    # ── shadows ───────────────────────────────────────────────────────────────

    @_z3_serialized
    def check_shadows(self) -> AnalysisResult:
        """
        Reachable(rₖ) = SAT(¬φ₁ ∧ ... ∧ ¬φₖ₋₁ ∧ φₖ)

        UNSAT → rule k is dead (shadowed by earlier rules).
        """
        if not _Z3_AVAILABLE:
            return _unavailable("shadows")
        if len(self.policy.rules) < 2:
            return AnalysisResult(
                kind="shadows", available=True, passed=True,
                message="No shadowing possible with fewer than 2 rules",
            )
        tr, formulas = self._translate()
        dead: list[ShadowedRule] = []
        for k in range(1, len(formulas)):
            s = _z3.Solver()
            s.add(*tr.domain_constraints())
            for i in range(k):
                s.add(_z3.Not(formulas[i]))
            s.add(formulas[k])
            if s.check() == _z3.unsat:
                rule = self.policy.rules[k]
                dead.append(ShadowedRule(
                    rule_index=k,
                    condition=rule.condition,
                    verdict=rule.verdict,
                    shadowed_by=list(range(k)),
                    description=(
                        f"Rule [{k}] `when {rule.condition}` is unreachable; "
                        f"rule(s) {list(range(k))} always match first"
                    ),
                ))
        if dead:
            return AnalysisResult(
                kind="shadows", available=True, passed=False,
                message=f"{len(dead)} dead rule(s) found",
                shadows=dead,
            )
        return AnalysisResult(
            kind="shadows", available=True, passed=True,
            message="No dead rules detected",
        )

    # ── conflicts ─────────────────────────────────────────────────────────────

    @_z3_serialized
    def check_conflicts(self) -> AnalysisResult:
        """
        Conflict(rᵢ, rⱼ) = SAT(φᵢ ∧ φⱼ) where vᵢ ≠ vⱼ

        SAT → both rules can fire for the same context (first-match-wins
        resolves it, but it may be unintentional).
        """
        if not _Z3_AVAILABLE:
            return _unavailable("conflicts")
        tr, formulas = self._translate()
        rules = self.policy.rules
        found: list[ConflictPair] = []
        for i in range(len(formulas)):
            for j in range(i + 1, len(formulas)):
                if rules[i].verdict == rules[j].verdict:
                    continue
                s = _z3.Solver()
                s.add(*tr.domain_constraints())
                s.add(formulas[i], formulas[j])
                if s.check() == _z3.sat:
                    found.append(ConflictPair(
                        rule_i=i,
                        rule_j=j,
                        verdict_i=rules[i].verdict,
                        verdict_j=rules[j].verdict,
                        example_context=_model_dict(s.model(), tr),
                        description=(
                            f"Rules [{i}] ({rules[i].verdict.value}) and "
                            f"[{j}] ({rules[j].verdict.value}) overlap. "
                            f"First-match-wins resolves to rule [{i}]."
                        ),
                    ))
        if found:
            return AnalysisResult(
                kind="conflicts", available=True, passed=False,
                message=f"{len(found)} conflicting rule pair(s)",
                conflicts=found,
            )
        return AnalysisResult(
            kind="conflicts", available=True, passed=True,
            message="No conflicts detected",
        )

    # ── equiv ─────────────────────────────────────────────────────────────────

    @staticmethod
    @_z3_serialized
    def check_equiv(p1: TarlPolicy, p2: TarlPolicy) -> AnalysisResult:
        """
        SAT(V(P₁,c) ≠ V(P₂,c)) — not equivalent if satisfiable.
        Uses a shared translator so both policies range over the same context.
        """
        if not _Z3_AVAILABLE:
            return _unavailable("equiv")
        tr = _ConditionToZ3()
        tr.infer_types(p1.rules + p2.rules)
        f1 = _build_formulas(tr, p1.rules)
        f2 = _build_formulas(tr, p2.rules)
        v1 = _verdict_ite(f1, p1.rules)
        v2 = _verdict_ite(f2, p2.rules)
        s = _z3.Solver()
        s.add(*tr.domain_constraints())
        s.add(v1 != v2)
        r = s.check()
        if r == _z3.unsat:
            return AnalysisResult(
                kind="equiv", available=True, passed=True,
                message=f"'{p1.name}' and '{p2.name}' are equivalent",
            )
        if r == _z3.sat:
            return AnalysisResult(
                kind="equiv", available=True, passed=False,
                message=f"'{p1.name}' and '{p2.name}' differ",
                counterexample=_model_dict(s.model(), tr),
            )
        return AnalysisResult(
            kind="equiv", available=True, passed=False,
            message="Z3 returned unknown",
        )

    # ── refines ───────────────────────────────────────────────────────────────

    @staticmethod
    @_z3_serialized
    def check_refines(strict: TarlPolicy, permissive: TarlPolicy) -> AnalysisResult:
        """
        strict ⊑ permissive iff SAT(strict_allows ∧ ¬permissive_allows) is UNSAT.
        I.e. strict never ALLOWs something that permissive would not ALLOW.
        """
        if not _Z3_AVAILABLE:
            return _unavailable("refines")
        tr = _ConditionToZ3()
        tr.infer_types(strict.rules + permissive.rules)
        fs = _build_formulas(tr, strict.rules)
        fp = _build_formulas(tr, permissive.rules)
        vs = _verdict_ite(fs, strict.rules)
        vp = _verdict_ite(fp, permissive.rules)
        _ALLOW = _z3.IntVal(_VERDICT_INT[TarlVerdict.ALLOW])
        s = _z3.Solver()
        s.add(*tr.domain_constraints())
        s.add(vs == _ALLOW, vp != _ALLOW)
        r = s.check()
        if r == _z3.unsat:
            return AnalysisResult(
                kind="refines", available=True, passed=True,
                message=(
                    f"'{strict.name}' ⊑ '{permissive.name}': "
                    "strict never allows what permissive would deny"
                ),
            )
        if r == _z3.sat:
            return AnalysisResult(
                kind="refines", available=True, passed=False,
                message=(
                    f"'{strict.name}' is NOT a refinement of '{permissive.name}'"
                ),
                counterexample=_model_dict(s.model(), tr),
            )
        return AnalysisResult(
            kind="refines", available=True, passed=False,
            message="Z3 returned unknown",
        )

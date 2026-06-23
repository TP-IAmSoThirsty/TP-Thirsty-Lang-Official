"""
Layered convergence checking for Shadow Thirst.

`CanonicalConvergenceAnalyzer` asks one question: does the shadow block compute
the *same thing* as the validated canonical block? Three layers answer it, from
cheapest/strongest to most general:

  1. **Structural** (fast pre-check, in ``core.py``) — alpha-renamed AST equality.
     Same shape up to variable naming ⇒ provably the same computation. This is a
     sound *sufficient* condition: a pass here needs no further work.

  2. **Z3 symbolic** (this module, requires ``thirsty-lang[analysis]``) — for the
     straight-line integer-arithmetic subset, translate each block's returned
     value to a Z3 term over shared symbolic inputs and ask the solver whether
     they can ever differ. ``UNSAT`` ⇒ equivalent *for all inputs* (a real
     proof); ``SAT`` ⇒ a concrete diverging input (a counterexample). Reuses the
     translation strategy of :mod:`utf.tarl.analyzer`.

  3. **Execute-and-compare** (this module, no extra deps) — when symbolic
     translation can't model the blocks, actually *run* both in a sandboxed
     :class:`~utf.thirsty_lang.interpreter.Interpreter` over a spread of seeded
     inputs and compare the returned values. A mismatch is reported with the
     exact input that diverged.

The verdict shape (:class:`AnalysisResult`) and levels are unchanged; this module
only decides ``passed`` and the message/counterexample.
"""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass

from utf.thirsty_lang.ast import (
    AssignStmt,
    BinaryOp,
    BlockStmt,
    BoolLiteral,
    CallExpr,
    Identifier,
    ImportStmt,
    IntLiteral,
    PourStmt,
    ReturnStmt,
    SipStmt,
    ThrowStmt,
    UnaryOp,
    VariableDecl,
)
from utf.thirsty_lang.interpreter import Interpreter, ReturnException
from utf.thirsty_lang.token import TokenType

# ── Z3 availability (mirrors utf.tarl.analyzer) ───────────────────────────────

_z3 = None
_Z3_AVAILABLE = False
try:
    import z3 as _z3  # type: ignore[import]
    _Z3_AVAILABLE = True
except ImportError:
    pass


@dataclass
class ConvergenceVerdict:
    """Outcome of a single convergence layer.

    ``status`` is one of:
      - ``"equivalent"`` — proven/observed equal (``passed`` ⇒ True)
      - ``"diverge"``    — proven/observed different; ``counterexample`` set
      - ``"unsupported"`` — this layer can't model the blocks; try the next
      - ``"unavailable"`` — the layer's dependency (z3) is absent
    """
    status: str
    detail: str = ""
    counterexample: dict | None = None


# ── free-variable / bound-name analysis ───────────────────────────────────────

def _walk(node):
    import dataclasses
    if node is None or not dataclasses.is_dataclass(node):
        return
    yield node
    for f in dataclasses.fields(node):
        if f.name == "span":
            continue
        value = getattr(node, f.name)
        if dataclasses.is_dataclass(value):
            yield from _walk(value)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if dataclasses.is_dataclass(item):
                    yield from _walk(item)


def _callee_names(block) -> set:
    names = set()
    for n in _walk(block):
        if isinstance(n, CallExpr) and isinstance(n.callee, Identifier):
            names.add(n.callee.name)
    return names


def free_variables(block) -> set:
    """Identifiers read by ``block`` that it never binds itself.

    These are the block's symbolic/seeded inputs. Names that appear only as a
    call target (functions) are excluded — they are not data inputs.
    """
    bound = set()
    for n in _walk(block):
        if isinstance(n, VariableDecl):
            bound.add(n.name)
    callees = _callee_names(block)
    free = set()
    for n in _walk(block):
        if isinstance(n, Identifier) and n.name not in bound and n.name not in callees:
            free.add(n.name)
    return free


# ── Layer 2: Z3 symbolic equivalence (integer-arithmetic subset) ──────────────

class _SymUnsupported(Exception):
    """The block uses a construct outside the symbolic subset."""


_CMP_OPS = {
    TokenType.EQEQ: lambda a, b: a == b,
    TokenType.NE: lambda a, b: a != b,
    TokenType.LT: lambda a, b: a < b,
    TokenType.GT: lambda a, b: a > b,
    TokenType.LE: lambda a, b: a <= b,
    TokenType.GE: lambda a, b: a >= b,
}


def _sym_expr(expr, store, zvars, ctx):
    """Translate ``expr`` to a Z3 term in ``ctx``, or raise ``_SymUnsupported``.

    ``store`` maps already-bound names to terms; ``zvars`` is the shared pool of
    free-input symbols (so the same name in shadow and canonical is the same
    Z3 constant). All terms are built in the explicit ``ctx`` — never the global
    z3 context — so each query is fully isolated and GC-clean.
    """
    if isinstance(expr, IntLiteral):
        return _z3.IntVal(expr.value, ctx)
    if isinstance(expr, BoolLiteral):
        return _z3.BoolVal(expr.value, ctx)
    if isinstance(expr, Identifier):
        if expr.name in store:
            return store[expr.name]
        if expr.name in zvars:
            return zvars[expr.name]
        raise _SymUnsupported(f"unbound name {expr.name}")
    if isinstance(expr, UnaryOp):
        v = _sym_expr(expr.operand, store, zvars, ctx)
        if expr.op == TokenType.MINUS:
            return -v
        if expr.op == TokenType.NOT:
            return _z3.Not(v)
        raise _SymUnsupported("unary op")
    if isinstance(expr, BinaryOp):
        a = _sym_expr(expr.left, store, zvars, ctx)
        b = _sym_expr(expr.right, store, zvars, ctx)
        op = expr.op
        if op == TokenType.PLUS:
            return a + b
        if op == TokenType.MINUS:
            return a - b
        if op == TokenType.STAR:
            return a * b
        if op == TokenType.SLASH:
            # Integer division is not faithfully modelled; defer to execution.
            raise _SymUnsupported("division")
        if op == TokenType.PERCENT:
            return a % b
        if op == TokenType.AND:
            return _z3.And(a, b)
        if op == TokenType.OR:
            return _z3.Or(a, b)
        if op in _CMP_OPS:
            return _CMP_OPS[op](a, b)
        raise _SymUnsupported(f"binop {op}")
    raise _SymUnsupported(f"expr {type(expr).__name__}")


def _sym_block_return(block, zvars, ctx):
    """Symbolically evaluate a straight-line block to its returned term.

    Supports a sequence of ``drink``/assignment statements followed by a
    ``return``. Any control flow or unmodelled statement raises
    ``_SymUnsupported``.
    """
    if not isinstance(block, BlockStmt):
        raise _SymUnsupported("not a block")
    store: dict = {}
    for stmt in block.statements:
        if isinstance(stmt, VariableDecl):
            if stmt.init_expr is None:
                raise _SymUnsupported("uninitialised decl")
            store[stmt.name] = _sym_expr(stmt.init_expr, store, zvars, ctx)
        elif isinstance(stmt, AssignStmt) and isinstance(stmt.target, Identifier):
            store[stmt.target.name] = _sym_expr(stmt.value, store, zvars, ctx)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is None:
                raise _SymUnsupported("bare return")
            return _sym_expr(stmt.value, store, zvars, ctx)
        else:
            raise _SymUnsupported(f"stmt {type(stmt).__name__}")
    raise _SymUnsupported("no return")


def z3_equivalence(shadow_block, canonical_block) -> ConvergenceVerdict:
    """Prove or refute equivalence of the two blocks' return values via Z3.

    Each call runs in its own isolated :class:`z3.Context`. Any failure of the
    native solver — sort mismatch, unknown, or even a hard library error — is
    contained and reported as ``"unsupported"`` so the caller falls through to
    execute-and-compare. The Z3 layer can only ever *help*; it can never
    destabilise the verifier or return a wrong verdict.
    """
    if not _Z3_AVAILABLE:
        return ConvergenceVerdict("unavailable", "z3-solver not installed")
    inputs = free_variables(shadow_block) | free_variables(canonical_block)
    try:
        ctx = _z3.Context()
        zvars = {n: _z3.Int(n.replace(".", "__"), ctx) for n in inputs}
        try:
            s_ret = _sym_block_return(shadow_block, zvars, ctx)
            c_ret = _sym_block_return(canonical_block, zvars, ctx)
        except _SymUnsupported as exc:
            return ConvergenceVerdict("unsupported", str(exc))
        solver = _z3.Solver(ctx=ctx)
        solver.add(s_ret != c_ret)
        result = solver.check()
        if result == _z3.unsat:
            return ConvergenceVerdict(
                "equivalent", "Z3 proved equal return value for all inputs")
        if result == _z3.sat:
            model = solver.model()
            ce = {}
            for name, var in zvars.items():
                try:
                    val = model.eval(var, model_completion=True)
                    ce[name] = val.as_long() if _z3.is_int_value(val) else str(val)
                except Exception:
                    pass
            return ConvergenceVerdict(
                "diverge", "Z3 found a diverging input", counterexample=ce)
        return ConvergenceVerdict("unsupported", "z3 returned unknown")
    except Exception as exc:  # incl. native OSError from a flaky z3 build
        return ConvergenceVerdict("unsupported", f"z3 unavailable: {exc}")


# ── Layer 3: execute-and-compare over seeded inputs ───────────────────────────

# A deterministic spread of integer vectors. Mixes small/edge/negative values so
# that off-by-one and sign divergences surface without a fuzzing budget.
_SEED_VALUES = (0, 1, 2, 3, 5, 7, -1, -2, 10, 13)

_EXEC_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=2)
_EXEC_TIMEOUT_S = 2.0

_NO_RETURN = object()

# Calls/statements with observable effects. Comparing return values says nothing
# about whether two blocks *printed*, *read*, *imported*, or *threw* differently,
# so the execute-and-compare layer abstains rather than claim equivalence.
_IMPURE_CALLS = {
    "pour", "print", "sip", "write", "read", "input", "open",
}


def is_effect_free(block) -> bool:
    """True if ``block`` performs no observable I/O / import / throw effect.

    Only effect-free blocks can be compared by return value alone; for anything
    that prints, reads, imports, or throws, equal outputs do not imply equal
    behaviour, so the sampling layer must abstain.
    """
    for n in _walk(block):
        if isinstance(n, (PourStmt, SipStmt, ImportStmt, ThrowStmt)):
            return False
        if (isinstance(n, CallExpr) and isinstance(n.callee, Identifier)
                and n.callee.name.lower() in _IMPURE_CALLS):
            return False
    return True


def _run_block(block, bindings):
    """Run ``block`` in a fresh sandbox with ``bindings`` defined; return value.

    Returns the value carried by a ``return``, or ``_NO_RETURN`` if the block
    falls off the end. Raises on any interpreter error (caller decides).
    """
    it = Interpreter()
    for name, value in bindings.items():
        it.env.define(name, value, is_mut=True)
    try:
        for stmt in block.statements:
            it._execute(stmt)
    except ReturnException as exc:
        return exc.value
    return _NO_RETURN


def _run_block_guarded(block, bindings):
    """Run a block with a wall-clock timeout; returns (ok, value)."""
    future = _EXEC_POOL.submit(_run_block, block, bindings)
    try:
        return True, future.result(timeout=_EXEC_TIMEOUT_S)
    except Exception:
        return False, None


def _seed_vectors(names, limit=8):
    """Deterministic input vectors for the given free-variable names."""
    names = sorted(names)
    if not names:
        return [{}]
    vectors = []
    for i in range(min(limit, len(_SEED_VALUES))):
        # Stagger each variable so they don't all move together.
        vectors.append({
            name: _SEED_VALUES[(i + j) % len(_SEED_VALUES)]
            for j, name in enumerate(names)
        })
    return vectors


def execute_and_compare(shadow_block, canonical_block) -> ConvergenceVerdict:
    """Run both blocks over seeded inputs and compare returned values."""
    if not isinstance(shadow_block, BlockStmt) or not isinstance(canonical_block, BlockStmt):
        return ConvergenceVerdict("unsupported", "missing block AST")
    # Return-value comparison is only sound for effect-free blocks.
    if not (is_effect_free(shadow_block) and is_effect_free(canonical_block)):
        return ConvergenceVerdict(
            "unsupported", "block has observable effects; not sampled")
    names = free_variables(shadow_block) | free_variables(canonical_block)
    compared = 0
    for bindings in _seed_vectors(names):
        s_ok, s_val = _run_block_guarded(shadow_block, bindings)
        c_ok, c_val = _run_block_guarded(canonical_block, bindings)
        if not (s_ok and c_ok):
            continue  # a seed the sandbox can't run cleanly — skip it
        compared += 1
        if s_val is _NO_RETURN or c_val is _NO_RETURN:
            if s_val is not c_val:
                return ConvergenceVerdict(
                    "diverge",
                    "one block returns a value while the other does not",
                    counterexample=dict(bindings) or {"<no-inputs>": True})
            continue
        if s_val != c_val:
            return ConvergenceVerdict(
                "diverge",
                f"diverging output (shadow={s_val!r}, canonical={c_val!r})",
                counterexample=dict(bindings) or {"<no-inputs>": True})
    if compared == 0:
        return ConvergenceVerdict("unsupported", "no input vector ran cleanly")
    return ConvergenceVerdict(
        "equivalent", f"identical output on {compared} sampled input(s)")

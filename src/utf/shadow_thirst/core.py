"""
Shadow Thirst Core — Mutation Parser, Analyzers, and Promotion Flow
Parses mutation definitions and runs 6 analyzers to determine PROMOTE/REJECT.

The analyzers reason over the **real Thirsty-Lang AST** (produced by
``utf.thirsty_lang``'s own lexer + parser), not over substrings of the source.
A variable merely *named* ``nowhere`` no longer trips the determinism check,
and a ``canonical.`` mention inside a comment no longer trips plane isolation —
because comments and incidental substrings simply aren't nodes in the tree.
When a block cannot be parsed, each analyzer falls back to the original lexical
heuristic so partial/garbled input still produces a verdict.
"""
import re
import hashlib
import dataclasses
from dataclasses import dataclass
from typing import Optional, List, Tuple

from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.ast import (
    Expr, Stmt, BlockStmt, Program, ShadowThirstMutation,
    VariableDecl, AssignStmt, CallExpr, Identifier, ReturnStmt,
    ForStmt, WhileStmt, NewExpr, FloodExpr, ArrayLiteral,
    PourStmt, SipStmt, ImportStmt,
    IntLiteral, FloatLiteral, StringLiteral, BoolLiteral, NoneLiteral,
)


class AnalysisLevel:
    CRITICAL = "critical"
    NON_CRITICAL = "non-critical"


# --- AST utilities (shared by the analyzers) ---

def _iter_child_values(value):
    """Yield AST nodes reachable from a dataclass-field value."""
    if isinstance(value, (Expr, Stmt)):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_child_values(item)


def astwalk(node):
    """Yield ``node`` and every descendant AST node (pre-order)."""
    if node is None:
        return
    yield node
    for f in dataclasses.fields(node):
        if f.name == "span":
            continue
        yield from (
            descendant
            for child in _iter_child_values(getattr(node, f.name))
            for descendant in astwalk(child)
        )


def parse_block(code: str):
    """Parse a snippet of Thirsty-Lang into a BlockStmt, or None on failure.

    The snippet is wrapped in braces and run through the language's own
    lexer/parser. Returns the first ``BlockStmt`` produced, or ``None`` if the
    source is empty or does not parse into a block.
    """
    if not code or not code.strip():
        return None
    try:
        tokens = Lexer("{\n" + code + "\n}").lex()
        program = Parser(tokens).parse()
    except Exception:
        return None
    if not isinstance(program, Program):
        return None
    for stmt in program.stmts:
        if isinstance(stmt, BlockStmt):
            return stmt
    return None


def _structural_signature(node, namemap):
    """Alpha-renamed structural signature of an AST subtree.

    Identifier *names* are replaced by positional placeholders (so two blocks
    that differ only in variable naming compare equal), while literal values
    and node shapes are preserved (so a different computation diverges).
    """
    if isinstance(node, Identifier):
        idx = namemap.setdefault(node.name, len(namemap))
        return ("Id", idx)
    if isinstance(node, (IntLiteral, FloatLiteral, StringLiteral, BoolLiteral)):
        return (type(node).__name__, node.value)
    if isinstance(node, NoneLiteral):
        return ("NoneLiteral",)
    if isinstance(node, (Expr, Stmt)):
        parts = [type(node).__name__]
        for f in dataclasses.fields(node):
            if f.name == "span":
                continue
            value = getattr(node, f.name)
            # A string ``name`` field is a binding identifier (e.g. the bound
            # name of a VariableDecl); alpha-rename it so two blocks that differ
            # only in variable naming still compare equal.
            if f.name == "name" and isinstance(value, str):
                idx = namemap.setdefault(value, len(namemap))
                parts.append(("BindId", idx))
            else:
                parts.append(_sig_value(value, namemap))
        return tuple(parts)
    return ("lit", node)


def _sig_value(value, namemap):
    if isinstance(value, (Expr, Stmt)):
        return _structural_signature(value, namemap)
    if isinstance(value, (list, tuple)):
        return tuple(_sig_value(v, namemap) for v in value)
    return value


@dataclass
class AnalysisResult:
    analyzer: str
    passed: bool
    level: str = AnalysisLevel.CRITICAL
    message: str = ""

    @property
    def name(self):
        return self.analyzer

    def __str__(self):
        status = "✅ PASS" if self.passed else "❌ FAIL"
        return f"{status} [{self.level}] {self.analyzer}: {self.message}"


@dataclass
class ShadowModule:
    """Parsed shadow thirst mutation.

    ``*_code`` are the raw block sources (kept for replay hashing and the
    lexical fallback). ``*_ast`` are the parsed Thirsty-Lang blocks the
    analyzers reason over; they are filled in automatically from the code
    strings (or supplied directly by :class:`MutationParser`).
    """
    name: str
    shadow_code: str = ""
    invariant_code: str = ""
    canonical_code: str = ""
    source: str = ""
    shadow_ast: Optional[Stmt] = None
    invariant_ast: Optional[Stmt] = None
    canonical_ast: Optional[Stmt] = None

    def __post_init__(self):
        # Parse any block whose AST was not supplied directly. Failures leave
        # the AST as None, and the analyzers fall back to the lexical path.
        if self.shadow_ast is None:
            self.shadow_ast = parse_block(self.shadow_code)
        if self.invariant_ast is None:
            self.invariant_ast = parse_block(self.invariant_code)
        if self.canonical_ast is None:
            self.canonical_ast = parse_block(self.canonical_code)

    def replay_hash(self) -> str:
        return hashlib.sha256(self.source.encode('utf-8')).hexdigest()


class MutationParser:
    """Parses mutation definitions from source text."""

    MUTATION_RE = re.compile(
        r'mutation\s+(\w+)\s*\{\s*'
        r'validated_canonical\s*\{'
        r'(.*)\}'
        r'\s*\}',
        re.DOTALL
    )

    BLOCK_RE = re.compile(
        r'(shadow|invariant|canonical)\s*\{'
        r'(.*?)\}',
        re.DOTALL
    )

    @classmethod
    def parse(cls, text: str) -> ShadowModule:
        """Parse mutation source text into a ShadowModule."""
        text = text.strip()
        mut_match = cls.MUTATION_RE.search(text)
        if not mut_match:
            raise ValueError("No valid mutation definition found")

        name = mut_match.group(1)
        validated_canonical_body = mut_match.group(2)

        module = ShadowModule(name=name, source=text)
        shadow_code = ""
        invariant_code = ""
        canonical_code = ""

        for block_match in cls.BLOCK_RE.finditer(validated_canonical_body):
            block_type = block_match.group(1).strip()
            block_content = block_match.group(2).strip()

            if block_type == 'shadow':
                shadow_code = block_content
                module.shadow_code = shadow_code
            elif block_type == 'invariant':
                invariant_code = block_content
                module.invariant_code = invariant_code
            elif block_type == 'canonical':
                canonical_code = block_content
                module.canonical_code = canonical_code

        # Also try parsing without the nested validated_canonical wrapper
        if not shadow_code and not invariant_code and not canonical_code:
            direct_blocks = cls.BLOCK_RE.finditer(text[len(f"mutation {name}"):])
            for block_match in direct_blocks:
                block_type = block_match.group(1).strip()
                block_content = block_match.group(2).strip()
                if block_type == 'shadow':
                    module.shadow_code = block_content
                elif block_type == 'invariant':
                    module.invariant_code = block_content
                elif block_type == 'canonical':
                    module.canonical_code = block_content

        # Prefer the language's own grammar: parse the whole mutation through
        # the real parser and lift the genuine shadow/invariant/canonical blocks
        # off the ShadowThirstMutation node. Falls back to the per-block parse
        # already done in ShadowModule.__post_init__ when this doesn't apply.
        try:
            program = Parser(Lexer(text).lex()).parse()
            for stmt in program.stmts:
                if isinstance(stmt, ShadowThirstMutation):
                    if stmt.shadow_block is not None:
                        module.shadow_ast = stmt.shadow_block
                    if stmt.invariant_block is not None:
                        module.invariant_ast = stmt.invariant_block
                    if stmt.canonical_block is not None:
                        module.canonical_ast = stmt.canonical_block
                    break
        except Exception:
            pass

        return module


# --- Analyzers ---
#
# Every analyzer is AST-first: it walks the parsed Thirsty-Lang block when one
# is available, and only falls back to the original substring heuristic when the
# block did not parse. This is what turns Shadow Thirst from a lexical linter
# into a real verifier — it distinguishes a *call* to `now()` from a variable
# named `nowhere`, and a write to a `canonical_*` binding from the word
# "canonical" appearing in a comment.

def _is_canonical_name(name: str) -> bool:
    low = name.lower()
    return low == "canonical_state" or low.startswith("canonical")


class PlaneIsolationAnalyzer:
    """Ensures the shadow plane never writes into canonical state."""

    def analyze(self, module: ShadowModule) -> AnalysisResult:
        ast = module.shadow_ast
        if ast is not None:
            writes = []
            for node in astwalk(ast):
                if isinstance(node, VariableDecl) and _is_canonical_name(node.name):
                    writes.append(node.name)
                elif (isinstance(node, AssignStmt)
                      and isinstance(node.target, Identifier)
                      and _is_canonical_name(node.target.name)):
                    writes.append(node.target.name)
                elif (isinstance(node, CallExpr)
                      and isinstance(node.callee, Identifier)
                      and "canonical" in node.callee.name.lower()):
                    writes.append(node.callee.name + "()")
            if writes:
                return AnalysisResult(
                    analyzer="PlaneIsolation", passed=False,
                    level=AnalysisLevel.CRITICAL,
                    message=f"Shadow block writes to canonical state: {', '.join(sorted(set(writes)))}",
                )
            return AnalysisResult(
                analyzer="PlaneIsolation", passed=True,
                level=AnalysisLevel.CRITICAL,
                message="Shadow block properly isolated from canonical state",
            )
        return self._lexical(module)

    def _lexical(self, module: ShadowModule) -> AnalysisResult:
        if 'canonical.' in module.shadow_code or 'canonical_state' in module.shadow_code:
            return AnalysisResult(
                analyzer="PlaneIsolation", passed=False,
                level=AnalysisLevel.CRITICAL,
                message="Shadow block writes to canonical state (lexical)",
            )
        return AnalysisResult(
            analyzer="PlaneIsolation", passed=True,
            level=AnalysisLevel.CRITICAL,
            message="Shadow block properly isolated from canonical state (lexical)",
        )


class DeterminismAnalyzer:
    """Ensures the shadow block calls no non-deterministic functions."""

    NON_DETERMINISTIC = {'now', 'rand', 'random', 'time', 'uuid', 'date', 'clock'}
    # Calls whose results vary across replays (matched on the callee name).
    NON_DET_CALLS = {
        'now', 'rand', 'random', 'randint', 'time', 'gettime', 'get_time',
        'uuid', 'uuid4', 'date', 'today', 'clock', 'utcnow', 'timestamp',
    }

    def analyze(self, module: ShadowModule) -> AnalysisResult:
        ast = module.shadow_ast
        if ast is not None:
            found = []
            for node in astwalk(ast):
                if (isinstance(node, CallExpr)
                        and isinstance(node.callee, Identifier)
                        and node.callee.name.lower() in self.NON_DET_CALLS):
                    found.append(node.callee.name)
            if found:
                return AnalysisResult(
                    analyzer="Determinism", passed=False,
                    level=AnalysisLevel.CRITICAL,
                    message=f"Non-deterministic calls found: {', '.join(sorted(set(found)))}",
                )
            return AnalysisResult(
                analyzer="Determinism", passed=True,
                level=AnalysisLevel.NON_CRITICAL,
                message="Shadow block is deterministic",
            )
        return self._lexical(module)

    def _lexical(self, module: ShadowModule) -> AnalysisResult:
        found_ops = [op for op in self.NON_DETERMINISTIC
                     if op in module.shadow_code.lower()]
        if found_ops:
            return AnalysisResult(
                analyzer="Determinism", passed=False,
                level=AnalysisLevel.CRITICAL,
                message=f"Non-deterministic operations found: {', '.join(found_ops)} (lexical)",
            )
        return AnalysisResult(
            analyzer="Determinism", passed=True,
            level=AnalysisLevel.NON_CRITICAL,
            message="Shadow block is deterministic (lexical)",
        )


class ResourceEstimator:
    """Estimates CPU/memory cost of the shadow block from its structure."""

    CPU_LIMIT_MS = 1000
    MEMORY_LIMIT_BYTES = 256 * 1024 * 1024  # 256MB

    # Per-node CPU weights (ms) for the AST path.
    NODE_WEIGHTS = {
        ForStmt: 10, WhileStmt: 20, CallExpr: 5, NewExpr: 8, FloodExpr: 4,
    }
    CPU_WEIGHTS = {
        'for': 10, 'while': 20, 'sort': 50, 'map': 5, 'filter': 5,
        'reduce': 10, 'recursion': 50, 'loop': 15,
    }

    def analyze(self, module: ShadowModule) -> AnalysisResult:
        ast = module.shadow_ast
        if ast is not None:
            estimated_cpu = 0
            node_count = 0
            for node in astwalk(ast):
                node_count += 1
                for node_type, weight in self.NODE_WEIGHTS.items():
                    if isinstance(node, node_type):
                        estimated_cpu += weight
            estimated_cpu += node_count  # base cost per node
            estimated_memory = node_count * 64
            return self._verdict(estimated_cpu, estimated_memory)
        return self._lexical(module)

    def _verdict(self, estimated_cpu, estimated_memory) -> AnalysisResult:
        issues = []
        if estimated_cpu > self.CPU_LIMIT_MS:
            issues.append(f"CPU estimate {estimated_cpu}ms exceeds {self.CPU_LIMIT_MS}ms limit")
        if estimated_memory > self.MEMORY_LIMIT_BYTES:
            issues.append(f"Memory estimate {estimated_memory} bytes exceeds {self.MEMORY_LIMIT_BYTES} bytes limit")
        if issues:
            return AnalysisResult(
                analyzer="ResourceEstimator", passed=False,
                level=AnalysisLevel.CRITICAL if estimated_cpu > self.CPU_LIMIT_MS else AnalysisLevel.NON_CRITICAL,
                message="; ".join(issues),
            )
        return AnalysisResult(
            analyzer="ResourceEstimator", passed=True,
            level=AnalysisLevel.CRITICAL,
            message=f"Resources within limits (CPU: ~{estimated_cpu}ms, Mem: ~{estimated_memory} bytes)",
        )

    def _lexical(self, module: ShadowModule) -> AnalysisResult:
        code = module.shadow_code.lower()
        estimated_cpu = sum(code.count(k) * w for k, w in self.CPU_WEIGHTS.items())
        estimated_cpu += len(code.split('\n')) * 5
        estimated_memory = len(code) * 2
        return self._verdict(estimated_cpu, estimated_memory)


class PuritySpringAnalyzer:
    """Ensures the invariant block is a pure expression (no side effects)."""

    IMPURE_KEYWORDS = {'print', 'write', 'read', 'input', 'open', 'exec', 'eval', 'import'}
    IMPURE_CALLS = {
        'print', 'pour', 'sip', 'write', 'read', 'input', 'open', 'exec',
        'eval', 'flood', 'evaporate', 'push', 'pop',
    }

    def analyze(self, module: ShadowModule) -> AnalysisResult:
        if not module.invariant_code and module.invariant_ast is None:
            return AnalysisResult(
                analyzer="PuritySpring", passed=True,
                level=AnalysisLevel.CRITICAL,
                message="No invariant block to check",
            )
        ast = module.invariant_ast
        if ast is not None:
            impure = []
            for node in astwalk(ast):
                if isinstance(node, (PourStmt, SipStmt, ImportStmt)):
                    impure.append(type(node).__name__)
                elif (isinstance(node, CallExpr)
                      and isinstance(node.callee, Identifier)
                      and node.callee.name.lower() in self.IMPURE_CALLS):
                    impure.append(node.callee.name + "()")
            if impure:
                return AnalysisResult(
                    analyzer="PuritySpring", passed=False,
                    level=AnalysisLevel.CRITICAL,
                    message=f"Impure operations in invariant: {', '.join(sorted(set(impure)))}",
                )
            return AnalysisResult(
                analyzer="PuritySpring", passed=True,
                level=AnalysisLevel.CRITICAL,
                message="Invariant block is pure",
            )
        return self._lexical(module)

    def _lexical(self, module: ShadowModule) -> AnalysisResult:
        code = module.invariant_code.lower()
        found_impure = [kw for kw in self.IMPURE_KEYWORDS if kw in code]
        if found_impure:
            return AnalysisResult(
                analyzer="PuritySpring", passed=False,
                level=AnalysisLevel.CRITICAL,
                message=f"Impure operations in invariant: {', '.join(found_impure)} (lexical)",
            )
        return AnalysisResult(
            analyzer="PuritySpring", passed=True,
            level=AnalysisLevel.CRITICAL,
            message="Invariant block is pure (lexical)",
        )


class MemoryEvaporationAnalyzer:
    """Estimates peak memory from allocation-producing AST nodes."""

    PEAK_LIMIT = 256 * 1024 * 1024  # 256MB

    def analyze(self, module: ShadowModule) -> AnalysisResult:
        ast = module.shadow_ast
        if ast is not None:
            node_count = 0
            allocations = 0
            for node in astwalk(ast):
                node_count += 1
                if isinstance(node, NewExpr):
                    allocations += 1000
                elif isinstance(node, (FloodExpr, ArrayLiteral)):  # reservoir / flood
                    allocations += 500
            estimated_peak = node_count * 32 + allocations
            return self._verdict(estimated_peak)
        return self._lexical(module)

    def _verdict(self, estimated_peak) -> AnalysisResult:
        if estimated_peak > self.PEAK_LIMIT:
            return AnalysisResult(
                analyzer="MemoryEvaporation", passed=False,
                level=AnalysisLevel.NON_CRITICAL,
                message=f"Estimated peak memory {estimated_peak} bytes exceeds {self.PEAK_LIMIT} bytes limit",
            )
        return AnalysisResult(
            analyzer="MemoryEvaporation", passed=True,
            level=AnalysisLevel.NON_CRITICAL,
            message=f"Peak memory within limits (~{estimated_peak} bytes)",
        )

    def _lexical(self, module: ShadowModule) -> AnalysisResult:
        code = module.shadow_code
        estimated_peak = len(code) * 4
        estimated_peak += code.count('new') * 1000
        estimated_peak += code.count('list') * 500
        estimated_peak += code.count('map') * 500
        estimated_peak += code.count('string') * 200
        estimated_peak += code.count('reservoir') * 2000
        return self._verdict(estimated_peak)


class CanonicalConvergenceAnalyzer:
    """Checks shadow and canonical converge via structural AST equivalence.

    Both blocks are reduced to an alpha-renamed structural signature: identifier
    *names* become positional placeholders (so naming differences don't matter)
    while node shapes, literal values, and return arity are preserved (so a
    genuinely different computation diverges).
    """

    def analyze(self, module: ShadowModule) -> AnalysisResult:
        if not module.shadow_code or not module.canonical_code:
            return AnalysisResult(
                analyzer="CanonicalConvergence", passed=False,
                level=AnalysisLevel.CRITICAL,
                message="Both shadow and canonical blocks must be present",
            )

        s_ast, c_ast = module.shadow_ast, module.canonical_ast
        if s_ast is not None and c_ast is not None:
            s_sig = _structural_signature(s_ast, {})
            c_sig = _structural_signature(c_ast, {})
            s_returns = sum(1 for n in astwalk(s_ast) if isinstance(n, ReturnStmt))
            c_returns = sum(1 for n in astwalk(c_ast) if isinstance(n, ReturnStmt))
            if s_returns != c_returns:
                return AnalysisResult(
                    analyzer="CanonicalConvergence", passed=False,
                    level=AnalysisLevel.NON_CRITICAL,
                    message=f"Return arity differs (shadow {s_returns}, canonical {c_returns}) — possible divergence",
                )
            if s_sig != c_sig:
                return AnalysisResult(
                    analyzer="CanonicalConvergence", passed=False,
                    level=AnalysisLevel.NON_CRITICAL,
                    message="Shadow and canonical AST shapes differ — possible divergence",
                )
            return AnalysisResult(
                analyzer="CanonicalConvergence", passed=True,
                level=AnalysisLevel.CRITICAL,
                message="Shadow and canonical blocks are structurally equivalent",
            )
        return self._lexical(module)

    def _lexical(self, module: ShadowModule) -> AnalysisResult:
        shadow_lines = [l.strip() for l in module.shadow_code.split('\n') if l.strip()]
        canonical_lines = [l.strip() for l in module.canonical_code.split('\n') if l.strip()]
        if len(shadow_lines) == 0 or len(canonical_lines) == 0:
            return AnalysisResult(
                analyzer="CanonicalConvergence", passed=False,
                level=AnalysisLevel.CRITICAL,
                message="Shadow or canonical block is empty",
            )
        shadow_return_count = module.shadow_code.count('return')
        canonical_return_count = module.canonical_code.count('return')
        if shadow_return_count != canonical_return_count:
            return AnalysisResult(
                analyzer="CanonicalConvergence", passed=False,
                level=AnalysisLevel.NON_CRITICAL,
                message=f"Shadow ({shadow_return_count} returns) and canonical ({canonical_return_count} returns) may not converge",
            )
        shadow_ops = set(re.findall(r'\b[a-z_]+\b', module.shadow_code.lower()))
        canonical_ops = set(re.findall(r'\b[a-z_]+\b', module.canonical_code.lower()))
        overlap = shadow_ops & canonical_ops
        if len(overlap) < max(1, min(len(shadow_ops), len(canonical_ops)) * 0.3):
            return AnalysisResult(
                analyzer="CanonicalConvergence", passed=False,
                level=AnalysisLevel.NON_CRITICAL,
                message="Shadow and canonical blocks use very different operations — possible divergence",
            )
        return AnalysisResult(
            analyzer="CanonicalConvergence", passed=True,
            level=AnalysisLevel.CRITICAL,
            message="Shadow and canonical blocks converge (lexical)",
        )


class PromotionEngine:
    """Executes the promote/reject flow based on analyzer results."""

    def __init__(self):
        self.analyzers = [
            ("PlaneIsolation", PlaneIsolationAnalyzer()),
            ("Determinism", DeterminismAnalyzer()),
            ("ResourceEstimation", ResourceEstimator()),
            ("PuritySpring", PuritySpringAnalyzer()),
            ("MemoryEvaporation", MemoryEvaporationAnalyzer()),
            ("CanonicalConvergence", CanonicalConvergenceAnalyzer()),
        ]

    def evaluate(self, module: ShadowModule) -> Tuple[str, List[AnalysisResult]]:
        """
        Evaluate a mutation module. Returns (verdict, results).
        Verdict is one of: PROMOTE, REJECT, FLAGGED
        """
        results = []

        for name, analyzer in self.analyzers:
            try:
                result = analyzer.analyze(module)
                results.append(result)
            except Exception as e:
                results.append(AnalysisResult(
                    analyzer=name,
                    passed=False,
                    level=AnalysisLevel.CRITICAL,
                    message=f"Analysis error: {e}"
                ))

        # Determine verdict
        critical_failures = [r for r in results if not r.passed and r.level == AnalysisLevel.CRITICAL]
        non_critical_failures = [r for r in results if not r.passed and r.level == AnalysisLevel.NON_CRITICAL]

        if critical_failures:
            verdict = "REJECT"
        elif non_critical_failures:
            verdict = "FLAGGED"
        else:
            verdict = "PROMOTE"

        return verdict, results

    @staticmethod
    def generate_mermaid(module: ShadowModule, verdict: str = "PROMOTE", results: List[AnalysisResult] = None) -> str:
        if results is None:
            results = []
        """Generate a Mermaid flowchart visualization of the promotion flow."""
        lines = ["```mermaid", "flowchart TD"]
        lines.append(f"    M[\"Mutation: {module.name}\"]")

        for i, (name, _) in enumerate([
            ("PlaneIsolationAnalyzer", None),
            ("DeterminismAnalyzer", None),
            ("ResourceEstimator", None),
            ("PuritySpringAnalyzer", None),
            ("MemoryEvaporationAnalyzer", None),
            ("CanonicalConvergenceAnalyzer", None),
        ]):
            r = results[i] if i < len(results) else AnalysisResult(analyzer=name, passed=True)
            status = "✅" if r.passed else "❌"
            lines.append(f"    A{i}[\"{status} {name}\"]")

            if i == 0:
                lines.append(f"    M --> A{i}")
            else:
                lines.append(f"    A{i - 1} --> A{i}")

        lines.append(f"    V[\"Verdict: {verdict}\"]")
        lines.append(f"    A{min(5, len(results) - 1)} --> V")

        if verdict == "PROMOTE":
            lines.append(f"    V --> P[\"🚀 PROMOTE\"]")
        elif verdict == "REJECT":
            lines.append(f"    V --> R[\"❌ REJECT\"]")
        else:
            lines.append(f"    V --> F[\"⚠️ FLAGGED\"]")

        lines.append("```")
        return "\n".join(lines)
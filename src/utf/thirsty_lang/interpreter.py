"""
Thirsty-Lang Tree-Walking Interpreter
Evaluates Thirsty-Lang AST programs with full environment scoping,
governance enforcement, tail-call optimization, and async support.
"""
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from utf.thirsty_lang.ast import (
    ArmorExpr,
    ArrayLiteral,
    AssignStmt,
    BinaryOp,
    BlockStmt,
    BoolLiteral,
    CallExpr,
    CascadeCall,
    ClassDecl,
    CleanupStmt,
    CombineExpr,
    CondenseExpr,
    DefendStrat,
    DripExpr,
    EnumDecl,
    ErrorLiteral,
    EvaporateExpr,
    Expr,
    ExprStmt,
    FloatLiteral,
    FloodExpr,
    ForStmt,
    FunctionDecl,
    GovernedFunctionDecl,
    GuardExpr,
    Identifier,
    IfStmt,
    ImportStmt,
    InterfaceDecl,
    IntLiteral,
    LambdaExpr,
    MemberAccess,
    MorphDef,
    NewExpr,
    NoneLiteral,
    PipeExpr,
    PipelineExpr,
    PourStmt,
    Program,
    QuenchedLiteral,
    ReturnStmt,
    SanitizeExpr,
    SecurityBlock,
    ShadowThirstMutation,
    SipStmt,
    SpillageStmt,
    Stmt,
    StringLiteral,
    StructDecl,
    SymbolExpr,
    SymbolStmt,
    ThrowStmt,
    TimesStmt,
    UnaryOp,
    VariableDecl,
    WhileStmt,
)
from utf.thirsty_lang.module_system import (
    SENSITIVE_STDLIB_CAPABILITIES,
    resolve_import,
)
from utf.thirsty_lang.token import TokenType


class ReturnException(Exception):
    """Used for control flow to unwind non-tail-called returns."""
    def __init__(self, value):
        self.value = value


class SpillageException(Exception):
    """Represents an error thrown via throw/spillage."""
    def __init__(self, value):
        self.value = value


class GovernanceViolation(Exception):
    """Raised when a governed function is denied at runtime.

    Carries the governed function name, a human-readable reason, and the
    optional ``TarlProof`` produced when the denial came from the policy
    engine, so callers (the CLI) can surface the proof certificate.
    """
    def __init__(self, name: str, reason: str, proof=None):
        self.name = name
        self.reason = reason
        self.proof = proof
        super().__init__(f"governance denied: {name}: {reason}")


class Environment:
    """Scoped variable storage."""

    def __init__(self, parent: 'Environment | None' = None):
        self.parent = parent
        self.vars: dict[str, object] = {}
        self.mutable: dict[str, bool] = {}

    def define(self, name: str, value: object, is_mut: bool = False):
        self.vars[name] = value
        self.mutable[name] = is_mut

    def get(self, name: str) -> object:
        if name in self.vars:
            return self.vars[name]
        if self.parent:
            return self.parent.get(name)
        raise NameError(f"Undefined variable: '{name}'")

    def set(self, name: str, value: object):
        if name in self.vars:
            if not self.mutable.get(name, False):
                raise TypeError(f"Cannot assign to immutable variable: '{name}'")
            self.vars[name] = value
            return
        if self.parent:
            self.parent.set(name, value)
            return
        raise NameError(f"Undefined variable: '{name}'")

    def has(self, name: str) -> bool:
        return name in self.vars or bool(self.parent and self.parent.has(name))

    def enter_scope(self) -> 'Environment':
        return Environment(self)

    def __repr__(self):
        return f"Environment({list(self.vars.keys())})"


class FountainInstance:
    """Instance of a fountain (class)."""

    def __init__(self, cls_decl: ClassDecl, env: Environment):
        self.cls_decl = cls_decl
        self.fields: dict[str, Any] = {}
        self.methods: dict[str, Any] = {}
        for field_spec in cls_decl.fields:
            self.fields[field_spec[0]] = None
        for method in cls_decl.methods:
            self.methods[method.name] = method

    def get_field(self, name: str) -> object:
        if name in self.fields:
            return self.fields[name]
        raise NameError(f"Undefined field: '{name}'")

    def set_field(self, name: str, value: object):
        if name in self.fields:
            self.fields[name] = value
        else:
            raise NameError(f"Undefined field: '{name}'")


class Interpreter:
    """Tree-walking interpreter with TCO, governance, and async support."""

    def __init__(self, opt_level: int = 0, debug_mode: bool = False):
        self.env = Environment()
        self.opt_level = opt_level
        self.debug_mode = debug_mode
        self.tco_enabled = opt_level >= 1
        self.mode = "core"
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._last_span = None
        # Governance wiring (Part A): optional policy engine + authority context.
        self.tarl_runtime = None
        self.authority = None
        # The verified credential (if any) behind ``authority``, retained so the
        # capability broker can be built with the same authenticity it sees here.
        self._verified_authority: Any = None
        # Optional filesystem confinement for governed file capabilities; when
        # set, ``thirst::fs`` targets are confined to these roots (C042).
        self.path_guard: Any = None
        # Authority provenance: a bare string authority is self-asserted
        # (authenticated=False, no grants); a verified signed claim sets these.
        self.authority_authenticated = False
        self.authority_grants: tuple[str, ...] = ()
        # Hardened posture: when True, governed gates additionally require an
        # authenticated authority and Ed25519-signed proofs, or they fail closed.
        self.hardened = False
        self._last_proof = None
        self._register_builtins()
        if self.opt_level >= 2:
            self._inline_simple_builtins()
        if self.opt_level >= 3:
            self._precompute_constants()

    def _precompute_constants(self):
        """Opt level 3: Pre-compute constant expressions at init time."""
        self._const_cache = {}

    def _inline_simple_builtins(self):
        """Opt level 2: Inline simple builtin functions for faster execution."""
        self._inlineable_builtins = set()
        for name in ("length", "size", "abs", "print", "pour", "push", "pop", "flood"):
            if name in self.env.vars:
                self._inlineable_builtins.add(name)

    def _register_builtins(self):
        """Register builtin functions in the global environment."""
        builtins_map = {
            "length": lambda x: len(x) if hasattr(x, '__len__') else 0,
            "contains": lambda x, y: y in x if hasattr(x, '__contains__') else False,
            "split": lambda s, sep=None: s.split(sep) if isinstance(s, str) else [],
            "abs": lambda x: abs(x) if hasattr(x, '__abs__') else 0,
            "min": lambda *args: min(args) if args else 0,
            "max": lambda *args: max(args) if args else 0,
            "push": lambda r, v: (r.append(v), len(r))[-1] if isinstance(r, list) else 0,  # type: ignore[func-returns-value]
            "pop": lambda r: r.pop() if isinstance(r, list) and r else None,
            "size": lambda x: len(x) if hasattr(x, '__len__') else 0,
            "get": lambda x, i: x[i] if hasattr(x, '__getitem__') else None,
            "flood": lambda r, v: (r.append(v), r)[-1] if isinstance(r, list) else r,  # type: ignore[func-returns-value]
            "condense": lambda q: q.get("value") if isinstance(q, dict) and "value" in q else None,
            "evaporate": lambda q: q.pop("value") if isinstance(q, dict) and "value" in q else None,
            "strain": lambda x: x,
            "transmute": lambda x, t: x,
            "distill": lambda x: x,
            "print": self._builtin_print,
            "pour": self._builtin_pour,
        }
        for name, func in builtins_map.items():
            self.env.define(name, func, is_mut=False)

    def _builtin_print(self, *args):
        self._gate_capability("write", "stdout")
        print(*args)
        return args[-1] if args else None

    def _builtin_pour(self, *args):
        self._gate_capability("write", "stdout")
        print(*args)
        return args[-1] if args else None

    def interpret(self, ast: Program, mode: str = "core",
                  force_mode: bool = False) -> object:
        """Interpret an entire Program AST.

        ``force_mode`` keeps ``mode`` even when the program declares a different
        one in its header — used when importing a ``.thirsty`` module under a
        governed caller, so the imported module's own ``: core`` header cannot
        downgrade out of the caller's governance.
        """
        self.mode = mode
        if ast.header and not force_mode:
            self.mode = ast.header.mode
        # Fail-closed: a governed program the parser flagged as malformed must
        # not execute. The parser already discarded its statements; refuse the
        # whole program with a denial proof rather than running an empty body.
        if self.mode == "governed" and getattr(ast, "parse_failed", False):
            from utf.tarl.spec import TarlVerdict
            proof = self._make_decision_proof(
                source="<fail-closed: governed module failed to parse>",
                context={"action": "execute", "reason": "parse_failed"},
                verdict=TarlVerdict.DENY, matched_condition="",
                trace=[{"kind": "fail-closed", "action": "execute",
                        "reason": "governed module had parse errors; "
                                  "execution refused"}])
            self._last_proof = proof
            raise GovernanceViolation(
                "<module>",
                "fail-closed: governed module failed to parse; refusing to "
                "execute recovered statements",
                proof)
        result = None
        try:
            for stmt in ast.stmts:
                result = self._execute(stmt)
                if isinstance(result, (ReturnException, SpillageException)):
                    break
        except ReturnException as e:
            result = e.value
        except SpillageException as e:
            result = e.value
        return result

    def _with_debug(self, stmt_or_expr, context: str = ""):
        """Wrapper that adds source-location tracking in debug mode."""
        if not self.debug_mode:
            return None  # No wrapping needed
        span = getattr(stmt_or_expr, 'span', None)
        if span:
            self._last_span = span
        return f"at line {span[0]}, column {span[1]}" if span else None

    def _execute(self, stmt: Stmt) -> object:
        """Execute a statement. Returns a value for expressions or None."""
        if self.debug_mode:
            try:
                return self._execute_impl(stmt)
            except Exception as e:
                loc = self._with_debug(stmt)
                loc_msg = f" at {loc}" if loc else ""
                raise type(e)(f"{e}{loc_msg}") from e
        else:
            return self._execute_impl(stmt)

    def _evaluate(self, expr: Expr) -> Any:
        """Evaluate an expression and return its value."""
        if self.debug_mode:
            try:
                return self._evaluate_impl(expr)
            except Exception as e:
                loc = self._with_debug(expr)
                loc_msg = f" at {loc}" if loc else ""
                raise type(e)(f"{e}{loc_msg}") from e
        else:
            return self._evaluate_impl(expr)

    def _execute_impl(self, stmt: Stmt) -> object:
        """Execute a statement. Returns a value for expressions or None."""
        if isinstance(stmt, BlockStmt):
            return self._execute_block(stmt)
        elif isinstance(stmt, ExprStmt):
            return self._evaluate(stmt.expr)
        elif isinstance(stmt, VariableDecl):
            return self._execute_variable_decl(stmt)
        elif isinstance(stmt, AssignStmt):
            return self._execute_assign(stmt)
        elif isinstance(stmt, SymbolStmt):
            return self._execute_symbol_stmt(stmt)
        elif isinstance(stmt, IfStmt):
            return self._execute_if(stmt)
        elif isinstance(stmt, WhileStmt):
            return self._execute_while(stmt)
        elif isinstance(stmt, ForStmt):
            return self._execute_for(stmt)
        elif isinstance(stmt, TimesStmt):
            return self._execute_times(stmt)
        elif isinstance(stmt, ReturnStmt):
            return self._execute_return(stmt)
        elif isinstance(stmt, PourStmt):
            return self._execute_pour(stmt)
        elif isinstance(stmt, SipStmt):
            return self._execute_sip(stmt)
        elif isinstance(stmt, ImportStmt):
            return self._execute_import(stmt)
        elif isinstance(stmt, FunctionDecl):
            return self._execute_function_decl(stmt)
        elif isinstance(stmt, ClassDecl):
            return self._execute_class_decl(stmt)
        elif isinstance(stmt, SpillageStmt):
            return self._execute_spillage(stmt)
        elif isinstance(stmt, CleanupStmt):
            return self._execute_cleanup(stmt)
        elif isinstance(stmt, ThrowStmt):
            return self._execute_throw(stmt)
        elif isinstance(stmt, SecurityBlock):
            return self._execute_security_block(stmt)
        elif isinstance(stmt, CascadeCall):
            return self._execute_cascade(stmt)
        elif isinstance(stmt, MorphDef):
            return self._execute_morph(stmt)
        elif isinstance(stmt, DefendStrat):
            return None
        elif isinstance(stmt, EnumDecl):
            return None
        elif isinstance(stmt, StructDecl):
            return None
        elif isinstance(stmt, InterfaceDecl):
            return None
        elif isinstance(stmt, GovernedFunctionDecl):
            return self._execute_governed_function_decl(stmt)
        elif isinstance(stmt, ShadowThirstMutation):
            return self._execute_shadow_thirst(stmt)
        return None

    def _execute_block(self, block: BlockStmt) -> object:
        old_env = self.env
        self.env = self.env.enter_scope()
        result = None
        try:
            for stmt in block.statements:
                result = self._execute(stmt)
                if isinstance(result, (ReturnException, SpillageException)):
                    break
        finally:
            self.env = old_env
        return result

    def _execute_variable_decl(self, stmt: VariableDecl) -> object:
        if self.mode == "strict" and stmt.init_expr is None:
            raise RuntimeError(
                f"'strict' module requires '{stmt.name}' to be initialized")
        value = None
        if stmt.init_expr:
            value = self._evaluate(stmt.init_expr)
        self.env.define(stmt.name, value, is_mut=stmt.is_mut)
        return None  # drink is a statement, not an expression — no value propagation

    def _execute_assign(self, stmt: AssignStmt) -> object:
        value = self._evaluate(stmt.value)
        if isinstance(stmt.target, Identifier):
            self.env.set(stmt.target.name, value)
        elif isinstance(stmt.target, MemberAccess):
            obj = self._evaluate(stmt.target.obj)
            if isinstance(obj, FountainInstance):
                obj.fields[stmt.target.member] = value
            elif isinstance(obj, dict):
                obj[stmt.target.member] = value
            else:
                raise TypeError(
                    f"Cannot assign member '{stmt.target.member}' on "
                    f"{type(obj).__name__}")
        return value

    def _execute_symbol_stmt(self, stmt: SymbolStmt) -> object:
        self.env.define(stmt.symbol_name, stmt.symbol_name, is_mut=False)
        return None

    def _execute_if(self, stmt: IfStmt) -> object:
        condition = self._evaluate(stmt.condition)
        if condition:
            return self._execute(stmt.then_block)
        elif stmt.else_block:
            if isinstance(stmt.else_block, IfStmt):
                return self._execute_if(stmt.else_block)
            return self._execute(stmt.else_block)
        return None

    def _execute_while(self, stmt: WhileStmt) -> object:
        result = None
        while self._evaluate(stmt.condition):
            result = self._execute(stmt.body)
            if isinstance(result, (ReturnException, SpillageException)):
                return result
        return result

    def _execute_for(self, stmt: ForStmt) -> object:
        iterable = self._evaluate(stmt.iterable)
        result = None
        if hasattr(iterable, '__iter__'):
            for item in iterable:
                old_env = self.env
                self.env = self.env.enter_scope()
                self.env.define(stmt.variable.name, item, is_mut=False)
                try:
                    result = self._execute(stmt.body)
                    if isinstance(result, (ReturnException, SpillageException)):
                        return result
                finally:
                    self.env = old_env
        return result

    def _execute_times(self, stmt: TimesStmt) -> object:
        count = self._evaluate(stmt.count)
        result = None
        for _ in range(int(count)):
            result = self._execute(stmt.body)
            if isinstance(result, (ReturnException, SpillageException)):
                return result
        return result

    def _execute_return(self, stmt: ReturnStmt) -> object:
        value = self._evaluate(stmt.value) if stmt.value else None
        if self.tco_enabled and stmt.value and isinstance(stmt.value, CallExpr):
            # TCO: evaluate the call directly instead of raising ReturnException
            return self._evaluate_call(stmt.value)
        raise ReturnException(value)

    def _execute_pour(self, stmt: PourStmt) -> object:
        if self.mode == "pure":
            raise RuntimeError(
                "I/O ('pour') is not allowed in a 'pure' module")
        self._gate_capability("write", "stdout")
        value = self._evaluate(stmt.value)
        print(value)
        return None  # pour handles its own output — no value propagation

    def _execute_sip(self, stmt: SipStmt) -> object:
        if self.mode == "pure":
            raise RuntimeError(
                "I/O ('sip') is not allowed in a 'pure' module")
        self._gate_capability("read", "stdin")
        value = input()
        if isinstance(stmt.target, Identifier):
            self.env.set(stmt.target.name, value)
        return value

    def _make_decision_proof(self, *, source: str, context: dict,
                             verdict, matched_condition: str, trace: list):
        """Build an (unsigned) ``TarlProof`` for a governance decision made
        outside the policy engine — a fail-closed capability denial or a
        design-by-contract verdict. Same certificate shape as a policy proof
        (``rule_index = -1``, no rule), so every governed decision carries a
        proof. Unsigned; see utf/tarl/spec.py:TarlProof for the signing model.
        """
        import hashlib
        import json
        from datetime import UTC, datetime

        from utf.tarl.spec import TarlProof
        policy_hash = "sha256:" + hashlib.sha256(
            source.encode("utf-8")).hexdigest()
        ctx_bytes = json.dumps(
            context, sort_keys=True, default=str, separators=(",", ":")
        ).encode("utf-8")
        context_hash = "sha256:" + hashlib.sha256(ctx_bytes).hexdigest()
        return TarlProof(
            policy_hash=policy_hash,
            context_hash=context_hash,
            rule_index=-1,
            matched_condition=matched_condition,
            verdict=verdict,
            evaluated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            trace=trace,
            signature="",
            key_id="",
        )

    def _gate_capability(
        self, action: str, target: str, *, path: str | None = None
    ) -> None:
        """Capability gate for sensitive operations (imports, I/O) in governed
        mode. Fail-closed: in governed mode a gated capability is denied unless
        a TARL policy engine + authority are attached AND return ALLOW. With no
        policy engine wired, governed mode cannot authorize the capability, so
        it is denied with a proof — governed mode never implies authority.
        Deny-by-default (no matching rule → DENY) comes from the engine itself.
        Core (ungoverned) mode is unaffected.

        The actual policy evaluation is delegated to a
        :class:`~utf.tarl.broker.CapabilityBroker` so in-language stdlib effects
        and out-of-language adapters share one mediation path (invariant #7,
        "no adapter side doors"). ``path`` (when given) is brokered through the
        path guard so the policy sees the confined canonical filesystem target.
        """
        if self.mode != "governed":
            return
        from utf.tarl.broker import CapabilityDenied
        from utf.tarl.spec import TarlVerdict
        ctx = {"action": action, "target": str(target),
               **self._authority_context()}
        # Hardened-mode prerequisites (authenticated authority + Ed25519 proofs)
        # fail closed before any policy is consulted.
        hardened_violation = self._hardened_precheck(action, target)
        if hardened_violation is not None:
            raise hardened_violation
        # Fail-closed: governed but no policy engine/authority to grant it.
        if self.tarl_runtime is None or self.authority is None:
            proof = self._make_decision_proof(
                source="<fail-closed: governed mode without policy engine>",
                context=ctx, verdict=TarlVerdict.DENY, matched_condition="",
                trace=[{"kind": "fail-closed", "action": action,
                        "target": str(target),
                        "reason": "no policy engine wired to authorize "
                                  "capability in governed mode"}])
            self._last_proof = proof
            raise GovernanceViolation(
                f"{action} {target}",
                "fail-closed: governed mode requires a policy engine to "
                "authorize this capability (run with --policy)",
                proof)
        broker = self.make_broker()
        try:
            if path is not None and self.path_guard is not None:
                decision = broker.require_path(action, path)
            else:
                decision = broker.require(action, target)
        except CapabilityDenied as denied:
            proof = denied.decision.proof
            self._last_proof = proof
            raise GovernanceViolation(
                f"{action} {target}",
                denied.decision.reason
                or f"capability denied ({proof.verdict})",
                proof) from None
        except GovernanceViolation:
            raise
        except Exception as exc:
            # Resource exhaustion / evaluator failure must DENY, never fail open
            # (C037), and must surface as a governance denial that spillage
            # cannot swallow — not a raw exception.
            proof = self._make_decision_proof(
                source="<fail-closed: policy evaluation error>",
                context=ctx, verdict=TarlVerdict.DENY, matched_condition="",
                trace=[{"kind": "fail-closed", "action": action,
                        "target": str(target),
                        "reason": f"policy evaluation error: {exc}"}])
            self._last_proof = proof
            raise GovernanceViolation(
                f"{action} {target}",
                f"fail-closed: policy evaluation error: {exc}", proof) from exc
        self._last_proof = decision.proof

    def _wrap_imported_module_capabilities(
        self, module_path: str, module: object
    ) -> Any:
        """Wrap sensitive stdlib module functions with runtime capability gates.

        Capability actions come from the single-source-of-truth table
        ``SENSITIVE_STDLIB_CAPABILITIES`` in ``module_system`` so every sensitive
        callable carries an explicit ``read``/``write``/``network``/``execute``
        action; the gate routing here only consumes that metadata.
        """
        if self.mode != "governed" or not isinstance(module, dict):
            return module

        policy = SENSITIVE_STDLIB_CAPABILITIES.get(module_path, {})
        if not policy:
            return module

        wrapped = dict(module)
        for name, action in policy.items():
            fn = wrapped.get(name)
            if not callable(fn):
                continue

            # Filesystem targets carry a real path in arg 0 — broker them through
            # the path guard so traversal/symlink escapes fail closed (C042).
            is_fs = module_path == "thirst::fs"

            def guarded(*args, __fn=fn, __name=name, __action=action,
                        __is_fs=is_fs):
                target_detail = args[0] if args else ""
                target = f"{module_path}.{__name}"
                if target_detail != "":
                    target = f"{target}:{target_detail}"
                path = (target_detail if __is_fs and isinstance(target_detail, str)
                        and target_detail != "" else None)
                self._gate_capability(__action, target, path=path)
                return __fn(*args)

            wrapped[name] = guarded
        return wrapped

    def _import_thirsty_file(self, path: str) -> dict:
        """Import a ``.thirsty`` source file under the caller's governance.

        The detached, core-mode interpreter that ``resolve_import`` uses for
        file imports is a governance bypass: an imported module's top-level
        effects run ungoverned, and the function closures it returns execute
        ungoverned when later called from governed code. Instead, run the
        imported source on a *child* interpreter that inherits this caller's
        policy engine and authority and is forced into governed mode, so

          * top-level gated effects (e.g. ``pour``) hit the capability gate
            during import, and
          * the returned function closures gate when invoked from governed code.

        Returns the imported module's new top-level bindings as a dict (the same
        shape stdlib modules use). The governed path deliberately bypasses the
        global ``ModuleCache`` to avoid leaking governed-bound closures into a
        later core-mode import of the same path.
        """
        import os

        from utf.thirsty_lang.lexer import Lexer
        from utf.thirsty_lang.parser import Parser
        if not os.path.exists(path):
            raise ImportError(f"File not found: {path}")
        with open(path) as f:
            source = f.read()
        parser = Parser(Lexer(source).lex())
        ast = parser.parse()
        if parser.errors:
            raise ImportError(f"Failed to import '{path}': {parser.errors[0]}")

        child = Interpreter()
        child.attach_tarl(self.tarl_runtime)
        child.set_authority(self.authority)
        baseline = set(child.env.vars)  # builtins to exclude from the module
        # Force governed mode regardless of the imported module's own header so
        # its effects are gated by *this* caller's policy, not its declaration.
        child.interpret(ast, mode="governed", force_mode=True)
        return {
            name: value
            for name, value in child.env.vars.items()
            if name not in baseline
        }

    def _execute_import(self, stmt: ImportStmt) -> object:
        self._gate_capability("import", stmt.module_path)
        try:
            module: object
            if (self.mode == "governed"
                    and stmt.module_path.endswith(".thirsty")):
                module = self._import_thirsty_file(stmt.module_path)
            else:
                module = resolve_import(stmt.module_path)
            module = self._wrap_imported_module_capabilities(
                stmt.module_path, module
            )
            alias = stmt.alias or stmt.module_path
            self.env.define(alias, module, is_mut=False)
            return module
        except GovernanceViolation:
            # A denied effect during imported-module execution is a governance
            # decision, not an import error — it must propagate, never be
            # swallowed into a SpillageException that handlers could catch.
            raise
        except Exception as e:
            raise SpillageException(str(e)) from e

    def _make_closure(self, params, body):
        # Capture the defining environment so the function closes over its
        # lexical scope (enclosing locals), rather than over whatever scope
        # happens to be active at call time.
        def_env = self.env

        def fn(*args):
            old_env = self.env
            self.env = def_env.enter_scope()
            for i, (pname, _) in enumerate(params):
                val = args[i] if i < len(args) else None
                self.env.define(pname, val, is_mut=False)
            result = None
            try:
                result = self._execute(body)
            except ReturnException as e:
                result = e.value
            finally:
                self.env = old_env
            return result
        return fn

    def _execute_function_decl(self, stmt: FunctionDecl) -> object:
        fn = self._make_closure(stmt.params, stmt.body)
        self.env.define(stmt.name, fn, is_mut=False)
        return fn

    def _execute_class_decl(self, stmt: ClassDecl) -> object:
        def constructor(*args):
            instance = FountainInstance(stmt, self.env)
            old_env = self.env
            self.env = self.env.enter_scope()
            self.env.define("this", instance, is_mut=False)
            # Apply field default initializers before running init.
            for field_spec in stmt.fields:
                default_expr = field_spec[2] if len(field_spec) > 2 else None
                if default_expr is not None:
                    instance.fields[field_spec[0]] = \
                        self._evaluate(default_expr)
            for method in stmt.methods:
                if method.name == "init":
                    self._call_user_fn(method, list(args), this_obj=instance)
            self.env = old_env
            return instance
        self.env.define(stmt.name, constructor, is_mut=False)
        return constructor

    def _execute_spillage(self, stmt: SpillageStmt) -> object:
        try:
            return self._execute(stmt.body)
        except (ReturnException, GovernanceViolation):
            # Control flow (return) and governance denials are not errors —
            # they must propagate, never be caught by spillage handlers.
            raise
        except SpillageException as exc:
            for error_var, handler in stmt.handlers:
                return self._run_spillage_handler(error_var, exc.value, handler)
            raise
        except Exception as exc:
            for error_var, handler in stmt.handlers:
                return self._run_spillage_handler(error_var, exc, handler)
            raise

    def _run_spillage_handler(self, error_var, err_value, handler) -> object:
        """Run a spillage error handler, binding the thrown value to the
        handler's optional name (``error (name) { ... }``)."""
        if error_var is None:
            return self._execute(handler)
        old_env = self.env
        self.env = self.env.enter_scope()
        self.env.define(error_var, err_value, is_mut=False)
        try:
            return self._execute(handler)
        finally:
            self.env = old_env

    def _execute_cleanup(self, stmt: CleanupStmt) -> object:
        try:
            return self._execute(stmt.body)
        finally:
            self._execute(stmt.finalizer)

    def _execute_throw(self, stmt: ThrowStmt) -> object:
        value = self._evaluate(stmt.value)
        raise SpillageException(value)

    def _execute_security_block(self, stmt: SecurityBlock) -> object:
        return self._execute(stmt.body)

    def _execute_cascade(self, stmt: CascadeCall) -> object:
        """cascade <call> — async call with await: runs on the pool and
        resolves to the call's value (not a Future)."""
        if isinstance(stmt.expr, CallExpr):
            callee = self._evaluate(stmt.expr.callee)
            args = [self._evaluate(a) for a in stmt.expr.args]
            if callable(callee):
                future = self.executor.submit(callee, *args)
                return future.result()
        return self._evaluate(stmt.expr)

    def _execute_morph(self, stmt: MorphDef) -> object:
        def transform(*args):
            old_env = self.env
            self.env = self.env.enter_scope()
            for i, (pname, _) in enumerate(stmt.params):
                val = args[i] if i < len(args) else None
                self.env.define(pname, val, is_mut=False)
            result = None
            try:
                result = self._execute(stmt.body)
            except ReturnException as e:
                result = e.value
            finally:
                self.env = old_env
            return result
        self.env.define(stmt.name, transform, is_mut=False)
        return transform

    def _execute_shadow_thirst(self, stmt: ShadowThirstMutation) -> object:
        if stmt.canonical_block:
            return self._execute(stmt.canonical_block)
        return None

    def attach_tarl(self, runtime) -> "Interpreter":
        """Wire a TARL policy engine for governed-function routing.

        ``runtime`` is a ``utf.tarl.runtime.TarlRuntime``.  Passing it here
        (rather than importing at module load) keeps thirsty_lang decoupled
        from tarl unless governance is actually used.  Returns self.
        """
        self.tarl_runtime = runtime
        return self

    def set_authority(self, authority) -> "Interpreter":
        """Set a *self-asserted* authority (a bare string subject).

        This carries no authenticity: ``authority_authenticated`` stays False and
        no grants are bound. In hardened mode such an authority cannot pass a
        gated capability. Use :meth:`set_verified_authority` for a signed
        credential. Passing a ``VerifiedAuthority`` here is also accepted.
        """
        from utf.tarl.authority import VerifiedAuthority
        if isinstance(authority, VerifiedAuthority):
            return self.set_verified_authority(authority)
        self.authority = authority
        self.authority_authenticated = False
        self.authority_grants = ()
        self._verified_authority = None
        return self

    def set_verified_authority(self, verified) -> "Interpreter":
        """Bind an authenticated authority resolved from a signed claim.

        ``verified`` is a ``utf.tarl.authority.VerifiedAuthority``. Its subject,
        grants, and authenticity flag are injected into every governance context.
        """
        self.authority = verified.subject
        self.authority_authenticated = bool(verified.authenticated)
        self.authority_grants = tuple(verified.grants)
        self._verified_authority = verified
        return self

    def set_hardened(self, hardened: bool = True) -> "Interpreter":
        """Enable the hardened posture (authenticated authority + Ed25519 proofs
        required at every governed gate, else fail closed)."""
        self.hardened = hardened
        return self

    def set_path_guard(self, roots) -> "Interpreter":
        """Confine governed ``thirst::fs`` targets to ``roots`` (C042).

        ``roots`` is an iterable of allowed directory roots, or a ready
        ``utf.tarl.pathguard.PathGuard``. Once set, file capabilities are
        brokered on the *canonical* path, so traversal/symlink escapes fail
        closed before the policy is consulted. With no guard set, file targets
        are brokered as-is (unchanged behaviour)."""
        from utf.tarl.pathguard import PathGuard
        if roots is None or isinstance(roots, PathGuard):
            self.path_guard = roots
        else:
            self.path_guard = PathGuard(list(roots))
        return self

    def make_broker(self):
        """Build a :class:`~utf.tarl.broker.CapabilityBroker` bound to this
        interpreter's runtime, authority, hardened posture, and path guard.

        This is the *single* mediation point: the in-language capability gate
        (:meth:`_gate_capability`) and any out-of-language adapters (FFI, MCP/
        agent tools, subprocess wrappers) all broker through an identically
        configured broker, so there is one enforcement path, not two."""
        from utf.tarl.broker import CapabilityBroker
        authority = (self._verified_authority
                     if self._verified_authority is not None
                     else (self.authority or ""))
        return CapabilityBroker(
            self.tarl_runtime, authority=authority,
            require_authenticated=self.hardened, path_guard=self.path_guard)

    def _authority_context(self) -> dict:
        """Authority fields merged into every governance evaluation context."""
        return {
            "authority": self.authority or "",
            "authority_subject": self.authority or "",
            "authority_authenticated": self.authority_authenticated,
            "authority_grants": list(self.authority_grants),
        }

    def _hardened_precheck(self, action: str, target: str):
        """Hardened-mode gate prerequisites, evaluated before policy routing.

        Returns a fail-closed ``GovernanceViolation`` to raise, or None when the
        prerequisites hold. Enforces: an authenticated authority, and a runtime
        configured to emit Ed25519-signed proofs (non-repudiable audit).
        """
        if not self.hardened:
            return None
        from utf.tarl.spec import TarlVerdict
        reason = None
        if not self.authority_authenticated:
            reason = ("hardened mode requires an authenticated (signed) "
                      "authority; a self-asserted authority is not sufficient")
        elif getattr(self.tarl_runtime, "_signing_alg", "") != "ed25519":
            reason = ("hardened mode requires Ed25519-signed proofs; configure "
                      "an Ed25519 signing key on the runtime")
        if reason is None:
            return None
        proof = self._make_decision_proof(
            source="<fail-closed: hardened-mode prerequisite>",
            context={**self._authority_context(), "action": action,
                     "target": str(target)},
            verdict=TarlVerdict.DENY, matched_condition="",
            trace=[{"kind": "fail-closed", "action": action,
                    "target": str(target), "reason": reason}])
        self._last_proof = proof
        return GovernanceViolation(f"{action} {target}", reason, proof)

    def _execute_governed_function_decl(self, stmt: GovernedFunctionDecl):
        """Define a top-level governed function with full contract enforcement."""
        def fn(*args):
            old_env = self.env
            self.env = self.env.enter_scope()
            context = {}
            for i, (pname, _) in enumerate(stmt.params):
                val = args[i] if i < len(args) else None
                self.env.define(pname, val, is_mut=False)
                context[pname] = val
            try:
                return self._run_governed(stmt, context, top_level=True)
            finally:
                self.env = old_env
        self.env.define(stmt.name, fn, is_mut=False)
        return fn

    def _run_governed(self, decl: GovernedFunctionDecl, context: dict,
                      top_level: bool):
        """Enforce entry contracts, run the body, then enforce exit contracts.

        Params are assumed already bound in the current scope. ``top_level``
        gates the cross-mode guard (E053): it applies to module-level governed
        functions, not to method contracts (which are design-by-contract
        assertions valid in any mode).
        """
        allowed, reason, proof = self._enforce_governance(
            context, decl, phase="entry", enforce_mode_guard=top_level)
        if proof is not None:
            self._last_proof = proof
        if not allowed:
            raise GovernanceViolation(decl.name, reason, proof)

        result = None
        try:
            result = self._execute(decl.body)
        except ReturnException as e:
            result = e.value

        # Exit contracts: bind `result` so ensures/invariant can reference it.
        self.env.define("result", result, is_mut=False)
        exit_ctx = dict(context)
        exit_ctx["result"] = result
        allowed, reason, proof = self._enforce_governance(
            exit_ctx, decl, phase="exit", enforce_mode_guard=top_level)
        if proof is not None:
            self._last_proof = proof
        if not allowed:
            raise GovernanceViolation(decl.name, reason, proof)
        return result

    def _eval_predicate(self, expr, annotation, label):
        """Evaluate a governance predicate; return (ok, reason)."""
        try:
            if self._evaluate(expr):
                return (True, "")
            return (False, f"{label} failed: {annotation or '<expr>'}")
        except Exception as exc:
            return (False, f"{label} error: {exc}")

    def _contract_predicates(self, decl, phase):
        """Yield (expr, annotation, label) for the contract predicates that
        apply at this boundary: requires + invariant on entry, ensures +
        invariant on exit. Empty when ``decl`` carries no contract.
        """
        if decl is None:
            return
        if phase == "entry":
            if getattr(decl, "requires_expr", None) is not None:
                yield (decl.requires_expr, decl.requires_annotation,
                       "precondition")
            if getattr(decl, "invariant_expr", None) is not None:
                yield (decl.invariant_expr, decl.invariant_annotation,
                       "invariant (entry)")
        else:
            if getattr(decl, "ensures_expr", None) is not None:
                yield (decl.ensures_expr, decl.ensures_annotation,
                       "postcondition")
            if getattr(decl, "invariant_expr", None) is not None:
                yield (decl.invariant_expr, decl.invariant_annotation,
                       "invariant (exit)")

    def _make_contract_proof(self, decl, phase, context, verdict,
                             matched_condition, trace):
        """Proof certificate for a design-by-contract verdict (Fix: every
        governed boundary decision carries a proof, not just policy ones)."""
        name = getattr(decl, "name", "<anon>") if decl is not None else "<anon>"
        source = f"contract:{name}:{phase}"
        return self._make_decision_proof(
            source=source, context=context, verdict=verdict,
            matched_condition=matched_condition, trace=trace)

    def _enforce_governance(self, context: dict, decl=None, phase="entry",
                            enforce_mode_guard=True):
        """Decide whether a governed call boundary is allowed.

        Returns ``(allowed, reason, proof)``. Design-by-contract predicates
        (requires/invariant at entry; ensures/invariant at exit) hold unless a
        declared predicate fails. The TARL layer adds deny-by-default access
        control when a policy engine + authority are configured. Every decision
        on a contract-bearing boundary carries a proof — ALLOW and DENY alike.
        """
        from utf.tarl.spec import TarlVerdict
        proof = None
        if phase == "entry":
            # Cross-mode guard (E053): top-level governed fn from core is denied.
            if decl is not None and enforce_mode_guard and self.mode != "governed":
                return (False,
                        "governed function invoked outside governed mode", None)

        # Design-by-contract predicates for this phase.
        trace = []
        for expr, ann, label in self._contract_predicates(decl, phase):
            ok, reason = self._eval_predicate(expr, ann, label)
            trace.append({"predicate": label, "annotation": ann or "<expr>",
                          "phase": phase, "result": "pass" if ok else "fail"})
            if not ok:
                deny = self._make_contract_proof(
                    decl, phase, context, TarlVerdict.DENY, ann or "", trace)
                self._last_proof = deny
                return (False, reason, deny)
        if trace:  # contract was checked and held → certify it
            proof = self._make_contract_proof(
                decl, phase, context, TarlVerdict.ALLOW, "", trace)

        if phase == "entry":
            # TARL policy routing (deny-by-default access control). A policy
            # proof supersedes the contract proof as the boundary certificate.
            if self.mode == "governed" and decl is not None and (
                    self.tarl_runtime is None or self.authority is None):
                reason = (
                    "governed function requires a policy engine and authority"
                )
                deny = self._make_contract_proof(
                    decl, phase, context, TarlVerdict.DENY, reason,
                    trace + [{"kind": "fail-closed", "phase": phase,
                              "reason": reason}])
                self._last_proof = deny
                return (False, reason, deny)
            if self.tarl_runtime is not None and self.authority is not None:
                # Hardened-mode prerequisites fail closed before policy routing.
                action_name = decl.name if decl is not None else "<call>"
                hardened_violation = self._hardened_precheck(
                    action_name, action_name)
                if hardened_violation is not None:
                    return (False, hardened_violation.reason,
                            hardened_violation.proof)
                policy_ctx = dict(context)
                policy_ctx.update(self._authority_context())
                if decl is not None:
                    policy_ctx.setdefault("action", decl.name)
                decision, proof = self.tarl_runtime.evaluate_with_proof(
                    policy_ctx)
                if decision.verdict != TarlVerdict.ALLOW:
                    return (False,
                            decision.reason
                            or f"policy verdict: {decision.verdict}",
                            proof)
        return (True, "allowed", proof)

    def _call_user_fn(self, func_decl: FunctionDecl, args: list,
                      this_obj: object = None) -> object:
        old_env = self.env
        self.env = self.env.enter_scope()
        # Bind the receiver for fountain methods. Two conventions are supported:
        #   * the `this` keyword (no receiver parameter declared), and
        #   * an explicit leading `self`/`this` parameter.
        # `this` is always bound so `this.field` resolves; if the method also
        # declares a leading self parameter, it receives the instance and is
        # not consumed from the caller's positional arguments.
        context = {}
        params = list(func_decl.params)
        if this_obj is not None:
            self.env.define("this", this_obj, is_mut=False)
            if params and params[0][0] in ("self", "this"):
                recv_name = params[0][0]
                self.env.define(recv_name, this_obj, is_mut=False)
                context[recv_name] = this_obj
                params = params[1:]
        for i, (pname, _) in enumerate(params):
            val = args[i] if i < len(args) else None
            self.env.define(pname, val, is_mut=False)
            context[pname] = val
        try:
            if isinstance(func_decl, GovernedFunctionDecl):
                # Method contracts: DBC enforcement, no cross-mode guard.
                return self._run_governed(func_decl, context, top_level=False)
            result = None
            try:
                result = self._execute(func_decl.body)
            except ReturnException as e:
                result = e.value
            return result
        finally:
            self.env = old_env

    def _evaluate_impl(self, expr: Expr) -> Any:
        """Evaluate an expression and return its value."""
        if isinstance(expr, IntLiteral):
            return expr.value
        elif isinstance(expr, FloatLiteral):
            return expr.value
        elif isinstance(expr, StringLiteral):
            return expr.value
        elif isinstance(expr, BoolLiteral):
            return expr.value
        elif isinstance(expr, NoneLiteral):
            return None
        elif isinstance(expr, ErrorLiteral):
            return Exception(expr.value)
        elif isinstance(expr, QuenchedLiteral):
            return {"type": expr.type_param, "value": self._evaluate(expr.value) if expr.value else None}
        elif isinstance(expr, AssignStmt):
            raise RuntimeError("assignment cannot be used as an expression")
        elif isinstance(expr, Identifier):
            if expr.name == "__error__":
                return None
            return self.env.get(expr.name)
        elif isinstance(expr, BinaryOp):
            return self._evaluate_binary(expr)
        elif isinstance(expr, UnaryOp):
            return self._evaluate_unary(expr)
        elif isinstance(expr, LambdaExpr):
            return self._make_closure(expr.params, expr.body)
        elif isinstance(expr, CallExpr):
            return self._evaluate_call(expr)
        elif isinstance(expr, PipeExpr):
            return self._evaluate_pipe(expr)
        elif isinstance(expr, GuardExpr):
            return self._evaluate_guard(expr)
        elif isinstance(expr, FloodExpr):
            return self._evaluate_flood(expr)
        elif isinstance(expr, DripExpr):
            return self._evaluate_drip(expr)
        elif isinstance(expr, EvaporateExpr):
            return self._evaluate_evaporate(expr)
        elif isinstance(expr, CondenseExpr):
            return self._evaluate_condense(expr)
        elif isinstance(expr, ArrayLiteral):
            return [self._evaluate_impl(e) for e in expr.elements]
        elif isinstance(expr, MemberAccess):
            return self._evaluate_member(expr)
        elif isinstance(expr, SanitizeExpr):
            return self._evaluate(expr.expr)
        elif isinstance(expr, ArmorExpr):
            return self._evaluate(expr.expr)
        elif isinstance(expr, NewExpr):
            return self._evaluate_new(expr)
        elif isinstance(expr, CascadeCall):
            return self._execute_cascade(expr)
        elif isinstance(expr, SymbolExpr):
            return expr.symbol_name
        elif isinstance(expr, PipelineExpr):
            return self._evaluate_pipeline(expr)
        elif isinstance(expr, CombineExpr):
            return self._evaluate_combine(expr)
        return None

    def _evaluate_binary(self, expr: BinaryOp) -> object:
        left = self._evaluate_impl(expr.left)
        right = self._evaluate_impl(expr.right)
        op = expr.op
        if op == TokenType.EQEQ:
            return left == right
        elif op == TokenType.NE:
            return left != right
        elif op == TokenType.LT:
            return left < right
        elif op == TokenType.LE:
            return left <= right
        elif op == TokenType.GT:
            return left > right
        elif op == TokenType.GE:
            return left >= right
        elif op == TokenType.PLUS:
            return left + right
        elif op == TokenType.MINUS:
            return left - right
        elif op == TokenType.STAR:
            return left * right
        elif op == TokenType.SLASH:
            return left / right
        elif op == TokenType.PERCENT:
            return left % right
        elif op == TokenType.AND:
            return left and right
        elif op == TokenType.OR:
            return left or right
        return None

    def _evaluate_unary(self, expr: UnaryOp) -> object:
        operand = self._evaluate_impl(expr.operand)
        if expr.op == TokenType.MINUS:
            return -operand
        elif expr.op == TokenType.NOT:
            return not operand
        return operand

    def _evaluate_call(self, expr: CallExpr) -> object:
        callee = self._evaluate_impl(expr.callee)
        args = [self._evaluate_impl(a) for a in expr.args]
        if callable(callee):
            return callee(*args)
        raise TypeError(f"Cannot call non-callable: {callee}")

    def _evaluate_pipe(self, expr: PipeExpr) -> object:
        left = self._evaluate_impl(expr.left)
        right = self._evaluate_impl(expr.right)
        if callable(right):
            return right(left)
        return left

    def _evaluate_guard(self, expr: GuardExpr) -> object:
        condition = self._evaluate_impl(expr.condition)
        if condition:
            return self._evaluate_impl(expr.expr)
        return None

    def _evaluate_flood(self, expr: FloodExpr) -> object:
        """flood <target> — fill a reservoir from a value.

        If the target is already a reservoir (list) it is returned as-is;
        otherwise the value is wrapped into a fresh single-element reservoir.
        """
        target = self._evaluate_impl(expr.target)
        if isinstance(target, list):
            return target
        return [target]

    def _evaluate_drip(self, expr: DripExpr) -> object:
        target = self._evaluate_impl(expr.target)
        if isinstance(target, list) and target:
            return target.pop()
        return None

    def _evaluate_evaporate(self, expr: EvaporateExpr) -> object:
        """evaporate <target> — release a resource; empties a reservoir/map."""
        target = self._evaluate_impl(expr.target)
        if isinstance(target, (list, dict)):
            target.clear()
        return None

    def _evaluate_condense(self, expr: CondenseExpr) -> object:
        target = self._evaluate_impl(expr.target)
        if isinstance(target, dict):
            return target.get("value")
        return None

    def _evaluate_member(self, expr: MemberAccess) -> object:
        """obj.member — read a fountain field, bind a method, or index a map."""
        obj = self._evaluate_impl(expr.obj)
        name = expr.member
        if isinstance(obj, FountainInstance):
            if name in obj.fields:
                return obj.fields[name]
            method = obj.methods.get(name)
            if method is not None:
                # Bound method: the instance is bound as `this`, and the call
                # arguments map to the method's declared params.
                return lambda *a: self._call_user_fn(
                    method, list(a), this_obj=obj)
            raise NameError(
                f"'{obj.cls_decl.name}' has no member '{name}'")
        if isinstance(obj, dict):
            return obj.get(name)
        raise TypeError(
            f"Cannot access member '{name}' on {type(obj).__name__}")

    def _evaluate_new(self, expr: NewExpr) -> object:
        constructor = self.env.get(expr.class_name)
        args = [self._evaluate_impl(a) for a in expr.args]
        if callable(constructor):
            return constructor(*args)
        raise TypeError(f"Cannot instantiate non-callable: {expr.class_name}")

    def _evaluate_pipeline(self, expr: PipelineExpr) -> object:
        """TSCG pipeline ``left -> right``: feed the left value into the right
        operand when it is callable (same shape as the ``|`` pipe operator).

        ``PipelineExpr`` is a binary node (``left``/``right``); an earlier
        version walked a non-existent ``.steps`` list and raised AttributeError
        on any ``->`` expression.
        """
        left = self._evaluate_impl(expr.left)
        right = self._evaluate_impl(expr.right)
        if callable(right):
            return right(left)
        return right

    def _evaluate_combine(self, expr: CombineExpr) -> object:
        left = self._evaluate_impl(expr.left)
        right = self._evaluate_impl(expr.right)
        if isinstance(left, bool) or isinstance(right, bool):
            if expr.op == "^":
                return bool(left) and bool(right)
            if expr.op == "||":
                return bool(left) or bool(right)
        if isinstance(left, dict) and isinstance(right, dict):
            merged = dict(left)
            merged.update(right)
            return merged
        if isinstance(left, list) and isinstance(right, list):
            return left + right
        return right

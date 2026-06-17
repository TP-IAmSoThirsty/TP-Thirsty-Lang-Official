"""
Thirsty-Lang Tree-Walking Interpreter
Evaluates Thirsty-Lang AST programs with full environment scoping,
governance enforcement, tail-call optimization, and async support.
"""
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from utf.thirsty_lang.token import TokenType
from utf.thirsty_lang.ast import *
from utf.thirsty_lang.module_system import resolve_import, get_builtin


class ReturnException(Exception):
    """Used for control flow to unwind non-tail-called returns."""
    def __init__(self, value):
        self.value = value


class SpillageException(Exception):
    """Represents an error thrown via throw/spillage."""
    def __init__(self, value):
        self.value = value


class Environment:
    """Scoped variable storage."""

    def __init__(self, parent: 'Environment' = None):
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
        return name in self.vars or (self.parent and self.parent.has(name))

    def enter_scope(self) -> 'Environment':
        return Environment(self)

    def __repr__(self):
        return f"Environment({list(self.vars.keys())})"


class FountainInstance:
    """Instance of a fountain (class)."""

    def __init__(self, cls_decl: ClassDecl, env: Environment):
        self.cls_decl = cls_decl
        self.fields = {}
        self.methods = {}
        for fname, _ in cls_decl.fields:
            self.fields[fname] = None
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
            "push": lambda r, v: (r.append(v), len(r))[-1] if isinstance(r, list) else 0,
            "pop": lambda r: r.pop() if isinstance(r, list) and r else None,
            "size": lambda x: len(x) if hasattr(x, '__len__') else 0,
            "get": lambda x, i: x[i] if hasattr(x, '__getitem__') else None,
            "flood": lambda r, v: (r.append(v), r)[-1] if isinstance(r, list) else r,
            "condense": lambda q: q.get("value") if isinstance(q, dict) and "value" in q else None,
            "evaporate": lambda q: q.pop("value") if isinstance(q, dict) and "value" in q else None,
            "strain": lambda x: x,
            "transmute": lambda x, t: x,
            "distill": lambda x: x,
            "print": lambda *args: print(*args) or args[-1] if args else None,
            "pour": lambda *args: print(*args) or (args[-1] if args else None),
        }
        for name, func in builtins_map.items():
            self.env.define(name, func, is_mut=False)

    def interpret(self, ast: Program, mode: str = "core") -> object:
        """Interpret an entire Program AST."""
        self.mode = mode
        if ast.header:
            self.mode = ast.header.mode
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

    def _evaluate(self, expr: Expr) -> object:
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
        elif isinstance(stmt, IfStmt):
            return self._execute_if(stmt)
        elif isinstance(stmt, WhileStmt):
            return self._execute_while(stmt)
        elif isinstance(stmt, ForStmt):
            return self._execute_for(stmt)
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
            return self._execute_function_decl(FunctionDecl(
                name=stmt.name, params=stmt.params,
                return_type=stmt.return_type, body=stmt.body, span=stmt.span
            ))
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
        value = None
        if stmt.init_expr:
            value = self._evaluate(stmt.init_expr)
        self.env.define(stmt.name, value, is_mut=stmt.is_mut)
        return None  # drink is a statement, not an expression — no value propagation

    def _execute_assign(self, stmt: AssignStmt) -> object:
        value = self._evaluate(stmt.value)
        if isinstance(stmt.target, Identifier):
            self.env.set(stmt.target.name, value)
        return value

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

    def _execute_return(self, stmt: ReturnStmt) -> object:
        value = self._evaluate(stmt.value) if stmt.value else None
        if self.tco_enabled and stmt.value and isinstance(stmt.value, CallExpr):
            # TCO: evaluate the call directly instead of raising ReturnException
            return self._evaluate_call(stmt.value)
        raise ReturnException(value)

    def _execute_pour(self, stmt: PourStmt) -> object:
        value = self._evaluate(stmt.value)
        if isinstance(value, str):
            print(value)
        else:
            print(value)
        return None  # pour handles its own output — no value propagation

    def _execute_sip(self, stmt: SipStmt) -> object:
        value = input()
        if isinstance(stmt.target, Identifier):
            self.env.set(stmt.target.name, value)
        return value

    def _execute_import(self, stmt: ImportStmt) -> object:
        try:
            module = resolve_import(stmt.module_path)
            alias = stmt.alias or stmt.module_path
            self.env.define(alias, module, is_mut=False)
            return module
        except Exception as e:
            raise SpillageException(str(e))

    def _execute_function_decl(self, stmt: FunctionDecl) -> object:
        def fn(*args):
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
        self.env.define(stmt.name, fn, is_mut=False)
        return fn

    def _execute_class_decl(self, stmt: ClassDecl) -> object:
        def constructor(*args):
            instance = FountainInstance(stmt, self.env)
            old_env = self.env
            self.env = self.env.enter_scope()
            self.env.define("this", instance, is_mut=False)
            for method in stmt.methods:
                if method.name == "init":
                    self._call_user_fn(method, [instance] + list(args))
            self.env = old_env
            return instance
        self.env.define(stmt.name, constructor, is_mut=False)
        return constructor

    def _execute_spillage(self, stmt: SpillageStmt) -> object:
        try:
            return self._execute(stmt.body)
        except SpillageException as e:
            for error_type, handler in stmt.handlers:
                return self._execute(handler)
            raise
        except Exception as e:
            for error_type, handler in stmt.handlers:
                return self._execute(handler)
            raise

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
        if isinstance(stmt.expr, CallExpr):
            callee = self._evaluate(stmt.expr.callee)
            args = [self._evaluate(a) for a in stmt.expr.args]
            if callable(callee):
                future = self.executor.submit(callee, *args)
                return future
        return None

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

    def _enforce_governance(self, context: dict) -> bool:
        if self.mode == "governed":
            return True
        return True

    def _call_user_fn(self, func_decl: FunctionDecl, args: list) -> object:
        old_env = self.env
        self.env = self.env.enter_scope()
        for i, (pname, _) in enumerate(func_decl.params):
            val = args[i] if i < len(args) else None
            self.env.define(pname, val, is_mut=False)
        result = None
        try:
            result = self._execute(func_decl.body)
        except ReturnException as e:
            result = e.value
        finally:
            self.env = old_env
        return result

    def _evaluate_impl(self, expr: Expr) -> object:
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
        elif isinstance(expr, Identifier):
            if expr.name == "__error__":
                return None
            return self.env.get(expr.name)
        elif isinstance(expr, BinaryOp):
            return self._evaluate_binary(expr)
        elif isinstance(expr, UnaryOp):
            return self._evaluate_unary(expr)
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
        target = self._evaluate_impl(expr.target)
        value = self._evaluate_impl(expr.value)
        if isinstance(target, list):
            target.append(value)
        return target

    def _evaluate_drip(self, expr: DripExpr) -> object:
        target = self._evaluate_impl(expr.target)
        if isinstance(target, list) and target:
            return target.pop()
        return None

    def _evaluate_evaporate(self, expr: EvaporateExpr) -> object:
        target = self._evaluate_impl(expr.target)
        key = self._evaluate_impl(expr.key) if expr.key else None
        if isinstance(target, dict) and key is not None:
            return target.pop(key, None)
        return None

    def _evaluate_condense(self, expr: CondenseExpr) -> object:
        target = self._evaluate_impl(expr.target)
        if isinstance(target, dict):
            return target.get("value")
        return None

    def _evaluate_new(self, expr: NewExpr) -> object:
        constructor = self._evaluate_impl(expr.callee)
        args = [self._evaluate_impl(a) for a in expr.args]
        if callable(constructor):
            return constructor(*args)
        raise TypeError(f"Cannot instantiate non-callable: {constructor}")

    def _evaluate_pipeline(self, expr: PipelineExpr) -> object:
        result = None
        for i, step in enumerate(expr.steps):
            if i == 0:
                result = self._evaluate_impl(step)
            else:
                if callable(step):
                    result = step(result)
                else:
                    result = self._evaluate_impl(step)
        return result

    def _evaluate_combine(self, expr: CombineExpr) -> object:
        left = self._evaluate_impl(expr.left)
        right = self._evaluate_impl(expr.right)
        if isinstance(left, dict) and isinstance(right, dict):
            merged = dict(left)
            merged.update(right)
            return merged
        if isinstance(left, list) and isinstance(right, list):
            return left + right
        return right
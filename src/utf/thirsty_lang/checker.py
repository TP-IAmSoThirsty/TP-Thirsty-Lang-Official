"""
Thirsty-Lang Type Checker / Semantic Analyzer
Lexical scoping, type checking, governance validation, and error reporting.
"""
from typing import cast

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
    Subscript,
    SymbolExpr,
    SymbolStmt,
    ThrowStmt,
    TimesStmt,
    TokenType,
    UnaryOp,
    VariableDecl,
    WhileStmt,
)
from utf.thirsty_lang.diagnostics import Diagnostic, make_error
from utf.thirsty_lang.typesys import (
    AnyType,
    BoolType,
    EnumType,
    ErrorType,
    FloatType,
    FunctionType,
    InterfaceType,
    IntType,
    QuenchedType,
    ReservoirType,
    StringType,
    StructType,
    TaskType,
    Type,
    VoidType,
    is_assignable,
    type_from_name,
    type_to_string,
)


def _edit_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _edit_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


def _nearest_match(name: str, candidates: list[str], max_dist: int = 3) -> list[str]:
    return [c for c in candidates if _edit_distance(name, c) <= max_dist]


class Scope:
    """A lexical scope with variable bindings and type information."""

    def __init__(self, parent: "Scope | None" = None):
        self.parent = parent
        self.bindings: dict[str, dict] = {}  # name -> {type, is_mut, kind}

    def declare(self, name: str, info: dict) -> bool:
        """Declare a new binding. Returns False if already declared in this scope."""
        if name in self.bindings:
            return False
        self.bindings[name] = info
        return True

    def lookup(self, name: str) -> dict | None:
        """Look up a binding in this scope or enclosing scopes."""
        if name in self.bindings:
            return self.bindings[name]
        if self.parent:
            return self.parent.lookup(name)
        return None

    def is_mutable(self, name: str) -> bool:
        info = self.lookup(name)
        return info is not None and info.get("is_mut", False)


class Checker:
    """Semantic analysis and type checking for Thirsty-Lang AST."""

    def __init__(self):
        self.scope = Scope()
        self.errors: list[Diagnostic] = []
        self.current_function_return_type: Type | None = None
        self.in_governed_mode = False
        self.imported_names: dict[str, str] = {}  # alias -> module_path
        self._hoisted: set = set()         # top-level fn/class names
        self._governed_names: set = set()  # governed function names

    def enter_scope(self):
        self.scope = Scope(self.scope)

    def exit_scope(self):
        if self.scope.parent:
            self.scope = self.scope.parent

    def check_all(self, ast: Program) -> list[Diagnostic]:
        """Type-check an entire Program AST."""
        self.errors = []
        # Register mode
        if ast.header:
            self.in_governed_mode = (ast.header.mode == "governed")
            # Register module name
            self.scope.declare("__module__", {"type": StringType(), "is_mut": False, "kind": "module"})
        # Register builtins
        self._register_builtins()
        # Hoist top-level function/class names so forward references resolve.
        self._hoist_declarations(ast.stmts)
        # Check all statements
        for stmt in ast.stmts:
            self._check_stmt(stmt)
        return self.errors

    def _hoist_declarations(self, stmts):
        """Pre-declare top-level functions/classes (enables forward references
        and mutual recursion) and record which functions are governed."""
        self._hoisted = set()
        self._governed_names = set()
        for stmt in stmts:
            name = getattr(stmt, "name", None)
            if isinstance(stmt, (FunctionDecl, GovernedFunctionDecl)):
                if name in self._hoisted:
                    self.errors.append(
                        make_error("E010", span=stmt.span, name=name))
                    continue
                # Register the real signature (param + return types) so that
                # forward references, self-recursion, and mutual recursion all
                # see the correct arity while bodies are being checked.
                param_types = [type_from_name(ptype) if ptype else AnyType()
                               for _pname, ptype in stmt.params]
                # No explicit return type → gradual default of Any (not Void),
                # so a value-returning un-annotated function flows into typed
                # operators and self-recursion type-checks. (review F2)
                ret_type = (type_from_name(stmt.return_type)
                            if stmt.return_type else AnyType())
                self.scope.declare(stmt.name, {
                    "type": FunctionType(param_types, ret_type),
                    "is_mut": False, "kind": "function"})
                self._hoisted.add(name)
                if isinstance(stmt, GovernedFunctionDecl):
                    self._governed_names.add(name)
            elif isinstance(stmt, ClassDecl):
                if name in self._hoisted:
                    self.errors.append(
                        make_error("E010", span=stmt.span, name=name))
                    continue
                self.scope.declare(stmt.name, {
                    "type": AnyType(), "is_mut": False, "kind": "class"})
                self._hoisted.add(name)

    def _register_builtins(self):
        builtins = [
            "length", "contains", "split", "abs", "min", "max",
            "push", "pop", "size", "get", "flood",
            "condense", "evaporate", "strain", "transmute", "distill",
            "pour", "sip", "print",
        ]
        for name in builtins:
            self.scope.declare(name, {"type": AnyType(), "is_mut": False, "kind": "builtin"})

    def _check_stmt(self, stmt: Stmt):
        if isinstance(stmt, VariableDecl):
            self._check_variable_decl(stmt)
        elif isinstance(stmt, FunctionDecl):
            self._check_function_decl(stmt)
        elif isinstance(stmt, ClassDecl):
            self._check_class_decl(stmt)
        elif isinstance(stmt, IfStmt):
            self._check_if_stmt(stmt)
        elif isinstance(stmt, WhileStmt):
            self._check_while_stmt(stmt)
        elif isinstance(stmt, ForStmt):
            self._check_for_stmt(stmt)
        elif isinstance(stmt, TimesStmt):
            self._check_times_stmt(stmt)
        elif isinstance(stmt, BlockStmt):
            self._check_block(stmt)
        elif isinstance(stmt, ReturnStmt):
            self._check_return_stmt(stmt)
        elif isinstance(stmt, PourStmt):
            self._check_expr(stmt.value)
        elif isinstance(stmt, SipStmt):
            self._check_expr(stmt.target)
        elif isinstance(stmt, AssignStmt):
            self._check_assign_stmt(stmt)
        elif isinstance(stmt, SymbolStmt):
            self._check_symbol_stmt(stmt)
        elif isinstance(stmt, ImportStmt):
            self._check_import_stmt(stmt)
        elif isinstance(stmt, ExprStmt):
            self._check_expr(stmt.expr)
        elif isinstance(stmt, SecurityBlock):
            self._check_block(stmt.body)
        elif isinstance(stmt, SpillageStmt):
            self._check_block(stmt.body)
            for error_var, handler in stmt.handlers:
                self.enter_scope()
                if error_var:
                    self.scope.declare(
                        error_var,
                        {"type": AnyType(), "is_mut": False, "kind": "error"})
                self._check_block(handler)
                self.exit_scope()
        elif isinstance(stmt, CleanupStmt):
            self._check_block(stmt.body)
            self._check_block(stmt.finalizer)
        elif isinstance(stmt, ThrowStmt):
            self._check_expr(stmt.value)
        elif isinstance(stmt, MorphDef):
            self._check_block(stmt.body)
        elif isinstance(stmt, DefendStrat):
            pass  # policy names are validated at runtime
        elif isinstance(stmt, EnumDecl):
            self._check_enum_decl(stmt)
        elif isinstance(stmt, StructDecl):
            self._check_struct_decl(stmt)
        elif isinstance(stmt, InterfaceDecl):
            self._check_interface_decl(stmt)
        elif isinstance(stmt, GovernedFunctionDecl):
            self._check_governed_function_decl(stmt)
        elif isinstance(stmt, ShadowThirstMutation):
            # Validate mutation blocks exist
            pass

    def _check_variable_decl(self, stmt: VariableDecl):
        # Check duplicate
        if not self.scope.declare(stmt.name, {"type": None, "is_mut": stmt.is_mut, "kind": "variable"}):
            self.errors.append(make_error("E010", span=stmt.span, name=stmt.name))
            return
        # Check init expression
        if stmt.init_expr:
            expr_type = self._check_expr(stmt.init_expr)
            if stmt.var_type:
                expected = type_from_name(stmt.var_type)
                if not is_assignable(expr_type, expected):
                    self.errors.append(make_error("E021", span=stmt.span,
                                                  found=type_to_string(expr_type),
                                                  expected=type_to_string(expected)))
            # Update binding type
            self.scope.bindings[stmt.name] = {
                "type": expr_type if not stmt.var_type else type_from_name(stmt.var_type),
                "is_mut": stmt.is_mut,
                "kind": "variable"
            }

    def _check_function_decl(self, stmt: FunctionDecl):
        # Top-level names are pre-declared by the hoist pass; only declare (and
        # duplicate-check) names that weren't hoisted (e.g. class methods).
        already_hoisted = (stmt.name in self._hoisted
                           and self.scope.bindings.get(stmt.name) is not None)
        if not already_hoisted:
            if not self.scope.declare(stmt.name, {"type": FunctionType([], AnyType()), "is_mut": False, "kind": "function"}):
                self.errors.append(make_error("E010", span=stmt.span, name=stmt.name))
                return
        self.enter_scope()
        # Register params
        param_types = []
        for pname, ptype in stmt.params:
            t = type_from_name(ptype) if ptype else AnyType()
            param_types.append(t)
            self.scope.declare(pname, {"type": t, "is_mut": False, "kind": "param"})
        # Set return type context. No annotation → Any (gradual default), so
        # returns are unconstrained rather than forced to Void. (review F2)
        old_return_type = self.current_function_return_type
        self.current_function_return_type = type_from_name(stmt.return_type) if stmt.return_type else AnyType()
        # Check body
        self._check_block(stmt.body)
        self.current_function_return_type = old_return_type
        self.exit_scope()
        # Update binding with proper function type
        ret_type = type_from_name(stmt.return_type) if stmt.return_type else AnyType()
        self.scope.bindings[stmt.name] = {
            "type": FunctionType(param_types, ret_type),
            "is_mut": False,
            "kind": "function"
        }

    def _check_class_decl(self, stmt: ClassDecl):
        already_hoisted = (stmt.name in self._hoisted
                           and self.scope.bindings.get(stmt.name) is not None)
        if not already_hoisted:
            if not self.scope.declare(stmt.name, {"type": AnyType(), "is_mut": False, "kind": "class"}):
                self.errors.append(make_error("E010", span=stmt.span, name=stmt.name))
        self.enter_scope()
        for field_spec in stmt.fields:
            fname, ftype = field_spec[0], field_spec[1]
            t = type_from_name(ftype) if ftype else AnyType()
            self.scope.declare(fname, {"type": t, "is_mut": True, "kind": "field"})
            default_expr = field_spec[2] if len(field_spec) > 2 else None
            if default_expr is not None:
                self._check_expr(default_expr)
        for method in stmt.methods:
            self._check_function_decl(method)
        self.exit_scope()

    def _check_if_stmt(self, stmt: IfStmt):
        cond_type = self._check_expr(stmt.condition)
        if not isinstance(cond_type, BoolType) and not isinstance(cond_type, AnyType):
            self.errors.append(make_error("E024", span=stmt.condition.span,
                                          found=type_to_string(cond_type)))
        self._check_block(stmt.then_block)
        if stmt.else_block:
            if isinstance(stmt.else_block, IfStmt):
                self._check_if_stmt(stmt.else_block)
            else:
                self._check_block(stmt.else_block)

    def _check_while_stmt(self, stmt: WhileStmt):
        cond_type = self._check_expr(stmt.condition)
        if not isinstance(cond_type, BoolType) and not isinstance(cond_type, AnyType):
            self.errors.append(make_error("E024", span=stmt.condition.span,
                                          found=type_to_string(cond_type)))
        self._check_block(stmt.body)

    def _check_for_stmt(self, stmt: ForStmt):
        self.enter_scope()
        self.scope.declare(stmt.variable.name, {"type": AnyType(), "is_mut": False, "kind": "loop_var"})
        self._check_expr(stmt.iterable)
        self._check_block(stmt.body)
        self.exit_scope()

    def _check_times_stmt(self, stmt: TimesStmt):
        # The count is evaluated to an int at runtime; just resolve the
        # expression (catches unknown identifiers) and check the body.
        self._check_expr(stmt.count)
        self._check_block(stmt.body)

    def _check_block(self, stmt: Stmt):
        if isinstance(stmt, BlockStmt):
            self.enter_scope()
            for s in stmt.statements:
                self._check_stmt(s)
            self.exit_scope()
        else:
            self._check_stmt(stmt)

    def _check_return_stmt(self, stmt: ReturnStmt):
        if stmt.value:
            val_type = self._check_expr(stmt.value)
            if self.current_function_return_type and not isinstance(self.current_function_return_type, VoidType):
                if not is_assignable(val_type, self.current_function_return_type):
                    self.errors.append(make_error("E023", span=stmt.span,
                                                  found=type_to_string(val_type),
                                                  expected=type_to_string(self.current_function_return_type)))
        elif self.current_function_return_type and not isinstance(self.current_function_return_type, VoidType):
            # returning nothing from non-void function
            self.errors.append(make_error("E023", span=stmt.span,
                                          found="Void",
                                          expected=type_to_string(self.current_function_return_type)))

    def _check_assign_stmt(self, stmt: AssignStmt):
        if isinstance(stmt.target, Identifier):
            name = stmt.target.name
            info = self.scope.lookup(name)
            if info is None:
                # Check "did you mean?"
                all_names = list(self.scope.bindings.keys()) if self.scope else []
                s: Scope | None = self.scope
                while s:
                    all_names.extend(s.bindings.keys())
                    s = s.parent
                suggestions = _nearest_match(name, all_names)
                msg = f"Unknown identifier: '{name}'"
                if suggestions:
                    msg += f" Did you mean: {', '.join(suggestions)}?"
                self.errors.append(Diagnostic("E011", msg, stmt.span, "error"))
                return
            if not info.get("is_mut", False):
                self.errors.append(make_error("E020", span=stmt.span, name=name))
        self._check_expr(stmt.value)

    def _check_symbol_stmt(self, stmt: SymbolStmt):
        if not self.scope.declare(
                stmt.symbol_name,
                {"type": StringType(), "is_mut": False, "kind": "symbol"}):
            self.errors.append(
                make_error("E010", span=stmt.span, name=stmt.symbol_name))

    def _check_import_stmt(self, stmt: ImportStmt):
        alias = stmt.alias or stmt.module_path
        self.scope.declare(alias, {"type": AnyType(), "is_mut": False, "kind": "module"})

    def _check_enum_decl(self, stmt: EnumDecl):
        if not self.scope.declare(stmt.name, {"type": EnumType(stmt.name, stmt.variants), "is_mut": False, "kind": "enum"}):
            self.errors.append(make_error("E010", span=stmt.span, name=stmt.name))

    def _check_struct_decl(self, stmt: StructDecl):
        field_types = {}
        for fname, ftype in stmt.fields:
            field_types[fname] = type_from_name(ftype) if ftype else AnyType()
        if not self.scope.declare(stmt.name, {"type": StructType(stmt.name, field_types), "is_mut": False, "kind": "struct"}):
            self.errors.append(make_error("E010", span=stmt.span, name=stmt.name))

    def _check_interface_decl(self, stmt: InterfaceDecl):
        method_sigs = {}
        for mname, params, _ret_type in stmt.methods:
            method_sigs[mname] = [type_from_name(p[1]) if p[1] else AnyType() for p in params]
        if not self.scope.declare(stmt.name, {"type": InterfaceType(stmt.name, method_sigs), "is_mut": False, "kind": "interface"}):
            self.errors.append(make_error("E010", span=stmt.span, name=stmt.name))

    def _check_governed_function_decl(self, stmt: GovernedFunctionDecl):
        # The parser only builds a GovernedFunctionDecl when at least one
        # contract clause (requires / ensures / invariant) is present, so the
        # "missing contract" case is structurally impossible here — no runtime
        # check needed. Type-check the function body like any other.
        self._check_function_decl(FunctionDecl(
            name=stmt.name, params=stmt.params,
            return_type=stmt.return_type, body=stmt.body, span=stmt.span
        ))

    def _check_expr(self, expr: Expr) -> Type:
        """Type-check an expression and return its Type."""
        if isinstance(expr, IntLiteral):
            return IntType()
        elif isinstance(expr, FloatLiteral):
            return FloatType()
        elif isinstance(expr, StringLiteral):
            return StringType()
        elif isinstance(expr, BoolLiteral):
            return BoolType()
        elif isinstance(expr, NoneLiteral):
            return VoidType()
        elif isinstance(expr, ErrorLiteral):
            return ErrorType()
        elif isinstance(expr, QuenchedLiteral):
            inner = type_from_name(expr.type_param) if expr.type_param else AnyType()
            return QuenchedType(inner)
        elif isinstance(expr, AssignStmt):
            self.errors.append(Diagnostic(
                "E901", "Assignment cannot be used as an expression",
                expr.span, "error"))
            return ErrorType()
        elif isinstance(expr, Identifier):
            if expr.name == "__error__":
                return ErrorType()
            # `this` is bound at runtime inside fountain methods; its members are
            # resolved dynamically, so treat the receiver as Any rather than
            # flagging it as an unknown identifier.
            if expr.name == "this":
                return AnyType()
            info = self.scope.lookup(expr.name)
            if info is None:
                suggestions: list[str] = []
                s: Scope | None = self.scope
                while s:
                    suggestions.extend(s.bindings.keys())
                    s = s.parent
                matches = _nearest_match(expr.name, list(set(suggestions)))
                msg = f"Unknown identifier: '{expr.name}'"
                if matches:
                    msg += f" Did you mean: {', '.join(matches)}?"
                self.errors.append(Diagnostic("E011", msg, expr.span, "error"))
                return ErrorType()
            return cast(Type, info.get("type", AnyType()))
        elif isinstance(expr, BinaryOp):
            left_type = self._check_expr(expr.left)
            right_type = self._check_expr(expr.right)
            # Comparison ops return Bool
            if expr.op in (TokenType.EQEQ, TokenType.NE, TokenType.LT,
                           TokenType.GT, TokenType.LE, TokenType.GE):
                if not isinstance(left_type, type(right_type)) and \
                   not isinstance(left_type, AnyType) and not isinstance(right_type, AnyType):
                    self.errors.append(make_error("E022", span=expr.span,
                                                  op=expr.op.name,
                                                  expected=type_to_string(left_type),
                                                  found=type_to_string(right_type)))
                return BoolType()
            # Logical ops return Bool
            if expr.op in (TokenType.AND, TokenType.OR):
                return BoolType()
            # Arithmetic ops
            if not is_assignable(right_type, left_type) and \
               not isinstance(left_type, AnyType) and not isinstance(right_type, AnyType):
                self.errors.append(make_error("E022", span=expr.span,
                                              op=expr.op.name,
                                              expected=type_to_string(left_type),
                                              found=type_to_string(right_type)))
            if isinstance(left_type, FloatType) or isinstance(right_type, FloatType):
                return FloatType()
            return left_type
        elif isinstance(expr, LambdaExpr):
            self.enter_scope()
            for pname, ptype in expr.params:
                t = type_from_name(ptype) if ptype else AnyType()
                self.scope.declare(
                    pname, {"type": t, "is_mut": False, "kind": "param"})
            self._check_block(expr.body)
            self.exit_scope()
            return AnyType()
        elif isinstance(expr, UnaryOp):
            operand_type = self._check_expr(expr.operand)
            if expr.op == TokenType.NOT:
                return BoolType()
            return operand_type
        elif isinstance(expr, CallExpr):
            # E053: a governed function may not be called from core mode.
            if (isinstance(expr.callee, Identifier)
                    and expr.callee.name in self._governed_names
                    and not self.in_governed_mode):
                self.errors.append(make_error(
                    "E053", span=expr.span, name=expr.callee.name))
            callee_type = self._check_expr(expr.callee)
            if isinstance(callee_type, FunctionType):
                expected = len(callee_type.param_types)
                got = len(expr.args)
                if expected != got and not (expected == 0 and isinstance(callee_type, AnyType)):
                    self.errors.append(make_error("E030", span=expr.span,
                                                  name=str(expr.callee),
                                                  expected=expected, got=got))
                # Check argument types
                for i, arg in enumerate(expr.args):
                    if i < len(callee_type.param_types):
                        arg_type = self._check_expr(arg)
                        if not is_assignable(arg_type, callee_type.param_types[i]):
                            self.errors.append(make_error("E021", span=arg.span if hasattr(arg, 'span') else expr.span,
                                                          found=type_to_string(arg_type),
                                                          expected=type_to_string(callee_type.param_types[i])))
                return callee_type.return_type
            # Check args anyway
            for arg in expr.args:
                self._check_expr(arg)
            return AnyType()
        elif isinstance(expr, PipeExpr):
            left_type = self._check_expr(expr.left)
            right_type = self._check_expr(expr.right)
            return right_type
        elif isinstance(expr, GuardExpr):
            cond_type = self._check_expr(expr.condition)
            if not isinstance(cond_type, BoolType) and not isinstance(cond_type, AnyType):
                self.errors.append(make_error("E024", span=expr.condition.span,
                                              found=type_to_string(cond_type)))
            return self._check_expr(expr.expr)
        elif isinstance(expr, FloodExpr):
            return ReservoirType(AnyType())
        elif isinstance(expr, DripExpr):
            return AnyType()
        elif isinstance(expr, EvaporateExpr):
            return VoidType()
        elif isinstance(expr, CondenseExpr):
            return ReservoirType(AnyType())
        elif isinstance(expr, ArrayLiteral):
            elem = self._check_expr(expr.elements[0]) if expr.elements else AnyType()
            return ReservoirType(elem)
        elif isinstance(expr, MemberAccess):
            self._check_expr(expr.obj)
            return AnyType()
        elif isinstance(expr, Subscript):
            self._check_expr(expr.obj)
            self._check_expr(expr.index)
            return AnyType()
        elif isinstance(expr, SanitizeExpr):
            return self._check_expr(expr.expr)
        elif isinstance(expr, ArmorExpr):
            return self._check_expr(expr.expr)
        elif isinstance(expr, NewExpr):
            return AnyType()
        elif isinstance(expr, CascadeCall):
            inner = self._check_expr(expr.expr)
            return TaskType(inner)
        elif isinstance(expr, SymbolExpr):
            return StringType()
        elif isinstance(expr, PipelineExpr):
            left_type = self._check_expr(expr.left)
            right_type = self._check_expr(expr.right)
            return right_type
        elif isinstance(expr, CombineExpr):
            lt = self._check_expr(expr.left)
            rt = self._check_expr(expr.right)
            l_bool, r_bool = isinstance(lt, BoolType), isinstance(rt, BoolType)
            l_any, r_any = isinstance(lt, AnyType), isinstance(rt, AnyType)
            # A bool combined with a known non-bool is a malformed predicate:
            # reject it statically so it fails closed rather than coercing at
            # runtime. (review F3)
            if (l_bool and not r_bool and not r_any) or \
               (r_bool and not l_bool and not l_any):
                self.errors.append(make_error(
                    "E022", span=expr.span, op=expr.op, expected="Bool",
                    found=type_to_string(rt if l_bool else lt)))
                return BoolType()
            if l_bool and r_bool:
                return BoolType()
            return AnyType()
        return AnyType()


def check_ast(ast: Program) -> list[Diagnostic]:
    """Convenience function to type-check a Program AST."""
    checker = Checker()
    return checker.check_all(ast)

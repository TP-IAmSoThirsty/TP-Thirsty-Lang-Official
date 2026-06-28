"""
Thirsty-Lang AST Node Definitions
All Abstract Syntax Tree node types for the Thirsty-Lang language family.
Every node carries a span tuple (line_start, col_start, line_end, col_end).
"""
from dataclasses import dataclass, field
from typing import Any

from utf.thirsty_lang.token import TokenType

# === Expressions ===

@dataclass
class Expr:
    """Base class for all expressions."""
    span: tuple


@dataclass
class IntLiteral(Expr):
    value: int


@dataclass
class FloatLiteral(Expr):
    value: float


@dataclass
class StringLiteral(Expr):
    value: str


@dataclass
class BoolLiteral(Expr):
    value: bool


@dataclass
class NoneLiteral(Expr):
    pass


@dataclass
class ErrorLiteral(Expr):
    value: str


@dataclass
class QuenchedLiteral(Expr):
    """A quenched (optional) value with a type parameter."""
    type_param: str  # type name like "Int", "String"
    value: Any | None = None


@dataclass
class Identifier(Expr):
    name: str


@dataclass
class BinaryOp(Expr):
    left: Expr
    op: TokenType
    right: Expr


@dataclass
class UnaryOp(Expr):
    operand: Expr
    op: TokenType  # NOT or MINUS


@dataclass
class PipeExpr(Expr):
    left: Expr
    right: Expr


@dataclass
class GuardExpr(Expr):
    """thirst (expr) quench (condition) — guarded expression."""
    expr: Expr
    condition: Expr


@dataclass
class CallExpr(Expr):
    callee: Expr
    args: list


@dataclass
class NewExpr(Expr):
    class_name: str
    args: list


@dataclass
class SanitizeExpr(Expr):
    expr: Expr


@dataclass
class ArmorExpr(Expr):
    expr: Expr


@dataclass
class FloodExpr(Expr):
    """Fills a reservoir, or pushes to a list."""
    target: Expr


@dataclass
class DripExpr(Expr):
    """Iterates over a reservoir."""
    target: Expr


@dataclass
class EvaporateExpr(Expr):
    """Releases/frees a resource."""
    target: Expr


@dataclass
class CondenseExpr(Expr):
    """Collects values into a reservoir."""
    target: Expr


@dataclass
class ArrayLiteral(Expr):
    """[e1, e2, ...] reservoir/array literal — evaluates to a list."""
    elements: list


@dataclass
class MemberAccess(Expr):
    """obj.member — field read or (as a CallExpr callee) method dispatch."""
    obj: Expr
    member: str


@dataclass
class CascadeCall(Expr):
    """Async call with await."""
    expr: Expr


# === TSCG Nodes ===

@dataclass
class SymbolExpr(Expr):
    symbol_name: str


@dataclass
class PipelineExpr(Expr):
    """TSCG pipeline operator: left -> right"""
    left: Expr
    right: Expr


@dataclass
class CombineExpr(Expr):
    """TSCG combine operator: left ^ right or left || right"""
    left: Expr
    op: str  # "^" or "||"
    right: Expr


# === Statements ===

@dataclass
class Stmt:
    """Base class for all statements."""
    span: tuple


@dataclass
class ExprStmt(Stmt):
    expr: Expr


@dataclass
class BlockStmt(Stmt):
    statements: list


@dataclass
class VariableDecl(Stmt):
    """drink name: type = expr  OR  drink mut name = expr"""
    name: str
    var_type: str | None  # type annotation string, or None
    init_expr: Expr | None
    is_mut: bool = False


@dataclass
class AssignStmt(Stmt):
    target: Expr  # typically an Identifier
    value: Expr


@dataclass
class SymbolStmt(Stmt):
    symbol_name: str


@dataclass
class IfStmt(Stmt):
    condition: Expr
    then_block: Stmt  # BlockStmt
    else_block: Stmt | None = None


@dataclass
class WhileStmt(Stmt):
    condition: Expr
    body: Stmt


@dataclass
class ForStmt(Stmt):
    variable: Identifier
    iterable: Expr
    body: Stmt


@dataclass
class ReturnStmt(Stmt):
    value: Expr | None = None


@dataclass
class PourStmt(Stmt):
    """Output/print statement."""
    value: Expr


@dataclass
class SipStmt(Stmt):
    """Input/read statement."""
    target: Expr


@dataclass
class ImportStmt(Stmt):
    module_path: str
    alias: str | None = None


@dataclass
class SpillageStmt(Stmt):
    """try/spillage block with error handlers."""
    body: Stmt
    handlers: list = field(default_factory=list)  # list of (error_type_expr, handler_block)


@dataclass
class CleanupStmt(Stmt):
    """finally/cleanup block."""
    body: Stmt
    finalizer: Stmt


@dataclass
class ThrowStmt(Stmt):
    value: Expr


# === Security Statements ===

@dataclass
class SecurityBlock(Stmt):
    """shield / sanitize / armor / morph / detect / defend block."""
    block_type: str
    body: Stmt


@dataclass
class MorphDef(Stmt):
    """morph name(params) { body }"""
    name: str
    params: list
    body: Stmt


@dataclass
class DefendStrat(Stmt):
    """defend name(policy) { actions }"""
    name: str
    policy: str
    actions: list


# === Declarations ===

@dataclass
class FunctionDecl(Stmt):
    """glass name(params) -> return_type { body }"""
    name: str
    params: list  # list of (name, type_str)
    return_type: str | None  # optional return type annotation
    body: Stmt


@dataclass
class ClassDecl(Stmt):
    """fountain name { fields, methods }"""
    name: str
    methods: list
    fields: list = field(default_factory=list)


@dataclass
class EnumDecl(Stmt):
    name: str
    variants: list  # list of variant names (str)


@dataclass
class StructDecl(Stmt):
    name: str
    fields: list  # list of (name, type_str)


@dataclass
class InterfaceDecl(Stmt):
    name: str
    methods: list  # list of method signatures


@dataclass
class GovernedFunctionDecl(Stmt):
    """Governed function with a `requires` precondition.

    ``requires_annotation`` holds the source-text form of the precondition
    (used by the formatter and the CLI module-info path).
    ``requires_expr`` holds the parsed precondition AST that the interpreter
    evaluates at call time to enforce governance.
    """
    name: str
    params: list
    return_type: str | None
    body: Stmt
    requires_annotation: str | None = None
    requires_expr: Expr | None = None
    # Postcondition: checked after the body with ``result`` bound to the return.
    ensures_annotation: str | None = None
    ensures_expr: Expr | None = None
    # Invariant: a predicate enforced at both call entry and exit.
    invariant_annotation: str | None = None
    invariant_expr: Expr | None = None


# === Module & Program ===

@dataclass
class ModuleHeader:
    name: str
    mode: str  # "core" or "governed"
    span: tuple


@dataclass
class Program:
    stmts: list
    header: ModuleHeader | None = None
    span: tuple = (0, 0, 0, 0)
    # Set when a governed module had parse errors: the parser discards all
    # recovered statements (fail-closed) and the interpreter refuses to run it.
    parse_failed: bool = False


# === Shadow Thirst Nodes ===

@dataclass
class ShadowThirstMutation(Stmt):
    """mutation name { validated_canonical { shadow { ... } invariant { ... } canonical { ... } } }"""
    name: str
    shadow_block: 'BlockStmt | None' = None
    invariant_block: 'BlockStmt | None' = None
    canonical_block: 'BlockStmt | None' = None


# Type alias for any AST node
ASTNode = Expr | Stmt | Program | ModuleHeader

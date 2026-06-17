"""
Thirsty-Lang AST Node Definitions
All Abstract Syntax Tree node types for the Thirsty-Lang language family.
Every node carries a span tuple (line_start, col_start, line_end, col_end).
"""
from dataclasses import dataclass, field
from typing import Any, Optional
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
    value: Optional[Any] = None


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
    var_type: Optional[str]  # type annotation string, or None
    init_expr: Optional[Expr]
    is_mut: bool = False


@dataclass
class AssignStmt(Stmt):
    target: Expr  # typically an Identifier
    value: Expr


@dataclass
class IfStmt(Stmt):
    condition: Expr
    then_block: Stmt  # BlockStmt
    else_block: Optional[Stmt] = None


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
    value: Optional[Expr] = None


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
    alias: Optional[str] = None


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
    return_type: Optional[str]  # optional return type annotation
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
    """Governed function with requires annotation."""
    name: str
    params: list
    return_type: Optional[str]
    body: Stmt
    requires_annotation: Optional[str] = None


# === Module & Program ===

@dataclass
class ModuleHeader:
    name: str
    mode: str  # "core" or "governed"
    span: tuple


@dataclass
class Program:
    stmts: list
    header: Optional[ModuleHeader] = None
    span: tuple = (0, 0, 0, 0)


# === Shadow Thirst Nodes ===

@dataclass
class ShadowThirstMutation(Stmt):
    """mutation name { validated_canonical { shadow { ... } invariant { ... } canonical { ... } } }"""
    name: str
    shadow_block: Optional[Stmt] = None
    invariant_block: Optional[Stmt] = None
    canonical_block: Optional[Stmt] = None


# Type alias for any AST node
ASTNode = Expr | Stmt | Program | ModuleHeader
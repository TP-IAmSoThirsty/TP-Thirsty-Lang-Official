"""Thirst of Gods — Core Deity Contract Parser and Interpreter.

The Thirst of Gods tier validates and enforces deity-level contracts
on Thirsty-Lang programs. It operates on the existing AST from
src.utf.thirsty_lang.ast and provides governance interpretation.
"""
from dataclasses import dataclass, field
from typing import Any

from utf.thirsty_lang.ast import (
    Program, FunctionDecl, ClassDecl, SpillageStmt, CleanupStmt,
    ThrowStmt, CascadeCall, CallExpr, Identifier,
)
from utf.thirsty_lang.diagnostics import Diagnostic, DiagnosticSeverity


class ThirstOfGodsError(Exception):
    """Custom exception for Thirst of Gods violations."""
    pass


@dataclass
class DeityContract:
    """Result of a deity-level contract validation.

    Attributes:
        has_fountain_init: True if a fountain (class) with an init method exists.
        has_cascade_handler: True if cascade (async) calls have error handling.
        has_spillage_handler: True if spillage blocks have at least one handler.
        has_cleanup: True if a cleanup function/block exists.
        violations: List of human-readable violation descriptions.
    """
    has_fountain_init: bool = False
    has_cascade_handler: bool = False
    has_spillage_handler: bool = False
    has_cleanup: bool = False
    violations: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """All required deity-level checks pass."""
        return len(self.violations) == 0


def to_gods(ast: Program) -> DeityContract:
    """Validate a Thirsty-Lang AST for deity-level contract compliance.

    Checks:
      - At least one fountain (class) with an init method
      - At least one cascade call that has error handling
      - At least one spillage block with handlers
      - At least one cleanup function/block

    Args:
        ast: A Thirsty-Lang Program AST.

    Returns:
        A DeityContract with the results and any violations.
    """
    has_fountain_init = False
    has_cascade_handler = False
    has_spillage_handler = False
    has_cleanup = False
    violations: list[str] = []

    # Scan all top-level statements
    for stmt in ast.stmts:
        # Check for fountain: either a ClassDecl with init, or a FunctionDecl named "fountain"
        if isinstance(stmt, ClassDecl):
            for method in stmt.methods:
                if method.name == "init":
                    has_fountain_init = True
                    break
        if isinstance(stmt, FunctionDecl) and stmt.name.lower() == "fountain":
            has_fountain_init = True

        # Check for a standalone spillage statement with handlers
        if isinstance(stmt, SpillageStmt):
            if stmt.handlers:
                has_spillage_handler = True

        # Check for a standalone cleanup statement
        if isinstance(stmt, CleanupStmt):
            has_cleanup = True

        # Check for function declarations named cascade, spillage, cleanup
        if isinstance(stmt, FunctionDecl):
            name_lower = stmt.name.lower()
            if name_lower == "cascade" and stmt.params:
                has_cascade_handler = True
            if name_lower == "spillage" and stmt.params:
                has_spillage_handler = True
            if name_lower == "cleanup" and stmt.params:
                has_cleanup = True

        # Recursively scan inside function bodies for cascade calls with spillage
        if isinstance(stmt, FunctionDecl):
            _scan_for_cascade_and_spillage(stmt, violations)

    # Build violation list for missing contracts
    if not has_fountain_init:
        violations.append("Missing fountain with init method")

    if not has_cascade_handler:
        violations.append("Missing cascade handler with error handling")

    if not has_spillage_handler:
        violations.append("Missing spillage block with error handlers")

    if not has_cleanup:
        violations.append("Missing cleanup block")

    return DeityContract(
        has_fountain_init=has_fountain_init,
        has_cascade_handler=has_cascade_handler,
        has_spillage_handler=has_spillage_handler,
        has_cleanup=has_cleanup,
        violations=violations,
    )


def _scan_for_cascade_and_spillage(stmt, violations: list[str]):
    """Recursively scan a statement for cascade calls inside spillage blocks."""
    from utf.thirsty_lang.ast import (
        BlockStmt, SpillageStmt, IfStmt, WhileStmt,
        ForStmt, ReturnStmt, ExprStmt, VariableDecl, AssignStmt,
    )

    if isinstance(stmt, BlockStmt):
        for s in stmt.statements:
            _scan_for_cascade_and_spillage(s, violations)

    elif isinstance(stmt, SpillageStmt):
        if stmt.handlers:
            if "Missing cascade handler with error handling" in violations:
                violations.remove("Missing cascade handler with error handling")

    elif isinstance(stmt, IfStmt):
        _scan_for_cascade_and_spillage(stmt.then_block, violations)
        if stmt.else_block:
            _scan_for_cascade_and_spillage(stmt.else_block, violations)

    elif isinstance(stmt, WhileStmt):
        _scan_for_cascade_and_spillage(stmt.body, violations)

    elif isinstance(stmt, ForStmt):
        _scan_for_cascade_and_spillage(stmt.body, violations)

    elif isinstance(stmt, ReturnStmt):
        if stmt.value:
            _scan_expr_for_cascade(stmt.value, violations)

    elif isinstance(stmt, ExprStmt):
        _scan_expr_for_cascade(stmt.expr, violations)

    elif isinstance(stmt, VariableDecl):
        if stmt.init_expr:
            _scan_expr_for_cascade(stmt.init_expr, violations)

    elif isinstance(stmt, AssignStmt):
        _scan_expr_for_cascade(stmt.value, violations)


def _scan_expr_for_cascade(expr, violations: list[str]):
    """Recursively scan expressions for cascade calls."""
    from utf.thirsty_lang.ast import (
        BinaryOp, UnaryOp, CallExpr, PipeExpr, GuardExpr,
        CascadeCall, FloodExpr, DripExpr,
    )

    if isinstance(expr, CascadeCall):
        if "Missing cascade handler with error handling" in violations:
            violations.remove("Missing cascade handler with error handling")

    elif isinstance(expr, BinaryOp):
        _scan_expr_for_cascade(expr.left, violations)
        _scan_expr_for_cascade(expr.right, violations)

    elif isinstance(expr, UnaryOp):
        _scan_expr_for_cascade(expr.operand, violations)

    elif isinstance(expr, CallExpr):
        _scan_expr_for_cascade(expr.callee, violations)
        for arg in expr.args:
            _scan_expr_for_cascade(arg, violations)

    elif isinstance(expr, PipeExpr):
        _scan_expr_for_cascade(expr.left, violations)
        _scan_expr_for_cascade(expr.right, violations)

    elif isinstance(expr, GuardExpr):
        _scan_expr_for_cascade(expr.expr, violations)
        _scan_expr_for_cascade(expr.condition, violations)


def validate_deity_contract(ast: Program) -> list[Diagnostic]:
    """Validate deity contract compliance and return diagnostics.

    Reuses the Diagnostic class from utf.thirsty_lang.diagnostics.
    Returns diagnostics for each contract violation.

    Args:
        ast: A Thirsty-Lang Program AST.

    Returns:
        A list of Diagnostic objects for any contract violations.
    """
    contract = to_gods(ast)
    diagnostics: list[Diagnostic] = []

    if not contract.has_fountain_init:
        diagnostics.append(Diagnostic(
            code="G001",
            message="Deity contract violation: missing fountain with init method",
            span=(ast.span[0] if ast.span else 0, 0, 0, 0),
            severity=DiagnosticSeverity.ERROR.value,
        ))

    if not contract.has_cascade_handler:
        diagnostics.append(Diagnostic(
            code="G002",
            message="Deity contract violation: missing cascade handler with error handling",
            span=(ast.span[0] if ast.span else 0, 0, 0, 0),
            severity=DiagnosticSeverity.ERROR.value,
        ))

    if not contract.has_spillage_handler:
        diagnostics.append(Diagnostic(
            code="G003",
            message="Deity contract violation: missing spillage block with error handlers",
            span=(ast.span[0] if ast.span else 0, 0, 0, 0),
            severity=DiagnosticSeverity.ERROR.value,
        ))

    if not contract.has_cleanup:
        diagnostics.append(Diagnostic(
            code="G004",
            message="Deity contract violation: missing cleanup block",
            span=(ast.span[0] if ast.span else 0, 0, 0, 0),
            severity=DiagnosticSeverity.WARNING.value,
        ))

    return diagnostics


def interpret_gods(ast: Program, mode: str = "gods") -> Any:
    """Validate the deity contract, then interpret the program.

    Validates that the AST complies with the deity-level contract.
    If validation passes, runs the program through the standard
    Thirsty-Lang interpreter and returns the result.

    Args:
        ast: A Thirsty-Lang Program AST.
        mode: Thirst mode string (default "gods").

    Returns:
        The result of interpretation, or None if contract fails.

    Raises:
        ThirstOfGodsError: If the deity contract is not satisfied.
    """
    from utf.thirsty_lang.interpreter import Interpreter

    contract = to_gods(ast)

    if not contract.passed:
        violation_msg = "; ".join(contract.violations)
        raise ThirstOfGodsError(
            f"Deity contract validation failed: {violation_msg}"
        )

    interpreter = Interpreter(opt_level=0, debug_mode=False)
    result = interpreter.interpret(ast, mode=mode if mode == "gods" else "core")
    return result
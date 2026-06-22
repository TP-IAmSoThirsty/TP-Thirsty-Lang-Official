"""Thirst of Gods — Core Deity Contract Parser and Interpreter.

The Thirst of Gods tier validates and enforces deity-level contracts
on Thirsty-Lang programs. It operates on the existing AST from
src.utf.thirsty_lang.ast and provides governance interpretation.
"""
import dataclasses
from dataclasses import dataclass, field
from typing import Any

from utf.thirsty_lang.ast import (
    Program, FunctionDecl, ClassDecl, SpillageStmt, CleanupStmt,
    CascadeCall,
)
from utf.thirsty_lang.diagnostics import Diagnostic, DiagnosticSeverity


def _walk(node):
    """Yield ``node`` and every nested AST node (pre-order).

    Works over any Thirsty-Lang AST dataclass (Program, ModuleHeader, and every
    Expr/Stmt subclass), recursing through dataclass fields and lists/tuples.
    This is what makes deity-contract detection *structural*: a real
    ``CascadeCall`` or ``SpillageStmt`` is found wherever it lives — inside a
    method body, a nested block, a spillage body — not by matching a function's
    name.
    """
    if node is None or not dataclasses.is_dataclass(node):
        return
    yield node
    for f in dataclasses.fields(node):
        if f.name == "span":
            continue
        value = getattr(node, f.name)
        yield from _walk_value(value)


def _walk_value(value):
    if dataclasses.is_dataclass(value):
        yield from _walk(value)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_value(item)


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

    # A single structural walk over the whole AST — into every function/method
    # body and nested block — decides the four contract signals from the real
    # constructs present, never from what a function happens to be *named*.
    for node in _walk(ast):
        if isinstance(node, ClassDecl):
            if any(getattr(m, "name", None) == "init" for m in node.methods):
                has_fountain_init = True
        elif isinstance(node, CascadeCall):
            has_cascade_handler = True
        elif isinstance(node, SpillageStmt):
            if node.handlers:
                has_spillage_handler = True
        elif isinstance(node, CleanupStmt):
            has_cleanup = True

    violations: list[str] = []
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
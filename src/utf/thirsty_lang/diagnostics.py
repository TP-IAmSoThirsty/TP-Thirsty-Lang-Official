"""
Thirsty-Lang Error Diagnostics
Error code registry, diagnostic formatting, and bundle reporting.
"""
from dataclasses import dataclass, field
from enum import Enum


class DiagnosticSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    def __str__(self):
        return self.value


ERROR_CODES = {
    # Lexer errors (E001-E009)
    "E001": "Unrecognized character '{char}'",
    "E002": "Unterminated string literal",
    "E003": "Unterminated block comment",

    # Binding errors (E010-E019)
    "E010": "Duplicate binding: '{name}' already defined in this scope",
    "E011": "Unknown identifier: '{name}'",
    "E012": "Cannot resolve module path: '{path}'",

    # Assignment errors (E020-E029)
    "E020": "Cannot assign to immutable variable '{name}'",

    # Type errors (E021-E029)
    "E021": "Type mismatch: cannot assign {found} to variable of type {expected}",
    "E022": "Type mismatch: operator '{op}' requires {expected} operands, got {found}",
    "E023": "Type mismatch: return type {found} does not match declared return type {expected}",
    "E024": "Type mismatch: condition must be Bool, got {found}",

    # Call errors (E030-E039)
    "E030": "Call arity mismatch: {name} expects {expected} arguments but got {got}",

    # Import errors (E040-E049)
    "E040": "Module not found: '{module}'",
    "E041": "Name '{name}' not exported by module '{module}'",
    "E042": "Circular import detected for module '{module}'",

    # Governance errors (E050-E059)
    # E051/E052 removed: never reachable. The parser only builds a
    # GovernedFunctionDecl when a contract clause exists, so "missing requires"
    # cannot occur, and requires-not-satisfied is enforced at runtime (a
    # GovernanceViolation), not as a static diagnostic.
    "E050": "Governance violation: {detail}",
    "E053": "Cannot call governed function '{name}' from core mode",

    # Reservoir errors (E060-E069)
    "E060": "Reservoir is empty",
    "E061": "Index out of bounds: reservoir size is {size}, got index {index}",
    "E062": "Cannot flood onto non-reservoir type",

    # Quenched errors (E070-E079)
    "E070": "Quenched value is empty (parched)",
    "E071": "Cannot condense on non-quenched type",
    "E072": "Cannot evaporate on non-quenched type",
    "E073": "Quenched type mismatch: expected {expected}, got {found}",

    # Pipe errors (E080-E089)
    "E080": "Pipe type mismatch: left side produces {left_type}, right side expects {right_type}",

    # Async errors (E090-E099)
    "E090": "Cascade call failed: {detail}",
    "E091": "Await used outside cascade context",
    "E092": "Cannot cascade non-function type",
    "E093": "Cascade timeout after {timeout}ms",

    # Internal errors (E100)
    "E100": "Internal error: {detail}",

    # TARL errors (E200-E299)
    "E200": "TARL policy evaluation error: {detail}",
    "E201": "Unknown policy rule: {rule}",
    "E202": "Policy expression error: {detail}",

    # Shadow Thirst errors (E300-E399)
    "E300": "Shadow Thirst mutation validation error: {detail}",
    "E301": "Shadow plane isolation violation: {detail}",
    "E302": "Determinism violation: {detail}",
    "E303": "Resource estimate exceeded: {detail}",
    "E304": "Purity violation in invariant block: {detail}",
    "E305": "Memory evaporation estimate exceeded: {detail}",
    "E306": "Canonical convergence failure: {detail}",
    "E307": "Promotion blocked by critical failure: {detail}",

    # TSCG errors (E400-E499)
    "E400": "TSCG parse error: {detail}",
    "E401": "Unknown TSCG symbol: {symbol}",

    # TSCG-B errors (E500-E599)
    "E500": "TSCG-B frame error: {detail}",
    "E501": "CRC32 checksum mismatch",
    "E502": "SHA-256 hash mismatch",
    "E503": "Invalid frame magic: got {magic}",

    # General errors (E900-E901)
    "E900": "IO error: {detail}",
    "E901": "Syntax error: {detail}",
}


@dataclass
class Diagnostic:
    code: str
    message: str
    span: tuple  # (line_start, col_start, line_end, col_end)
    severity: str = "error"  # "error", "warning", "info"

    def format(self, source_lines: list[str] | None = None) -> str:
        result = f"[{self.code}] {self.severity}: {self.message}"
        if source_lines and len(source_lines) > 0:
            line, col = self.span[0], self.span[1]
            if 0 < line <= len(source_lines):
                source_line = source_lines[line - 1].rstrip("\n")
                result += f"\n  | {source_line}"
                caret = " " * (col - 1) + "^" if col > 0 else "^"
                result += f"\n  | {caret}"
        return result


@dataclass
class DiagnosticBundle:
    diagnostics: list[Diagnostic] = field(default_factory=list)
    source_lines: list[str] | None = None

    def add(self, diagnostic: Diagnostic):
        self.diagnostics.append(diagnostic)

    def has_errors(self) -> bool:
        return any(d.severity == "error" for d in self.diagnostics)

    def format_all(self) -> str:
        if not self.diagnostics:
            return "No diagnostics."
        parts = [f"Found {len(self.diagnostics)} diagnostic(s):"]
        for d in self.diagnostics:
            parts.append(d.format(self.source_lines))
        return "\n\n".join(parts)

    def __len__(self):
        return len(self.diagnostics)

    def __bool__(self):
        return len(self.diagnostics) > 0


def format_diagnostic(error: Diagnostic, source_lines: list[str] | None = None) -> str:
    """Convenience function to format a single diagnostic with source context."""
    return error.format(source_lines)


def make_error(code: str, span: tuple = (0, 0, 0, 0), **kwargs) -> Diagnostic:
    """Create a Diagnostic with the given error code and format its message with kwargs."""
    template = ERROR_CODES.get(code, f"Unknown error: {code}")
    message = template.format(**kwargs) if kwargs else template
    return Diagnostic(code=code, message=message, span=span, severity="error")


def make_warning(code: str, span: tuple = (0, 0, 0, 0), **kwargs) -> Diagnostic:
    template = ERROR_CODES.get(code, f"Unknown warning: {code}")
    message = template.format(**kwargs) if kwargs else template
    return Diagnostic(code=code, message=message, span=span, severity="warning")

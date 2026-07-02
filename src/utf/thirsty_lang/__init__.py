"""
Thirsty-Lang — A governance-first programming language
Part of the Universal Thirsty Family (UTF) language stack.
"""

from utf.thirsty_lang.ast import (
    ArmorExpr,
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
    ModuleHeader,
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
    StringLiteral,
    StructDecl,
    SymbolExpr,
    SymbolStmt,
    ThrowStmt,
    UnaryOp,
    VariableDecl,
    WhileStmt,
)
from utf.thirsty_lang.checker import Checker, check_ast
from utf.thirsty_lang.diagnostics import (
    ERROR_CODES,
    Diagnostic,
    DiagnosticBundle,
    DiagnosticSeverity,
    format_diagnostic,
)
from utf.thirsty_lang.formatter import format
from utf.thirsty_lang.interpreter import Environment, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.module_system import (
    get_builtin,
    list_builtins,
    list_stdlib_modules,
    resolve_import,
)
from utf.thirsty_lang.package_manager import PackageManager
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.token import KEYWORDS, Token, TokenType
from utf.thirsty_lang.typesys import (
    AnyType,
    BoolType,
    EnumType,
    ErrorType,
    FloatType,
    FunctionType,
    GenericType,
    GovernedType,
    InterfaceType,
    IntType,
    QuenchedType,
    ReservoirType,
    ResultType,
    StringType,
    StructType,
    TaskType,
    Type,
    TypeVariable,
    VoidType,
    is_assignable,
    type_to_string,
    unify,
)


# Lazy import to avoid RuntimeWarning about sys.modules
def main():
    from utf.thirsty_lang.cli import main as _cli_main
    return _cli_main()


try:
    from importlib.metadata import version as _version
    __version__ = _version("thirsty-lang")
except Exception:
    __version__ = "0.8.2"  # fallback
__all__ = [
    "Token", "TokenType", "KEYWORDS",
    "Lexer",
    "Program", "ModuleHeader",
    "FunctionDecl", "ClassDecl", "VariableDecl",
    "BinaryOp", "UnaryOp",
    "IfStmt", "WhileStmt", "ForStmt",
    "ReturnStmt", "PourStmt", "SipStmt",
    "ImportStmt", "AssignStmt", "ExprStmt", "BlockStmt",
    "IntLiteral", "FloatLiteral", "StringLiteral", "BoolLiteral", "NoneLiteral",
    "ErrorLiteral", "QuenchedLiteral",
    "Identifier", "CallExpr",
    "PipeExpr", "GuardExpr",
    "SecurityBlock", "SanitizeExpr", "ArmorExpr",
    "MorphDef", "DefendStrat",
    "EnumDecl", "StructDecl", "InterfaceDecl",
    "GovernedFunctionDecl",
    "SpillageStmt", "CleanupStmt", "ThrowStmt", "CascadeCall",
    "NewExpr", "FloodExpr", "DripExpr", "EvaporateExpr", "CondenseExpr",
    "SymbolExpr", "SymbolStmt", "PipelineExpr", "CombineExpr",
    "ShadowThirstMutation",
    "Parser",
    "Type", "IntType", "FloatType", "BoolType", "StringType", "VoidType", "AnyType", "ErrorType",
    "GenericType", "QuenchedType", "ReservoirType", "TaskType", "ResultType", "GovernedType",
    "EnumType", "StructType", "InterfaceType",
    "TypeVariable", "FunctionType",
    "is_assignable", "type_to_string", "unify",
    "Checker", "check_ast",
    "Interpreter", "Environment",
    "Diagnostic", "DiagnosticBundle", "DiagnosticSeverity", "ERROR_CODES", "format_diagnostic",
    "resolve_import", "get_builtin", "list_stdlib_modules", "list_builtins",
    "format",
    "PackageManager",
    "main",
]

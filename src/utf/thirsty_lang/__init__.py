"""
Thirsty-Lang — A governance-first programming language
Part of the Universal Thirsty Family (UTF) language stack.
"""

from utf.thirsty_lang.token import Token, TokenType, KEYWORDS
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.ast import (
    Program, ModuleHeader,
    FunctionDecl, ClassDecl, VariableDecl,
    BinaryOp, UnaryOp,
    IfStmt, WhileStmt, ForStmt,
    ReturnStmt, PourStmt, SipStmt,
    ImportStmt, AssignStmt, ExprStmt, BlockStmt,
    IntLiteral, FloatLiteral, StringLiteral, BoolLiteral, NoneLiteral, ErrorLiteral, QuenchedLiteral,
    Identifier, CallExpr,
    PipeExpr, GuardExpr,
    SecurityBlock, SanitizeExpr, ArmorExpr,
    MorphDef, DefendStrat,
    EnumDecl, StructDecl, InterfaceDecl,
    GovernedFunctionDecl,
    SpillageStmt, CleanupStmt, ThrowStmt, CascadeCall,
    NewExpr, FloodExpr, DripExpr, EvaporateExpr, CondenseExpr,
    SymbolExpr, PipelineExpr, CombineExpr,
    ShadowThirstMutation,
)
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.typesys import (
    Type, IntType, FloatType, BoolType, StringType, VoidType, AnyType, ErrorType,
    GenericType, QuenchedType, ReservoirType, TaskType, ResultType, GovernedType,
    EnumType, StructType, InterfaceType,
    TypeVariable, FunctionType,
    is_assignable, type_to_string, unify,
)
from utf.thirsty_lang.checker import Checker, check_ast
from utf.thirsty_lang.interpreter import Interpreter, Environment
from utf.thirsty_lang.diagnostics import Diagnostic, DiagnosticBundle, DiagnosticSeverity, ERROR_CODES, format_diagnostic
from utf.thirsty_lang.module_system import resolve_import, get_builtin, list_stdlib_modules, list_builtins
from utf.thirsty_lang.formatter import format
from utf.thirsty_lang.package_manager import PackageManager
# Lazy import to avoid RuntimeWarning about sys.modules
def main():
    from utf.thirsty_lang.cli import main as _cli_main
    return _cli_main()


__version__ = "1.0.0"
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
    "SymbolExpr", "PipelineExpr", "CombineExpr",
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
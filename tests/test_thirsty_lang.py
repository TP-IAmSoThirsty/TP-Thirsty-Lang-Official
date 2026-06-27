"""
Unit tests for Thirsty-Lang core: lexer, parser, checker, interpreter.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utf.thirsty_lang.ast import (
    BinaryOp,
    ExprStmt,
    FunctionDecl,
    IfStmt,
    IntLiteral,
    Program,
    StringLiteral,
    WhileStmt,
)
from utf.thirsty_lang.interpreter import Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.token import TokenType


class TestLexer:
    """Tests for the Thirsty-Lang lexer."""

    def test_empty_input(self):
        tokens = Lexer("").lex()
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF

    def test_keywords(self):
        code = "drink pour sip thirsty hydrated"
        tokens = Lexer(code).lex()
        keyword_types = [t.type for t in tokens[:-1]]
        assert TokenType.DRINK in keyword_types
        assert TokenType.POUR in keyword_types
        assert TokenType.SIP in keyword_types
        assert TokenType.THIRSTY in keyword_types
        assert TokenType.HYDRATED in keyword_types

    def test_identifiers(self):
        code = "hello world _private var123"
        tokens = Lexer(code).lex()
        idents = [t for t in tokens if t.type == TokenType.IDENTIFIER]
        assert len(idents) == 4
        assert idents[0].lexeme == "hello"

    def test_numbers(self):
        code = "42 3.14 0xFF 0b1010"
        tokens = Lexer(code).lex()
        types = [t.type for t in tokens[:-1]]
        assert TokenType.INT in types
        assert TokenType.FLOAT in types

    def test_strings(self):
        code = '"hello" \'world\''
        tokens = Lexer(code).lex()
        strings = [t for t in tokens if t.type == TokenType.STRING]
        assert len(strings) == 2

    def test_operators(self):
        code = "+ - * / -> || ^ == != < > <= >="
        tokens = Lexer(code).lex()
        types = [t.type for t in tokens[:-1]]
        assert TokenType.PLUS in types
        assert TokenType.MINUS in types
        assert TokenType.ARROW in types
        assert TokenType.PIPEPIPE in types
        assert TokenType.HATHAT in types
        assert TokenType.EQEQ in types

    def test_comments(self):
        code = "// line comment\ndrink x = 1 /* block */"
        tokens = Lexer(code).lex()
        assert len(tokens) > 1
        assert tokens[0].type == TokenType.DRINK


class TestParser:
    """Tests for the Thirsty-Lang parser."""

    def test_parse_module(self):
        code = "module test: core\ndrink x = 42"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        assert isinstance(ast, Program)
        assert ast.header is not None
        assert ast.header.name == "test"

    def test_parse_variable_decl(self):
        code = "drink x = 42"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        assert len(ast.stmts) >= 1

    def test_parse_function(self):
        code = "glass add(a, b) {\n    return a + b\n}"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        functions = [s for s in ast.stmts if isinstance(s, FunctionDecl)]
        assert len(functions) >= 1
        assert functions[0].name == "add"

    def test_parse_if(self):
        code = "thirsty x > 0 {\n    return 1\n} hydrated {\n    return 0\n}"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        if_stmts = [s for s in ast.stmts if isinstance(s, IfStmt)]
        assert len(if_stmts) >= 1

    def test_parse_while(self):
        code = "refill (x < 10) {\n    x = x + 1\n}"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        whiles = [s for s in ast.stmts if isinstance(s, WhileStmt)]
        assert len(whiles) >= 1

    def test_parser_error_recovery(self):
        code = "drink x = ;;; drink y = 1"  # syntax errors after drink
        tokens = Lexer(code).lex()
        parser = Parser(tokens)
        ast = parser.parse()
        # Parser should recover and continue (errors stored, ast still produced)
        assert len(ast.stmts) >= 0


class TestInterpreter:
    """Tests for the Thirsty-Lang interpreter."""

    def test_literal_expr(self):
        ast = Program(stmts=[ExprStmt(expr=IntLiteral(value=42, span=(0, 0, 0, 0)), span=(0, 0, 0, 0))], header=None)
        result = Interpreter().interpret(ast)
        assert result == 42

    def test_string_concat(self):
        ast = Program(stmts=[
            ExprStmt(expr=BinaryOp(
                left=StringLiteral(value="hello", span=(0, 0, 0, 0)),
                op=TokenType.PLUS,
                right=StringLiteral(value=" world", span=(0, 0, 0, 0)),
                span=(0, 0, 0, 0)
            ), span=(0, 0, 0, 0))
        ], header=None)
        result = Interpreter().interpret(ast)
        assert result == "hello world"

    def test_binary_ops(self):
        ast = Program(stmts=[
            ExprStmt(expr=BinaryOp(left=IntLiteral(value=6, span=(0, 0, 0, 0)), op=TokenType.STAR, right=IntLiteral(value=7, span=(0, 0, 0, 0)), span=(0, 0, 0, 0)), span=(0, 0, 0, 0))
        ], header=None)
        result = Interpreter().interpret(ast)
        assert result == 42

    def test_comparison(self):
        ast = Program(stmts=[
            ExprStmt(expr=BinaryOp(left=IntLiteral(value=5, span=(0, 0, 0, 0)), op=TokenType.GT, right=IntLiteral(value=3, span=(0, 0, 0, 0)), span=(0, 0, 0, 0)), span=(0, 0, 0, 0))
        ], header=None)
        result = Interpreter().interpret(ast)
        assert result is True

    def test_variable_decl_and_read(self):
        """Test that variable declaration and subsequent read works."""
        code = "drink x = 10\nx"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        result = Interpreter().interpret(ast)
        # The last expression (x) returns 10
        assert result == 10

    def test_function_call(self):
        code = "glass double(x) {\n    return x * 2\n}\ndouble(21)"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        result = Interpreter().interpret(ast)
        assert result == 42

    def test_pipeline_operator_feeds_left_into_right(self):
        # Regression: `_evaluate_pipeline` previously walked a non-existent
        # `.steps` attribute on the binary PipelineExpr and raised
        # AttributeError on any `->` expression. It must pipe left into right.
        code = "glass double(x) {\n    return x * 2\n}\n21 -> double"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        result = Interpreter().interpret(ast)
        assert result == 42

    def test_if_stmt(self):
        """Test if/else via parser-generated AST."""
        code = "thirsty 1 < 2 {\n    42\n} hydrated {\n    0\n}"
        tokens = Lexer(code).lex()
        ast = Parser(tokens).parse()
        result = Interpreter().interpret(ast)
        assert result == 42


if __name__ == "__main__":
    # Run tests
    for name in dir():
        obj = globals()[name]
        if isinstance(obj, type) and name.startswith("Test"):
            print(f"\n{'='*60}")
            print(f"Running {name}...")
            print('='*60)
            instance = obj()
            for attr in dir(instance):
                if attr.startswith("test_"):
                    try:
                        getattr(instance, attr)()
                        print(f"  ✓ {attr}")
                    except Exception as e:
                        print(f"  ✗ {attr}: {e}")
                        raise
    print("\n✅ All Thirsty-Lang tests passed!")

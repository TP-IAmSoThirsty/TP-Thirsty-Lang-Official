"""Tests for the newly-implemented language features:
`let`, `:=` (walrus define), the `for … in` keyword loop, and the
`strict` / `pure` module modes."""
import pytest

from utf.thirsty_lang.ast import ForStmt, VariableDecl
from utf.thirsty_lang.interpreter import Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.token import TokenType


def _parse(src):
    parser = Parser(Lexer(src).lex())
    ast = parser.parse()
    assert not parser.errors, parser.errors
    return ast


def _run(src):
    return Interpreter().interpret(_parse(src))


# --- lexer ----------------------------------------------------------------

def test_walrus_token():
    tokens = Lexer("x := 1").lex()
    assert tokens[1].type == TokenType.COLONEQ
    # bare colon still lexes as COLON
    assert Lexer("a: int").lex()[1].type == TokenType.COLON


def test_keywords_lex():
    for kw, tt in [("let", TokenType.LET), ("for", TokenType.FOR),
                   ("strict", TokenType.STRICT), ("pure", TokenType.PURE)]:
        assert Lexer(kw).lex()[0].type == tt


# --- let ------------------------------------------------------------------

def test_let_binding(capsys):
    _run("module m: core\nlet x = 5\npour x")
    assert capsys.readouterr().out.strip() == "5"


def test_let_is_immutable():
    with pytest.raises(TypeError, match="immutable"):
        _run("module m: core\nlet x = 1\nx = 2")


def test_let_with_type_annotation():
    ast = _parse("module m: core\nlet x: int = 7")
    decls = [s for s in ast.stmts if isinstance(s, VariableDecl)]
    assert decls[0].var_type == "int"
    assert decls[0].is_mut is False


# --- walrus := ------------------------------------------------------------

def test_walrus_defines_mutable(capsys):
    _run("module m: core\nx := 10\nx = 20\npour x")
    assert capsys.readouterr().out.strip() == "20"


def test_walrus_ast_is_mutable_decl():
    ast = _parse("module m: core\ny := 3")
    decl = [s for s in ast.stmts if isinstance(s, VariableDecl)][0]
    assert decl.is_mut is True
    assert decl.name == "y"


# --- for … in -------------------------------------------------------------

def test_for_in_keyword(capsys):
    _run("module m: core\nfor i in [1, 2, 3] {\n  pour i\n}")
    assert capsys.readouterr().out.split() == ["1", "2", "3"]


def test_for_in_with_parens(capsys):
    _run("module m: core\nfor (i in [4, 5]) {\n  pour i\n}")
    assert capsys.readouterr().out.split() == ["4", "5"]


def test_for_parses_to_forstmt():
    ast = _parse("module m: core\nfor i in [1] { pour i }")
    assert any(isinstance(s, ForStmt) for s in ast.stmts)


# --- strict mode ----------------------------------------------------------

def test_strict_requires_initialization():
    with pytest.raises(RuntimeError, match="strict"):
        _run("module m: strict\ndrink x")


def test_strict_allows_initialized(capsys):
    _run("module m: strict\ndrink x = 1\npour x")
    assert capsys.readouterr().out.strip() == "1"


def test_strict_mode_on_header():
    ast = _parse("module m: strict\ndrink x = 1")
    assert ast.header.mode == "strict"


# --- pure mode ------------------------------------------------------------

def test_pure_forbids_pour():
    with pytest.raises(RuntimeError, match="pure"):
        _run("module m: pure\npour 1")


def test_pure_forbids_sip():
    with pytest.raises(RuntimeError, match="pure"):
        _run("module m: pure\nsip x")


def test_pure_allows_pure_computation():
    result = _run("module m: pure\ndrink x = 2 + 3")
    # No exception; computation is allowed, only I/O is blocked.
    assert result is None or result == 5 or result is None

"""Parser recovery fail-closed tests mapped to THREAT_MODEL C036."""
import pytest

from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def test_governed_parser_errors_produce_non_executable_program(capsys):
    source = 'module m: governed\ndrink x = ;\npour "owned"\n'
    parser = Parser(Lexer(source).lex())
    ast = parser.parse()
    assert parser.errors
    assert ast.stmts == []
    with pytest.raises(GovernanceViolation):
        Interpreter().interpret(ast)
    assert "owned" not in capsys.readouterr().out

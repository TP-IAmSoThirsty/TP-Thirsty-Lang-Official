"""
Lock test: every shipped example parses, type-checks, and (where runnable)
executes with zero diagnostics. This keeps the language's own examples from
drifting away from the implemented grammar.
"""
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from utf.thirsty_lang.checker import check_ast
from utf.thirsty_lang.interpreter import Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser

EXAMPLES_DIR = os.path.join(
    os.path.dirname(__file__), '..', 'src', 'utf', 'examples')

THIRSTY_EXAMPLES = sorted(
    glob.glob(os.path.join(EXAMPLES_DIR, '**', '*.thirsty'), recursive=True)
    + glob.glob(os.path.join(EXAMPLES_DIR, '**', '*.thirstofgods'), recursive=True)
)
TARL_EXAMPLES = sorted(
    glob.glob(os.path.join(EXAMPLES_DIR, '**', '*.tarl'), recursive=True))


def _rel(path):
    return os.path.relpath(path, EXAMPLES_DIR)


@pytest.mark.parametrize("path", THIRSTY_EXAMPLES, ids=_rel)
def test_thirsty_example_parses_checks_runs(path):
    with open(path, encoding='utf-8') as f:
        source = f.read()

    lexer = Lexer(source)
    tokens = lexer.lex()
    assert not lexer.errors, f"lex errors in {_rel(path)}: {lexer.errors}"

    parser = Parser(tokens)
    ast = parser.parse()
    assert not parser.errors, (
        f"parse errors in {_rel(path)}: "
        f"{[e.message for e in parser.errors]}")

    diags = check_ast(ast)
    assert not diags, (
        f"checker diagnostics in {_rel(path)}: "
        f"{[d.message for d in diags]}")

    # Execution must not raise. The mode is taken from the module header.
    # Governed mode is fail-closed: a governed example that exercises a gated
    # capability needs a wired policy. If a sibling ``policy.tarl`` exists, run
    # the example through it (governance enforced, not implied).
    interp = Interpreter()
    policy_path = os.path.join(os.path.dirname(path), 'policy.tarl')
    if os.path.isfile(policy_path):
        from utf.tarl.core import PolicyParser
        from utf.tarl.runtime import TarlRuntime
        with open(policy_path, encoding='utf-8') as pf:
            policy = PolicyParser.parse(pf.read())
        interp.attach_tarl(TarlRuntime(policy)).set_authority('example')
    interp.interpret(ast)


@pytest.mark.parametrize("path", TARL_EXAMPLES, ids=_rel)
def test_tarl_example_parses(path):
    from utf.tarl.core import PolicyParser
    with open(path, encoding='utf-8') as f:
        source = f.read()
    policy = PolicyParser.parse(source)
    assert policy is not None


def test_examples_discovered():
    # Guard against the globs silently matching nothing.
    assert THIRSTY_EXAMPLES, "no .thirsty/.thirstofgods examples found"
    assert TARL_EXAMPLES, "no .tarl examples found"

"""Offensive file-import tests mapped to THREAT_MODEL C035."""
import pytest

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.module_system import ModuleCache
from utf.thirsty_lang.parser import Parser


def _run(src, policy_text):
    parser = Parser(Lexer(src).lex())
    ast = parser.parse()
    assert not parser.errors, parser.errors
    interp = Interpreter()
    interp.attach_tarl(TarlRuntime(PolicyParser.parse(policy_text)))
    interp.set_authority("admin")
    return interp.interpret(ast)


@pytest.fixture(autouse=True)
def clear_cache():
    ModuleCache.clear()
    yield
    ModuleCache.clear()


def test_imported_thirsty_function_uses_callers_governed_gate(tmp_path, capsys):
    lib = tmp_path / "lib.thirsty"
    lib.write_text(
        'module lib: core\n'
        'glass leak() {\n'
        '    pour "owned"\n'
        '    return 1\n'
        '}\n'
    )
    src = (
        "module m: governed\n"
        f"import \"{lib.as_posix()}\" as lib\n"
        "drink _ = lib.leak()\n"
    )
    policy = (
        'policy p\n'
        'when action == "import" => ALLOW\n'
        'when true => DENY\n'
    )
    with pytest.raises(GovernanceViolation) as exc:
        _run(src, policy)
    assert exc.value.proof is not None
    assert exc.value.proof.verdict == TarlVerdict.DENY
    assert "owned" not in capsys.readouterr().out


def test_imported_thirsty_top_level_effect_is_denied_during_import(tmp_path):
    lib = tmp_path / "lib_top.thirsty"
    lib.write_text('module lib: core\npour "owned"\n')
    src = (
        "module m: governed\n"
        f"import \"{lib.as_posix()}\" as lib\n"
    )
    policy = (
        'policy p\n'
        'when action == "import" => ALLOW\n'
        'when true => DENY\n'
    )
    with pytest.raises(GovernanceViolation):
        _run(src, policy)

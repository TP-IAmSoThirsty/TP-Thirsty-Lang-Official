"""Offensive capability-broker tests mapped to THREAT_MODEL C029-C032."""
import os

import pytest

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.module_system import SENSITIVE_STDLIB_CAPABILITIES
from utf.thirsty_lang.parser import Parser


def _run(src, policy_text, authority="admin"):
    parser = Parser(Lexer(src).lex())
    ast = parser.parse()
    assert not parser.errors, parser.errors
    interp = Interpreter()
    interp.attach_tarl(TarlRuntime(PolicyParser.parse(policy_text)))
    interp.set_authority(authority)
    return interp.interpret(ast)


IMPORT_ONLY = (
    'policy p\n'
    'when action == "import" => ALLOW\n'
    'when true => DENY\n'
)


@pytest.mark.parametrize(
    "module_path,alias,call_expr,side_effect_probe",
    [
        ("thirst::fs", "fs", 'fs.write_file("{path}", "owned")',
         lambda path: os.path.exists(path)),
        ("thirst::fs", "fs", 'fs.read_file("{path}")',
         lambda _path: False),
        ("thirst::fs", "fs", 'fs.mkdir("{path}")',
         lambda path: os.path.isdir(path)),
        ("thirst::fs", "fs", 'fs.remove("{path}")',
         lambda _path: False),
        ("thirst::http", "http", 'http.get("http://example.com")',
         lambda _path: False),
        ("thirst::http", "http", 'http.post("http://example.com", "x")',
         lambda _path: False),
        ("thirst::http", "http", 'http.put("http://example.com", "x")',
         lambda _path: False),
        ("thirst::http", "http", 'http.delete("http://example.com")',
         lambda _path: False),
        ("thirst::net", "net", 'net.tcp_connect("example.com", 80)',
         lambda _path: False),
        ("thirst::net", "net", 'net.tcp_listen(8080)',
         lambda _path: False),
        ("thirst::net", "net", 'net.udp_send("example.com", 53, "x")',
         lambda _path: False),
        ("thirst::process", "proc", 'proc.run("echo owned")',
         lambda _path: False),
        ("thirst::process", "proc", 'proc.exit(0)',
         lambda _path: False),
        ("thirst::env", "env", 'env.set("THIRSTY_ATTACK_TEST", "1")',
         lambda _path: os.environ.get("THIRSTY_ATTACK_TEST") == "1"),
        ("thirst::env", "env", 'env.all()',
         lambda _path: False),
        ("thirst::log", "log", 'log.info("owned")',
         lambda _path: False),
        ("thirst::log", "log", 'log.warn("owned")',
         lambda _path: False),
        ("thirst::log", "log", 'log.error("owned")',
         lambda _path: False),
        ("thirst::log", "log", 'log.debug("owned")',
         lambda _path: False),
        ("thirst::test", "test", 'test.describe("owned")',
         lambda _path: False),
        ("thirst::test", "test", 'test.it("owned")',
         lambda _path: False),
        ("thirst::sqlite", "sql", 'sql.connect("{path}")',
         lambda path: os.path.exists(path)),
        ("thirst::sqlite", "sql", 'sql.query("missing", "select 1")',
         lambda _path: False),
        ("thirst::sqlite", "sql", 'sql.execute("missing", "create table x(y)")',
         lambda _path: False),
        ("thirst::sqlite", "sql", 'sql.close("missing")',
         lambda _path: False),
    ],
)
def test_import_allow_does_not_grant_any_sensitive_stdlib_action(
    module_path, alias, call_expr, side_effect_probe, tmp_path, monkeypatch,
):
    monkeypatch.delenv("THIRSTY_ATTACK_TEST", raising=False)
    target = (tmp_path / "owned").as_posix()
    src = (
        "module m: governed\n"
        f"import \"{module_path}\" as {alias}\n"
        f"drink _ = {call_expr.format(path=target)}\n"
    )
    with pytest.raises(GovernanceViolation) as exc:
        _run(src, IMPORT_ONLY)
    assert exc.value.proof is not None
    assert exc.value.proof.verdict == TarlVerdict.DENY
    assert not side_effect_probe(target)


def test_sensitive_stdlib_metadata_has_explicit_actions():
    allowed = {"read", "write", "network", "execute"}
    for module_path, functions in SENSITIVE_STDLIB_CAPABILITIES.items():
        assert module_path.startswith("thirst::")
        assert functions
        for function_name, action in functions.items():
            assert function_name
            assert action in allowed

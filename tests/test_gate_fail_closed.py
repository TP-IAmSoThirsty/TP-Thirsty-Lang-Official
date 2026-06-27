"""
Denial tests for the fail-closed capability gate and proof-carrying decisions.

Governed mode never implies authority: a gated capability (write / read /
import) is DENIED unless a TARL policy engine + authority are wired AND return
ALLOW. Core mode is unaffected. Every governed boundary decision — capability
gate, contract ALLOW, contract DENY — carries a proof.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser


def _run(src, mode="governed", policy_text=None, authority=None):
    interp = Interpreter()
    if policy_text is not None:
        interp.attach_tarl(TarlRuntime(PolicyParser.parse(policy_text)))
    if authority is not None:
        interp.set_authority(authority)
    interp.interpret(Parser(Lexer(src).lex()).parse(), mode=mode)
    return interp


# ── Fail-closed: governed + no policy denies each gated capability ───────────

@pytest.mark.parametrize("src,action", [
    ('module m: governed\npour "hi"\n', "write"),
    ('module m: governed\ndrink _ = print("hi")\n', "write"),
    ('module m: governed\nsip x\n', "read"),
    ('module m: governed\nimport foo\n', "import"),
])
def test_gated_capability_denied_without_policy(src, action):
    with pytest.raises(GovernanceViolation) as exc:
        _run(src)
    proof = exc.value.proof
    assert proof is not None
    assert proof.verdict == TarlVerdict.DENY
    assert proof.rule_index == -1
    # Unsigned by design (symmetric MAC is opt-in; see docs/SIGNING.md).
    assert proof.signature == ""


def test_core_mode_capability_unaffected(capsys):
    # Core (ungoverned) mode is the default posture; no gating.
    _run('pour "hi"\n', mode="core")
    assert "hi" in capsys.readouterr().out


def test_policy_allow_lets_capability_through(capsys):
    # With a wired policy that ALLOWs write, the governed pour runs.
    _run('module m: governed\npour "hi"\n',
         policy_text='policy p\nwhen action == "write" => ALLOW\n'
                     'when true => DENY\n',
         authority="admin")
    assert "hi" in capsys.readouterr().out


@pytest.mark.parametrize("src", [
    'module m: governed\ndrink _ = print("hi")\n',
])
def test_policy_allow_lets_callable_stdout_builtins_through(src, capsys):
    _run(src,
         policy_text='policy p\nwhen action == "write" => ALLOW\n'
                     'when true => DENY\n',
         authority="admin")
    assert "hi" in capsys.readouterr().out


def test_policy_default_deny_blocks_capability():
    # A wired policy that does not match the write action denies it.
    with pytest.raises(GovernanceViolation):
        _run('module m: governed\npour "hi"\n',
             policy_text='policy p\nwhen action == "read" => ALLOW\n'
                         'when true => DENY\n',
             authority="admin")


def test_import_allow_does_not_grant_stdlib_fs_write(tmp_path):
    target = (tmp_path / "owned.txt").as_posix()
    src = (
        "module m: governed\n"
        "import 'thirst::fs' as fs\n"
        f"drink _ = fs.write_file(\"{target}\", \"owned\")\n"
    )
    with pytest.raises(GovernanceViolation) as exc:
        _run(src,
             policy_text='policy p\nwhen action == "import" => ALLOW\n'
                         'when true => DENY\n',
             authority="admin")
    assert exc.value.proof is not None
    assert exc.value.proof.verdict == TarlVerdict.DENY
    assert not (tmp_path / "owned.txt").exists()


@pytest.mark.parametrize("module_path,alias,call_expr", [
    ("thirst::process", "proc", 'proc.run("echo hi")'),
    ("thirst::env", "env", 'env.set("THIRSTY_ATTACK_TEST", "1")'),
    ("thirst::http", "http", 'http.get("http://example.com")'),
    ("thirst::net", "net", 'net.tcp_connect("example.com", 80)'),
    ("thirst::log", "log", 'log.info("hi")'),
])
def test_import_allow_does_not_grant_sensitive_stdlib_calls(
    module_path, alias, call_expr, monkeypatch,
):
    monkeypatch.delenv("THIRSTY_ATTACK_TEST", raising=False)
    src = (
        "module m: governed\n"
        f"import '{module_path}' as {alias}\n"
        f"drink _ = {call_expr}\n"
    )
    with pytest.raises(GovernanceViolation) as exc:
        _run(src,
             policy_text='policy p\nwhen action == "import" => ALLOW\n'
                         'when true => DENY\n',
             authority="admin")
    assert exc.value.proof is not None
    assert exc.value.proof.verdict == TarlVerdict.DENY
    assert os.environ.get("THIRSTY_ATTACK_TEST") is None


def test_separate_write_policy_allows_stdlib_fs_write(tmp_path):
    target = (tmp_path / "allowed.txt").as_posix()
    src = (
        "module m: governed\n"
        "import 'thirst::fs' as fs\n"
        f"drink _ = fs.write_file(\"{target}\", \"allowed\")\n"
    )
    _run(src,
         policy_text='policy p\nwhen action == "import" => ALLOW\n'
                     'when action == "write" => ALLOW\n'
                     'when true => DENY\n',
         authority="admin")
    assert (tmp_path / "allowed.txt").read_text() == "allowed"


# ── Proof-carrying contracts (ALLOW and DENY both certified) ─────────────────

_WITHDRAW = (
    "module bank: governed\n"
    "glass withdraw(balance, amount) requires balance - amount >= 0 "
    "{ return balance - amount }\n"
)


def test_contract_allow_carries_proof():
    interp = _run(_WITHDRAW + "drink r = withdraw(100, 50)\n")
    proof = interp._last_proof
    assert proof is not None
    assert proof.verdict == TarlVerdict.ALLOW
    assert any(e["result"] == "pass" for e in proof.trace)


def test_contract_deny_carries_proof():
    with pytest.raises(GovernanceViolation) as exc:
        _run(_WITHDRAW + "drink r = withdraw(100, 200)\n")
    proof = exc.value.proof
    assert proof is not None
    assert proof.verdict == TarlVerdict.DENY
    assert any(e["result"] == "fail" for e in proof.trace)

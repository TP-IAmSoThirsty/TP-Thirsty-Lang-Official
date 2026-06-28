"""WS1 regression: the in-language capability gate and out-of-language adapters
share a single CapabilityBroker mediation path (THREAT_MODEL invariant #7,
"no adapter side doors"), and governed filesystem targets are confined to the
allowed roots when a path guard is set (C042).
"""
import os

import pytest

from utf.tarl.broker import CapabilityBroker
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser

ALLOW_FS = (
    'policy p\n'
    'when action == "import" => ALLOW\n'
    'when action == "read" => ALLOW\n'
    'when action == "write" => ALLOW\n'
    'when true => DENY\n'
)


def _interp(policy_text=ALLOW_FS, authority="admin"):
    interp = Interpreter()
    interp.attach_tarl(TarlRuntime(PolicyParser.parse(policy_text)))
    interp.set_authority(authority)
    return interp


def _run(interp, src):
    parser = Parser(Lexer(src).lex())
    ast = parser.parse()
    assert not parser.errors, parser.errors
    return interp.interpret(ast)


def test_gate_delegates_to_capability_broker(monkeypatch):
    """Every gated stdlib call must flow through CapabilityBroker.require, so
    there is one enforcement path rather than a parallel one."""
    interp = _interp()
    seen = []
    real_require = CapabilityBroker.require

    def spy_require(self, action, target="", **ctx):
        seen.append((action, target))
        return real_require(self, action, target, **ctx)

    monkeypatch.setattr(CapabilityBroker, "require", spy_require)
    src = (
        "module m: governed\n"
        'import "thirst::log" as log\n'
        'drink _ = log.info("hello")\n'
    )
    _run(interp, src)
    assert any(a == "write" and t.startswith("thirst::log.info")
               for a, t in seen), seen


def test_make_broker_matches_gate_authority_context():
    """The broker built for adapters carries the same authority context the
    in-language gate uses, so both paths evaluate identically."""
    interp = _interp(authority="ops")
    broker = interp.make_broker()
    assert broker._authority_context() == interp._authority_context()


def test_path_guard_confines_fs_writes(tmp_path):
    """With a path guard, a write inside the allowed root is permitted but a
    traversal escape fails closed before the effect runs."""
    root = tmp_path / "sandbox"
    root.mkdir()
    interp = _interp()
    interp.set_path_guard([str(root)])

    inside = (root / "ok.txt").as_posix()
    _run(interp, (
        "module m: governed\n"
        'import "thirst::fs" as fs\n'
        f'drink _ = fs.write_file("{inside}", "data")\n'
    ))
    assert os.path.exists(inside)

    escape = (tmp_path / "outside.txt").as_posix()
    interp2 = _interp()
    interp2.set_path_guard([str(root)])
    with pytest.raises(GovernanceViolation) as exc:
        _run(interp2, (
            "module m: governed\n"
            'import "thirst::fs" as fs\n'
            f'drink _ = fs.write_file("{escape}", "owned")\n'
        ))
    assert exc.value.proof is not None
    assert exc.value.proof.verdict == TarlVerdict.DENY
    assert not os.path.exists(escape)


def test_no_path_guard_leaves_fs_behavior_unchanged(tmp_path):
    """Without a path guard, fs targets are brokered as-is (no confinement),
    preserving pre-existing behavior."""
    interp = _interp()
    target = (tmp_path / "plain.txt").as_posix()
    _run(interp, (
        "module m: governed\n"
        'import "thirst::fs" as fs\n'
        f'drink _ = fs.write_file("{target}", "data")\n'
    ))
    assert os.path.exists(target)

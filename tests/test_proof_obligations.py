import json
import os

import pytest

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.thirsty_lang import cli
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser
from utf.thirsty_lang.proof_obligations import (
    derive_context_schema,
    extract_proof_obligations,
    load_explicit_context_schema,
)

PROGRAM = """module demo: governed
import "thirst::fs" as fs

glass withdraw(amount) requires amount > 0 {
    fs.write_file("proof-side-effect.txt", "no")
    return amount
}

drink main = withdraw(1)
"""

POLICY = """policy p
when action == "import" and target == "thirst::fs" and authority == "admin" => ALLOW
when action == "write" and target == "thirst::fs.write_file" and authority == "admin" => ALLOW
when action == "withdraw" and amount > 0 and authority_authenticated == true => ALLOW
when true => DENY
"""


def _parse(src=PROGRAM):
    return Parser(Lexer(src).lex()).parse()


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def _run_cli(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["thirsty", *args])
    cli.main()


def test_proof_obligation_extraction_reports_core_surfaces(tmp_path):
    report = extract_proof_obligations(
        _parse(), PROGRAM, str(tmp_path / "p.thirsty"), policy_text=POLICY
    )
    assert report["format"] == "thirsty.proof_obligations.v1"
    assert report["side_effects_executed"] is False
    assert any(fn["name"] == "withdraw" and fn["governed"] for fn in report["functions"])
    assert any(item["module_path"] == "thirst::fs" for item in report["imports"])
    assert any(call["function"] == "write_file" for call in report["stdlib_sensitive_calls"])
    assert any(call["name"] == "withdraw" for call in report["governed_calls"])
    assert {"import", "write", "withdraw"} <= set(report["required_tarl_actions"])


def test_contract_obligations_preserve_string_literals():
    program = """module demo: governed
glass write_report(path) requires path != "" ensures result == "ok" {
    return "ok"
}
"""
    report = extract_proof_obligations(_parse(program), program, "p.thirsty")
    obligations = {
        (item["function"], item["phase"]): item["annotation"]
        for item in report["contract_obligations"]
    }
    assert obligations[("write_report", "entry")] == 'path != ""'
    assert obligations[("write_report", "exit")] == 'result == "ok"'


def test_derived_schema_from_policy_is_machine_readable():
    schema = derive_context_schema(POLICY).to_dict()
    assert schema["status"] == "complete"
    fields = {field["name"]: field for field in schema["fields"]}
    assert fields["action"]["kinds"] == ["string"]
    assert fields["target"]["kinds"] == ["string"]
    assert fields["authority"]["kinds"] == ["string"]
    assert fields["amount"]["kinds"] == ["number"]
    assert fields["authority_authenticated"]["kinds"] == ["bool"]


def test_missing_schema_fails_closed_in_prove(tmp_path, monkeypatch, capsys):
    source = _write(tmp_path, "p.thirsty", "module m: governed\ndrink main = 1\n")
    policy = _write(tmp_path, "p.tarl", "policy p\nwhen mystery => ALLOW\n")
    with pytest.raises(SystemExit) as exc:
        _run_cli(monkeypatch, "prove", source, "--policy", policy)
    assert exc.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["context_schema"]["status"] == "incomplete"
    assert report["side_effects_executed"] is False


def test_explicit_schema_mapping_shape_is_authoritative(tmp_path):
    schema_file = _write(
        tmp_path,
        "schema.json",
        json.dumps({
            "fields": {
                "user.role": "string",
                "risk": {"kind": "number", "required": False},
                "flags": ["string", "bool"],
            }
        }),
    )
    schema = load_explicit_context_schema(schema_file).to_dict()
    fields = {field["name"]: field for field in schema["fields"]}
    assert schema["status"] == "explicit"
    assert fields["user.role"]["kinds"] == ["string"]
    assert fields["risk"]["kinds"] == ["number"]
    assert fields["risk"]["required"] is False
    assert fields["flags"]["kinds"] == ["bool", "string"]


def test_sensitive_stdlib_call_appears_in_cli_manifest(tmp_path, monkeypatch, capsys):
    source = _write(tmp_path, "p.thirsty", PROGRAM)
    policy = _write(tmp_path, "p.tarl", POLICY)
    _run_cli(monkeypatch, "prove", source, "--policy", policy, "--emit-manifest")
    report = json.loads(capsys.readouterr().out)
    assert any(call["function"] == "write_file" for call in report["stdlib_sensitive_calls"])
    assert os.path.exists(os.path.splitext(source)[0] + ".proof-obligations.json")


def test_governed_build_manifest_records_proof_requirements(
    tmp_path, monkeypatch, capsys,
):
    source = _write(tmp_path, "p.thirsty", PROGRAM)
    policy = _write(tmp_path, "p.tarl", POLICY)
    _run_cli(
        monkeypatch,
        "build",
        "--target",
        "js",
        "--allow-governance-loss",
        "--emit-manifest",
        "--policy",
        policy,
        source,
    )
    capsys.readouterr()
    manifest = json.loads(open(os.path.splitext(source)[0] + ".manifest.json").read())
    assert manifest["source_hash"].startswith("sha256:")
    assert manifest["policy_dependencies"]["hash"].startswith("sha256:")
    assert manifest["context_schema"]["status"] == "complete"
    assert manifest["authority_requirements"]["authority_required"] is True
    assert manifest["proof_mode"]["verification"] == "required-for-governed-effects"
    assert manifest["audit_requirement"]["required"] is True
    assert manifest["governance_loss_status"] == "explicitly_allowed"


def test_denial_explanation_identifies_missing_authority_policy_context(
    tmp_path, monkeypatch, capsys,
):
    source = _write(tmp_path, "p.thirsty", "module m: governed\ndrink main = 1\n")
    _run_cli(monkeypatch, "explain-denial", source)
    explanation = json.loads(capsys.readouterr().out)
    categories = {item["category"] for item in explanation["missing"]}
    assert {"authority", "policy", "context"} <= categories
    policy_gaps = [
        item for item in explanation["missing"] if item["category"] == "policy"
    ]
    assert len(policy_gaps) == 1
    assert explanation["side_effects_executed"] is False


def test_thirsty_prove_does_not_execute_side_effects(tmp_path, monkeypatch, capsys):
    source = _write(tmp_path, "p.thirsty", PROGRAM)
    policy = _write(tmp_path, "p.tarl", POLICY)
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        _run_cli(monkeypatch, "prove", source, "--policy", policy)
    finally:
        os.chdir(cwd)
    report = json.loads(capsys.readouterr().out)
    assert report["side_effects_executed"] is False
    assert not (tmp_path / "proof-side-effect.txt").exists()


def test_replay_audit_proof_behavior_remains_unchanged():
    runtime = TarlRuntime(PolicyParser.parse('policy p\nwhen role == "admin" => ALLOW\n'))
    decision, proof = runtime.evaluate_with_proof({"role": "admin"})
    assert decision.verdict == TarlVerdict.ALLOW
    assert proof.verdict == TarlVerdict.ALLOW
    assert proof.policy_hash.startswith("sha256:")
    assert proof.context_hash.startswith("sha256:")

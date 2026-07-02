"""Regression tests for the 0.8.1 TARL adversarial peer review."""
import datetime

import pytest

from utf.tarl import cli as tarl_cli
from utf.tarl.core import PolicyParser, SafeExpr, evaluate_policy
from utf.tarl.spec import TarlProof, TarlVerdict
from utf.tarl.verifier import ProofVerifier


def test_numeric_string_ordering_is_numeric_not_lexicographic():
    policy = (
        "policy risk_gate:\n"
        "  when risk_score > 9 => DENY\n"
        "  when true => ALLOW\n"
    )

    decision = evaluate_policy({"risk_score": "50"}, policy_text=policy)

    assert decision.verdict == TarlVerdict.DENY
    assert decision.rule_index == 0


def test_non_numeric_ordering_mismatch_fails_closed():
    policy = (
        "policy risk_gate:\n"
        "  when risk_score > 9 => DENY\n"
        "  when true => ALLOW\n"
    )

    decision = evaluate_policy({"risk_score": "admin"}, policy_text=policy)

    assert decision.verdict == TarlVerdict.DENY
    assert decision.rule_index == 0
    assert "fail-closed" in decision.reason


def test_malformed_rule_condition_rejected_at_policy_load():
    policy = (
        "policy contract:\n"
        "  when authority == => DENY\n"
        "  when true => ALLOW\n"
    )

    with pytest.raises(SafeExpr.ParseError):
        PolicyParser.parse(policy)


def test_rule_evaluation_error_does_not_fall_through_to_allow():
    policy = PolicyParser.parse(
        "policy contract:\n"
        "  when risk_score > 9 => DENY\n"
        "  when true => ALLOW\n"
    )
    decision = evaluate_policy({"risk_score": object()}, policy=policy)

    assert decision.verdict == TarlVerdict.DENY
    assert decision.rule_index == 0
    assert "fail-closed" in decision.reason


def test_proof_verifier_rejects_forged_unsigned_proof_by_default():
    proof = TarlProof(
        policy_hash="sha256:" + "0" * 64,
        context_hash="sha256:" + "1" * 64,
        rule_index=0,
        matched_condition="true",
        verdict=TarlVerdict.ALLOW,
        evaluated_at="2026-07-01T00:00:00Z",
        trace=[{
            "rule_index": 0,
            "condition": "true",
            "verdict": "ALLOW",
            "matched": True,
        }],
        signature="",
        key_id="",
    )

    default_result = ProofVerifier().verify(proof)
    permissive_result = ProofVerifier(require_signature=False).verify(proof)

    assert not default_result.valid
    assert default_result.checks["signature"] is False
    assert permissive_result.valid


def test_trace_verdict_mismatch_is_invalid_even_when_unsigned_allowed():
    proof = TarlProof(
        policy_hash="sha256:" + "0" * 64,
        context_hash="sha256:" + "1" * 64,
        rule_index=0,
        matched_condition="true",
        verdict=TarlVerdict.ALLOW,
        evaluated_at="2026-07-01T00:00:00Z",
        trace=[{
            "rule_index": 0,
            "condition": "true",
            "verdict": "DENY",
            "matched": True,
        }],
        signature="",
        key_id="",
    )

    result = ProofVerifier(require_signature=False).verify(proof)

    assert not result.valid
    assert result.checks["trace"] is False


def test_evaluate_policy_threads_trusted_time_to_temporal_builtins():
    policy = "policy office:\n  when CURRENT_HOUR >= 9 => ALLOW\n  when true => DENY\n"

    decision = evaluate_policy(
        {},
        policy_text=policy,
        now=datetime.datetime(2026, 7, 1, 8, 0, tzinfo=datetime.UTC),
    )

    assert decision.verdict == TarlVerdict.DENY
    assert decision.rule_index == 1


def test_tarl_eval_refuses_temporal_policy_without_trusted_now(
    monkeypatch, tmp_path, capsys
):
    policy_path = tmp_path / "clock.tarl"
    policy_path.write_text(
        "policy clock:\n"
        "  when CURRENT_HOUR >= 9 => ALLOW\n"
        "  when true => DENY\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.argv", ["tarl", "eval", str(policy_path)])

    with pytest.raises(SystemExit) as exc:
        tarl_cli.main()

    assert exc.value.code == 1
    assert "--now" in capsys.readouterr().err


def test_tarl_parse_reports_malformed_policy_without_traceback(
    monkeypatch, tmp_path, capsys
):
    policy_path = tmp_path / "bad.tarl"
    policy_path.write_text(
        "policy bad:\n"
        "  when authority == => DENY\n"
        "  when true => ALLOW\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.argv", ["tarl", "parse", str(policy_path)])

    with pytest.raises(SystemExit) as exc:
        tarl_cli.main()

    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert "Error parsing policy" in captured.err
    assert "Traceback" not in captured.err


def test_tarl_eval_uses_explicit_trusted_now(monkeypatch, tmp_path, capsys):
    policy_path = tmp_path / "clock.tarl"
    policy_path.write_text(
        "policy clock:\n"
        "  when CURRENT_HOUR >= 9 => ALLOW\n"
        "  when true => DENY\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["tarl", "eval", str(policy_path), "--now", "2026-07-01T08:00:00Z"],
    )

    tarl_cli.main()

    assert "DENY" in capsys.readouterr().out


def test_auto_tarl_policy_matches_runtime_action_context(monkeypatch, tmp_path):
    src = tmp_path / "app.thirsty"
    src.write_text(
        "module app: governed\n"
        "glass deploy() {\n"
        "  return 1\n"
        "}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.argv", ["thirsty", "govern", "--auto-tarl", str(src)])

    from utf.thirsty_lang.cli import main as thirsty_main

    thirsty_main()
    generated = src.with_suffix(".tarl").read_text(encoding="utf-8")
    decision = evaluate_policy({"action": "deploy"}, policy_text=generated)

    assert 'when action == "deploy" => ALLOW' in generated
    assert decision.verdict == TarlVerdict.ALLOW

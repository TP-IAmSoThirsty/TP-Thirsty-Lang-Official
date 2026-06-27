"""CLI coverage for the hardening surfaces: tarl lint, audit verify-chain,
and strict verify flags (freshness / revocation)."""
import sys

import pytest

from utf.tarl import cli
from utf.tarl.archive import TarlAuditArchive
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime


def _run(argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["tarl", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_lint_flags_broad_allow_nonzero(tmp_path, monkeypatch, capsys):
    p = tmp_path / "broad.tarl"
    p.write_text("policy p\nwhen true => ALLOW\n")
    code = _run(["lint", str(p)], monkeypatch)
    assert code == 1
    assert "BROAD-ALLOW" in capsys.readouterr().out


def test_lint_clean_policy_zero(tmp_path, monkeypatch, capsys):
    p = tmp_path / "ok.tarl"
    p.write_text('policy p\nwhen role == "admin" => ALLOW\nwhen true => DENY\n')
    code = _run(["lint", str(p)], monkeypatch)
    assert code == 0


def test_audit_verify_chain_intact(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "a.db")
    rt = TarlRuntime(PolicyParser.parse("policy p\nwhen true => ALLOW\n"))
    with TarlAuditArchive(db) as arc:
        for i in range(3):
            _d, proof = rt.evaluate_with_proof({"i": i})
            arc.store(proof)
    code = _run(["audit", "verify-chain", "--db", db], monkeypatch)
    assert code == 0
    assert "INTACT" in capsys.readouterr().out


def test_audit_verify_chain_detects_tamper(tmp_path, monkeypatch, capsys):
    import sqlite3
    db = str(tmp_path / "a.db")
    rt = TarlRuntime(PolicyParser.parse("policy p\nwhen true => ALLOW\n"))
    with TarlAuditArchive(db) as arc:
        for i in range(3):
            _d, proof = rt.evaluate_with_proof({"i": i})
            arc.store(proof)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE proofs SET proof_json='{}' WHERE id=2")
    conn.commit()
    conn.close()
    code = _run(["audit", "verify-chain", "--db", db], monkeypatch)
    assert code == 1
    assert "BROKEN" in capsys.readouterr().out

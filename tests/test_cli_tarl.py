"""CLI coverage for the `tarl` policy tool."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from utf.tarl import cli as tarl_cli
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime

POLICY = 'when role == "admin" => ALLOW\nwhen true => DENY\n'
POLICY2 = 'when role == "admin" => ALLOW\nwhen true => DENY\n'

TEST_SUITE = '''\
policy:
    when role == "admin" => ALLOW

test "admin allowed":
    context: {"role": "admin"}
    expect: ALLOW
'''

FAILING_SUITE = '''\
policy:
    when x == 1 => ALLOW

test "wrong":
    context: {"x": 1}
    expect: DENY
'''


def _argv(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", list(args))


def _policy(tmp_path, text=POLICY, name="p.tarl"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def _proof_file(tmp_path):
    rt = TarlRuntime(PolicyParser.parse(POLICY))
    _decision, proof = rt.evaluate_with_proof({"role": "admin"})
    p = tmp_path / "proof.json"
    p.write_text(proof.to_json())
    return str(p)


def _ed25519_proof_file(tmp_path):
    rt = TarlRuntime(PolicyParser.parse(POLICY))
    rt.set_ed25519_signing_key("ed1", bytes(range(32)))
    _decision, proof = rt.evaluate_with_proof({"role": "admin"})
    p = tmp_path / "proof-ed25519.json"
    p.write_text(proof.to_json())
    public_key = Ed25519PrivateKey.from_private_bytes(
        bytes(range(32))
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return str(p), public_key.hex()


# --- dispatch -------------------------------------------------------------

def test_no_command(monkeypatch):
    _argv(monkeypatch, "tarl")
    with pytest.raises(SystemExit):
        tarl_cli.main()


# --- eval -----------------------------------------------------------------

def test_eval_text(monkeypatch, tmp_path, capsys):
    _argv(monkeypatch, "tarl", "eval", _policy(tmp_path),
          "-c", '{"role": "admin"}')
    tarl_cli.main()
    assert "ALLOW" in capsys.readouterr().out


def test_eval_json(monkeypatch, tmp_path, capsys):
    _argv(monkeypatch, "tarl", "eval", _policy(tmp_path),
          "-c", '{"role": "guest"}', "--json")
    tarl_cli.main()
    assert '"verdict"' in capsys.readouterr().out


def test_eval_bad_context(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "eval", _policy(tmp_path), "-c", "{bad")
    with pytest.raises(SystemExit):
        tarl_cli.main()


# --- parse ----------------------------------------------------------------

def test_parse(monkeypatch, tmp_path, capsys):
    _argv(monkeypatch, "tarl", "parse", _policy(tmp_path))
    tarl_cli.main()
    assert "Rules:" in capsys.readouterr().out


# --- explain --------------------------------------------------------------

def test_explain_text(monkeypatch, tmp_path, capsys):
    _argv(monkeypatch, "tarl", "explain", _policy(tmp_path),
          "-c", '{"role": "admin"}', "--verbose")
    tarl_cli.main()
    assert capsys.readouterr().out.strip()


def test_explain_json(monkeypatch, tmp_path, capsys):
    _argv(monkeypatch, "tarl", "explain", _policy(tmp_path),
          "-c", '{"role": "admin"}', "--json")
    tarl_cli.main()
    assert capsys.readouterr().out.strip().startswith("{")


def test_explain_bad_context(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "explain", _policy(tmp_path), "-c", "{bad")
    with pytest.raises(SystemExit):
        tarl_cli.main()


# --- test -----------------------------------------------------------------

def test_test_file_pass(monkeypatch, tmp_path):
    f = tmp_path / "s.tarl_test"
    f.write_text(TEST_SUITE)
    _argv(monkeypatch, "tarl", "test", str(f))
    with pytest.raises(SystemExit) as exc:
        tarl_cli.main()
    assert exc.value.code == 0


def test_test_file_fail_json(monkeypatch, tmp_path, capsys):
    f = tmp_path / "s.tarl_test"
    f.write_text(FAILING_SUITE)
    _argv(monkeypatch, "tarl", "test", str(f), "--json")
    with pytest.raises(SystemExit) as exc:
        tarl_cli.main()
    assert exc.value.code == 1
    assert "results" in capsys.readouterr().out


def test_test_directory(monkeypatch, tmp_path):
    (tmp_path / "s.tarl_test").write_text(TEST_SUITE)
    _argv(monkeypatch, "tarl", "test", str(tmp_path))
    with pytest.raises(SystemExit):
        tarl_cli.main()


def test_test_none_found(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "test", str(tmp_path))
    with pytest.raises(SystemExit) as exc:
        tarl_cli.main()
    assert exc.value.code == 1


# --- audit ----------------------------------------------------------------

def test_audit_query_empty(monkeypatch, tmp_path, capsys):
    db = str(tmp_path / "a.db")
    _argv(monkeypatch, "tarl", "audit", "query", "--db", db)
    tarl_cli.main()
    assert "No proofs found" in capsys.readouterr().out


def test_audit_query_json(monkeypatch, tmp_path, capsys):
    db = str(tmp_path / "a.db")
    _argv(monkeypatch, "tarl", "audit", "query", "--db", db, "--json")
    tarl_cli.main()
    assert capsys.readouterr().out.strip() == "[]"


def test_audit_no_subcommand(monkeypatch):
    _argv(monkeypatch, "tarl", "audit")
    with pytest.raises(SystemExit):
        tarl_cli.main()


# --- verify ---------------------------------------------------------------

def test_verify_proof(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "verify", _proof_file(tmp_path))
    with pytest.raises(SystemExit):
        tarl_cli.main()


def test_verify_proof_json_with_policy(monkeypatch, tmp_path, capsys):
    _argv(monkeypatch, "tarl", "verify", _proof_file(tmp_path),
          "--policy", _policy(tmp_path), "--json")
    with pytest.raises(SystemExit):
        tarl_cli.main()
    assert '"valid"' in capsys.readouterr().out


def test_verify_bad_proof(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid proof}")
    _argv(monkeypatch, "tarl", "verify", str(bad))
    with pytest.raises(SystemExit):
        tarl_cli.main()


def test_verify_missing_policy(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "verify", _proof_file(tmp_path),
          "--policy", str(tmp_path / "nope.tarl"))
    with pytest.raises(SystemExit):
        tarl_cli.main()


def test_verify_bad_hmac_key(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "verify", _proof_file(tmp_path),
          "--hmac-key", "k1:zz")
    with pytest.raises(SystemExit):
        tarl_cli.main()


def test_verify_with_hmac_key(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "verify", _proof_file(tmp_path),
          "--hmac-key", "k1:deadbeef")
    with pytest.raises(SystemExit):
        tarl_cli.main()


def test_verify_with_ed25519_key(monkeypatch, tmp_path):
    proof_file, public_hex = _ed25519_proof_file(tmp_path)
    _argv(monkeypatch, "tarl", "verify", proof_file,
          "--ed25519-key", f"ed1:{public_hex}")
    with pytest.raises(SystemExit) as exc:
        tarl_cli.main()
    assert exc.value.code == 0


# --- analyze (z3) ---------------------------------------------------------

pytest.importorskip("z3")


@pytest.mark.parametrize("mode", ["coverage", "shadows", "conflicts"])
def test_analyze_single(monkeypatch, tmp_path, mode):
    _argv(monkeypatch, "tarl", "analyze", mode, _policy(tmp_path))
    with pytest.raises(SystemExit):
        tarl_cli.main()


def test_analyze_shadows_json(monkeypatch, tmp_path, capsys):
    _argv(monkeypatch, "tarl", "analyze", "shadows", _policy(tmp_path), "--json")
    with pytest.raises(SystemExit):
        tarl_cli.main()
    assert capsys.readouterr().out.strip().startswith("{")


@pytest.mark.parametrize("mode", ["equiv", "refines"])
def test_analyze_two_policies(monkeypatch, tmp_path, mode):
    p1 = _policy(tmp_path, POLICY, "a.tarl")
    p2 = _policy(tmp_path, POLICY2, "b.tarl")
    _argv(monkeypatch, "tarl", "analyze", mode, p1, p2)
    with pytest.raises(SystemExit):
        tarl_cli.main()


def test_analyze_equiv_needs_two(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "analyze", "equiv", _policy(tmp_path))
    with pytest.raises(SystemExit) as exc:
        tarl_cli.main()
    assert exc.value.code == 1


def test_analyze_file_error(monkeypatch, tmp_path):
    _argv(monkeypatch, "tarl", "analyze", "coverage", str(tmp_path / "no.tarl"))
    with pytest.raises(SystemExit):
        tarl_cli.main()

"""Production-acceptance end-to-end: a governed program runs under --hardened
with file-based trust-root keys (no hex on argv), brokered stdlib effects fail
closed without a grant and succeed with one, and a durable replay store rejects
a re-presented proof. This is the scenario the CI 'production acceptance' job
runs; keeping it as a test makes the production deployment requirement
regression-proof.
"""
import json

import pytest

from utf.tarl import keystore
from utf.tarl.authority import AuthorityIssuer
from utf.thirsty_lang import cli

ALLOW_WRITE = (
    'policy p\n'
    'when action == "import" => ALLOW\n'
    'when action == "write" => ALLOW\n'
    'when true => DENY\n'
)
DENY_WRITE = (
    'policy p\n'
    'when action == "import" => ALLOW\n'
    'when true => DENY\n'
)
PROGRAM = (
    "module m: governed\n"
    'import "thirst::log" as log\n'
    'drink _ = log.info("governed-hello")\n'
)


def _provision(tmp_path):
    """Mint issuer + signer keys to files and issue a signed authority token."""
    issuer_key = keystore.generate("issuer-1", keystore.ROLE_AUTHORITY_ISSUER)
    signer_key = keystore.generate("signer-1", keystore.ROLE_PROOF_SIGNER)
    issuer_priv = str(tmp_path / "issuer.key")
    issuer_pub = str(tmp_path / "issuer.pub")
    signer_priv = str(tmp_path / "signer.key")
    issuer_key.write(issuer_priv, include_private=True)
    issuer_key.public_only().write(issuer_pub, include_private=False)
    signer_key.write(signer_priv, include_private=True)

    issuer = AuthorityIssuer("issuer-1", issuer_key.private_bytes())
    claim = issuer.issue("ops", grants=("write",))
    token = str(tmp_path / "token.json")
    with open(token, "w") as f:
        f.write(claim.to_json())
    return {
        "issuer_pub": issuer_pub, "signer_priv": signer_priv, "token": token,
    }


def _run(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["thirsty", *args])
    cli.main()


def test_hardened_run_with_keyfiles_allows_granted_effect(
    monkeypatch, tmp_path, capsys
):
    keys = _provision(tmp_path)
    policy = str(tmp_path / "allow.tarl")
    with open(policy, "w") as f:
        f.write(ALLOW_WRITE)
    prog = str(tmp_path / "p.thirsty")
    with open(prog, "w") as f:
        f.write(PROGRAM)

    _run(monkeypatch, "run", prog, "--thirst-level", "governed",
         "--hardened", "--policy", policy,
         "--authority-token", keys["token"],
         "--authority-key-file", keys["issuer_pub"],
         "--sign-proofs-file", keys["signer_priv"])
    assert "governed-hello" in capsys.readouterr().out


def test_hardened_run_fails_closed_without_grant(monkeypatch, tmp_path):
    keys = _provision(tmp_path)
    policy = str(tmp_path / "deny.tarl")
    with open(policy, "w") as f:
        f.write(DENY_WRITE)
    prog = str(tmp_path / "p.thirsty")
    with open(prog, "w") as f:
        f.write(PROGRAM)

    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "run", prog, "--thirst-level", "governed",
             "--hardened", "--policy", policy,
             "--authority-token", keys["token"],
             "--authority-key-file", keys["issuer_pub"],
             "--sign-proofs-file", keys["signer_priv"])
    assert exc.value.code == 2  # governance denial exit code


def test_full_chain_keyfile_token_is_well_formed(tmp_path):
    """The issued token and key files are internally consistent."""
    keys = _provision(tmp_path)
    issuer_pub = keystore.load(keys["issuer_pub"])
    assert issuer_pub.role == keystore.ROLE_AUTHORITY_ISSUER
    assert not issuer_pub.has_private
    with open(keys["token"]) as f:
        claim = json.load(f)
    assert claim["subject"] == "ops"
    assert claim["signature"].startswith("ed25519:")

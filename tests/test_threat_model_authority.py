"""Authority-provenance and hardened-mode tests (THREAT_MODEL C027-C028).

Authority must come from an authenticated, Ed25519-signed credential — never
from a bare ``--authority`` string or the environment alone. In hardened mode a
governed gate additionally requires the runtime to emit Ed25519-signed proofs.
"""
import pytest

from utf.tarl.authority import (
    AuthorityClaim,
    AuthorityIssuer,
    AuthorityVerifier,
    VerifiedAuthority,
)
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.thirsty_lang.interpreter import GovernanceViolation, Interpreter
from utf.thirsty_lang.lexer import Lexer
from utf.thirsty_lang.parser import Parser

ISSUER_SEED = bytes(range(32))
WRONG_SEED = bytes([255 - i for i in range(32)])
PROOF_SEED = bytes(range(1, 33))

ALLOW_WRITE = (
    'policy p\n'
    'when action == "write" => ALLOW\n'
    'when true => DENY\n'
)
REQUIRE_AUTHENTICATED = (
    'policy p\n'
    'when authority_authenticated == true => ALLOW\n'
    'when true => DENY\n'
)


def _issuer():
    return AuthorityIssuer("issuer-1", ISSUER_SEED)


def _verifier(issuer=None):
    issuer = issuer or _issuer()
    return AuthorityVerifier().add_ed25519_key(
        issuer.key_id, issuer.public_key_bytes()
    )


# ── AuthorityVerifier unit tests ───────────────────────────────────────────────

def test_issued_claim_verifies_and_carries_grants():
    issuer = _issuer()
    claim = issuer.issue("admin", grants=("charge", "refund"))
    result = _verifier(issuer).verify(claim)
    assert result.valid
    assert result.authority.authenticated
    assert result.authority.subject == "admin"
    assert result.authority.has_grant("charge")


def test_unsigned_claim_is_rejected():
    claim = AuthorityClaim(subject="admin")  # no signature
    result = _verifier().verify(claim)
    assert not result.valid
    assert result.authority is None


def test_wrong_issuer_key_is_rejected():
    claim = _issuer().issue("admin")
    wrong_issuer = AuthorityIssuer("issuer-1", WRONG_SEED)
    verifier = AuthorityVerifier().add_ed25519_key(
        "issuer-1", wrong_issuer.public_key_bytes()
    )
    assert not verifier.verify(claim).valid


def test_unknown_issuer_key_id_is_rejected():
    claim = _issuer().issue("admin")
    assert not AuthorityVerifier().verify(claim).valid


@pytest.mark.parametrize("field,value", [
    ("subject", "root"),
    ("grants", ("charge", "drain")),
    ("issued_at", "2099-01-01T00:00:00+00:00"),
])
def test_tampered_claim_is_rejected(field, value):
    claim = _issuer().issue("admin", grants=("charge",))
    setattr(claim, field, value)  # tamper after signing
    assert not _verifier().verify(claim).valid


def test_expired_claim_is_rejected():
    import datetime
    past = datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC)
    claim = _issuer().issue("admin", ttl_seconds=60, now=past)
    assert not _verifier().verify(claim).valid


def test_hmac_style_signature_is_rejected():
    claim = _issuer().issue("admin")
    claim.signature = "hmac-sha256:" + claim.signature.split(":", 1)[1]
    assert not _verifier().verify(claim).valid


# ── Interpreter hardened-mode integration ──────────────────────────────────────

def _interp(policy_text, *, hardened, authority, sign_ed25519):
    interp = Interpreter()
    runtime = TarlRuntime(PolicyParser.parse(policy_text))
    if sign_ed25519:
        runtime.set_ed25519_signing_key("proof-1", PROOF_SEED)
    interp.attach_tarl(runtime)
    if isinstance(authority, VerifiedAuthority):
        interp.set_verified_authority(authority)
    else:
        interp.set_authority(authority)
    if hardened:
        interp.set_hardened(True)
    return interp


def _run(interp, src="module m: governed\npour \"x\"\n"):
    ast = Parser(Lexer(src).lex()).parse()
    return interp.interpret(ast)


def test_c027_bare_string_authority_denied_in_hardened_mode(capsys):
    # Forging authority by passing `--authority admin` must not grant anything
    # in hardened mode, even when the policy would ALLOW the action.
    interp = _interp(ALLOW_WRITE, hardened=True, authority="admin",
                     sign_ed25519=True)
    with pytest.raises(GovernanceViolation) as exc:
        _run(interp)
    assert exc.value.proof.verdict == TarlVerdict.DENY
    assert "authenticated" in exc.value.reason
    assert "x" not in capsys.readouterr().out


def test_hardened_requires_ed25519_signed_proofs():
    issuer = _issuer()
    verified = _verifier(issuer).verify(issuer.issue("admin")).authority
    # Authenticated authority, but the runtime is not configured to sign proofs.
    interp = _interp(ALLOW_WRITE, hardened=True, authority=verified,
                     sign_ed25519=False)
    with pytest.raises(GovernanceViolation) as exc:
        _run(interp)
    assert "Ed25519" in exc.value.reason


def test_hardened_allows_authenticated_authority_with_signed_proofs(capsys):
    issuer = _issuer()
    verified = _verifier(issuer).verify(
        issuer.issue("admin", grants=("charge",))
    ).authority
    interp = _interp(ALLOW_WRITE, hardened=True, authority=verified,
                     sign_ed25519=True)
    _run(interp)
    assert "x" in capsys.readouterr().out
    assert interp._last_proof.signature.startswith("ed25519:")


def test_policy_can_require_authenticated_authority(capsys):
    issuer = _issuer()
    verified = _verifier(issuer).verify(issuer.issue("admin")).authority
    interp = _interp(REQUIRE_AUTHENTICATED, hardened=True, authority=verified,
                     sign_ed25519=True)
    _run(interp)
    assert "x" in capsys.readouterr().out


def test_unauthenticated_authority_fails_authenticity_policy(capsys):
    # Non-hardened, but the policy itself demands authenticity: a bare authority
    # is reported as authority_authenticated == False and is denied.
    interp = _interp(REQUIRE_AUTHENTICATED, hardened=False, authority="admin",
                     sign_ed25519=False)
    with pytest.raises(GovernanceViolation):
        _run(interp)
    assert "x" not in capsys.readouterr().out


def test_non_hardened_bare_authority_still_works(capsys):
    # Backward compatibility: outside hardened mode a bare authority + an
    # ALLOW policy continues to authorize the capability.
    interp = _interp(ALLOW_WRITE, hardened=False, authority="admin",
                     sign_ed25519=False)
    _run(interp)
    assert "x" in capsys.readouterr().out

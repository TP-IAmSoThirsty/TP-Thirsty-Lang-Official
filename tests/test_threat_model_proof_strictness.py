"""Strict proof-verifier tests mapped to THREAT_MODEL C025."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.tarl.verifier import ProofVerifier

POLICY = (
    'policy p\n'
    'when role == "admin" => ALLOW\n'
    'when true => DENY\n'
)
SECRET = b"strict-proof-secret"
PRIVATE_BYTES = bytes(range(32))


def _runtime():
    return TarlRuntime(PolicyParser.parse(POLICY))


def _unsigned_proof():
    _decision, proof = _runtime().evaluate_with_proof({"role": "admin"})
    return proof


def _hmac_proof():
    rt = _runtime()
    rt.set_signing_key("h1", SECRET)
    _decision, proof = rt.evaluate_with_proof({"role": "admin"})
    return proof


def _ed25519_proof():
    rt = _runtime()
    rt.set_ed25519_signing_key("ed1", PRIVATE_BYTES)
    _decision, proof = rt.evaluate_with_proof({"role": "admin"})
    return proof


def _public_bytes(private_bytes=PRIVATE_BYTES):
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_default_verifier_rejects_unsigned_proofs():
    result = ProofVerifier().verify(_unsigned_proof())
    assert not result.valid
    assert result.checks["signature"] is False


def test_permissive_verifier_allows_unsigned_proofs_when_explicit():
    assert ProofVerifier(require_signature=False).verify(_unsigned_proof()).valid


def test_strict_verifier_rejects_unsigned_proof():
    result = ProofVerifier(require_signature=True).verify(_unsigned_proof())
    assert not result.valid
    assert result.checks["signature"] is False


def test_ed25519_only_strict_verifier_rejects_hmac_proof():
    verifier = ProofVerifier(
        require_signature=True,
        allowed_signature_algorithms={"ed25519"},
    ).add_hmac_key("h1", SECRET)
    result = verifier.verify(_hmac_proof())
    assert not result.valid
    assert result.checks["signature"] is False


def test_ed25519_only_strict_verifier_accepts_ed25519_proof():
    verifier = ProofVerifier(
        require_signature=True,
        allowed_signature_algorithms={"ed25519"},
    ).add_ed25519_key("ed1", _public_bytes())
    assert verifier.verify(_ed25519_proof()).valid


def test_strict_verifier_rejects_wrong_ed25519_key():
    wrong_private = bytes([255 - i for i in range(32)])
    verifier = ProofVerifier(require_signature=True).add_ed25519_key(
        "ed1", _public_bytes(wrong_private)
    )
    result = verifier.verify(_ed25519_proof())
    assert not result.valid
    assert result.checks["signature"] is False


def test_strict_verifier_rejects_tampered_fields():
    proof = _ed25519_proof()
    proof.verdict = TarlVerdict.DENY
    verifier = ProofVerifier(require_signature=True).add_ed25519_key(
        "ed1", _public_bytes()
    )
    result = verifier.verify(proof)
    assert not result.valid
    assert result.checks["signature"] is False


def test_strict_verifier_rejects_missing_policy_source_when_required():
    verifier = ProofVerifier(require_policy_source=True)
    result = verifier.verify(_unsigned_proof())
    assert not result.valid
    assert result.checks["policy_hash"] is False

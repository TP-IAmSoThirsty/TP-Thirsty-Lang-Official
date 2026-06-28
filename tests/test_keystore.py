"""WS3: deployment key management — keygen, on-disk format, load, and rotation.

Covers the generate -> write -> load -> sign -> verify round trip for the three
trust roots, the public-only export, file permissions (POSIX), and a rotation
where a new signing key is used while the old public key still verifies.
"""
import os
import stat

import pytest

from utf.tarl import keystore
from utf.tarl.authority import AuthorityIssuer, AuthorityVerifier
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.tarl.verifier import ProofVerifier

POLICY = 'when role == "admin" => ALLOW\nwhen true => DENY\n'


def test_generate_write_load_roundtrip(tmp_path):
    key = keystore.generate("signer-1", keystore.ROLE_PROOF_SIGNER)
    priv = str(tmp_path / "signer.key")
    pub = str(tmp_path / "signer.pub")
    key.write(priv, include_private=True)
    key.public_only().write(pub, include_private=False)

    loaded = keystore.load(priv)
    assert loaded.key_id == "signer-1"
    assert loaded.role == keystore.ROLE_PROOF_SIGNER
    assert loaded.has_private
    assert loaded.private_bytes() == key.private_bytes()

    loaded_pub = keystore.load(pub)
    assert not loaded_pub.has_private
    assert loaded_pub.public_bytes() == key.public_bytes()
    with pytest.raises(ValueError):
        loaded_pub.private_bytes()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_private_key_file_is_0600(tmp_path):
    key = keystore.generate("k", keystore.ROLE_TIME_AUTHORITY)
    priv = str(tmp_path / "ta.key")
    key.write(priv, include_private=True)
    mode = stat.S_IMODE(os.stat(priv).st_mode)
    assert mode == 0o600


def test_unknown_role_rejected():
    with pytest.raises(ValueError):
        keystore.generate("x", "not-a-role")


def test_load_rejects_bad_format(tmp_path):
    bad = tmp_path / "bad.key"
    bad.write_text('{"format": "nope", "public_key": "00"}')
    with pytest.raises(ValueError):
        keystore.load(str(bad))


def test_proof_signer_key_signs_and_verifies(tmp_path):
    key = keystore.generate("signer-1", keystore.ROLE_PROOF_SIGNER)
    priv = str(tmp_path / "s.key")
    key.write(priv, include_private=True)

    loaded = keystore.load(priv)
    rt = TarlRuntime(PolicyParser.parse(POLICY))
    rt.set_ed25519_signing_key(loaded.key_id, loaded.private_bytes())
    decision, proof = rt.evaluate_with_proof({"role": "admin"})
    assert decision.verdict == TarlVerdict.ALLOW

    verifier = ProofVerifier(require_signature=True,
                             allowed_signature_algorithms={"ed25519"})
    verifier.add_ed25519_key(loaded.key_id, key.public_bytes())
    result = verifier.verify(proof)
    assert result.valid, result.summary


def test_authority_issuer_key_issues_and_verifies(tmp_path):
    key = keystore.generate("issuer-1", keystore.ROLE_AUTHORITY_ISSUER)
    priv = str(tmp_path / "i.key")
    key.write(priv, include_private=True)

    loaded = keystore.load(priv)
    issuer = AuthorityIssuer(loaded.key_id, loaded.private_bytes())
    claim = issuer.issue("admin", grants=("charge",))
    verifier = AuthorityVerifier().add_ed25519_key(
        loaded.key_id, loaded.public_bytes())
    result = verifier.verify(claim)
    assert result.valid


def test_rotation_old_public_key_still_verifies(tmp_path):
    """Mint a new signing key; a proof signed by the new key verifies while the
    old public key remains registered (verifier keyed by key_id)."""
    old = keystore.generate("signer-1", keystore.ROLE_PROOF_SIGNER)
    new = keystore.generate("signer-2", keystore.ROLE_PROOF_SIGNER)

    rt = TarlRuntime(PolicyParser.parse(POLICY))
    rt.set_ed25519_signing_key(new.key_id, new.private_bytes())
    _d, proof = rt.evaluate_with_proof({"role": "admin"})

    # A verifier registered with BOTH public keys validates the new proof.
    verifier = ProofVerifier(allowed_signature_algorithms={"ed25519"})
    verifier.add_ed25519_key(old.key_id, old.public_bytes())
    verifier.add_ed25519_key(new.key_id, new.public_bytes())
    assert verifier.verify(proof).valid

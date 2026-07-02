"""Replay / freshness / policy-revocation tests (THREAT_MODEL C023-C024).

A valid signature is not enough: an old ALLOW proof must not be replayable for a
different context, after it has gone stale, after its policy is revoked, or by
exact reuse.
"""
import datetime

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.verifier import ProofVerifier, ReplayGuard, canonical_context_hash

POLICY = (
    'policy p\n'
    'when role == "admin" => ALLOW\n'
    'when true => DENY\n'
)
CTX = {"role": "admin", "action": "charge"}


def _proof(context=CTX):
    # Unsigned proofs isolate the replay/freshness/revocation checks under test
    # from signature verification (covered in test_threat_model_proof_strictness).
    rt = TarlRuntime(PolicyParser.parse(POLICY))
    _decision, proof = rt.evaluate_with_proof(context)
    return proof


# ── C023: replay an old proof against a different context ──────────────────────

def test_context_binding_accepts_the_matching_context():
    proof = _proof()
    result = ProofVerifier(require_signature=False).verify(proof, expected_context=CTX)
    assert result.checks["context_binding"] is True
    assert result.valid


def test_context_binding_rejects_a_different_context():
    proof = _proof()
    result = ProofVerifier(require_signature=False).verify(
        proof, expected_context={"role": "admin", "action": "drain_account"}
    )
    assert result.checks["context_binding"] is False
    assert not result.valid


def test_canonical_context_hash_matches_runtime_stamp():
    proof = _proof()
    assert proof.context_hash == canonical_context_hash(CTX)


# ── C024: stale proof ──────────────────────────────────────────────────────────

def test_fresh_proof_within_window_is_accepted():
    proof = _proof()
    result = ProofVerifier(
        require_signature=False,
        max_age_seconds=300,
    ).verify(proof)
    assert result.checks["freshness"] is True
    assert result.valid


def test_stale_proof_is_rejected():
    proof = _proof()
    later = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    result = ProofVerifier(
        require_signature=False,
        max_age_seconds=60,
    ).verify(proof, now=later)
    assert result.checks["freshness"] is False
    assert not result.valid


# ── C024: policy revocation ────────────────────────────────────────────────────

def test_revoked_policy_hash_is_rejected():
    proof = _proof()
    result = ProofVerifier(
        require_signature=False,
        revoked_policy_hashes={proof.policy_hash}
    ).verify(proof)
    assert result.checks["not_revoked"] is False
    assert not result.valid


def test_non_revoked_policy_passes():
    proof = _proof()
    result = ProofVerifier(
        require_signature=False,
        revoked_policy_hashes={"sha256:deadbeef"}
    ).verify(proof)
    assert result.checks["not_revoked"] is True
    assert result.valid


# ── Exact replay (single-use) ──────────────────────────────────────────────────

def test_replay_guard_rejects_second_use():
    proof = _proof()
    guard = ReplayGuard()
    verifier = ProofVerifier(require_signature=False, replay_guard=guard)
    first = verifier.verify(proof)
    second = verifier.verify(proof)
    assert first.checks["not_replayed"] is True and first.valid
    assert second.checks["not_replayed"] is False and not second.valid


# ── Backward compatibility: none of these checks fire by default ───────────────

def test_default_verifier_does_not_apply_replay_checks():
    proof = _proof()
    result = ProofVerifier(require_signature=False).verify(proof)
    assert result.checks["context_binding"] is None
    assert result.checks["freshness"] is None
    assert result.checks["not_revoked"] is None
    assert result.checks["not_replayed"] is None
    assert result.valid

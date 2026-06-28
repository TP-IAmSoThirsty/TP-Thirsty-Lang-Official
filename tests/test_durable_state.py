"""WS2: durable, cross-process replay/revocation state and external audit
checkpoints. Each test simulates a second process by opening a *fresh* store
instance on the same database file.
"""
from utf.tarl.archive import TarlAuditArchive
from utf.tarl.core import PolicyParser
from utf.tarl.durable import DurableReplayGuard, RevocationStore
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict
from utf.tarl.verifier import ProofVerifier

POLICY = (
    'policy p\n'
    'when role == "admin" => ALLOW\n'
    'when true => DENY\n'
)


def _signed_proof(tmp_path):
    rt = TarlRuntime(PolicyParser.parse(POLICY))
    rt.set_signing_key("k1", b"secret-hmac-key")
    decision, proof = rt.evaluate_with_proof({"role": "admin"})
    assert decision.verdict == TarlVerdict.ALLOW
    return proof


def test_durable_replay_guard_rejects_across_instances(tmp_path):
    db = str(tmp_path / "replay.db")
    proof = _signed_proof(tmp_path)

    with DurableReplayGuard(db) as guard_a:
        assert guard_a.check_and_record(proof) is True
        # same instance: immediate replay rejected
        assert guard_a.check_and_record(proof) is False

    # second "process": a fresh instance on the same DB still rejects the replay
    with DurableReplayGuard(db) as guard_b:
        assert guard_b.check_and_record(proof) is False


def test_durable_replay_guard_plugs_into_verifier(tmp_path):
    db = str(tmp_path / "replay.db")
    proof = _signed_proof(tmp_path)

    guard = DurableReplayGuard(db)
    verifier = ProofVerifier(replay_guard=guard)
    verifier.add_hmac_key("k1", b"secret-hmac-key")
    first = verifier.verify(proof)
    assert first.valid, first.summary
    guard.close()

    # New verifier + fresh guard on the same DB: the replay is caught.
    guard2 = DurableReplayGuard(db)
    verifier2 = ProofVerifier(replay_guard=guard2)
    verifier2.add_hmac_key("k1", b"secret-hmac-key")
    second = verifier2.verify(proof)
    guard2.close()
    assert not second.valid
    assert second.checks.get("not_replayed") is False


def test_revocation_store_roundtrip(tmp_path):
    db = str(tmp_path / "revocations.db")
    with RevocationStore(db) as store:
        assert store.add("sha256:abc", reason="leaked key") is True
        assert store.add("sha256:abc") is False  # idempotent
        assert "sha256:abc" in store

    # second "process" sees the durable revocation
    with RevocationStore(db) as store2:
        assert store2.all() == {"sha256:abc"}
        assert store2.remove("sha256:abc") is True
        assert store2.remove("sha256:abc") is False
        assert store2.all() == set()


def test_revoked_policy_hash_rejects_proof(tmp_path):
    db = str(tmp_path / "revocations.db")
    proof = _signed_proof(tmp_path)
    with RevocationStore(db) as store:
        store.add(proof.policy_hash, reason="rotated policy")

    with RevocationStore(db) as store:
        verifier = ProofVerifier(revoked_policy_hashes=store.all())
        verifier.add_hmac_key("k1", b"secret-hmac-key")
        result = verifier.verify(proof)
    assert not result.valid
    assert result.checks.get("not_revoked") is False


def test_audit_checkpoint_detects_truncation(tmp_path):
    db = str(tmp_path / "audit.db")
    rt = TarlRuntime(PolicyParser.parse(POLICY))
    with TarlAuditArchive(db) as arc:
        for role in ("admin", "guest", "admin"):
            _d, proof = rt.evaluate_with_proof({"role": role})
            arc.store(proof)
        trusted_head = arc.head_hash()
        # Chain is intact and matches its own head.
        assert arc.verify_chain(expected_head=trusted_head).valid

    # Simulate suffix truncation: drop the last record (a valid prefix).
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM proofs WHERE id = (SELECT MAX(id) FROM proofs)")
    conn.commit()
    conn.close()

    with TarlAuditArchive(db) as arc:
        # Internal walk still passes (prefix re-links), but the head no longer
        # matches the trusted checkpoint.
        assert arc.verify_chain().valid
        checked = arc.verify_chain(expected_head=trusted_head)
        assert not checked.valid
        assert "checkpoint" in checked.reason

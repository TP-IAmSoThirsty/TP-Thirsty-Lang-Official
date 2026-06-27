"""Tamper-evident audit-chain tests (THREAT_MODEL C022/C026/C049).

The audit archive hash-links every record, so deleting a DENY, editing a stored
proof, or reordering records breaks the chain and is detectable.
"""
import sqlite3

from utf.tarl.archive import TarlAuditArchive
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime


def _proofs(verdicts=("ALLOW", "DENY", "ALLOW")):
    """Generate distinct proofs with the requested verdicts."""
    out = []
    for i, v in enumerate(verdicts):
        cond = "true" if v == "ALLOW" else "false"
        policy = f'policy p{i}\nwhen {cond} => ALLOW\nwhen true => DENY\n'
        rt = TarlRuntime(PolicyParser.parse(policy))
        _d, proof = rt.evaluate_with_proof({"i": i})
        out.append(proof)
    return out


def _populate(db, verdicts=("ALLOW", "DENY", "ALLOW")):
    with TarlAuditArchive(db) as arc:
        for proof in _proofs(verdicts):
            arc.store(proof)


def test_intact_chain_verifies(tmp_path):
    db = str(tmp_path / "audit.db")
    _populate(db)
    with TarlAuditArchive(db) as arc:
        result = arc.verify_chain()
    assert result.valid
    assert result.length == 3
    assert result.broken_at is None


def test_head_hash_advances_and_is_stable(tmp_path):
    db = str(tmp_path / "audit.db")
    with TarlAuditArchive(db) as arc:
        proofs = _proofs(("ALLOW", "ALLOW"))
        arc.store(proofs[0])
        h1 = arc.head_hash()
        arc.store(proofs[1])
        h2 = arc.head_hash()
        assert h1 != h2
        assert arc.head_hash() == h2  # stable on re-read


def test_tampering_with_a_stored_proof_is_detected(tmp_path):
    db = str(tmp_path / "audit.db")
    _populate(db)
    # Edit the middle record's stored JSON out of band.
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE proofs SET proof_json = ? WHERE id = 2",
        ('{"verdict": "ALLOW", "tampered": true}',),
    )
    conn.commit()
    conn.close()
    with TarlAuditArchive(db) as arc:
        result = arc.verify_chain()
    assert not result.valid
    assert result.broken_at == 2
    assert "tamper" in result.reason


def test_deleting_a_deny_record_breaks_the_chain(tmp_path):
    # C026: a deleted DENY must leave a detectable gap, not vanish silently.
    db = str(tmp_path / "audit.db")
    _populate(db, ("ALLOW", "DENY", "ALLOW"))
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM proofs WHERE verdict = 'DENY'")
    conn.commit()
    conn.close()
    with TarlAuditArchive(db) as arc:
        result = arc.verify_chain()
    assert not result.valid
    assert "deletion" in result.reason or "reordering" in result.reason


def test_reordering_records_is_detected(tmp_path):
    db = str(tmp_path / "audit.db")
    _populate(db, ("ALLOW", "DENY", "ALLOW"))
    # Swap the entry_hash linkage order by swapping ids of two records.
    conn = sqlite3.connect(db)
    conn.execute("UPDATE proofs SET id = 99 WHERE id = 1")
    conn.execute("UPDATE proofs SET id = 1 WHERE id = 3")
    conn.execute("UPDATE proofs SET id = 3 WHERE id = 99")
    conn.commit()
    conn.close()
    with TarlAuditArchive(db) as arc:
        result = arc.verify_chain()
    assert not result.valid


def test_query_and_count_still_work_with_chain(tmp_path):
    db = str(tmp_path / "audit.db")
    _populate(db, ("ALLOW", "DENY", "ALLOW"))
    with TarlAuditArchive(db) as arc:
        assert arc.count() == 3
        assert len(arc.query()) == 3
        assert arc.verify_chain().valid

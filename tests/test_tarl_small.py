"""Coverage for the tarl audit archive query/count filters and the proof
verifier's signature/summary branches."""
from types import SimpleNamespace

from utf.tarl.archive import TarlAuditArchive
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.verifier import ProofVerifier, VerificationResult

POLICY = 'when role == "admin" => ALLOW\nwhen true => DENY\n'


def _proof():
    rt = TarlRuntime(PolicyParser.parse(POLICY))
    _decision, proof = rt.evaluate_with_proof({"role": "admin"})
    return proof


def test_archive_query_and_count_filters(tmp_path):
    db = str(tmp_path / "audit.db")
    with TarlAuditArchive(db) as arc:
        arc.store(_proof())
        # query with all filters exercised
        rows = arc.query(verdict="ALLOW", from_dt="2000-01-01",
                         to_dt="2100-01-01", limit=10)
        assert len(rows) == 1
        # count with the same filters
        assert arc.count(verdict="ALLOW", from_dt="2000-01-01",
                         to_dt="2100-01-01") == 1
        # query with a verifier applies the signature filter
        filtered = arc.query(verifier=ProofVerifier())
        assert len(filtered) == 1


def test_verifier_signature_no_separator():
    v = ProofVerifier()
    assert v._check_signature(SimpleNamespace(signature="nosep")) is False


def test_verifier_signature_unknown_algorithm():
    v = ProofVerifier()
    assert v._check_signature(
        SimpleNamespace(signature="weird-alg:abcd", key_id=None)) is False


def test_verifier_signature_none():
    v = ProofVerifier()
    assert v._check_signature(SimpleNamespace(signature="")) is None


def test_verification_result_summary_marks():
    r = VerificationResult(
        valid=False,
        checks={"signature": True, "policy_hash": False, "trace": None},
        message="mixed",
    )
    s = r.summary
    assert "✓" in s and "✗" in s and "-" in s

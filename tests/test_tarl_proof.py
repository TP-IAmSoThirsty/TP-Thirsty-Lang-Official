"""
Tests for T.A.R.L. Phase 4 — Proof-Carrying Evaluation.

Covers:
  - TarlProof dataclass and serialisation
  - TarlRuntime.set_signing_key / evaluate_with_proof
  - ProofVerifier: signature, policy hash, trace checks
  - VerificationResult dataclass
  - Tamper detection (modified proof fields)
  - Public API exports
"""
import hashlib
import json
import os
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))  # noqa: E402

from utf.tarl.core import PolicyParser  # noqa: E402
from utf.tarl.runtime import TarlRuntime  # noqa: E402
from utf.tarl.spec import TarlProof, TarlVerdict  # noqa: E402
from utf.tarl.verifier import (  # noqa: E402
    ProofVerifier,
    VerificationResult,
    _check_policy_hash,
    _check_trace,
)

# ── fixtures ──────────────────────────────────────────────────────────────────

_POLICY_TEXT = (
    "policy access:\n"
    "  when role == \"admin\" => ALLOW\n"
    "  when role == \"guest\" => DENY\n"
)

_SECRET = b"thirsty-test-secret-key-32bytes!"
_ED25519_PRIVATE_BYTES = bytes(range(32))


def _runtime(policy_text: str = _POLICY_TEXT) -> TarlRuntime:
    policy = PolicyParser.parse(policy_text)
    return TarlRuntime(policy)


def _signed_runtime(policy_text: str = _POLICY_TEXT) -> TarlRuntime:
    policy = PolicyParser.parse(policy_text)
    rt = TarlRuntime(policy)
    rt.set_signing_key("k1", _SECRET)
    return rt


def _ed25519_runtime(policy_text: str = _POLICY_TEXT) -> TarlRuntime:
    policy = PolicyParser.parse(policy_text)
    rt = TarlRuntime(policy)
    rt.set_ed25519_signing_key("ed1", _ED25519_PRIVATE_BYTES)
    return rt


def _ed25519_public_bytes() -> bytes:
    private_key = Ed25519PrivateKey.from_private_bytes(_ED25519_PRIVATE_BYTES)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _make_proof(**overrides) -> TarlProof:
    defaults = {
        'policy_hash': "sha256:abc123",
        'context_hash': "sha256:def456",
        'rule_index': 0,
        'matched_condition': 'role == "admin"',
        'verdict': TarlVerdict.ALLOW,
        'evaluated_at': "2026-06-20T12:00:00Z",
        'trace': [{"rule_index": 0, "condition": 'role == "admin"', "matched": True}],
        'signature': "",
        'key_id': "",
    }
    defaults.update(overrides)
    return TarlProof(**defaults)


# ── TarlProof dataclass ───────────────────────────────────────────────────────

class TestTarlProofDataclass(unittest.TestCase):

    def test_fields_exist(self):
        p = _make_proof()
        self.assertEqual(p.policy_hash, "sha256:abc123")
        self.assertEqual(p.rule_index, 0)
        self.assertEqual(p.verdict, TarlVerdict.ALLOW)

    def test_default_deny_sentinel(self):
        p = _make_proof(rule_index=-1, matched_condition="",
                         verdict=TarlVerdict.DENY, trace=[])
        self.assertEqual(p.rule_index, -1)
        self.assertEqual(p.matched_condition, "")

    def test_trace_is_list(self):
        p = _make_proof()
        self.assertIsInstance(p.trace, list)

    def test_signature_defaults_empty(self):
        p = _make_proof()
        self.assertEqual(p.signature, "")
        self.assertEqual(p.key_id, "")


# ── TarlProof serialisation ───────────────────────────────────────────────────

class TestTarlProofSerialisation(unittest.TestCase):

    def test_to_dict_verdict_is_string(self):
        p = _make_proof()
        d = p.to_dict()
        self.assertIsInstance(d["verdict"], str)
        self.assertEqual(d["verdict"], "ALLOW")

    def test_to_dict_round_trips(self):
        p = _make_proof()
        d = p.to_dict()
        p2 = TarlProof.from_dict(d)
        self.assertEqual(p, p2)

    def test_to_json_is_valid_json(self):
        p = _make_proof()
        s = p.to_json()
        parsed = json.loads(s)
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed["verdict"], "ALLOW")

    def test_from_json_round_trips(self):
        p = _make_proof()
        p2 = TarlProof.from_json(p.to_json())
        self.assertEqual(p, p2)

    def test_from_json_verdict_enum_restored(self):
        p = _make_proof()
        p2 = TarlProof.from_json(p.to_json())
        self.assertIsInstance(p2.verdict, TarlVerdict)

    def test_from_dict_optional_fields_default(self):
        d = {
            "policy_hash": "sha256:x",
            "context_hash": "sha256:y",
            "rule_index": -1,
            "verdict": "DENY",
            "evaluated_at": "2026-06-20T00:00:00Z",
            "trace": [],
        }
        p = TarlProof.from_dict(d)
        self.assertEqual(p.matched_condition, "")
        self.assertEqual(p.signature, "")
        self.assertEqual(p.key_id, "")

    def test_trace_entries_preserved(self):
        trace = [
            {"rule_index": 0, "condition": "x > 0", "matched": False},
            {"rule_index": 1, "condition": "x == 5", "matched": True},
        ]
        p = _make_proof(rule_index=1, matched_condition="x == 5", trace=trace)
        p2 = TarlProof.from_json(p.to_json())
        self.assertEqual(p2.trace, trace)


# ── canonical_bytes ───────────────────────────────────────────────────────────

class TestCanonicalBytes(unittest.TestCase):

    def test_returns_bytes(self):
        p = _make_proof()
        self.assertIsInstance(p.canonical_bytes(), bytes)

    def test_deterministic(self):
        p = _make_proof()
        self.assertEqual(p.canonical_bytes(), p.canonical_bytes())

    def test_excludes_signature_field(self):
        p1 = _make_proof(signature="hmac-sha256:aaa", key_id="k1")
        p2 = _make_proof(signature="hmac-sha256:bbb", key_id="k2")
        self.assertEqual(p1.canonical_bytes(), p2.canonical_bytes())

    def test_sensitive_to_verdict_change(self):
        p1 = _make_proof(verdict=TarlVerdict.ALLOW)
        p2 = _make_proof(verdict=TarlVerdict.DENY)
        self.assertNotEqual(p1.canonical_bytes(), p2.canonical_bytes())

    def test_sensitive_to_rule_index_change(self):
        p1 = _make_proof(rule_index=0)
        p2 = _make_proof(rule_index=1)
        self.assertNotEqual(p1.canonical_bytes(), p2.canonical_bytes())

    def test_sensitive_to_policy_hash_change(self):
        p1 = _make_proof(policy_hash="sha256:aaa")
        p2 = _make_proof(policy_hash="sha256:bbb")
        self.assertNotEqual(p1.canonical_bytes(), p2.canonical_bytes())


# ── TarlRuntime.set_signing_key ───────────────────────────────────────────────

class TestSetSigningKey(unittest.TestCase):

    def test_returns_self_for_chaining(self):
        rt = _runtime()
        result = rt.set_signing_key("k1", b"secret")
        self.assertIs(result, rt)

    def test_key_stored(self):
        rt = _runtime()
        rt.set_signing_key("k1", b"secret")
        self.assertIn("k1", rt._signing_keys)
        self.assertEqual(rt._signing_keys["k1"], b"secret")

    def test_active_key_updated(self):
        rt = _runtime()
        rt.set_signing_key("k1", b"s1")
        rt.set_signing_key("k2", b"s2")
        self.assertEqual(rt._signing_key_id, "k2")

    def test_multiple_keys_stored(self):
        rt = _runtime()
        rt.set_signing_key("k1", b"s1")
        rt.set_signing_key("k2", b"s2")
        self.assertEqual(len(rt._signing_keys), 2)

    def test_ed25519_key_stored(self):
        rt = _runtime()
        rt.set_ed25519_signing_key("ed1", _ED25519_PRIVATE_BYTES)
        self.assertIn("ed1", rt._ed25519_signing_keys)
        self.assertEqual(rt._signing_key_id, "ed1")
        self.assertEqual(rt._signing_alg, "ed25519")


# ── TarlRuntime.evaluate_with_proof ──────────────────────────────────────────

class TestEvaluateWithProof(unittest.TestCase):

    def test_returns_tuple(self):
        rt = _runtime()
        result = rt.evaluate_with_proof({"role": "admin"})
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_decision_correct(self):
        rt = _runtime()
        decision, _ = rt.evaluate_with_proof({"role": "admin"})
        self.assertEqual(decision.verdict, TarlVerdict.ALLOW)

    def test_decision_deny(self):
        rt = _runtime()
        decision, _ = rt.evaluate_with_proof({"role": "guest"})
        self.assertEqual(decision.verdict, TarlVerdict.DENY)

    def test_default_deny_no_match(self):
        rt = _runtime()
        decision, proof = rt.evaluate_with_proof({"role": "unknown"})
        self.assertEqual(decision.verdict, TarlVerdict.DENY)
        self.assertEqual(proof.rule_index, -1)

    def test_proof_is_tarlproof(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertIsInstance(proof, TarlProof)

    def test_proof_rule_index_correct(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertEqual(proof.rule_index, 0)

    def test_proof_verdict_matches_decision(self):
        rt = _runtime()
        decision, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertEqual(proof.verdict, decision.verdict)

    def test_proof_policy_hash_is_sha256(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertTrue(proof.policy_hash.startswith("sha256:"))

    def test_proof_context_hash_is_sha256(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertTrue(proof.context_hash.startswith("sha256:"))

    def test_proof_evaluated_at_is_iso(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertTrue(proof.evaluated_at.endswith("Z"))
        self.assertIn("T", proof.evaluated_at)

    def test_proof_trace_not_empty_on_match(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertGreater(len(proof.trace), 0)

    def test_proof_trace_stops_at_first_match(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        # rule 0 matches → trace has exactly 1 entry
        self.assertEqual(len(proof.trace), 1)
        self.assertTrue(proof.trace[0]["matched"])

    def test_proof_trace_second_rule(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "guest"})
        # rule 0 no-match, rule 1 matches → trace has 2 entries
        self.assertEqual(len(proof.trace), 2)
        self.assertFalse(proof.trace[0]["matched"])
        self.assertTrue(proof.trace[1]["matched"])

    def test_proof_trace_all_false_on_default_deny(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "unknown"})
        self.assertTrue(all(not e["matched"] for e in proof.trace))

    def test_no_signature_without_key(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertEqual(proof.signature, "")
        self.assertEqual(proof.key_id, "")

    def test_signature_present_with_key(self):
        rt = _signed_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertTrue(proof.signature.startswith("hmac-sha256:"))

    def test_key_id_set_in_proof(self):
        rt = _signed_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertEqual(proof.key_id, "k1")

    def test_ed25519_signature_present_with_key(self):
        rt = _ed25519_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertTrue(proof.signature.startswith("ed25519:"))
        self.assertEqual(proof.key_id, "ed1")

    def test_different_contexts_different_context_hash(self):
        rt = _signed_runtime()
        _, p1 = rt.evaluate_with_proof({"role": "admin"})
        _, p2 = rt.evaluate_with_proof({"role": "guest"})
        self.assertNotEqual(p1.context_hash, p2.context_hash)

    def test_evaluate_with_policy_text(self):
        rt = TarlRuntime()
        decision, proof = rt.evaluate_with_proof(
            {"x": 1},
            policy_text="policy p:\n  when x == 1 => ALLOW",
        )
        self.assertEqual(decision.verdict, TarlVerdict.ALLOW)
        self.assertEqual(proof.rule_index, 0)

    def test_proof_matched_condition_text(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        self.assertIn("admin", proof.matched_condition)

    def test_proof_matched_condition_empty_on_default_deny(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "nobody"})
        self.assertEqual(proof.matched_condition, "")


# ── ProofVerifier ─────────────────────────────────────────────────────────────

class TestProofVerifier(unittest.TestCase):

    def test_returns_self_from_add_key(self):
        v = ProofVerifier(require_signature=False)
        result = v.add_hmac_key("k1", b"secret")
        self.assertIs(result, v)

    def test_verify_returns_verification_result(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        result = ProofVerifier(require_signature=False).verify(proof)
        self.assertIsInstance(result, VerificationResult)

    def test_unsigned_proof_valid_without_keys(self):
        rt = _runtime()  # no signing key
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        result = ProofVerifier(require_signature=False).verify(proof)
        self.assertTrue(result.valid)

    def test_signed_proof_valid_with_correct_key(self):
        rt = _signed_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        v = ProofVerifier(require_signature=False).add_hmac_key("k1", _SECRET)
        result = v.verify(proof)
        self.assertTrue(result.valid)

    def test_signed_proof_invalid_with_wrong_key(self):
        rt = _signed_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        v = ProofVerifier(require_signature=False).add_hmac_key("k1", b"wrong-secret-32-bytes-padding!!")
        result = v.verify(proof)
        self.assertFalse(result.valid)
        self.assertFalse(result.checks["signature"])

    def test_signed_proof_invalid_without_key(self):
        rt = _signed_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        result = ProofVerifier(require_signature=False).verify(proof)
        self.assertFalse(result.valid)

    def test_ed25519_signed_proof_valid_with_public_key(self):
        rt = _ed25519_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        v = ProofVerifier(require_signature=False).add_ed25519_key("ed1", _ed25519_public_bytes())
        result = v.verify(proof)
        self.assertTrue(result.valid)

    def test_ed25519_signed_proof_invalid_with_wrong_public_key(self):
        rt = _ed25519_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        wrong_public = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        v = ProofVerifier(require_signature=False).add_ed25519_key("ed1", wrong_public)
        result = v.verify(proof)
        self.assertFalse(result.valid)
        self.assertFalse(result.checks["signature"])

    def test_ed25519_signed_proof_invalid_without_public_key(self):
        rt = _ed25519_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        result = ProofVerifier(require_signature=False).verify(proof)
        self.assertFalse(result.valid)

    def test_policy_hash_check_passes(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        v = ProofVerifier(require_signature=False)
        result = v.verify(proof, policy_source=_POLICY_TEXT)
        self.assertTrue(result.checks["policy_hash"])
        self.assertTrue(result.valid)

    def test_policy_hash_check_fails_wrong_source(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        v = ProofVerifier(require_signature=False)
        result = v.verify(proof, policy_source="policy wrong:\n  when 1==1 => DENY")
        self.assertFalse(result.checks["policy_hash"])
        self.assertFalse(result.valid)

    def test_policy_hash_check_skipped_when_not_provided(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        result = ProofVerifier(require_signature=False).verify(proof)
        self.assertIsNone(result.checks["policy_hash"])

    def test_trace_check_passes(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        result = ProofVerifier(require_signature=False).verify(proof)
        self.assertTrue(result.checks["trace"])

    def test_signature_check_skipped_for_unsigned(self):
        rt = _runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        result = ProofVerifier(require_signature=False).verify(proof)
        self.assertIsNone(result.checks["signature"])


# ── VerificationResult dataclass ──────────────────────────────────────────────

class TestVerificationResult(unittest.TestCase):

    def test_str_valid(self):
        r = VerificationResult(valid=True, message="ok")
        self.assertIn("VALID", str(r))

    def test_str_invalid(self):
        r = VerificationResult(valid=False, message="bad sig")
        self.assertIn("INVALID", str(r))

    def test_summary_shows_checks(self):
        r = VerificationResult(
            valid=True, message="ok",
            checks={"signature": True, "trace": True, "policy_hash": None},
        )
        s = r.summary
        self.assertIn("signature", s)
        self.assertIn("trace", s)

    def test_defaults(self):
        r = VerificationResult(valid=True)
        self.assertEqual(r.checks, {})
        self.assertEqual(r.message, "")


# ── Tamper detection ──────────────────────────────────────────────────────────

class TestTamperDetection(unittest.TestCase):

    def _signed_proof(self) -> TarlProof:
        rt = _signed_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        return proof

    def _verifier(self) -> ProofVerifier:
        return ProofVerifier(require_signature=False).add_hmac_key("k1", _SECRET)

    def test_valid_proof_passes(self):
        proof = self._signed_proof()
        result = self._verifier().verify(proof)
        self.assertTrue(result.valid)

    def test_tampered_verdict_fails(self):
        proof = self._signed_proof()
        proof.verdict = TarlVerdict.DENY
        result = self._verifier().verify(proof)
        self.assertFalse(result.valid)

    def test_tampered_rule_index_fails(self):
        proof = self._signed_proof()
        proof.rule_index = 99
        result = self._verifier().verify(proof)
        self.assertFalse(result.valid)

    def test_tampered_policy_hash_fails(self):
        proof = self._signed_proof()
        proof.policy_hash = "sha256:0000"
        result = self._verifier().verify(proof)
        self.assertFalse(result.valid)

    def test_tampered_context_hash_fails(self):
        proof = self._signed_proof()
        proof.context_hash = "sha256:ffff"
        result = self._verifier().verify(proof)
        self.assertFalse(result.valid)

    def test_tampered_trace_fails(self):
        proof = self._signed_proof()
        proof.trace = [{"rule_index": 0, "condition": "fake", "matched": True}]
        result = self._verifier().verify(proof)
        self.assertFalse(result.valid)

    def test_tampered_matched_condition_fails(self):
        proof = self._signed_proof()
        proof.matched_condition = "1 == 1"
        result = self._verifier().verify(proof)
        self.assertFalse(result.valid)

    def test_ed25519_tampered_verdict_fails(self):
        rt = _ed25519_runtime()
        _, proof = rt.evaluate_with_proof({"role": "admin"})
        proof.verdict = TarlVerdict.DENY
        verifier = ProofVerifier(require_signature=False).add_ed25519_key(
            "ed1", _ed25519_public_bytes()
        )
        result = verifier.verify(proof)
        self.assertFalse(result.valid)


# ── _check_policy_hash ────────────────────────────────────────────────────────

class TestCheckPolicyHash(unittest.TestCase):

    def test_correct_hash_passes(self):
        source = "policy p:\n  when 1==1 => ALLOW"
        expected = "sha256:" + hashlib.sha256(source.encode()).hexdigest()
        proof = _make_proof(policy_hash=expected)
        self.assertTrue(_check_policy_hash(proof, source))

    def test_wrong_source_fails(self):
        source = "policy p:\n  when 1==1 => ALLOW"
        expected = "sha256:" + hashlib.sha256(source.encode()).hexdigest()
        proof = _make_proof(policy_hash=expected)
        self.assertFalse(_check_policy_hash(proof, "different source"))

    def test_malformed_hash_fails(self):
        proof = _make_proof(policy_hash="notsha256:abc")
        self.assertFalse(_check_policy_hash(proof, "anything"))

    def test_no_separator_fails(self):
        proof = _make_proof(policy_hash="invalidhash")
        self.assertFalse(_check_policy_hash(proof, "anything"))


# ── _check_trace ──────────────────────────────────────────────────────────────

class TestCheckTrace(unittest.TestCase):

    def _entry(self, idx: int, cond: str = "x > 0",
               matched: bool = False) -> dict:
        return {"rule_index": idx, "condition": cond, "matched": matched}

    def test_single_match_at_0_passes(self):
        proof = _make_proof(
            rule_index=0,
            trace=[self._entry(0, matched=True)],
        )
        self.assertTrue(_check_trace(proof))

    def test_match_at_1_with_non_match_at_0_passes(self):
        proof = _make_proof(
            rule_index=1,
            matched_condition="x == 2",
            trace=[
                self._entry(0, matched=False),
                self._entry(1, matched=True),
            ],
        )
        self.assertTrue(_check_trace(proof))

    def test_default_deny_empty_trace_passes(self):
        proof = _make_proof(
            rule_index=-1,
            matched_condition="",
            verdict=TarlVerdict.DENY,
            trace=[],
        )
        self.assertTrue(_check_trace(proof))

    def test_default_deny_all_false_passes(self):
        proof = _make_proof(
            rule_index=-1,
            matched_condition="",
            verdict=TarlVerdict.DENY,
            trace=[self._entry(0), self._entry(1)],
        )
        self.assertTrue(_check_trace(proof))

    def test_earlier_rule_matches_is_inconsistent(self):
        # rule_index=1 but rule 0 claims matched=True
        proof = _make_proof(
            rule_index=1,
            trace=[
                self._entry(0, matched=True),   # earlier rule matched → inconsistent
                self._entry(1, matched=True),
            ],
        )
        self.assertFalse(_check_trace(proof))

    def test_matched_entry_false_is_inconsistent(self):
        # rule_index=0 but trace entry says matched=False
        proof = _make_proof(
            rule_index=0,
            trace=[self._entry(0, matched=False)],
        )
        self.assertFalse(_check_trace(proof))

    def test_extra_entries_after_match_is_inconsistent(self):
        # trace continues past the first match
        proof = _make_proof(
            rule_index=0,
            trace=[
                self._entry(0, matched=True),
                self._entry(1, matched=False),  # should not be here
            ],
        )
        self.assertFalse(_check_trace(proof))

    def test_wrong_rule_index_in_entry_fails(self):
        proof = _make_proof(
            rule_index=0,
            trace=[{"rule_index": 5, "condition": "x", "matched": True}],
        )
        self.assertFalse(_check_trace(proof))

    def test_non_list_trace_fails(self):
        proof = _make_proof(rule_index=0, trace="not a list")
        self.assertFalse(_check_trace(proof))

    def test_non_dict_entry_fails(self):
        proof = _make_proof(rule_index=0, trace=["not a dict"])
        self.assertFalse(_check_trace(proof))


# ── Public API exports ────────────────────────────────────────────────────────

class TestPublicAPIExports(unittest.TestCase):

    def test_tarlproof_exported(self):
        import utf.tarl as tarl
        self.assertTrue(hasattr(tarl, 'TarlProof'))

    def test_proofverifier_exported(self):
        import utf.tarl as tarl
        self.assertTrue(hasattr(tarl, 'ProofVerifier'))

    def test_verificationresult_exported(self):
        import utf.tarl as tarl
        self.assertTrue(hasattr(tarl, 'VerificationResult'))

    def test_runtime_has_evaluate_with_proof(self):
        self.assertTrue(hasattr(TarlRuntime, 'evaluate_with_proof'))

    def test_runtime_has_set_signing_key(self):
        self.assertTrue(hasattr(TarlRuntime, 'set_signing_key'))


if __name__ == '__main__':
    unittest.main()

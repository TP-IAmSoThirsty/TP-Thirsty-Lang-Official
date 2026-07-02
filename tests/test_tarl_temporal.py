"""
Tests for Phase 5 — Temporal Governance

Covers:
  5a  Time-bound verdicts (for: <duration>)
  5b  Policy effective windows (valid_from / valid_until)
  5c  Policy succession (if_unresolved_after / revert_to)
  5d  Temporal audit archive (TarlAuditArchive)
"""
import unittest

from utf.tarl.archive import TarlAuditArchive
from utf.tarl.composer import PolicyComposer
from utf.tarl.core import (
    PolicyParser,
    _check_policy_temporal,
    _parse_duration,
    evaluate_policy,
)
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import (
    TarlDecision,
    TarlPolicy,
    TarlRule,
    TarlVerdict,
)

# ── helpers ───────────────────────────────────────────────────────────────────

FAR_PAST = "2000-01-01T00:00:00Z"
FAR_FUTURE = "2099-12-31T23:59:59Z"

_SIMPLE_POLICY = """\
policy access:
    when role == "admin" => ALLOW
    when role == "user" => DENY
"""


# ── 5a: _parse_duration ───────────────────────────────────────────────────────

class TestParseDuration(unittest.TestCase):

    def test_seconds(self):
        assert _parse_duration("30s") == 30

    def test_minutes(self):
        assert _parse_duration("5m") == 300

    def test_hours(self):
        assert _parse_duration("4h") == 14400

    def test_days(self):
        assert _parse_duration("1d") == 86400

    def test_weeks(self):
        assert _parse_duration("2w") == 1209600

    def test_compound_1h30m(self):
        assert _parse_duration("1h30m") == 5400

    def test_compound_2d12h(self):
        assert _parse_duration("2d12h") == 86400 * 2 + 43200

    def test_bare_number_is_seconds(self):
        assert _parse_duration("3600") == 3600

    def test_empty_returns_none(self):
        assert _parse_duration("") is None

    def test_invalid_returns_none(self):
        assert _parse_duration("abc") is None
        assert _parse_duration("4x") is None

    def test_zero_returns_none(self):
        assert _parse_duration("0s") is None


# ── 5a: parser support for "for: <duration>" ──────────────────────────────────

class TestRuleDurationParsing(unittest.TestCase):

    def test_for_hours_parsed(self):
        policy = PolicyParser.parse(
            'when role == "admin" => ALLOW for: 4h'
        )
        assert policy.rules[0].duration_seconds == 14400

    def test_for_minutes_parsed(self):
        policy = PolicyParser.parse(
            'when role == "user" => ESCALATE for: 30m'
        )
        assert policy.rules[0].duration_seconds == 1800

    def test_for_days_parsed(self):
        policy = PolicyParser.parse(
            'when env == "prod" => ALLOW for: 1d'
        )
        assert policy.rules[0].duration_seconds == 86400

    def test_no_duration_is_none(self):
        policy = PolicyParser.parse('when x == 1 => ALLOW')
        assert policy.rules[0].duration_seconds is None

    def test_rule_str_shows_duration(self):
        rule = TarlRule("x == 1", TarlVerdict.ALLOW, duration_seconds=7200)
        assert "for: 2h" in str(rule)

    def test_rule_str_minutes(self):
        rule = TarlRule("x == 1", TarlVerdict.ALLOW, duration_seconds=90)
        assert "for: 90s" in str(rule)

    def test_rule_str_no_duration(self):
        rule = TarlRule("x == 1", TarlVerdict.ALLOW)
        assert "for:" not in str(rule)


# ── 5a: expires_at in TarlDecision ───────────────────────────────────────────

class TestExpiresAt(unittest.TestCase):

    def test_evaluate_policy_sets_expires_at(self):
        decision = evaluate_policy(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW for: 1h',
        )
        assert decision.verdict == TarlVerdict.ALLOW
        assert decision.expires_at is not None
        assert "T" in decision.expires_at   # ISO-8601 contains T

    def test_no_duration_no_expires_at(self):
        decision = evaluate_policy(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        assert decision.expires_at is None

    def test_default_deny_no_expires_at(self):
        decision = evaluate_policy({}, policy_text='when x == 1 => ALLOW')
        assert decision.expires_at is None

    def test_runtime_sets_expires_at(self):
        rt = TarlRuntime()
        decision = rt.evaluate(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW for: 2h',
        )
        assert decision.verdict == TarlVerdict.ALLOW
        assert decision.expires_at is not None

    def test_runtime_proof_no_expires_at_field_on_proof(self):
        """TarlProof does not carry expires_at; it lives on TarlDecision."""
        rt = TarlRuntime()
        decision, proof = rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW for: 2h',
        )
        assert decision.expires_at is not None
        assert not hasattr(proof, "expires_at")

    def test_decision_str_includes_expires(self):
        d = TarlDecision(
            verdict=TarlVerdict.ALLOW,
            reason="matched",
            expires_at="2099-12-31T23:59:59+00:00",
        )
        assert "expires" in str(d)


# ── 5b: valid_from / valid_until parsing ─────────────────────────────────────

class TestTemporalWindowParsing(unittest.TestCase):

    def test_valid_from_parsed(self):
        policy = PolicyParser.parse(
            "policy p:\n  valid_from: 2026-07-01\n  when x == 1 => ALLOW"
        )
        assert policy.valid_from == "2026-07-01"

    def test_valid_until_parsed(self):
        policy = PolicyParser.parse(
            "policy p:\n  valid_until: 2026-12-31\n  when x == 1 => ALLOW"
        )
        assert policy.valid_until == "2026-12-31"

    def test_on_expiry_parsed(self):
        policy = PolicyParser.parse(
            "policy p:\n  on_expiry: DENY\n  when x == 1 => ALLOW"
        )
        assert policy.on_expiry == TarlVerdict.DENY

    def test_supersedes_parsed(self):
        policy = PolicyParser.parse(
            "policy p v2:\n  supersedes: v1\n  when x == 1 => ALLOW"
        )
        assert policy.supersedes == "v1"
        assert policy.version == "2"

    def test_if_unresolved_after_parsed(self):
        policy = PolicyParser.parse(
            "policy emerg:\n"
            "  valid_from: 2026-01-01T00:00:00Z\n"
            "  if_unresolved_after: 8h => revert_to: baseline\n"
            "  when x == 1 => ALLOW"
        )
        assert policy.if_unresolved_after == 8 * 3600
        assert policy.revert_to == "baseline"

    def test_policy_str_includes_temporal(self):
        policy = TarlPolicy(
            name="p",
            valid_from="2026-07-01",
            valid_until="2026-12-31",
            on_expiry=TarlVerdict.ESCALATE,
        )
        s = str(policy)
        assert "valid_from: 2026-07-01" in s
        assert "valid_until: 2026-12-31" in s
        assert "on_expiry: ESCALATE" in s

    def test_policy_str_if_unresolved(self):
        policy = TarlPolicy(
            name="emerg",
            if_unresolved_after=28800,
            revert_to="baseline",
        )
        s = str(policy)
        assert "if_unresolved_after: 8h" in s
        assert "revert_to: baseline" in s


# ── 5b: _check_policy_temporal ────────────────────────────────────────────────

class TestCheckPolicyTemporal(unittest.TestCase):

    def test_no_window_returns_none(self):
        policy = TarlPolicy(name="p")
        assert _check_policy_temporal(policy) is None

    def test_past_valid_from_returns_none(self):
        policy = TarlPolicy(name="p", valid_from=FAR_PAST)
        assert _check_policy_temporal(policy) is None

    def test_future_valid_from_returns_decision(self):
        policy = TarlPolicy(name="p", valid_from=FAR_FUTURE)
        result = _check_policy_temporal(policy)
        assert result is not None
        assert result.verdict == TarlVerdict.ESCALATE
        assert "not yet effective" in result.reason

    def test_future_valid_from_with_on_expiry_deny(self):
        policy = TarlPolicy(
            name="p", valid_from=FAR_FUTURE, on_expiry=TarlVerdict.DENY
        )
        result = _check_policy_temporal(policy)
        assert result is not None
        assert result.verdict == TarlVerdict.DENY

    def test_past_valid_until_returns_decision(self):
        policy = TarlPolicy(name="p", valid_until=FAR_PAST)
        result = _check_policy_temporal(policy)
        assert result is not None
        assert result.verdict == TarlVerdict.ESCALATE
        assert "expired" in result.reason

    def test_future_valid_until_returns_none(self):
        policy = TarlPolicy(name="p", valid_until=FAR_FUTURE)
        assert _check_policy_temporal(policy) is None

    def test_window_open_both_bounds(self):
        policy = TarlPolicy(
            name="p", valid_from=FAR_PAST, valid_until=FAR_FUTURE
        )
        assert _check_policy_temporal(policy) is None

    def test_if_unresolved_after_triggers_when_elapsed(self):
        # if_unresolved_after=60s from valid_from in the far past → elapsed
        policy = TarlPolicy(
            name="p",
            valid_from=FAR_PAST,
            if_unresolved_after=60,
        )
        result = _check_policy_temporal(policy)
        assert result is not None
        assert "expired" in result.reason

    def test_if_unresolved_after_not_yet_elapsed(self):
        # valid_from=FAR_FUTURE so the succession clock hasn't started
        policy = TarlPolicy(
            name="p",
            valid_from=FAR_FUTURE,
            if_unresolved_after=86400,
        )
        result = _check_policy_temporal(policy)
        # not-yet-active fires first
        assert result is not None
        assert "not yet effective" in result.reason


# ── 5b: evaluate_policy enforces temporal window ─────────────────────────────

class TestEvaluatePolicyTemporalWindow(unittest.TestCase):

    def test_not_yet_active_returns_escalate(self):
        decision = evaluate_policy(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_from: {FAR_FUTURE}\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert decision.verdict == TarlVerdict.ESCALATE

    def test_expired_returns_escalate(self):
        decision = evaluate_policy(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_until: {FAR_PAST}\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert decision.verdict == TarlVerdict.ESCALATE

    def test_expired_with_on_expiry_deny(self):
        decision = evaluate_policy(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_until: {FAR_PAST}\n"
                f"  on_expiry: DENY\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert decision.verdict == TarlVerdict.DENY

    def test_in_window_evaluates_normally(self):
        decision = evaluate_policy(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_from: {FAR_PAST}\n"
                f"  valid_until: {FAR_FUTURE}\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert decision.verdict == TarlVerdict.ALLOW

    def test_no_window_evaluates_normally(self):
        decision = evaluate_policy(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        assert decision.verdict == TarlVerdict.ALLOW


# ── 5b: TarlRuntime enforces temporal window ──────────────────────────────────

class TestRuntimeTemporalWindow(unittest.TestCase):

    def test_not_yet_active(self):
        rt = TarlRuntime()
        decision = rt.evaluate(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_from: {FAR_FUTURE}\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert decision.verdict == TarlVerdict.ESCALATE

    def test_expired_policy(self):
        rt = TarlRuntime()
        decision = rt.evaluate(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_until: {FAR_PAST}\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert decision.verdict == TarlVerdict.ESCALATE

    def test_in_window_allows(self):
        rt = TarlRuntime()
        decision = rt.evaluate(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_from: {FAR_PAST}\n"
                f"  valid_until: {FAR_FUTURE}\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert decision.verdict == TarlVerdict.ALLOW

    def test_temporal_policy_not_cached(self):
        """Temporal policy skips LRU cache so the window is re-evaluated each call."""
        rt = TarlRuntime()
        policy_text = (
            f"policy p:\n"
            f"  valid_from: {FAR_PAST}\n"
            f"  valid_until: {FAR_FUTURE}\n"
            f'  when role == "admin" => ALLOW'
        )
        d1 = rt.evaluate({"role": "admin"}, policy_text=policy_text)
        d2 = rt.evaluate({"role": "admin"}, policy_text=policy_text)
        assert d1.verdict == TarlVerdict.ALLOW
        assert d2.verdict == TarlVerdict.ALLOW
        assert rt.cache.size == 0   # not cached

    def test_evaluate_with_proof_temporal_window(self):
        rt = TarlRuntime()
        decision, proof = rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_until: {FAR_PAST}\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert decision.verdict == TarlVerdict.ESCALATE
        assert proof.verdict == TarlVerdict.ESCALATE
        assert proof.rule_index == -1
        assert proof.trace == []


# ── 5c: policy succession in PolicyComposer ──────────────────────────────────

class TestPolicySuccession(unittest.TestCase):

    def test_succession_revert_to_baseline(self):
        """Expired emergency policy reverts to baseline via revert_to."""
        baseline = PolicyParser.parse(
            'policy baseline:\n  when x == 1 => ALLOW\n  when x == 2 => DENY'
        )
        emergency = TarlPolicy(
            name="emergency",
            rules=[TarlRule("x == 1", TarlVerdict.DENY)],
            valid_from=FAR_PAST,
            if_unresolved_after=1,  # 1 second — always elapsed from FAR_PAST
            revert_to="baseline",
        )
        composer = PolicyComposer()
        composer.register(baseline)
        composer.register(emergency)

        decision = composer.evaluate("emergency", {"x": 1})
        # Emergency has expired (1s from FAR_PAST), so baseline is evaluated
        assert decision.verdict == TarlVerdict.ALLOW

    def test_succession_without_revert_escalates(self):
        """Expired policy with no revert_to returns on_expiry/ESCALATE."""
        p = TarlPolicy(
            name="p",
            rules=[TarlRule("x == 1", TarlVerdict.ALLOW)],
            valid_until=FAR_PAST,
        )
        composer = PolicyComposer()
        composer.register(p)
        decision = composer.evaluate("p", {"x": 1})
        assert decision.verdict == TarlVerdict.ESCALATE

    def test_succession_revert_to_unregistered_escalates(self):
        """revert_to points to unknown policy → escalate, no KeyError."""
        p = TarlPolicy(
            name="p",
            rules=[TarlRule("x == 1", TarlVerdict.ALLOW)],
            valid_until=FAR_PAST,
            revert_to="nonexistent",
        )
        composer = PolicyComposer()
        composer.register(p)
        decision = composer.evaluate("p", {"x": 1})
        assert decision.verdict == TarlVerdict.ESCALATE

    def test_succession_parse_and_evaluate(self):
        """Full round-trip: parse if_unresolved_after directive, then evaluate."""
        composer = PolicyComposer()
        composer.register_from_text(
            "policy baseline:\n  when role == \"admin\" => ALLOW\n"
        )
        composer.register_from_text(
            f"policy emerg:\n"
            f"  valid_from: {FAR_PAST}\n"
            f"  if_unresolved_after: 1s => revert_to: baseline\n"
            f'  when role == "admin" => DENY\n'
        )
        # Emergency expired → baseline evaluated → ALLOW
        decision = composer.evaluate("emerg", {"role": "admin"})
        assert decision.verdict == TarlVerdict.ALLOW


# ── 5d: TarlAuditArchive ─────────────────────────────────────────────────────

class TestTarlAuditArchive(unittest.TestCase):

    def _make_proof(self, verdict=TarlVerdict.ALLOW):
        """Generate a real proof via TarlRuntime for testing."""
        rt = TarlRuntime()
        ctx = {"role": "admin"} if verdict == TarlVerdict.ALLOW else {"role": "other"}
        _, proof = rt.evaluate_with_proof(
            ctx,
            policy_text='when role == "admin" => ALLOW',
        )
        return proof

    def test_store_and_count(self):
        with TarlAuditArchive(":memory:") as arc:
            proof = self._make_proof(TarlVerdict.ALLOW)
            arc.store(proof)
            assert arc.count() == 1

    def test_store_multiple(self):
        with TarlAuditArchive(":memory:") as arc:
            arc.store(self._make_proof(TarlVerdict.ALLOW))
            arc.store(self._make_proof(TarlVerdict.ALLOW))
            arc.store(self._make_proof(TarlVerdict.DENY))
            assert arc.count() == 3

    def test_query_all(self):
        with TarlAuditArchive(":memory:") as arc:
            arc.store(self._make_proof(TarlVerdict.ALLOW))
            arc.store(self._make_proof(TarlVerdict.ALLOW))
            proofs = arc.query()
            assert len(proofs) == 2

    def test_query_by_verdict(self):
        rt = TarlRuntime()
        _, p_allow = rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        _, p_deny = rt.evaluate_with_proof(
            {"role": "guest"},
            policy_text='when role == "admin" => ALLOW',
        )
        with TarlAuditArchive(":memory:") as arc:
            arc.store(p_allow)
            arc.store(p_deny)
            allows = arc.query(verdict="ALLOW")
            denies = arc.query(verdict="DENY")
            assert len(allows) == 1
            assert len(denies) == 1

    def test_query_returns_valid_proofs(self):
        with TarlAuditArchive(":memory:") as arc:
            proof = self._make_proof()
            arc.store(proof)
            [retrieved] = arc.query()
            assert retrieved.policy_hash == proof.policy_hash
            assert retrieved.context_hash == proof.context_hash
            assert retrieved.verdict == proof.verdict

    def test_store_with_expires_at(self):
        with TarlAuditArchive(":memory:") as arc:
            proof = self._make_proof()
            row_id = arc.store(proof, expires_at="2099-01-01T00:00:00+00:00")
            assert row_id == 1

    def test_count_with_filter(self):
        rt = TarlRuntime()
        _, p1 = rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        _, p2 = rt.evaluate_with_proof(
            {"role": "guest"},
            policy_text='when role == "admin" => ALLOW',
        )
        with TarlAuditArchive(":memory:") as arc:
            arc.store(p1)
            arc.store(p2)
            assert arc.count(verdict="ALLOW") == 1
            assert arc.count(verdict="DENY") == 1
            assert arc.count(verdict="ESCALATE") == 0

    def test_query_limit(self):
        with TarlAuditArchive(":memory:") as arc:
            for _ in range(5):
                arc.store(self._make_proof())
            proofs = arc.query(limit=3)
            assert len(proofs) == 3

    def test_context_manager_closes(self):
        arc = TarlAuditArchive(":memory:")
        arc.store(self._make_proof())
        arc.close()
        arc.close()  # double close is safe


# ── 5d: runtime auto-archives proofs ─────────────────────────────────────────

class TestRuntimeArchiveIntegration(unittest.TestCase):

    def test_auto_store_on_evaluate_with_proof(self):
        arc = TarlAuditArchive(":memory:")
        rt = TarlRuntime()
        rt.set_archive(arc)
        rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        assert arc.count() == 1
        arc.close()

    def test_set_archive_returns_self(self):
        rt = TarlRuntime()
        arc = TarlAuditArchive(":memory:")
        result = rt.set_archive(arc)
        assert result is rt
        arc.close()

    def test_multiple_evaluations_stored(self):
        arc = TarlAuditArchive(":memory:")
        rt = TarlRuntime()
        rt.set_archive(arc)
        rt.evaluate_with_proof({"role": "admin"},
                                policy_text='when role == "admin" => ALLOW')
        rt.evaluate_with_proof({"role": "guest"},
                                policy_text='when role == "admin" => ALLOW')
        assert arc.count() == 2
        arc.close()

    def test_temporal_rejection_also_stored(self):
        """An out-of-window verdict (ESCALATE from temporal check) is archived."""
        arc = TarlAuditArchive(":memory:")
        rt = TarlRuntime()
        rt.set_archive(arc)
        rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text=(
                f"policy p:\n"
                f"  valid_until: {FAR_PAST}\n"
                f'  when role == "admin" => ALLOW'
            ),
        )
        assert arc.count() == 1
        [proof] = arc.query()
        assert proof.verdict == TarlVerdict.ESCALATE
        arc.close()

    def test_no_archive_no_error(self):
        """Runtime without archive attached does not raise on evaluate_with_proof."""
        rt = TarlRuntime()
        decision, proof = rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        assert decision.verdict == TarlVerdict.ALLOW


# ── is_expired() — re-check contract ────────────────────────────────────────

class TestIsExpired(unittest.TestCase):

    def test_no_expires_at_not_expired(self):
        d = TarlDecision(verdict=TarlVerdict.ALLOW)
        assert not d.is_expired()

    def test_far_future_not_expired(self):
        d = TarlDecision(verdict=TarlVerdict.ALLOW, expires_at=FAR_FUTURE)
        assert not d.is_expired()

    def test_far_past_is_expired(self):
        d = TarlDecision(verdict=TarlVerdict.ALLOW, expires_at=FAR_PAST)
        assert d.is_expired()

    def test_evaluate_with_duration_sets_unexpired(self):
        rt = TarlRuntime()
        decision = rt.evaluate(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW for: 4h',
        )
        assert decision.expires_at is not None
        assert not decision.is_expired()   # 4h from now is not past yet

    def test_deny_with_duration_can_be_expired(self):
        d = TarlDecision(verdict=TarlVerdict.DENY, expires_at=FAR_PAST)
        assert d.is_expired()

    def test_malformed_expires_at_not_expired(self):
        d = TarlDecision(verdict=TarlVerdict.ALLOW, expires_at="not-a-date")
        assert not d.is_expired()   # bad date → False, not an exception


# ── succession cycle detection ────────────────────────────────────────────────

class TestSuccessionCycles(unittest.TestCase):

    def test_simple_cycle_raises(self):
        """A→B→A succession cycle must raise CompositionError."""
        from utf.tarl.composer import CompositionError

        a = TarlPolicy(
            name="a",
            rules=[TarlRule("x == 1", TarlVerdict.ALLOW)],
            valid_until=FAR_PAST,
            revert_to="b",
        )
        b = TarlPolicy(
            name="b",
            rules=[TarlRule("x == 1", TarlVerdict.DENY)],
            valid_until=FAR_PAST,
            revert_to="a",
        )
        composer = PolicyComposer()
        composer.register(a)
        composer.register(b)
        with self.assertRaises(CompositionError):
            composer.evaluate("a", {"x": 1})

    def test_self_referential_cycle_raises(self):
        """A→A (policy reverts to itself) must raise CompositionError."""
        from utf.tarl.composer import CompositionError

        a = TarlPolicy(
            name="a",
            rules=[TarlRule("x == 1", TarlVerdict.ALLOW)],
            valid_until=FAR_PAST,
            revert_to="a",
        )
        composer = PolicyComposer()
        composer.register(a)
        with self.assertRaises(CompositionError):
            composer.evaluate("a", {"x": 1})

    def test_non_cycle_chain_works(self):
        """A (expired) → B (in-window) must succeed without error."""
        from utf.tarl.spec import TarlRule

        baseline = TarlPolicy(
            name="b",
            rules=[TarlRule("x == 1", TarlVerdict.ALLOW)],
        )
        expired_a = TarlPolicy(
            name="a",
            rules=[TarlRule("x == 1", TarlVerdict.DENY)],
            valid_until=FAR_PAST,
            revert_to="b",
        )
        composer = PolicyComposer()
        composer.register(baseline)
        composer.register(expired_a)
        decision = composer.evaluate("a", {"x": 1})
        assert decision.verdict == TarlVerdict.ALLOW


# ── query() verifier parameter ────────────────────────────────────────────────

class TestArchiveQueryVerifier(unittest.TestCase):

    def _make_signed_proof(self):
        rt = TarlRuntime()
        rt.set_signing_key("k1", b"secret-key-for-testing")
        _, proof = rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        return proof

    def _make_unsigned_proof(self):
        rt = TarlRuntime()
        _, proof = rt.evaluate_with_proof(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        return proof

    def test_query_without_verifier_returns_all(self):
        signed = self._make_signed_proof()
        unsigned = self._make_unsigned_proof()
        with TarlAuditArchive(":memory:") as arc:
            arc.store(signed)
            arc.store(unsigned)
            assert len(arc.query()) == 2

    def test_query_with_verifier_keeps_valid_sig(self):
        from utf.tarl.verifier import ProofVerifier
        proof = self._make_signed_proof()
        verifier = ProofVerifier(require_signature=False)
        verifier.add_hmac_key("k1", b"secret-key-for-testing")
        with TarlAuditArchive(":memory:") as arc:
            arc.store(proof)
            results = arc.query(verifier=verifier)
        assert len(results) == 1

    def test_query_with_verifier_excludes_tampered_sig(self):
        """A proof with a valid-looking but wrong signature is filtered out."""
        from utf.tarl.verifier import ProofVerifier
        proof = self._make_signed_proof()
        # Register the WRONG key → signature will fail verification
        verifier = ProofVerifier(require_signature=False)
        verifier.add_hmac_key("k1", b"wrong-key")
        with TarlAuditArchive(":memory:") as arc:
            arc.store(proof)
            results = arc.query(verifier=verifier)
        assert len(results) == 0

    def test_query_with_verifier_keeps_unsigned_proofs(self):
        """Unsigned proofs (sig='') pass through even with a verifier attached."""
        from utf.tarl.verifier import ProofVerifier
        proof = self._make_unsigned_proof()
        verifier = ProofVerifier(require_signature=False)
        with TarlAuditArchive(":memory:") as arc:
            arc.store(proof)
            results = arc.query(verifier=verifier)
        # unsigned → sig check returns None (not False) → kept
        assert len(results) == 1


# ── public API export check ───────────────────────────────────────────────────

class TestPhase5APIExports(unittest.TestCase):

    def test_tarl_audit_archive_in_all(self):
        import utf.tarl as pkg
        assert "TarlAuditArchive" in pkg.__all__

    def test_expires_at_on_decision(self):
        from utf.tarl.spec import TarlDecision, TarlVerdict
        d = TarlDecision(verdict=TarlVerdict.ALLOW)
        assert hasattr(d, "expires_at")
        assert d.expires_at is None

    def test_duration_seconds_on_rule(self):
        from utf.tarl.spec import TarlRule, TarlVerdict
        r = TarlRule(condition="x==1", verdict=TarlVerdict.ALLOW)
        assert hasattr(r, "duration_seconds")
        assert r.duration_seconds is None

    def test_if_unresolved_and_revert_to_on_policy(self):
        from utf.tarl.spec import TarlPolicy
        p = TarlPolicy(name="p")
        assert hasattr(p, "if_unresolved_after")
        assert hasattr(p, "revert_to")


if __name__ == "__main__":
    unittest.main()

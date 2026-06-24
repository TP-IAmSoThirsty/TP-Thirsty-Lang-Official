"""Extra coverage for tarl.spec: verdict ordering, durations, expiry."""
from utf.tarl.spec import (
    CompositionOp,
    TarlDecision,
    TarlPolicy,
    TarlRule,
    TarlVerdict,
)


def test_verdict_ordering():
    assert TarlVerdict.ALLOW > TarlVerdict.DENY
    assert TarlVerdict.DENY < TarlVerdict.ALLOW
    assert TarlVerdict.ALLOW >= TarlVerdict.ALLOW
    assert TarlVerdict.DENY <= TarlVerdict.ESCALATE
    assert str(TarlVerdict.ALLOW) == "ALLOW"


def test_verdict_notimplemented():
    assert TarlVerdict.ALLOW.__lt__("x") is NotImplemented
    assert TarlVerdict.ALLOW.__le__("x") is NotImplemented
    assert TarlVerdict.ALLOW.__gt__("x") is NotImplemented
    assert TarlVerdict.ALLOW.__ge__("x") is NotImplemented


def test_verdict_meet_join():
    assert TarlVerdict.meet(TarlVerdict.ALLOW, TarlVerdict.DENY) == TarlVerdict.DENY
    assert TarlVerdict.join(TarlVerdict.ALLOW, TarlVerdict.DENY) == TarlVerdict.ALLOW


def test_composition_str():
    assert str(CompositionOp.EXTENDS) == "EXTENDS"


def test_rule_str_durations():
    assert "for: 1h" in str(TarlRule("x", TarlVerdict.ALLOW, duration_seconds=3600))
    assert "for: 2m" in str(TarlRule("x", TarlVerdict.ALLOW, duration_seconds=120))
    assert "for: 90s" in str(TarlRule("x", TarlVerdict.ALLOW, duration_seconds=90))


def test_policy_str_full():
    p = TarlPolicy(
        rules=[TarlRule("true", TarlVerdict.ALLOW)],
        name="p", parent="base", composition=CompositionOp.EXTENDS,
        version="2", supersedes="old", valid_from="2020-01-01",
        valid_until="2030-01-01", on_expiry=TarlVerdict.DENY,
        if_unresolved_after=120, revert_to="fallback",
    )
    s = str(p)
    assert "supersedes: old" in s
    assert "if_unresolved_after: 2m => revert_to: fallback" in s
    assert "EXTENDS base" in s


def test_policy_str_duration_variants():
    for secs, frag in [(3600, "1h"), (45, "45s")]:
        p = TarlPolicy(name="p", if_unresolved_after=secs, revert_to="f")
        assert frag in str(p)


def test_decision_str_and_expiry():
    d = TarlDecision(verdict=TarlVerdict.ALLOW, reason="ok",
                     expires_at="2000-01-01T00:00:00")  # naive, in the past
    assert "expires" in str(d)
    assert d.is_expired() is True
    assert TarlDecision(verdict=TarlVerdict.ALLOW).is_expired() is False
    assert TarlDecision(verdict=TarlVerdict.ALLOW,
                        expires_at="not-a-date").is_expired() is False

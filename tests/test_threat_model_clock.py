"""Trusted-clock / time-spoofing tests (THREAT_MODEL C043).

Temporal policy windows must be decided against a verified signed time, so a
spoofed host clock cannot satisfy (or dodge) a window.
"""
import datetime

from utf.tarl.clock import SignedTime, TimeAuthority, TrustedClock
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict

SEED = bytes(range(32))
WRONG_SEED = bytes([7] * 32)


def _authority():
    return TimeAuthority("time-1", SEED)


def _clock(authority=None):
    authority = authority or _authority()
    return TrustedClock().add_ed25519_key(
        authority.key_id, authority.public_key_bytes()
    )


# ── TrustedClock verification ──────────────────────────────────────────────────

def test_valid_signed_time_verifies():
    auth = _authority()
    now = datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.UTC)
    dt = _clock(auth).verify(auth.stamp(now))
    assert dt == now


def test_unsigned_time_is_rejected():
    assert _clock().verify(SignedTime(timestamp="2026-06-01T00:00:00+00:00")) is None


def test_wrong_key_is_rejected():
    real = _authority()
    forger = TimeAuthority("time-1", WRONG_SEED)
    clock = TrustedClock().add_ed25519_key("time-1", real.public_key_bytes())
    assert clock.verify(forger.stamp()) is None


def test_tampered_timestamp_is_rejected():
    auth = _authority()
    signed = auth.stamp()
    signed.timestamp = "2099-01-01T00:00:00+00:00"  # move time after signing
    assert _clock(auth).verify(signed) is None


def test_out_of_skew_signed_time_is_rejected():
    auth = _authority()
    clock = TrustedClock(max_skew_seconds=60).add_ed25519_key(
        auth.key_id, auth.public_key_bytes()
    )
    old = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)
    assert clock.verify(auth.stamp(old)) is None


# ── Runtime uses trusted time for temporal windows ─────────────────────────────

WINDOW_POLICY = (
    'policy p\n'
    '  valid_from: 2026-01-01T00:00:00Z\n'
    '  valid_until: 2026-12-31T23:59:59Z\n'
    'when true => ALLOW\n'
)


def _runtime_with_trusted_now(trusted_dt):
    auth = _authority()
    clock = _clock(auth)
    signed = auth.stamp(trusted_dt)
    rt = TarlRuntime(PolicyParser.parse(WINDOW_POLICY))
    # The runtime consults trusted time, never the host clock.
    rt.set_clock(lambda: clock.verify(signed))
    return rt


def test_trusted_time_inside_window_allows():
    inside = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)
    decision = _runtime_with_trusted_now(inside).evaluate({"x": 1})
    assert decision.verdict == TarlVerdict.ALLOW


def test_trusted_time_after_window_is_not_allowed():
    after = datetime.datetime(2027, 6, 1, tzinfo=datetime.UTC)
    decision = _runtime_with_trusted_now(after).evaluate({"x": 1})
    # Outside the window the policy is not in effect (on_expiry / ESCALATE).
    assert decision.verdict != TarlVerdict.ALLOW


def test_trusted_time_before_window_is_not_allowed():
    before = datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC)
    decision = _runtime_with_trusted_now(before).evaluate({"x": 1})
    assert decision.verdict != TarlVerdict.ALLOW

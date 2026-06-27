"""Path-confinement tests (THREAT_MODEL C042).

Traversal and symlink escapes from an allowed filesystem root must be denied on
the canonical (symlink-resolved) path, not the attacker-supplied string.
"""
import os

import pytest

from utf.tarl.broker import ACTION_WRITE, CapabilityBroker, CapabilityDenied
from utf.tarl.core import PolicyParser
from utf.tarl.pathguard import PathGuard, canonical_path, is_within_root
from utf.tarl.runtime import TarlRuntime

ALLOW_WRITE_IN_ROOT = (
    'policy p\n'
    'when action == "write" and within_root == true => ALLOW\n'
    'when true => DENY\n'
)


def test_path_within_root_is_allowed(tmp_path):
    guard = PathGuard([str(tmp_path)])
    result = guard.check(str(tmp_path / "sub" / "file.txt"))
    assert result.ok
    assert result.canonical == canonical_path(str(tmp_path / "sub" / "file.txt"))


def test_directory_traversal_escapes_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    guard = PathGuard([str(root)])
    result = guard.check(str(root / ".." / ".." / "etc" / "passwd"))
    assert not result.ok
    assert "escapes" in result.reason


def test_sibling_prefix_is_not_within_root(tmp_path):
    # /tmp/data must not admit /tmp/data-evil (component-aware comparison).
    (tmp_path / "data").mkdir()
    (tmp_path / "data-evil").mkdir()
    guard = PathGuard([str(tmp_path / "data")])
    assert not guard.check(str(tmp_path / "data-evil" / "x")).ok


def test_symlink_escape_is_detected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("top secret")
    link = root / "link"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")
    guard = PathGuard([str(root)])
    # The path looks inside root, but its real target is outside it.
    assert not guard.check(str(link / "secret.txt")).ok


def test_is_within_root_helper(tmp_path):
    assert is_within_root(str(tmp_path / "a" / "b"), str(tmp_path))
    assert not is_within_root(str(tmp_path.parent), str(tmp_path))


def test_pathguard_requires_a_root():
    with pytest.raises(ValueError):
        PathGuard([])


# ── Broker integration: require_path confines before brokering ─────────────────

def _broker(tmp_path):
    rt = TarlRuntime(PolicyParser.parse(ALLOW_WRITE_IN_ROOT))
    return CapabilityBroker(
        rt, authority="admin", path_guard=PathGuard([str(tmp_path)])
    )


def test_require_path_allows_inside_root(tmp_path):
    decision = _broker(tmp_path).require_path(
        ACTION_WRITE, str(tmp_path / "out.txt")
    )
    assert decision.allowed


def test_require_path_denies_traversal(tmp_path):
    broker = _broker(tmp_path)
    with pytest.raises(CapabilityDenied) as exc:
        broker.require_path(ACTION_WRITE, str(tmp_path / ".." / "evil.txt"))
    assert "escapes" in exc.value.decision.reason

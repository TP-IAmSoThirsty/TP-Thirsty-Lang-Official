"""Capability-broker tests for out-of-language adapters.

Covers FFI/native brokering (C033) and AI/MCP tool-adapter brokering
(C040-C041): every external side-effect path must call the same broker and is
denied by default.
"""
import pytest

from utf.tarl.authority import AuthorityIssuer, AuthorityVerifier
from utf.tarl.broker import (
    ACTION_EXECUTE,
    ACTION_TOOL,
    CapabilityBroker,
    CapabilityDenied,
)
from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict

DENY_ALL = 'policy p\nwhen true => DENY\n'
ALLOW_EXECUTE = (
    'policy p\n'
    'when action == "execute" => ALLOW\n'
    'when true => DENY\n'
)
ALLOW_TOOL_FOR_AUTH = (
    'policy p\n'
    'when action == "tool" and authority_authenticated == true => ALLOW\n'
    'when true => DENY\n'
)


def _runtime(policy):
    return TarlRuntime(PolicyParser.parse(policy))


# ── Fail-closed: no runtime, default deny ──────────────────────────────────────

def test_broker_without_runtime_fails_closed():
    broker = CapabilityBroker()  # no runtime
    decision = broker.request(ACTION_EXECUTE, "ffi:libc.system")
    assert not decision.allowed
    assert decision.verdict == TarlVerdict.DENY
    assert decision.proof.verdict == TarlVerdict.DENY


def test_deny_all_policy_denies_every_capability():
    broker = CapabilityBroker(_runtime(DENY_ALL), authority="admin")
    for action, target in [
        (ACTION_EXECUTE, "ffi:native_symbol"),
        (ACTION_TOOL, "mcp:filesystem.write"),
        ("network", "http://x"),
    ]:
        assert not broker.request(action, target).allowed


# ── C033: FFI / native is denied unless brokered ───────────────────────────────

def test_ffi_native_call_denied_by_default():
    broker = CapabilityBroker(_runtime(DENY_ALL), authority="admin")
    with pytest.raises(CapabilityDenied) as exc:
        broker.require(ACTION_EXECUTE, "ffi:ctypes.CDLL")
    assert exc.value.decision.proof.verdict == TarlVerdict.DENY


def test_ffi_native_call_allowed_when_policy_permits():
    broker = CapabilityBroker(_runtime(ALLOW_EXECUTE), authority="admin")
    decision = broker.require(ACTION_EXECUTE, "ffi:ctypes.CDLL")
    assert decision.allowed
    assert decision.verdict == TarlVerdict.ALLOW


# ── C040-C041: AI/MCP tool adapters must broker before invoking ────────────────

def test_mcp_tool_invocation_denied_by_default():
    broker = CapabilityBroker(_runtime(DENY_ALL), authority="agent")
    with pytest.raises(CapabilityDenied):
        broker.require(ACTION_TOOL, "mcp:shell.exec", tool="shell.exec")


def test_tool_requires_authenticated_authority():
    # Policy grants the tool only to an authenticated authority; a bare agent
    # string is authority_authenticated == False and is denied.
    bare = CapabilityBroker(_runtime(ALLOW_TOOL_FOR_AUTH), authority="agent")
    assert not bare.request(ACTION_TOOL, "mcp:search").allowed

    issuer = AuthorityIssuer("idp", bytes(range(32)))
    verified = (
        AuthorityVerifier()
        .add_ed25519_key("idp", issuer.public_key_bytes())
        .verify(issuer.issue("agent", grants=("search",)))
        .authority
    )
    authed = CapabilityBroker(_runtime(ALLOW_TOOL_FOR_AUTH), authority=verified)
    assert authed.require(ACTION_TOOL, "mcp:search").allowed


def test_require_authenticated_flag_fails_closed_for_bare_authority():
    broker = CapabilityBroker(
        _runtime(ALLOW_EXECUTE), authority="admin", require_authenticated=True
    )
    decision = broker.request(ACTION_EXECUTE, "ffi:x")
    assert not decision.allowed
    assert "authenticated" in decision.reason


def test_broker_proof_can_be_archived_and_chained(tmp_path):
    # Brokered decisions produce real proofs that flow into the audit chain.
    from utf.tarl.archive import TarlAuditArchive
    runtime = _runtime(ALLOW_EXECUTE)
    db = str(tmp_path / "broker_audit.db")
    with TarlAuditArchive(db) as arc:
        runtime.set_archive(arc)
        broker = CapabilityBroker(runtime, authority="admin")
        broker.require(ACTION_EXECUTE, "ffi:a")
        broker.require(ACTION_EXECUTE, "ffi:b")
        assert arc.verify_chain().valid
        assert arc.count() == 2

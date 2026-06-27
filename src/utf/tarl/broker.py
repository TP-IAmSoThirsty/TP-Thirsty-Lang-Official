"""
Capability broker — the single mediation point for side-effecting adapters.

Inside the interpreter, governed I/O/imports already route through the capability
gate. But effects that originate *outside* the language — an FFI/native call
(C033), an AI agent invoking an MCP/tool adapter (C040, C041), a subprocess
wrapper, a file or network adapter — need the same gate. The acceptance bar for a
hardened runtime requires that **all** side-effect adapters are mediated by the
*same* broker.

:class:`CapabilityBroker` is that broker. An adapter calls
``broker.require(action, target, **context)`` *before* performing its effect; the
broker evaluates the request through a T.A.R.L. runtime (with the bound authority,
context schema, signing, and audit archive of that runtime) and either returns an
ALLOW decision or raises :class:`CapabilityDenied`. It is **fail-closed**: with no
runtime configured, or in a hardened broker with an unauthenticated authority,
every request is denied with a proof.
"""
from __future__ import annotations

from dataclasses import dataclass

from utf.tarl.spec import TarlProof, TarlVerdict


@dataclass
class BrokerDecision:
    """A brokered capability decision, carrying the proof certificate."""

    allowed: bool
    verdict: TarlVerdict
    proof: TarlProof
    reason: str = ""


class CapabilityDenied(Exception):
    """Raised by :meth:`CapabilityBroker.require` when a capability is denied."""

    def __init__(self, action: str, target: str, decision: BrokerDecision):
        self.action = action
        self.target = target
        self.decision = decision
        super().__init__(
            f"capability denied: {action} {target}: {decision.reason}"
        )


class CapabilityBroker:
    """Mediates out-of-language side effects through a T.A.R.L. runtime.

    All adapters (FFI/native, subprocess, file, network, MCP/agent tools) call
    :meth:`require` before acting, so every external effect is governed by the
    same policy, authority, schema, and audit pipeline as in-language effects.
    """

    def __init__(
        self,
        runtime=None,
        authority=None,
        *,
        require_authenticated: bool = False,
        path_guard=None,
    ):
        """``authority`` may be a bare string or a
        ``utf.tarl.authority.VerifiedAuthority``. ``require_authenticated`` makes
        the broker fail closed unless the authority was authenticated (signed).
        ``path_guard`` is an optional ``utf.tarl.pathguard.PathGuard`` used by
        :meth:`require_path` to confine filesystem targets to allowed roots."""
        self.runtime = runtime
        self.require_authenticated = require_authenticated
        self.path_guard = path_guard
        self._subject = ""
        self._authenticated = False
        self._grants: tuple[str, ...] = ()
        if authority is not None:
            self.set_authority(authority)

    def set_authority(self, authority) -> CapabilityBroker:
        from utf.tarl.authority import VerifiedAuthority
        if isinstance(authority, VerifiedAuthority):
            self._subject = authority.subject
            self._authenticated = bool(authority.authenticated)
            self._grants = tuple(authority.grants)
        else:
            self._subject = str(authority)
            self._authenticated = False
            self._grants = ()
        return self

    def _authority_context(self) -> dict:
        return {
            "authority": self._subject,
            "authority_subject": self._subject,
            "authority_authenticated": self._authenticated,
            "authority_grants": list(self._grants),
        }

    def _fail_closed_proof(self, action: str, target: str, reason: str):
        import hashlib
        import json
        from datetime import UTC, datetime
        ctx = {**self._authority_context(), "action": action,
               "target": str(target)}
        ctx_bytes = json.dumps(
            ctx, sort_keys=True, default=str, separators=(",", ":")
        ).encode("utf-8")
        return TarlProof(
            policy_hash="sha256:" + hashlib.sha256(
                b"<broker fail-closed: no policy>").hexdigest(),
            context_hash="sha256:" + hashlib.sha256(ctx_bytes).hexdigest(),
            rule_index=-1,
            matched_condition="",
            verdict=TarlVerdict.DENY,
            evaluated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            trace=[{"kind": "fail-closed", "action": action,
                    "target": str(target), "matched": False, "reason": reason}],
            signature="",
            key_id="",
        )

    def request(
        self,
        action: str,
        target: str = "",
        **context,
    ) -> BrokerDecision:
        """Evaluate a capability request and return a decision with a proof.

        Never raises for a denial — use :meth:`require` when the call site should
        abort. Fail-closed when no runtime is configured or (for a broker that
        requires authentication) the authority is not authenticated.
        """
        if self.runtime is None:
            reason = ("fail-closed: no policy runtime configured to authorize "
                      "this capability")
            proof = self._fail_closed_proof(action, target, reason)
            return BrokerDecision(False, TarlVerdict.DENY, proof, reason)

        if self.require_authenticated and not self._authenticated:
            reason = ("fail-closed: broker requires an authenticated authority "
                      "to authorize this capability")
            proof = self._fail_closed_proof(action, target, reason)
            return BrokerDecision(False, TarlVerdict.DENY, proof, reason)

        ctx = {**self._authority_context(), **context,
               "action": action, "target": str(target)}
        decision, proof = self.runtime.evaluate_with_proof(ctx)
        allowed = decision.verdict == TarlVerdict.ALLOW
        return BrokerDecision(
            allowed, decision.verdict, proof,
            decision.reason or f"verdict: {decision.verdict}")

    def require(
        self,
        action: str,
        target: str = "",
        **context,
    ) -> BrokerDecision:
        """Like :meth:`request`, but raise :class:`CapabilityDenied` unless ALLOW.

        Adapters call this immediately before performing their effect."""
        decision = self.request(action, target, **context)
        if not decision.allowed:
            raise CapabilityDenied(action, target, decision)
        return decision

    def require_path(
        self,
        action: str,
        path: str,
        **context,
    ) -> BrokerDecision:
        """Confine a filesystem ``path`` to the broker's PathGuard roots, then
        broker the request on the canonical path.

        Traversal/symlink escapes fail closed *before* the policy is consulted;
        a path within an allowed root is brokered with ``within_root == True``
        and ``target`` set to the canonical path so policies see the real
        location, not the attacker-supplied string. Requires a ``path_guard``."""
        if self.path_guard is None:
            raise ValueError("require_path needs a PathGuard on the broker")
        check = self.path_guard.check(path)
        if not check.ok:
            reason = f"fail-closed: {check.reason}"
            proof = self._fail_closed_proof(action, path, reason)
            decision = BrokerDecision(False, TarlVerdict.DENY, proof, reason)
            raise CapabilityDenied(action, path, decision)
        return self.require(
            action, check.canonical, within_root=True, **context)


# A reference vocabulary of broker actions, so adapters classify consistently.
ACTION_READ = "read"
ACTION_WRITE = "write"
ACTION_NETWORK = "network"
ACTION_EXECUTE = "execute"   # subprocess, FFI/native calls
ACTION_TOOL = "tool"         # AI/MCP tool invocation


__all__ = [
    "BrokerDecision",
    "CapabilityDenied",
    "CapabilityBroker",
    "ACTION_READ",
    "ACTION_WRITE",
    "ACTION_NETWORK",
    "ACTION_EXECUTE",
    "ACTION_TOOL",
]

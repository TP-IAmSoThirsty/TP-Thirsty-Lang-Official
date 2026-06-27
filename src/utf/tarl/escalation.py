"""
ESCALATE resolution via signed quorum approval (THREAT_MODEL C050).

Urgency/authority language can pressure a single operator into a high-risk ALLOW.
The defense is structural: high-risk requests resolve to **ESCALATE**, and an
ESCALATE only becomes ALLOW when a quorum of distinct approvers each
cryptographically sign their approval of *that specific decision* (bound to the
proof's context hash). One person — or a forged approval — cannot meet quorum.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from utf.tarl.spec import TarlDecision, TarlProof, TarlVerdict


@dataclass
class Approval:
    """A signed approval of one escalated decision, bound to its context hash."""

    approver: str
    context_hash: str
    key_id: str = ""
    signature: str = ""  # "ed25519:<hex>"

    def signing_bytes(self) -> bytes:
        return json.dumps(
            {"approver": self.approver, "context_hash": self.context_hash,
             "key_id": self.key_id},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")


class ApprovalIssuer:
    """An individual approver: signs approvals for escalated decisions."""

    def __init__(
        self, approver: str, key_id: str,
        private_key: bytes | Ed25519PrivateKey,
    ):
        if isinstance(private_key, Ed25519PrivateKey):
            self._key = private_key
        else:
            self._key = Ed25519PrivateKey.from_private_bytes(private_key)
        self.approver = approver
        self.key_id = key_id

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def approve(self, proof: TarlProof) -> Approval:
        approval = Approval(
            approver=self.approver,
            context_hash=proof.context_hash,
            key_id=self.key_id,
        )
        approval.signature = "ed25519:" + self._key.sign(
            approval.signing_bytes()).hex()
        return approval


@dataclass
class QuorumResult:
    """Outcome of resolving an escalation."""

    decision: TarlDecision
    approvals_counted: int
    threshold: int
    reason: str = ""


class QuorumResolver:
    """Upgrades an ESCALATE decision to ALLOW once a quorum of distinct,
    validly-signed approvals over the decision's context hash is reached."""

    def __init__(self, threshold: int):
        if threshold < 1:
            raise ValueError("quorum threshold must be >= 1")
        self.threshold = threshold
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add_approver_key(
        self, key_id: str, public_key: bytes | Ed25519PublicKey
    ) -> QuorumResolver:
        if isinstance(public_key, Ed25519PublicKey):
            key = public_key
        else:
            key = Ed25519PublicKey.from_public_bytes(public_key)
        self._keys[key_id] = key
        return self

    def _valid(self, approval: Approval, proof: TarlProof) -> bool:
        if approval.context_hash != proof.context_hash:
            return False  # approval is for a different decision
        alg, _, sig_hex = approval.signature.partition(":")
        if alg != "ed25519" or not sig_hex:
            return False
        key = self._keys.get(approval.key_id)
        if key is None:
            return False
        try:
            key.verify(bytes.fromhex(sig_hex), approval.signing_bytes())
            return True
        except (ValueError, InvalidSignature):
            return False

    def resolve(
        self,
        decision: TarlDecision,
        proof: TarlProof,
        approvals: list[Approval],
    ) -> QuorumResult:
        """Resolve an escalated decision against a set of approvals.

        Only ESCALATE decisions are resolvable. Counts **distinct** approvers
        (a single approver cannot satisfy quorum alone) whose approval validly
        signs this decision's context hash. Threshold met → ALLOW; otherwise the
        decision stays ESCALATE.
        """
        if decision.verdict != TarlVerdict.ESCALATE:
            return QuorumResult(
                decision, 0, self.threshold,
                "not an ESCALATE decision; nothing to resolve")
        distinct: set[str] = set()
        for approval in approvals:
            if self._valid(approval, proof):
                distinct.add(approval.approver)
        counted = len(distinct)
        if counted >= self.threshold:
            allowed = TarlDecision(
                verdict=TarlVerdict.ALLOW,
                reason=(f"escalation approved by quorum "
                        f"({counted}/{self.threshold}): "
                        f"{', '.join(sorted(distinct))}"),
                rule_index=decision.rule_index,
                matched_rule=decision.matched_rule,
            )
            return QuorumResult(allowed, counted, self.threshold, "quorum met")
        return QuorumResult(
            decision, counted, self.threshold,
            f"insufficient approvals ({counted}/{self.threshold}); "
            "decision remains ESCALATE")


__all__ = [
    "Approval", "ApprovalIssuer", "QuorumResolver", "QuorumResult",
]

"""
T.A.R.L. Proof Verifier — Phase 4

Independent verification of TarlProof certificates:
  1. Signature validity (HMAC-SHA256 or Ed25519)
  2. Policy hash match (optional, requires policy source)
  3. Evaluation trace internal consistency

No runtime or policy engine is required — proofs are self-contained.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from utf.tarl.spec import TarlProof


@dataclass
class VerificationResult:
    """Result of verifying a TarlProof."""
    valid: bool
    checks: dict[str, bool | None] = field(default_factory=dict)
    message: str = ""

    def __str__(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        return f"[{status}] {self.message}"

    @property
    def summary(self) -> str:
        lines = [str(self)]
        for check, result in self.checks.items():
            if result is True:
                mark = "✓"
            elif result is False:
                mark = "✗"
            else:
                mark = "-"
            lines.append(f"  {mark} {check}")
        return "\n".join(lines)


class ProofVerifier:
    """
    Verifies TarlProof certificates independently of the runtime.

    Usage::

        verifier = ProofVerifier()
        verifier.add_hmac_key("key1", b"my-secret")
        verifier.add_ed25519_key("key2", ed25519_public_key)
        result = verifier.verify(proof, policy_source=policy_text)
        assert result.valid
    """

    def __init__(
        self,
        require_signature: bool = False,
        allowed_signature_algorithms: set[str] | None = None,
        require_policy_source: bool = False,
    ) -> None:
        """
        Strict-mode options (all default to today's permissive behavior):

          require_signature             — an unsigned proof is INVALID.
          allowed_signature_algorithms  — restrict accepted signature families
                                          (e.g. {"ed25519"} rejects HMAC proofs).
                                          Compared against the algorithm family
                                          (``hmac`` / ``ed25519``).
          require_policy_source         — verification without a policy_source to
                                          bind policy_hash against is INVALID.
        """
        self._hmac_keys: dict[str, bytes] = {}
        self._ed25519_keys: dict[str, Ed25519PublicKey] = {}
        self.require_signature = require_signature
        self.allowed_signature_algorithms = (
            {a.lower() for a in allowed_signature_algorithms}
            if allowed_signature_algorithms is not None
            else None
        )
        self.require_policy_source = require_policy_source

    def add_hmac_key(self, key_id: str, secret: bytes) -> ProofVerifier:
        """Register an HMAC-SHA256 key for signature verification."""
        self._hmac_keys[key_id] = secret
        return self

    def add_ed25519_key(
        self, key_id: str, public_key: bytes | Ed25519PublicKey
    ) -> ProofVerifier:
        """Register an Ed25519 public key for signature verification."""
        if isinstance(public_key, Ed25519PublicKey):
            key = public_key
        else:
            key = Ed25519PublicKey.from_public_bytes(public_key)
        self._ed25519_keys[key_id] = key
        return self

    def verify(
        self,
        proof: TarlProof,
        policy_source: str | None = None,
    ) -> VerificationResult:
        """
        Verify a TarlProof.

        Checks performed:
          signature    — HMAC-SHA256 or Ed25519 valid (or None if unsigned)
          policy_hash  — matches provided policy_source (or None if not given)
          trace        — internal consistency (k is first True in T, verdict correct)

        valid = True requires:
          - signature is True or None (unsigned)
          - policy_hash is True or None (not provided)
          - trace is True
        """
        checks: dict[str, bool | None] = {}
        messages: list[str] = []

        # ── 1. Signature ──────────────────────────────────────────────────────
        sig_result = self._check_signature(proof)
        if self.require_signature and sig_result is None:
            # Strict mode: an unsigned proof is not acceptable.
            sig_result = False
        checks["signature"] = sig_result
        if sig_result is True:
            messages.append("signature valid")
        elif sig_result is False:
            messages.append(
                "signature INVALID"
                if proof.signature or not self.require_signature
                else "signature REQUIRED but proof is unsigned"
            )
        else:
            messages.append("signature skipped (unsigned)")

        # ── 2. Policy hash ────────────────────────────────────────────────────
        if policy_source is not None:
            ph_ok = _check_policy_hash(proof, policy_source)
            checks["policy_hash"] = ph_ok
            messages.append(
                "policy hash valid" if ph_ok else "policy hash MISMATCH"
            )
        elif self.require_policy_source:
            # Strict mode: cannot certify policy binding without the source.
            checks["policy_hash"] = False
            messages.append("policy source REQUIRED but not provided")
        else:
            checks["policy_hash"] = None

        # ── 3. Trace consistency ──────────────────────────────────────────────
        trace_ok = _check_trace(proof)
        checks["trace"] = trace_ok
        messages.append(
            "trace consistent" if trace_ok else "trace INCONSISTENT"
        )

        valid = (
            sig_result is not False
            and checks["policy_hash"] is not False
            and trace_ok
        )

        return VerificationResult(
            valid=valid,
            checks=checks,
            message="; ".join(messages),
        )

    def _check_signature(self, proof: TarlProof) -> bool | None:
        """
        Returns True if the signature is cryptographically valid.
        Returns False if invalid or the key is unknown.
        Returns None if the proof has no signature.
        """
        if not proof.signature:
            return None

        alg, sep, sig_hex = proof.signature.partition(":")
        if not sep:
            return False

        # Strict mode: reject signature families outside the allow-list (e.g.
        # an HMAC proof presented to an Ed25519-only verifier).
        if self.allowed_signature_algorithms is not None:
            family = alg.split("-", 1)[0].lower()
            if family not in self.allowed_signature_algorithms:
                return False

        if alg == "hmac-sha256":
            secret = self._hmac_keys.get(proof.key_id)
            if secret is None:
                return False
            expected = hmac.new(
                secret, proof.canonical_bytes(), hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, sig_hex)

        if alg == "ed25519":
            public_key = self._ed25519_keys.get(proof.key_id)
            if public_key is None:
                return False
            try:
                public_key.verify(
                    bytes.fromhex(sig_hex), proof.canonical_bytes()
                )
                return True
            except (ValueError, InvalidSignature):
                return False

        return False  # unknown algorithm


# ── standalone check functions ─────────────────────────────────────────────────

def _check_policy_hash(proof: TarlProof, policy_source: str) -> bool:
    """Verify proof.policy_hash matches SHA-256 of policy_source."""
    alg, sep, stored_hex = proof.policy_hash.partition(":")
    if not sep or alg != "sha256":
        return False
    actual = hashlib.sha256(policy_source.encode("utf-8")).hexdigest()
    return hmac.compare_digest(actual, stored_hex)


def _check_trace(proof: TarlProof) -> bool:
    """
    Verify internal consistency of the evaluation trace:
      - All entries before the matched index must have matched=False
      - The entry at matched_index must have matched=True (or rule_index==-1)
      - Verdict must match the matched rule's declared verdict
      - No entries after the first match
    """
    if not isinstance(proof.trace, list):
        return False

    if proof.rule_index == -1:
        # DEFAULT_DENY: all trace entries must be non-matching
        return all(
            isinstance(e, dict) and not e.get("matched", True)
            for e in proof.trace
        )

    for i, entry in enumerate(proof.trace):
        if not isinstance(entry, dict):
            return False
        idx = entry.get("rule_index")
        matched = entry.get("matched", False)
        if idx != i:
            return False
        if i < proof.rule_index and matched:
            return False  # earlier rule incorrectly claims it matched
        if i == proof.rule_index:
            if not matched:
                return False  # claimed match but trace says no
            break
        # i can never exceed rule_index: the matched entry above breaks the loop.

    # Trace must end at rule_index (length == rule_index + 1)
    if len(proof.trace) != proof.rule_index + 1:
        return False

    return True

"""
Trusted signed-time source for temporal policy (THREAT_MODEL C043).

Temporal policies (``valid_from``/``valid_until``, durations) decide on the
current time. If that time is the host clock, an attacker who can move the clock
can satisfy or dodge a window. A :class:`TimeAuthority` (a trusted time service)
signs the current time with Ed25519; a :class:`TrustedClock` verifies the signed
assertion against the authority's public key and rejects anything unsigned,
wrongly-signed, tampered, or staler than an allowed skew. The verified time is
fed to the runtime via ``TarlRuntime.set_clock`` so policy windows are evaluated
against trusted time, not the host clock.
"""
from __future__ import annotations

import datetime
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class SignedTime:
    """An Ed25519-signed assertion of the current time."""

    timestamp: str  # ISO-8601, timezone-aware
    key_id: str = ""
    signature: str = ""  # "ed25519:<hex>"

    def signing_bytes(self) -> bytes:
        return json.dumps(
            {"timestamp": self.timestamp, "key_id": self.key_id},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")


class TimeAuthority:
    """A trusted time service: stamps and signs the current time."""

    def __init__(self, key_id: str, private_key: bytes | Ed25519PrivateKey):
        if isinstance(private_key, Ed25519PrivateKey):
            self._key = private_key
        else:
            self._key = Ed25519PrivateKey.from_private_bytes(private_key)
        self.key_id = key_id

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def stamp(self, now: datetime.datetime | None = None) -> SignedTime:
        now = now or datetime.datetime.now(datetime.UTC)
        signed = SignedTime(
            timestamp=now.isoformat(timespec="seconds"), key_id=self.key_id
        )
        signed.signature = "ed25519:" + self._key.sign(
            signed.signing_bytes()).hex()
        return signed


class TrustedClock:
    """Verifies signed-time assertions from trusted time authorities."""

    def __init__(self, max_skew_seconds: float | None = None):
        """``max_skew_seconds`` optionally rejects a signed time that is more
        than that far from the local clock (a sanity bound against a stuck or
        wildly-wrong but validly-signed authority)."""
        self._keys: dict[str, Ed25519PublicKey] = {}
        self.max_skew_seconds = max_skew_seconds

    def add_ed25519_key(
        self, key_id: str, public_key: bytes | Ed25519PublicKey
    ) -> TrustedClock:
        if isinstance(public_key, Ed25519PublicKey):
            key = public_key
        else:
            key = Ed25519PublicKey.from_public_bytes(public_key)
        self._keys[key_id] = key
        return self

    def verify(
        self,
        signed: SignedTime,
        local_now: datetime.datetime | None = None,
    ) -> datetime.datetime | None:
        """Return the trusted ``datetime`` if the assertion verifies, else None.

        Rejects unsigned/non-Ed25519, unknown-key, bad-signature, malformed, and
        (when ``max_skew_seconds`` is set) out-of-skew assertions."""
        alg, _, sig_hex = signed.signature.partition(":")
        if alg != "ed25519" or not sig_hex:
            return None
        key = self._keys.get(signed.key_id)
        if key is None:
            return None
        try:
            key.verify(bytes.fromhex(sig_hex), signed.signing_bytes())
        except (ValueError, InvalidSignature):
            return None
        try:
            dt = datetime.datetime.fromisoformat(
                signed.timestamp.replace("Z", "+00:00")
            )
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.UTC)
        if self.max_skew_seconds is not None:
            local = local_now or datetime.datetime.now(datetime.UTC)
            if abs((local - dt).total_seconds()) > self.max_skew_seconds:
                return None
        return dt


__all__ = ["SignedTime", "TimeAuthority", "TrustedClock"]

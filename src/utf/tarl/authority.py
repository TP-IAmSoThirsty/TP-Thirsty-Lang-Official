"""
Authenticated authority provenance for governed execution.

A bare authority *string* (e.g. ``--authority admin``) is a self-asserted
identity: it identifies who *claims* to be acting, but proves nothing. In
hardened mode it grants no elevated authority on its own.

An :class:`AuthorityClaim` is an Ed25519-signed assertion minted by a trusted
issuer (an identity provider) that binds a ``subject``, a set of ``grants``, and
a validity window. The runtime verifies the claim against trusted issuer public
keys via :class:`AuthorityVerifier` before binding the verified identity into the
governance context. This closes threat-model challenges C027 (authority forged by
passing ``--authority admin``) and C028 (authority asserted from the environment):
authority must come from an authenticated, signed credential, never from a string
or an env var alone.

The governance context exposes:

  authority                — the subject string (compat with existing policies)
  authority_subject        — same subject, explicit
  authority_authenticated  — bool: was a valid signed claim presented?
  authority_grants         — list[str] of grants from a verified claim ([] otherwise)

so policies can require ``authority_authenticated == true`` and gate on grants.
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
class AuthorityClaim:
    """A (possibly signed) assertion of identity and grants.

    Unsigned by construction; an :class:`AuthorityIssuer` signs it. ``grants`` is
    a free-form set of capability/role tokens the issuer vouches for.
    """

    subject: str
    grants: tuple[str, ...] = ()
    issued_at: str = ""
    expires_at: str | None = None
    key_id: str = ""
    signature: str = ""  # "ed25519:<hex>"

    def signing_bytes(self) -> bytes:
        """Canonical bytes covered by the signature (excludes the signature)."""
        payload = {
            "subject": self.subject,
            "grants": list(self.grants),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "grants": list(self.grants),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> AuthorityClaim:
        return cls(
            subject=d["subject"],
            grants=tuple(d.get("grants", [])),
            issued_at=d.get("issued_at", ""),
            expires_at=d.get("expires_at"),
            key_id=d.get("key_id", ""),
            signature=d.get("signature", ""),
        )

    @classmethod
    def from_json(cls, s: str) -> AuthorityClaim:
        return cls.from_dict(json.loads(s))


@dataclass(frozen=True)
class VerifiedAuthority:
    """The result of resolving an authority for a governed run.

    ``authenticated`` is True only when a valid signed claim was verified against
    a trusted issuer key. An unauthenticated authority still carries a subject
    (for logging/policy) but no grants and no authenticity.
    """

    subject: str
    grants: tuple[str, ...] = ()
    authenticated: bool = True

    def has_grant(self, grant: str) -> bool:
        return grant in self.grants

    @classmethod
    def unauthenticated(cls, subject: str) -> VerifiedAuthority:
        return cls(subject=subject, grants=(), authenticated=False)

    def context(self) -> dict:
        """Authority fields to merge into a governance evaluation context."""
        return {
            "authority": self.subject,
            "authority_subject": self.subject,
            "authority_authenticated": self.authenticated,
            "authority_grants": list(self.grants),
        }


class AuthorityIssuer:
    """Mints Ed25519-signed :class:`AuthorityClaim` credentials.

    Held by a trusted identity provider, never by the executing program. Tests
    and local operators can construct one from a raw 32-byte seed.
    """

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

    def issue(
        self,
        subject: str,
        grants: tuple[str, ...] | list[str] = (),
        ttl_seconds: int | None = None,
        now: datetime.datetime | None = None,
    ) -> AuthorityClaim:
        now = now or datetime.datetime.now(datetime.UTC)
        issued_at = now.isoformat(timespec="seconds")
        expires_at = None
        if ttl_seconds is not None:
            expires_at = (
                now + datetime.timedelta(seconds=ttl_seconds)
            ).isoformat(timespec="seconds")
        claim = AuthorityClaim(
            subject=subject,
            grants=tuple(grants),
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=self.key_id,
        )
        claim.signature = "ed25519:" + self._key.sign(
            claim.signing_bytes()
        ).hex()
        return claim


@dataclass
class AuthorityVerificationResult:
    """Outcome of verifying a claim — carries a reason on failure."""

    authority: VerifiedAuthority | None
    valid: bool
    reason: str = ""


class AuthorityVerifier:
    """Verifies :class:`AuthorityClaim` credentials against trusted issuer keys.

    Only Ed25519 is accepted — authority is a non-repudiation decision, so a
    symmetric MAC (forgeable by any holder) is never sufficient.
    """

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add_ed25519_key(
        self, key_id: str, public_key: bytes | Ed25519PublicKey
    ) -> AuthorityVerifier:
        if isinstance(public_key, Ed25519PublicKey):
            key = public_key
        else:
            key = Ed25519PublicKey.from_public_bytes(public_key)
        self._keys[key_id] = key
        return self

    def verify(
        self,
        claim: AuthorityClaim,
        now: datetime.datetime | None = None,
    ) -> AuthorityVerificationResult:
        alg, _, sig_hex = claim.signature.partition(":")
        if alg != "ed25519" or not sig_hex:
            return AuthorityVerificationResult(
                None, False, "authority claim is unsigned or not Ed25519"
            )
        key = self._keys.get(claim.key_id)
        if key is None:
            return AuthorityVerificationResult(
                None, False, f"unknown issuer key_id {claim.key_id!r}"
            )
        try:
            key.verify(bytes.fromhex(sig_hex), claim.signing_bytes())
        except (ValueError, InvalidSignature):
            return AuthorityVerificationResult(
                None, False, "authority signature is invalid"
            )
        if claim.expires_at:
            now = now or datetime.datetime.now(datetime.UTC)
            try:
                exp = datetime.datetime.fromisoformat(claim.expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=datetime.UTC)
                if now > exp:
                    return AuthorityVerificationResult(
                        None, False, "authority claim has expired"
                    )
            except ValueError:
                return AuthorityVerificationResult(
                    None, False, "authority claim has a malformed expiry"
                )
        return AuthorityVerificationResult(
            VerifiedAuthority(
                subject=claim.subject,
                grants=claim.grants,
                authenticated=True,
            ),
            True,
            "ok",
        )


__all__ = [
    "AuthorityClaim",
    "VerifiedAuthority",
    "AuthorityIssuer",
    "AuthorityVerifier",
    "AuthorityVerificationResult",
]

"""
Deployment key management for the T.A.R.L. trust roots.

A hardened deployment depends on three Ed25519 trust roots — the **authority
issuer** (signs authority claims), the **proof signer** (signs decision proofs),
and the **time authority** (signs trusted time). Before this module those keys
existed only as raw 32-byte seeds passed as hex on the command line: there was
no generation tool, no on-disk format, and no rotation story, and a hex seed on
an argv line is exposed to anything that can read the process table.

This module defines:

  * a versioned on-disk key format (:class:`KeyFile`) — JSON with ``key_id``,
    ``alg``, ``role``, ``created_at``, ``public_key`` and (for a private file)
    ``private_key``; private files are written ``0600``;
  * :func:`generate` to mint a keypair, and :meth:`KeyFile.write` /
    :func:`load` to persist and read it back;
  * accessors that hand back ``cryptography`` key objects for the issuer,
    runtime, and clock APIs.

Rotation is operational, not cryptographic: mint a new key with a fresh
``key_id``, register its public half alongside the old one (verifier registries
are keyed by ``key_id``, so both validate in-flight artifacts), then switch
signing to the new key. See ``docs/PRODUCTION_DEPLOYMENT.md``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

KEY_FORMAT = "tarl-key/v1"

# The three trust roots a hardened deployment must provision.
ROLE_AUTHORITY_ISSUER = "authority-issuer"
ROLE_PROOF_SIGNER = "proof-signer"
ROLE_TIME_AUTHORITY = "time-authority"
ROLES = (ROLE_AUTHORITY_ISSUER, ROLE_PROOF_SIGNER, ROLE_TIME_AUTHORITY)


@dataclass
class KeyFile:
    """A trust-root key, optionally including its private half.

    ``private_key_hex`` is empty for a public-only file (safe to distribute to
    verifiers); a private file carries both halves and must stay ``0600``."""

    key_id: str
    role: str
    public_key_hex: str
    private_key_hex: str = ""
    created_at: str = ""

    @property
    def has_private(self) -> bool:
        return bool(self.private_key_hex)

    def public_bytes(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)

    def private_bytes(self) -> bytes:
        if not self.private_key_hex:
            raise ValueError(
                f"key {self.key_id!r} is public-only; no private key")
        return bytes.fromhex(self.private_key_hex)

    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_bytes())

    def private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.private_bytes())

    def public_only(self) -> KeyFile:
        """A copy without the private half, for distribution to verifiers."""
        return KeyFile(
            key_id=self.key_id, role=self.role,
            public_key_hex=self.public_key_hex, private_key_hex="",
            created_at=self.created_at)

    def to_dict(self, include_private: bool = False) -> dict:
        d = {
            "format": KEY_FORMAT,
            "key_id": self.key_id,
            "alg": "ed25519",
            "role": self.role,
            "created_at": self.created_at,
            "public_key": self.public_key_hex,
        }
        if include_private and self.private_key_hex:
            d["private_key"] = self.private_key_hex
        return d

    def write(self, path: str, include_private: bool = False) -> None:
        """Write this key to ``path`` as JSON. A file that includes the private
        half is created ``0600`` so only the owner can read it."""
        data = json.dumps(self.to_dict(include_private), indent=2)
        # Create private files with restrictive permissions from the start.
        if include_private and self.private_key_hex:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(path, flags, 0o600)
            try:
                os.write(fd, (data + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass  # best-effort on platforms without POSIX modes
        else:
            with open(path, "w") as f:
                f.write(data + "\n")


def generate(key_id: str, role: str) -> KeyFile:
    """Mint a fresh Ed25519 keypair for ``role`` under ``key_id``."""
    if role not in ROLES:
        raise ValueError(f"unknown key role {role!r}; expected one of {ROLES}")
    private = Ed25519PrivateKey.generate()
    private_hex = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    public_hex = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return KeyFile(
        key_id=key_id, role=role, public_key_hex=public_hex,
        private_key_hex=private_hex,
        created_at=datetime.now(UTC).isoformat(timespec="seconds"))


def load(path: str) -> KeyFile:
    """Load a :class:`KeyFile` written by :meth:`KeyFile.write`."""
    with open(path) as f:
        data = json.load(f)
    fmt = data.get("format")
    if fmt != KEY_FORMAT:
        raise ValueError(
            f"{path}: unsupported key format {fmt!r} (expected {KEY_FORMAT})")
    if data.get("alg") != "ed25519":
        raise ValueError(f"{path}: unsupported alg {data.get('alg')!r}")
    public_hex = data.get("public_key", "")
    if not public_hex:
        raise ValueError(f"{path}: missing public_key")
    return KeyFile(
        key_id=data.get("key_id", ""),
        role=data.get("role", ""),
        public_key_hex=public_hex,
        private_key_hex=data.get("private_key", ""),
        created_at=data.get("created_at", ""))


__all__ = [
    "KEY_FORMAT",
    "ROLE_AUTHORITY_ISSUER",
    "ROLE_PROOF_SIGNER",
    "ROLE_TIME_AUTHORITY",
    "ROLES",
    "KeyFile",
    "generate",
    "load",
]

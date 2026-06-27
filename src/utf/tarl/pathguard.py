"""
Filesystem path confinement for governed file capabilities (THREAT_MODEL C042).

A policy may allow filesystem access, but the *target* path is attacker-influenced.
Two escapes matter:

  * **Traversal** — ``../../etc/passwd`` walks out of an allowed root.
  * **Symlink** — a path inside the root is a symlink whose real target is
    outside it.

:class:`PathGuard` resolves a path to its real (symlink-followed, normalized)
location and confines it to one or more allowed roots. Confinement is decided on
the **canonical** path, so neither traversal nor a symlink can escape. Adapters
check a path *before* opening it and deny on escape.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def canonical_path(path: str) -> str:
    """Absolute, symlink-resolved, normalized form of ``path``."""
    return os.path.realpath(os.path.abspath(path))


def is_within_root(path: str, root: str) -> bool:
    """True iff the canonical ``path`` is inside the canonical ``root``.

    Comparison is path-component aware (so ``/srv/data`` does not match
    ``/srv/data-evil``) and follows symlinks on both sides."""
    real = canonical_path(path)
    real_root = canonical_path(root)
    try:
        return os.path.commonpath([real, real_root]) == real_root
    except ValueError:
        # Different drives / mount roots (e.g. Windows C: vs D:) — not within.
        return False


@dataclass
class PathCheck:
    """Result of confining a path to the allowed roots."""

    ok: bool
    canonical: str
    reason: str = ""


class PathGuard:
    """Confines filesystem paths to a set of allowed roots (canonicalized)."""

    def __init__(self, roots: list[str] | tuple[str, ...]):
        if not roots:
            raise ValueError("PathGuard requires at least one allowed root")
        self._roots = [canonical_path(r) for r in roots]

    def check(self, path: str) -> PathCheck:
        real = canonical_path(path)
        for root in self._roots:
            try:
                if os.path.commonpath([real, root]) == root:
                    return PathCheck(True, real)
            except ValueError:
                continue
        return PathCheck(
            False, real,
            f"path {real!r} escapes the allowed root(s) "
            f"{', '.join(map(repr, self._roots))}",
        )


__all__ = ["PathGuard", "PathCheck", "canonical_path", "is_within_root"]

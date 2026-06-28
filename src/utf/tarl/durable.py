"""
Durable, cross-process governance state for production deployments.

``ReplayGuard`` (single-use enforcement) and the policy-revocation set are
correct in-process but, by default, in-memory: a proof replayed in a *second*
process, or after a restart, would be accepted because the first process's
state is gone. For a hardened deployment that spans workers/restarts, that
state must be durable and shared.

This module provides SQLite-backed equivalents that share the archive's storage
discipline (a single file, an internal lock, safe concurrent access):

  * :class:`DurableReplayGuard` — a :class:`~utf.tarl.verifier.ReplayGuard` whose
    seen-set lives in SQLite, so a replay is rejected across processes and
    restarts. Drop-in for ``ProofVerifier(replay_guard=...)``.
  * :class:`RevocationStore` — a durable set of revoked policy hashes that a
    verifier hydrates (``ProofVerifier(revoked_policy_hashes=store.all())``) and
    that the ``tarl revoke`` CLI manages.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime

from utf.tarl.spec import TarlProof
from utf.tarl.verifier import ReplayGuard


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class _SqliteBacked:
    """Shared SQLite lifecycle: lazy connect, internal lock, context manager."""

    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self._path, check_same_thread=False)
        return self._conn

    def _ensure_schema(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *_) -> None:
        self.close()


class DurableReplayGuard(_SqliteBacked, ReplayGuard):
    """A :class:`~utf.tarl.verifier.ReplayGuard` backed by SQLite.

    The seen-proof set is persisted, so a proof accepted by one process is
    rejected as a replay by any other process (or after a restart) pointed at
    the same database. The proof identity is unchanged
    (``context_hash|evaluated_at|signature``)."""

    def __init__(self, db_path: str = "tarl_replay.db") -> None:
        _SqliteBacked.__init__(self, db_path)

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS seen_proofs (
                    proof_id    TEXT PRIMARY KEY,
                    recorded_at TEXT NOT NULL
                );
            """)
            conn.commit()

    def check_and_record(self, proof: TarlProof) -> bool:
        """Return True the first time this proof is seen (across all processes
        sharing the database), False on every reuse."""
        pid = self.proof_id(proof)
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "INSERT OR IGNORE INTO seen_proofs (proof_id, recorded_at) "
                "VALUES (?, ?)", (pid, _now_iso()))
            conn.commit()
            # rowcount == 1 means a fresh insert; 0 means the id already existed.
            return cur.rowcount == 1


class RevocationStore(_SqliteBacked):
    """A durable set of revoked policy hashes (policy revocation; C024).

    A verifier is hydrated from this store at construction
    (``ProofVerifier(revoked_policy_hashes=store.all())``); the ``tarl revoke``
    CLI adds/removes/lists entries between runs."""

    def __init__(self, db_path: str = "tarl_revocations.db") -> None:
        _SqliteBacked.__init__(self, db_path)

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS revoked_policies (
                    policy_hash TEXT PRIMARY KEY,
                    revoked_at  TEXT NOT NULL,
                    reason      TEXT
                );
            """)
            conn.commit()

    def add(self, policy_hash: str, reason: str = "") -> bool:
        """Revoke ``policy_hash``. Returns True if newly added, False if it was
        already revoked."""
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "INSERT OR IGNORE INTO revoked_policies "
                "(policy_hash, revoked_at, reason) VALUES (?, ?, ?)",
                (policy_hash, _now_iso(), reason))
            conn.commit()
            return cur.rowcount == 1

    def remove(self, policy_hash: str) -> bool:
        """Un-revoke ``policy_hash``. Returns True if it was present."""
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "DELETE FROM revoked_policies WHERE policy_hash = ?",
                (policy_hash,))
            conn.commit()
            return cur.rowcount > 0

    def all(self) -> set[str]:
        """All currently revoked policy hashes."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT policy_hash FROM revoked_policies").fetchall()
        return {str(r[0]) for r in rows}

    def entries(self) -> list[tuple[str, str, str]]:
        """``(policy_hash, revoked_at, reason)`` for every revocation."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT policy_hash, revoked_at, reason FROM revoked_policies "
                "ORDER BY revoked_at").fetchall()
        return [(str(h), str(t), str(r or "")) for h, t, r in rows]

    def __contains__(self, policy_hash: str) -> bool:
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT 1 FROM revoked_policies WHERE policy_hash = ?",
                (policy_hash,)).fetchone()
        return row is not None


__all__ = ["DurableReplayGuard", "RevocationStore"]

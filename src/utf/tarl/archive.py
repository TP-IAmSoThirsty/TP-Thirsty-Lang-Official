"""
T.A.R.L. Temporal Audit Archive — Phase 5

Append-only, thread-safe SQLite store for TarlProof certificates.
Supports querying by verdict and time window.

Usage::

    with TarlAuditArchive("tarl_audit.db") as arc:
        arc.store(proof, expires_at=decision.expires_at)
        for p in arc.query(verdict="DENY", from_dt="2026-01-01"):
            print(p.to_json())
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass

from utf.tarl.spec import TarlProof

# Genesis link for the per-archive hash chain (prev_hash of the first record).
_GENESIS = "sha256:" + hashlib.sha256(b"TARL-AUDIT-GENESIS").hexdigest()


def _entry_hash(prev_hash: str, proof_json: str) -> str:
    """Chain link: binds this record to its predecessor and its exact contents."""
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\x00")
    h.update(proof_json.encode("utf-8"))
    return "sha256:" + h.hexdigest()


@dataclass
class ChainVerification:
    """Result of walking the archive's hash chain end to end."""

    valid: bool
    length: int
    broken_at: int | None = None  # row id where the chain first breaks
    reason: str = ""

    def __str__(self) -> str:
        status = "INTACT" if self.valid else "BROKEN"
        tail = "" if self.valid else f" at row {self.broken_at}: {self.reason}"
        return f"[{status}] audit chain, {self.length} record(s){tail}"


class TarlAuditArchive:
    """
    Append-only audit log of TarlProof certificates backed by SQLite.

    Thread-safe: concurrent stores and queries are serialised by an
    internal lock.  Use the context-manager form to ensure the connection
    is closed properly::

        with TarlAuditArchive("tarl_audit.db") as archive:
            archive.store(proof)

    Or manage the lifecycle manually with :meth:`close`.
    """

    def __init__(self, db_path: str = "tarl_audit.db") -> None:
        self._path = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._ensure_schema()

    # ── Schema ────────────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self._path, check_same_thread=False
            )
        return self._conn

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS proofs (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_hash   TEXT    NOT NULL,
                    context_hash  TEXT    NOT NULL,
                    verdict       TEXT    NOT NULL,
                    rule_index    INTEGER NOT NULL,
                    evaluated_at  TEXT    NOT NULL,
                    expires_at    TEXT,
                    signature     TEXT,
                    proof_json    TEXT    NOT NULL,
                    prev_hash     TEXT,
                    entry_hash    TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_verdict
                    ON proofs (verdict);
                CREATE INDEX IF NOT EXISTS idx_evaluated_at
                    ON proofs (evaluated_at);
            """)
            # Migrate older archives that predate the hash chain.
            existing = {r[1] for r in conn.execute(
                "PRAGMA table_info(proofs)").fetchall()}
            for col in ("prev_hash", "entry_hash"):
                if col not in existing:
                    conn.execute(f"ALTER TABLE proofs ADD COLUMN {col} TEXT")
            conn.commit()

    # ── Write ─────────────────────────────────────────────────────────────────

    def store(
        self,
        proof: TarlProof,
        expires_at: str | None = None,
    ) -> int:
        """
        Persist a proof in the archive.

        :param proof:       The TarlProof to store.
        :param expires_at:  Optional ISO-8601 UTC expiry from TarlDecision.expires_at.
        :returns:           Row id of the inserted record.
        """
        proof_json = proof.to_json()
        with self._lock:
            conn = self._connect()
            # Link this record to the current chain head (genesis if empty).
            head = conn.execute(
                "SELECT entry_hash FROM proofs ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = head[0] if head and head[0] else _GENESIS
            entry_hash = _entry_hash(prev_hash, proof_json)
            cursor = conn.execute(
                """INSERT INTO proofs
                   (policy_hash, context_hash, verdict, rule_index,
                    evaluated_at, expires_at, signature, proof_json,
                    prev_hash, entry_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    proof.policy_hash,
                    proof.context_hash,
                    proof.verdict.value,
                    proof.rule_index,
                    proof.evaluated_at,
                    expires_at,
                    proof.signature or None,
                    proof_json,
                    prev_hash,
                    entry_hash,
                ),
            )
            conn.commit()
            # lastrowid is the new AUTOINCREMENT id after a successful INSERT;
            # it is only None if no row was inserted (never on this path).
            return cursor.lastrowid or 0

    # ── Read ──────────────────────────────────────────────────────────────────

    def query(
        self,
        verdict: str | None = None,
        from_dt: str | None = None,
        to_dt: str | None = None,
        limit: int = 100,
        verifier=None,
    ) -> list[TarlProof]:
        """
        Query stored proofs, newest first.

        :param verdict:   Filter by verdict ("ALLOW", "DENY", or "ESCALATE").
        :param from_dt:   ISO-8601 lower bound on evaluated_at (inclusive).
        :param to_dt:     ISO-8601 upper bound on evaluated_at (inclusive).
        :param limit:     Maximum number of results (default 100).
        :param verifier:  Optional ProofVerifier.  When supplied, proofs whose
                          signature check returns False (cryptographically
                          invalid) are excluded from results.  Unsigned proofs
                          (signature="") are kept; only actively invalid
                          signatures are rejected.  Without a verifier, rows
                          are returned as-is from SQLite with no tamper check
                          — callers that need tamper-evidence must pass one.
        :returns:         List of TarlProof objects.
        """
        conditions: list[str] = []
        params: list = []
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict.upper())
        if from_dt:
            conditions.append("evaluated_at >= ?")
            params.append(from_dt)
        if to_dt:
            conditions.append("evaluated_at <= ?")
            params.append(to_dt)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                f"SELECT proof_json FROM proofs {where} "
                f"ORDER BY evaluated_at DESC LIMIT ?",
                params,
            ).fetchall()
        proofs = [TarlProof.from_json(row[0]) for row in rows]
        if verifier is not None:
            proofs = [
                p for p in proofs
                if verifier.verify(p).checks.get("signature") is not False
            ]
        return proofs

    def count(
        self,
        verdict: str | None = None,
        from_dt: str | None = None,
        to_dt: str | None = None,
    ) -> int:
        """Count proofs matching the given filters."""
        conditions: list[str] = []
        params: list = []
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict.upper())
        if from_dt:
            conditions.append("evaluated_at >= ?")
            params.append(from_dt)
        if to_dt:
            conditions.append("evaluated_at <= ?")
            params.append(to_dt)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                f"SELECT COUNT(*) FROM proofs {where}", params
            ).fetchone()
        return int(row[0]) if row else 0

    # ── Tamper-evidence ───────────────────────────────────────────────────────

    def head_hash(self) -> str:
        """Return the current chain head (latest entry_hash), or genesis if empty.

        Persist this externally as a checkpoint: a later ``verify_chain`` whose
        head differs from a trusted checkpoint reveals suffix rewriting even if
        the chain re-links internally."""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT entry_hash FROM proofs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return str(row[0]) if row and row[0] else _GENESIS

    def verify_chain(
        self, expected_head: str | None = None
    ) -> ChainVerification:
        """Walk the hash chain in insertion order and report its integrity.

        Detects record tampering (a modified ``proof_json`` no longer hashes to
        its stored ``entry_hash``), deletion/reordering (a record's ``prev_hash``
        no longer matches its predecessor's ``entry_hash``), and a tampered head.

        ``expected_head`` is a trusted external checkpoint (see :meth:`head_hash`
        and ``tarl audit checkpoint``). A chain that re-links internally but
        whose head differs from the checkpoint reveals suffix rewriting or
        truncation — the case the internal walk alone cannot catch.
        """
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT id, proof_json, prev_hash, entry_hash "
                "FROM proofs ORDER BY id ASC"
            ).fetchall()
        prev = _GENESIS
        for row_id, proof_json, prev_hash, entry_hash in rows:
            if prev_hash != prev:
                return ChainVerification(
                    False, len(rows), row_id,
                    "prev_hash does not match the preceding record "
                    "(deletion, insertion, or reordering)")
            expected = _entry_hash(prev, proof_json)
            if entry_hash != expected:
                return ChainVerification(
                    False, len(rows), row_id,
                    "record contents do not match entry_hash (tampered)")
            prev = entry_hash
        if expected_head is not None and prev != expected_head:
            return ChainVerification(
                False, len(rows), None,
                f"chain head {prev!r} does not match the trusted checkpoint "
                f"{expected_head!r} (suffix rewrite or truncation)")
        return ChainVerification(True, len(rows))

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __enter__(self) -> TarlAuditArchive:
        return self

    def __exit__(self, *_) -> None:
        self.close()

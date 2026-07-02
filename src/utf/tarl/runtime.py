"""
T.A.R.L. Runtime — LRU-cached, parallel policy evaluation.

Phase 2: register_source(name, provider) — bind a live data provider to
         source:name references in policy conditions.
Phase 4: evaluate_with_proof() — evaluate and return a TarlProof alongside
         the TarlDecision. The proof is unsigned unless a signing key is
         registered; HMAC-SHA256 is retained for compatibility, and Ed25519 is
         available for non-repudiable asymmetric signatures.
"""
import datetime
import hashlib
import hmac
import json
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from utf.tarl.core import PolicyParser, SafeExpr, _check_policy_temporal
from utf.tarl.spec import (
    DEFAULT_DENY,
    TarlDecision,
    TarlPolicy,
    TarlProof,
    TarlRule,
    TarlVerdict,
)


def _is_temporally_constrained(policy: TarlPolicy) -> bool:
    """Return True if the policy has any temporal constraints that make caching unsafe."""
    if policy.valid_from or policy.valid_until or policy.if_unresolved_after:
        return True
    return any(r.duration_seconds for r in policy.rules)


class LRUCache:
    """Simple LRU cache with maximum size."""

    def __init__(self, maxsize: int = 128):
        self.maxsize = maxsize
        self._cache: OrderedDict[str, TarlDecision] = OrderedDict()

    def get(self, key: str) -> TarlDecision | None:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def put(self, key: str, value: TarlDecision):
        self._cache[key] = value
        self._cache.move_to_end(key)
        if len(self._cache) > self.maxsize:
            self._cache.popitem(last=False)

    def invalidate(self, key: str):
        self._cache.pop(key, None)

    def clear(self):
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


class TarlRuntime:
    """
    TARL policy runtime:
    - LRU decision cache (128 entries)
    - ThreadPoolExecutor for parallel rule evaluation
    - Adaptive ordering (most-frequently-matched rules evaluated first)
    - Dynamic source registry for source:name condition references
    """

    def __init__(
        self,
        policy: TarlPolicy | None = None,
        max_workers: int = 4,
    ):
        self.policy = policy or TarlPolicy()
        self.cache = LRUCache(maxsize=128)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._hit_counts: dict = {}
        self._throw_counts: dict = {}   # rule_index -> number of evaluation exceptions
        self._sources: dict = {}
        self._signing_keys: dict = {}   # key_id -> bytes (HMAC secrets)
        self._ed25519_signing_keys: dict = {}  # key_id -> Ed25519PrivateKey
        self._signing_key_id: str = ""  # active key
        self._signing_alg: str = ""     # "hmac-sha256" or "ed25519"
        self._archive = None            # TarlAuditArchive | None
        self._context_schema = None     # ContextSchema | None
        self._require_audit = False     # fail closed if audit cannot persist
        # Trusted time source for temporal checks; None => host clock.
        self._clock: Callable[[], datetime.datetime | None] | None = None

    def set_clock(self, clock) -> "TarlRuntime":
        """Use a trusted time source for temporal-policy checks instead of the
        host clock. ``clock`` is a zero-arg callable returning a timezone-aware
        ``datetime`` (typically obtained by verifying a signed-time assertion via
        ``utf.tarl.clock.TrustedClock``). A spoofed system clock then cannot
        satisfy a temporal window (C043). Returns self."""
        self._clock = clock
        return self

    def _now(self):
        return self._clock() if self._clock is not None else None

    def set_require_audit(self, required: bool = True) -> "TarlRuntime":
        """When True and an audit archive is attached, a failure to persist a
        proof downgrades the decision to a fail-closed DENY (C038): execution
        cannot proceed if the required audit record could not be written."""
        self._require_audit = required
        return self

    def _persist(
        self,
        policy: TarlPolicy,
        ctx: dict,
        decision: TarlDecision,
        proof: TarlProof,
    ) -> tuple[TarlDecision, TarlProof]:
        """Store the proof; on a persistence failure, fail closed when audit is
        required. Returns the (possibly downgraded) ``(decision, proof)``."""
        if self._archive is None:
            return decision, proof
        try:
            self._archive.store(proof, expires_at=decision.expires_at)
            return decision, proof
        except Exception as exc:  # disk full, DoS on the audit sink, etc.
            if not self._require_audit:
                return decision, proof
            denied = TarlDecision(
                verdict=TarlVerdict.DENY,
                reason=f"fail-closed: required audit could not be persisted: {exc}",
            )
            denied_proof = self._generate_proof(
                policy, ctx, denied, -1,
                [{"kind": "audit-fail", "matched": False, "reason": str(exc)}])
            return denied, denied_proof

    # ── Context schema ────────────────────────────────────────────────────────

    def set_context_schema(self, schema) -> "TarlRuntime":
        """Attach a ``utf.tarl.schema.ContextSchema``. When set, every context is
        validated before any rule runs; a missing required field or a
        type-confused value short-circuits to the schema's fail-closed verdict
        (DENY by default) instead of silently matching a permissive later rule.
        Returns self for chaining."""
        self._context_schema = schema
        return self

    def _schema_decision(self, context: dict) -> "TarlDecision | None":
        """Return a fail-closed decision when ``context`` violates the schema,
        else None."""
        if self._context_schema is None:
            return None
        violations = self._context_schema.validate(context)
        if not violations:
            return None
        return TarlDecision(
            verdict=self._context_schema.on_violation,
            reason="context schema violation: " + "; ".join(violations),
        )

    # ── Audit archive ─────────────────────────────────────────────────────────

    def set_archive(self, archive) -> "TarlRuntime":
        """
        Attach a TarlAuditArchive.  Proofs generated by evaluate_with_proof()
        are stored automatically.  Returns self for chaining.
        """
        self._archive = archive
        return self

    # ── Signing key registry ──────────────────────────────────────────────────

    def set_signing_key(
        self, key_id: str, secret: bytes
    ) -> "TarlRuntime":
        """
        Register an HMAC-SHA256 signing key for proof generation.
        The most recently set key becomes the active key.
        Returns self for chaining.
        """
        self._signing_keys[key_id] = secret
        self._signing_key_id = key_id
        self._signing_alg = "hmac-sha256"
        return self

    def set_ed25519_signing_key(
        self, key_id: str, private_key: bytes | Ed25519PrivateKey
    ) -> "TarlRuntime":
        """
        Register an Ed25519 private key for proof generation.

        ``private_key`` may be a cryptography Ed25519PrivateKey or the raw
        32-byte private seed accepted by Ed25519PrivateKey.from_private_bytes().
        The most recently set key becomes the active key.
        """
        if isinstance(private_key, Ed25519PrivateKey):
            key = private_key
        else:
            key = Ed25519PrivateKey.from_private_bytes(private_key)
        self._ed25519_signing_keys[key_id] = key
        self._signing_key_id = key_id
        self._signing_alg = "ed25519"
        return self

    # ── Source registry ───────────────────────────────────────────────────────

    def register_source(
        self, name: str, provider
    ) -> "TarlRuntime":
        """
        Bind a data provider to source:<name> condition references.

        provider — a list/set (static) or a zero-arg callable that
                   returns a list/set each time it is called.
        Returns self for chaining.
        """
        self._sources[name] = provider
        return self

    def _inject_sources(self, context: dict) -> dict:
        """Resolve all registered sources and inject into a context copy."""
        if not self._sources:
            return context
        ctx = dict(context)
        for name, provider in self._sources.items():
            try:
                value = provider() if callable(provider) else provider
            except Exception:
                value = []
            ctx[f"source:{name}"] = value
        return ctx

    # ── Policy management ─────────────────────────────────────────────────────

    def throw_stats(self) -> dict:
        """
        Return throw counts per rule index.

        **What the number means:**
        Counts reflect distinct contexts that missed the cache and threw, not
        total call frequency.  A rule that throws on one bad context evaluated
        a thousand times shows throw_count == 1, not 1000, because cached
        results bypass rule evaluation entirely.  The stat answers "how many
        distinct inputs break this rule," not "how often throwing happens in
        production."  Do not use it to gauge live-traffic blast radius without
        accounting for cache hit rate.

        **Predicates:**
        - throw_count > 0 and hit_count == 0 → dead-by-exception: the rule
          has never matched cleanly and throws on every context seen so far.
        - throw_count > 0 and hit_count > 0 → partial-throw: the rule matches
          on some inputs but throws on others.  hit_count > 0 does not mean
          healthy; partial-throw is a distinct broken state.
        """
        return dict(self._throw_counts)

    def set_policy(self, new_policy: TarlPolicy):
        """Replace the active policy and reset the cache and hit counts."""
        self.policy = new_policy
        self.cache.clear()
        self._hit_counts = dict.fromkeys(range(len(new_policy.rules)), 0)
        self._throw_counts = {}

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        context: dict,
        policy_text: str | None = None,
    ) -> TarlDecision:
        """
        Evaluate the active policy (or policy_text if supplied) against
        context. Sources are resolved before evaluation. Returns the
        first matching rule's verdict, or DEFAULT_DENY.
        """
        ctx = self._inject_sources(context)

        # Context schema validation fails closed before any rule evaluation.
        schema_decision = self._schema_decision(ctx)
        if schema_decision is not None:
            return schema_decision

        cache_key = str(sorted(ctx.items()))

        if policy_text is not None:
            policy = PolicyParser.parse(policy_text)
        else:
            policy = self.policy

        # Phase 5: enforce temporal window before any rule evaluation
        temporal = _check_policy_temporal(policy, now=self._now())
        if temporal is not None:
            return temporal

        if not policy.rules:
            return DEFAULT_DENY

        # Policies with temporal constraints must not be cached — the window
        # check and expires_at timestamps would be stale on subsequent calls.
        use_cache = not _is_temporally_constrained(policy)

        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        ordered_indices = sorted(
            range(len(policy.rules)),
            key=lambda i: self._hit_counts.get(i, 0),
            reverse=True,
        )

        futures_by_idx = {}
        trusted_now = self._now()
        for idx in ordered_indices:
            rule = policy.rules[idx]
            future = self.executor.submit(
                self._evaluate_rule, rule, ctx, trusted_now
            )
            futures_by_idx[idx] = (future, rule)

        results = {}
        for idx, (future, rule) in futures_by_idx.items():
            try:
                matched, decision, threw = future.result()
                results[idx] = (matched, decision, rule, threw)
            except Exception:
                results[idx] = (
                    False,
                    TarlDecision(
                        verdict=TarlVerdict.DENY,
                        reason="Evaluation error",
                    ),
                    rule,
                    True,
                )

        # Iterate in POLICY ORDER (not hit-count order) to honour
        # first-match-wins semantics. Adaptive ordering affects which
        # futures are submitted first, not which result wins.
        for idx in range(len(policy.rules)):
            matched, decision, rule, threw = results[idx]
            if threw:
                self._throw_counts[idx] = (
                    self._throw_counts.get(idx, 0) + 1
                )
                return TarlDecision(
                    verdict=TarlVerdict.DENY,
                    reason=(
                        f"fail-closed: rule {idx} could not be evaluated: "
                        f"{decision.reason}"
                    ),
                    rule_index=idx,
                    matched_rule=str(rule),
                )
            if matched:
                self._hit_counts[idx] = (
                    self._hit_counts.get(idx, 0) + 1
                )
                expires_at = None
                if rule.duration_seconds:
                    expires_at = (
                        datetime.datetime.now(datetime.UTC)
                        + datetime.timedelta(seconds=rule.duration_seconds)
                    ).isoformat(timespec="seconds")
                result = TarlDecision(
                    verdict=decision.verdict,
                    reason=decision.reason or f"Rule matched: {rule}",
                    rule_index=idx,
                    matched_rule=str(rule),
                    expires_at=expires_at,
                )
                if use_cache:
                    self.cache.put(cache_key, result)
                return result

        if use_cache:
            self.cache.put(cache_key, DEFAULT_DENY)
        return DEFAULT_DENY

    def _evaluate_rule(
        self,
        rule: TarlRule,
        context: dict,
        now: datetime.datetime | None = None,
    ) -> tuple:
        """
        Evaluate one rule. Returns (matched: bool, TarlDecision, threw: bool).

        threw=True when the condition raised an exception.  The rule is
        treated as non-matching in either case (fail-safe), but callers
        increment _throw_counts so persistent exception behaviour is visible
        via throw_stats().
        """
        try:
            tokens = PolicyParser._tokenize(rule.condition)
            matched = SafeExpr.evaluate(tokens, context, now=now)
            if matched:
                return True, TarlDecision(
                    verdict=rule.verdict,
                    reason=f"Condition '{rule.condition}' matched",
                ), False
            return False, TarlDecision(
                verdict=rule.verdict,
                reason="Condition did not match",
            ), False
        except Exception as exc:
            return False, TarlDecision(
                verdict=TarlVerdict.DENY,
                reason=f"Evaluation error: {exc}",
            ), True

    # ── Proof-carrying evaluation ─────────────────────────────────────────────

    def evaluate_with_proof(
        self,
        context: dict,
        policy_text: str | None = None,
    ) -> tuple[TarlDecision, TarlProof]:
        """
        Evaluate sequentially, recording a full evaluation trace, then sign.

        Returns (TarlDecision, TarlProof). The proof contains:
          - SHA-256 hash of policy source
          - SHA-256 hash of canonical context
          - Per-rule trace up to (and including) the first match
          - HMAC-SHA256 or Ed25519 signature if a signing key is registered
        """
        ctx = self._inject_sources(context)
        if policy_text is not None:
            policy = PolicyParser.parse(policy_text)
        else:
            policy = self.policy

        # Context schema validation fails closed before any rule evaluation,
        # carrying a proof that records which fields were missing or mistyped.
        schema_decision = self._schema_decision(ctx)
        if schema_decision is not None:
            trace = [{"kind": "schema-violation", "matched": False,
                      "reason": schema_decision.reason}]
            proof = self._generate_proof(policy, ctx, schema_decision, -1, trace)
            return self._persist(policy, ctx, schema_decision, proof)

        # Phase 5: temporal window check — return early with proof if outside window
        temporal = _check_policy_temporal(policy, now=self._now())
        if temporal is not None:
            proof = self._generate_proof(policy, ctx, temporal, -1, [])
            return self._persist(policy, ctx, temporal, proof)

        trace = []
        decision = DEFAULT_DENY
        matched_idx = -1
        trusted_now = self._now()

        for i, rule in enumerate(policy.rules):
            matched, rule_dec, threw = self._evaluate_rule(
                rule, ctx, trusted_now
            )
            if threw:
                self._throw_counts[i] = (
                    self._throw_counts.get(i, 0) + 1
                )
            trace.append({
                "rule_index": i,
                "condition": rule.condition,
                "verdict": rule.verdict.value,
                "matched": matched,
                **({"error": rule_dec.reason} if threw else {}),
            })
            if threw:
                decision = TarlDecision(
                    verdict=TarlVerdict.DENY,
                    reason=(
                        f"fail-closed: rule {i} could not be evaluated: "
                        f"{rule_dec.reason}"
                    ),
                    rule_index=i,
                    matched_rule=str(rule),
                )
                matched_idx = -1
                break
            if matched:
                matched_idx = i
                expires_at = None
                if rule.duration_seconds:
                    expires_at = (
                        datetime.datetime.now(datetime.UTC)
                        + datetime.timedelta(seconds=rule.duration_seconds)
                    ).isoformat(timespec="seconds")
                decision = TarlDecision(
                    verdict=rule_dec.verdict,
                    reason=f"Condition '{rule.condition}' matched",
                    rule_index=i,
                    matched_rule=str(rule),
                    expires_at=expires_at,
                )
                break

        proof = self._generate_proof(policy, ctx, decision, matched_idx, trace)
        return self._persist(policy, ctx, decision, proof)

    def _generate_proof(
        self,
        policy: TarlPolicy,
        context: dict,
        decision: TarlDecision,
        matched_idx: int,
        trace: list,
    ) -> TarlProof:
        policy_hash = "sha256:" + hashlib.sha256(
            policy.source.encode("utf-8")
        ).hexdigest()
        ctx_bytes = json.dumps(
            context, sort_keys=True, default=str, separators=(",", ":")
        ).encode("utf-8")
        context_hash = "sha256:" + hashlib.sha256(ctx_bytes).hexdigest()
        evaluated_at = (
            datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        )
        matched_condition = (
            policy.rules[matched_idx].condition if matched_idx >= 0 else ""
        )
        proof = TarlProof(
            policy_hash=policy_hash,
            context_hash=context_hash,
            rule_index=matched_idx,
            matched_condition=matched_condition,
            verdict=decision.verdict,
            evaluated_at=evaluated_at,
            trace=trace,
            signature="",
            key_id="",
        )
        if self._signing_key_id and self._signing_alg == "hmac-sha256":
            secret = self._signing_keys.get(self._signing_key_id)
            if secret is not None:
                sig_hex = hmac.new(
                    secret, proof.canonical_bytes(), hashlib.sha256
                ).hexdigest()
                proof.signature = f"hmac-sha256:{sig_hex}"
                proof.key_id = self._signing_key_id
        elif self._signing_key_id and self._signing_alg == "ed25519":
            key = self._ed25519_signing_keys.get(self._signing_key_id)
            if key is not None:
                sig_hex = key.sign(proof.canonical_bytes()).hex()
                proof.signature = f"ed25519:{sig_hex}"
                proof.key_id = self._signing_key_id
        return proof

    def shutdown(self):
        """Clean up the thread pool."""
        self.executor.shutdown(wait=False)

"""
T.A.R.L. Runtime — LRU-cached, parallel policy evaluation with adaptive ordering.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict
from typing import Optional
from tarl.spec import TarlVerdict, TarlDecision, TarlPolicy, TarlRule, DEFAULT_DENY
from utf.tarl.core import SafeExpr, PolicyParser, evaluate_policy


class LRUCache:
    """Simple LRU cache with maximum size."""

    def __init__(self, maxsize: int = 128):
        self.maxsize = maxsize
        self._cache = OrderedDict()

    def get(self, key: str) -> Optional[TarlDecision]:
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
    TARL policy runtime with:
    - LRU cache (128 entries)
    - ThreadPoolExecutor for parallel rule evaluation
    - Adaptive policy ordering (most-frequently-matched rules first)
    """

    def __init__(self, policy: Optional[TarlPolicy] = None, max_workers: int = 4):
        self.policy = policy or TarlPolicy()
        self.cache = LRUCache(maxsize=128)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._hit_counts = {}

    def set_policy(self, new_policy: TarlPolicy):
        """Set or replace the policy and reset adaptive ordering."""
        self.policy = new_policy
        self.cache.clear()
        self._hit_counts = {i: 0 for i in range(len(new_policy.rules))}

    def evaluate(self, context: dict, policy_text: str = None) -> TarlDecision:
        """
        Evaluate the policy against the given context.
        Accepts optional policy_text parameter; if provided, uses it instead of self.policy.
        Returns the first matching rule's verdict, or DEFAULT_DENY.
        """
        # Build cache key from context sorted by keys
        cache_key = str(sorted(context.items()))

        # Use provided policy text or self.policy
        if policy_text is not None:
            from utf.tarl.core import PolicyParser
            policy = PolicyParser.parse(policy_text)
        else:
            policy = self.policy

        # If no rules, default deny
        if not policy.rules:
            return DEFAULT_DENY

        # Check cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        # Evaluate all rules in parallel, ordered by hit frequency
        ordered_indices = sorted(
            range(len(policy.rules)),
            key=lambda i: self._hit_counts.get(i, 0),
            reverse=True
        )

        # Submit all rules for evaluation
        futures = {}
        for idx in ordered_indices:
            rule = policy.rules[idx]
            future = self.executor.submit(self._evaluate_rule, rule, context)
            futures[future] = (idx, rule)

        # Collect results in order of submission (most-hit first)
        for future in as_completed(futures):
            idx, rule = futures[future]
            try:
                matched, decision = future.result()
                if matched:
                    # Update hit count
                    self._hit_counts[idx] = self._hit_counts.get(idx, 0) + 1
                    result = TarlDecision(
                        verdict=decision.verdict,
                        reason=decision.reason or f"Rule matched: {rule}",
                        rule_index=idx,
                        matched_rule=str(rule)
                    )
                    self.cache.put(cache_key, result)
                    return result
            except Exception:
                continue

        # Default deny
        result = DEFAULT_DENY
        self.cache.put(cache_key, result)
        return result

    def _evaluate_rule(self, rule: TarlRule, context: dict) -> tuple:
        """
        Evaluate a single rule against context.
        Returns (matched: bool, decision: TarlDecision).
        """
        try:
            tokens = PolicyParser._tokenize(rule.condition)
            result = SafeExpr.evaluate(tokens, context)
            if result:
                return True, TarlDecision(verdict=rule.verdict, reason=f"Condition '{rule.condition}' matched")
            return False, TarlDecision(verdict=rule.verdict, reason="Condition did not match")
        except Exception as e:
            return False, TarlDecision(verdict=rule.verdict, reason=f"Evaluation error: {e}")

    def shutdown(self):
        """Clean up thread pool."""
        self.executor.shutdown(wait=False)
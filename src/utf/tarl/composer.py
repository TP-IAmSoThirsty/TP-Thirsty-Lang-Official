"""
T.A.R.L. Policy Composer — Phase 2: Composition Algebra

Supported composition operators:
  EXTENDS   — child rules first; falls through to parent on no match
              STOP keyword blocks parent fallthrough
  RESTRICTS — evaluates both independently; final = meet(child, parent)
  INCLUDES  — pre-evaluates named sub-policies; injects verdicts as context

Supported set operators (TarlPolicySet):
  UNION     — join (∨): ALLOW if any member ALLOWs
  INTERSECT — meet (∧): ALLOW only if all members ALLOW
  MAJORITY  — ALLOW if strictly more than half of members ALLOW

Multiple groups in a policy_set are combined via meet (strictest wins).
"""
from __future__ import annotations

import os

from utf.tarl.spec import (
    DEFAULT_DENY,
    CompositionOp,
    SetOp,
    TarlDecision,
    TarlPolicy,
    TarlPolicyRef,
    TarlPolicySet,
    TarlVerdict,
)


class CompositionError(Exception):
    """Raised for invalid composition: unknown parent, circular reference."""


class PolicyComposer:
    """
    Registry and evaluator for composed T.A.R.L. policies.

    Phase 5: temporal window enforcement and policy succession (revert_to)
    are applied automatically before EXTENDS/RESTRICTS dispatch.

    Usage:
        composer = PolicyComposer()
        composer.register(base_policy)
        composer.register(child_policy)   # child EXTENDS base
        decision = composer.evaluate("child", context)
    """

    def __init__(self, base_path: str = "."):
        self._policies: dict[str, TarlPolicy] = {}
        self._sets: dict[str, TarlPolicySet] = {}
        self._base_path = base_path

    # ── Registration ─────────────────────────────────────────────────────────

    def register(self, policy: TarlPolicy) -> PolicyComposer:
        """Register a TarlPolicy by name. Returns self for chaining."""
        self._policies[policy.name] = policy
        return self

    def register_set(self, policy_set: TarlPolicySet) -> PolicyComposer:
        """Register a TarlPolicySet by name. Returns self for chaining."""
        self._sets[policy_set.name] = policy_set
        return self

    def register_from_text(
        self, text: str, name: str | None = None
    ) -> PolicyComposer:
        """
        Parse text and register all policies and policy_sets it contains.
        Returns self for chaining.
        """
        from utf.tarl.core import PolicyParser

        items = PolicyParser.parse_all(text)
        for item in items:
            if isinstance(item, TarlPolicySet):
                self._sets[item.name] = item
            elif isinstance(item, TarlPolicy):
                if name and len(items) == 1 and item.name == "unnamed":
                    item.name = name
                self._policies[item.name] = item
        return self

    def load_file(self, path: str) -> PolicyComposer:
        """
        Read a .tarl file and register everything it contains.
        Paths are resolved relative to self._base_path.
        Returns self for chaining.
        """
        full = (
            path if os.path.isabs(path)
            else os.path.join(self._base_path, path)
        )
        with open(full, encoding="utf-8") as fh:
            return self.register_from_text(fh.read())

    def names(self) -> list[str]:
        """All registered policy names."""
        return list(self._policies.keys())

    def set_names(self) -> list[str]:
        """All registered policy_set names."""
        return list(self._sets.keys())

    # ── Public evaluation ─────────────────────────────────────────────────────

    def evaluate(self, name: str, context: dict) -> TarlDecision:
        """
        Evaluate a named policy or policy_set against context.
        Raises CompositionError if the name is not registered.
        """
        if name in self._sets:
            return self._evaluate_set(name, context)
        if name in self._policies:
            return self._evaluate_policy(
                self._policies[name], context, frozenset()
            )
        registered = sorted(self._policies) + sorted(self._sets)
        raise CompositionError(
            f"Unknown policy or policy_set: {name!r}. "
            f"Registered: {registered}"
        )

    # ── Internal policy evaluation ────────────────────────────────────────────

    def _evaluate_policy(
        self,
        policy: TarlPolicy,
        context: dict,
        chain: frozenset[str],
    ) -> TarlDecision:
        """Dispatch to the correct composition handler."""
        from utf.tarl.core import _check_policy_temporal, evaluate_policy

        # Phase 5: temporal window check before any rule evaluation.
        # If the policy has a revert_to target registered in this composer,
        # evaluate that policy instead (succession). Otherwise return the
        # on_expiry verdict (or ESCALATE).
        temporal = _check_policy_temporal(policy)
        if temporal is not None:
            if policy.revert_to and policy.revert_to in self._policies:
                # Guard against succession cycles (A→B→A) using the same
                # chain mechanism as EXTENDS/RESTRICTS.
                self._check_cycle(policy.name, chain)
                revert_policy = self._policies[policy.revert_to]
                return self._evaluate_policy(
                    revert_policy, context, chain | {policy.name}
                )
            return temporal

        # Pre-evaluate INCLUDE directives, inject into context copy
        ctx = dict(context)
        if policy.includes:
            ctx = self._inject_includes(policy.includes, ctx, chain)

        if policy.composition == CompositionOp.EXTENDS:
            return self._evaluate_extends(policy, ctx, chain)
        if policy.composition == CompositionOp.RESTRICTS:
            return self._evaluate_restricts(policy, ctx, chain)

        return evaluate_policy(ctx, policy=policy)

    def _evaluate_extends(
        self,
        policy: TarlPolicy,
        context: dict,
        chain: frozenset[str],
    ) -> TarlDecision:
        """
        EXTENDS semantics:
          1. Evaluate child rules only.
          2. If a child rule matched → return that decision.
          3. If STOP is set → return DEFAULT_DENY (no parent fallthrough).
          4. Otherwise → fall through to parent rules.
        """
        from utf.tarl.core import evaluate_policy

        self._check_cycle(policy.name, chain)

        child_only = TarlPolicy(
            rules=list(policy.rules),
            name=policy.name,
        )
        decision = evaluate_policy(context, policy=child_only)

        if decision.rule_index >= 0:
            return decision

        if policy.has_stop:
            return DEFAULT_DENY

        if not policy.parent:
            return DEFAULT_DENY

        parent = self._require(policy.parent, policy.name)
        return self._evaluate_policy(
            parent, context, chain | {policy.name}
        )

    def _evaluate_restricts(
        self,
        policy: TarlPolicy,
        context: dict,
        chain: frozenset[str],
    ) -> TarlDecision:
        """
        RESTRICTS semantics:
          Evaluate child and parent independently.
          Final verdict = meet(child, parent) — stricter wins.
        """
        from utf.tarl.core import evaluate_policy

        self._check_cycle(policy.name, chain)

        child_only = TarlPolicy(
            rules=list(policy.rules),
            name=policy.name,
        )
        child_dec = evaluate_policy(context, policy=child_only)

        parent = self._require(policy.parent, policy.name)
        parent_dec = self._evaluate_policy(
            parent, context, chain | {policy.name}
        )

        meet = TarlVerdict.meet(child_dec.verdict, parent_dec.verdict)
        src = child_dec if meet == child_dec.verdict else parent_dec
        return TarlDecision(
            verdict=meet,
            reason=(
                f"RESTRICTS({policy.parent}): "
                f"child={child_dec.verdict.value}, "
                f"parent={parent_dec.verdict.value}"
            ),
            rule_index=src.rule_index,
            matched_rule=src.matched_rule,
        )

    def _inject_includes(
        self,
        refs: list[TarlPolicyRef],
        context: dict,
        chain: frozenset[str],
    ) -> dict:
        """
        Pre-evaluate each INCLUDE'd policy and inject its verdict into ctx.

        Injects two keys per include:
          ctx["<alias>"] = {"verdict": "<VERDICT>", "rule_index": <int>}
          ctx["<alias>.verdict"] = "<VERDICT>"
        """
        ctx = dict(context)
        for ref in refs:
            alias = ref.alias or ref.name

            # Resolve file-based includes
            policy_name = ref.name
            if ref.is_file:
                stem = os.path.splitext(os.path.basename(ref.name))[0]
                if stem not in self._policies:
                    try:
                        self.load_file(ref.name)
                    except OSError:
                        ctx[alias] = {"verdict": "DENY", "rule_index": -1}
                        ctx[f"{alias}.verdict"] = "DENY"
                        continue
                policy_name = stem

            if policy_name not in self._policies:
                ctx[alias] = {"verdict": "DENY", "rule_index": -1}
                ctx[f"{alias}.verdict"] = "DENY"
                continue

            inc_policy = self._policies[policy_name]
            inc_dec = self._evaluate_policy(inc_policy, ctx, chain)
            ctx[alias] = {
                "verdict": inc_dec.verdict.value,
                "rule_index": inc_dec.rule_index,
            }
            ctx[f"{alias}.verdict"] = inc_dec.verdict.value

        return ctx

    # ── Policy-set evaluation ─────────────────────────────────────────────────

    def _evaluate_set(self, name: str, context: dict) -> TarlDecision:
        """
        policy_set evaluation:
          Each group produces a verdict via its SetOp.
          The final verdict is the meet (∧) of all group verdicts.
          If no groups are defined, the set's default_verdict is returned.
        """
        ps = self._sets[name]

        if not ps.groups:
            return TarlDecision(
                verdict=ps.default_verdict,
                reason=f"policy_set {name}: no groups defined",
            )

        group_verdicts: list[TarlVerdict] = []
        group_summaries: list[str] = []

        for op, policy_names in ps.groups:
            dec = self._evaluate_group(op, policy_names, context)
            group_verdicts.append(dec.verdict)
            group_summaries.append(f"{op.value}={dec.verdict.value}")

        final = group_verdicts[0]
        for v in group_verdicts[1:]:
            final = TarlVerdict.meet(final, v)

        return TarlDecision(
            verdict=final,
            reason=f"policy_set {name}: " + ", ".join(group_summaries),
        )

    def _evaluate_group(
        self,
        op: SetOp,
        policy_names: list[str],
        context: dict,
    ) -> TarlDecision:
        """Evaluate a single combine group using the given operator."""
        verdicts: list[TarlVerdict] = []
        for pname in policy_names:
            if pname in self._policies:
                dec = self._evaluate_policy(
                    self._policies[pname], context, frozenset()
                )
                verdicts.append(dec.verdict)
            else:
                verdicts.append(TarlVerdict.DENY)

        if not verdicts:
            return TarlDecision(
                verdict=TarlVerdict.DENY,
                reason=f"{op.value}: empty group",
            )

        if op == SetOp.UNION:
            result = verdicts[0]
            for v in verdicts[1:]:
                result = TarlVerdict.join(result, v)
        elif op == SetOp.INTERSECT:
            result = verdicts[0]
            for v in verdicts[1:]:
                result = TarlVerdict.meet(result, v)
        elif op == SetOp.MAJORITY:
            allow_count = sum(
                1 for v in verdicts if v == TarlVerdict.ALLOW
            )
            result = (
                TarlVerdict.ALLOW
                if allow_count > len(verdicts) / 2
                else TarlVerdict.DENY
            )
        else:
            result = TarlVerdict.DENY

        return TarlDecision(
            verdict=result,
            reason=(
                f"{op.value}("
                + ", ".join(v.value for v in verdicts)
                + f") = {result.value}"
            ),
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _require(self, name: str | None, from_name: str) -> TarlPolicy:
        if name is None or name not in self._policies:
            raise CompositionError(
                f"Policy {from_name!r} references unknown policy "
                f"{name!r}. Registered: {sorted(self._policies.keys())}"
            )
        return self._policies[name]

    def _check_cycle(self, name: str, chain: frozenset[str]) -> None:
        if name in chain:
            path = " -> ".join(sorted(chain)) + f" -> {name}"
            raise CompositionError(
                f"Circular policy reference detected: {path}"
            )

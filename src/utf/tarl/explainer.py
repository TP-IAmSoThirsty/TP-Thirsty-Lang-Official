"""
T.A.R.L. Policy Explainer — Phase 6

Produces a human-readable trace of how a policy decision was reached,
showing each rule evaluated in order with its match result.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from utf.tarl.spec import TarlPolicy, TarlVerdict


@dataclass
class RuleTrace:
    """Evaluation trace for a single rule."""
    rule_index: int
    condition: str
    verdict: TarlVerdict
    matched: bool
    evaluated: bool = True       # False if skipped — earlier rule already matched
    error: str | None = None

    def __str__(self) -> str:
        if not self.evaluated:
            return f"  [{self.rule_index}] (skipped — earlier rule matched)"
        status = "MATCHED" if self.matched else "no match"
        err = f"  [error: {self.error}]" if self.error else ""
        return (
            f"  [{self.rule_index}] when {self.condition}"
            f" => {self.verdict.value}"
            f"  →  {status}{err}"
        )


@dataclass
class PolicyExplanation:
    """Full explanation of a policy evaluation."""
    policy_name: str
    verdict: TarlVerdict
    matched_rule_index: int               # -1 = DEFAULT_DENY
    rule_traces: list[RuleTrace] = field(default_factory=list)
    temporal_reason: str | None = None
    expires_at: str | None = None

    def format(self, verbose: bool = False) -> str:
        """
        Return a human-readable explanation string.

        :param verbose: When True, include skipped rules in the trace.
        """
        lines = [
            f"Policy:   {self.policy_name}",
            f"Verdict:  {self.verdict.value}",
        ]
        if self.matched_rule_index >= 0:
            lines.append(f"Matched:  Rule #{self.matched_rule_index}")
        else:
            lines.append("Matched:  DEFAULT_DENY (no rule matched)")
        if self.expires_at:
            lines.append(f"Expires:  {self.expires_at}")
        if self.temporal_reason:
            lines.append(f"\nTemporal: {self.temporal_reason}")
            return "\n".join(lines)
        if not self.rule_traces:
            return "\n".join(lines)
        lines.append("\nRule evaluation trace:")
        for trace in self.rule_traces:
            if verbose or trace.evaluated:
                lines.append(str(trace))
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "policy_name": self.policy_name,
            "verdict": self.verdict.value,
            "matched_rule_index": self.matched_rule_index,
            "expires_at": self.expires_at,
            "temporal_reason": self.temporal_reason,
            "rule_traces": [
                {
                    "rule_index": t.rule_index,
                    "condition": t.condition,
                    "verdict": t.verdict.value,
                    "matched": t.matched,
                    "evaluated": t.evaluated,
                    "error": t.error,
                }
                for t in self.rule_traces
            ],
        }


class TarlExplainer:
    """
    Explains T.A.R.L. policy evaluations in human-readable form.

    Evaluates a policy rule-by-rule, recording why each rule matched or
    did not, and returns a :class:`PolicyExplanation` with the full trace.

    Usage::

        explainer = TarlExplainer()
        exp = explainer.explain({"user": {"role": "admin"}}, policy_text=src)
        print(exp.format())
    """

    def explain(
        self,
        context: dict,
        policy_text: str = "",
        policy: TarlPolicy | None = None,
    ) -> PolicyExplanation:
        """
        Evaluate a policy against context and return a full explanation.

        :param context:     The evaluation context dict.
        :param policy_text: Policy source text (used if policy is None).
        :param policy:      Pre-parsed TarlPolicy (takes precedence).
        """
        from utf.tarl.core import PolicyParser, SafeExpr, _check_policy_temporal

        if policy is None:
            if not policy_text:
                return PolicyExplanation(
                    policy_name="unnamed",
                    verdict=TarlVerdict.DENY,
                    matched_rule_index=-1,
                )
            policy = PolicyParser.parse(policy_text)

        # Temporal window check fires before any rule evaluation
        temporal = _check_policy_temporal(policy)
        if temporal is not None:
            return PolicyExplanation(
                policy_name=policy.name,
                verdict=temporal.verdict,
                matched_rule_index=-1,
                temporal_reason=temporal.reason,
            )

        traces: list[RuleTrace] = []
        matched_index = -1
        expires_at = None

        for i, rule in enumerate(policy.rules):
            if matched_index >= 0:
                traces.append(RuleTrace(
                    rule_index=i,
                    condition=rule.condition,
                    verdict=rule.verdict,
                    matched=False,
                    evaluated=False,
                ))
                continue

            error = None
            matched = False
            try:
                matched = bool(SafeExpr.evaluate(rule.condition, context))
            except Exception as exc:
                error = str(exc)

            traces.append(RuleTrace(
                rule_index=i,
                condition=rule.condition,
                verdict=rule.verdict,
                matched=matched,
                evaluated=True,
                error=error,
            ))

            if matched:
                matched_index = i
                if rule.duration_seconds:
                    expires_at = (
                        datetime.datetime.now(datetime.UTC)
                        + datetime.timedelta(seconds=rule.duration_seconds)
                    ).isoformat(timespec="seconds")

        verdict = (
            policy.rules[matched_index].verdict
            if matched_index >= 0
            else TarlVerdict.DENY
        )

        return PolicyExplanation(
            policy_name=policy.name,
            verdict=verdict,
            matched_rule_index=matched_index,
            rule_traces=traces,
            expires_at=expires_at,
        )

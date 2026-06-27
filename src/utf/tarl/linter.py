"""
Policy linter — flags over-broad or unsafe policies (THREAT_MODEL C039).

An AI-generated or hastily-written policy often hides a broad grant: an
unconditional ``when true => ALLOW``, an ALLOW that isn't gated by any
authority/role/grant, or a missing default-DENY floor. These pass evaluation
silently but defeat least-privilege. The linter is a fast, dependency-free static
pass (no Z3) that surfaces them so a human reviews before deployment.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from utf.tarl.spec import TarlPolicy, TarlVerdict

# Tokens that indicate a rule is gated by *who* is acting rather than open to all.
_AUTHORITY_TOKENS = (
    "authority", "role", "subject", "authenticated", "grant", "identity",
)

_TAUTOLOGY = re.compile(r"^\s*(true|1)\s*$", re.IGNORECASE)


@dataclass
class LintFinding:
    """One policy-lint observation."""

    rule_index: int       # -1 for whole-policy findings
    severity: str         # "high" | "medium" | "low"
    code: str
    message: str

    def __str__(self) -> str:
        where = "policy" if self.rule_index < 0 else f"rule [{self.rule_index}]"
        return f"[{self.severity.upper()}] {self.code} {where}: {self.message}"


def _gated_by_authority(condition: str) -> bool:
    low = condition.lower()
    return any(tok in low for tok in _AUTHORITY_TOKENS)


def lint_policy(policy: TarlPolicy) -> list[LintFinding]:
    """Return lint findings for ``policy`` (empty list = clean)."""
    findings: list[LintFinding] = []
    allow_indices = [
        i for i, r in enumerate(policy.rules) if r.verdict == TarlVerdict.ALLOW
    ]

    for i, rule in enumerate(policy.rules):
        if rule.verdict != TarlVerdict.ALLOW:
            continue
        if _TAUTOLOGY.match(rule.condition):
            findings.append(LintFinding(
                i, "high", "TARL-LINT-BROAD-ALLOW",
                "unconditional 'when true => ALLOW' grants every request; "
                "scope it or require explicit review"))
        elif not _gated_by_authority(rule.condition):
            findings.append(LintFinding(
                i, "medium", "TARL-LINT-UNGATED-ALLOW",
                f"ALLOW on '{rule.condition}' is not gated by any authority/"
                "role/grant; confirm this is intentionally open"))

    # A policy with ALLOW rules but no terminal default-DENY relies on the
    # engine's implicit DEFAULT_DENY; flag it so the floor is explicit.
    if allow_indices and not _has_explicit_default_deny(policy):
        findings.append(LintFinding(
            -1, "low", "TARL-LINT-NO-DEFAULT-DENY",
            "policy has ALLOW rules but no explicit 'when true => DENY' floor; "
            "add one to make the deny-by-default posture self-documenting"))

    return findings


def _has_explicit_default_deny(policy: TarlPolicy) -> bool:
    return any(
        r.verdict == TarlVerdict.DENY and _TAUTOLOGY.match(r.condition)
        for r in policy.rules
    )


def lint_passes(policy: TarlPolicy, max_severity: str = "low") -> bool:
    """True if no finding meets/exceeds ``max_severity`` (default: any finding
    fails). Useful as a CI gate."""
    order = {"low": 0, "medium": 1, "high": 2}
    threshold = order[max_severity]
    return all(order[f.severity] < threshold for f in lint_policy(policy))


__all__ = ["LintFinding", "lint_policy", "lint_passes"]

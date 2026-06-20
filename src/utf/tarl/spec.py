"""
T.A.R.L. Specification Types

Verdict lattice:  DENY ≺ ESCALATE ≺ ALLOW
Restrictive meet: a ∧ b = min(a, b)   — DENY beats all
Permissive join:  a ∨ b = max(a, b)   — ALLOW beats all
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

# Safety ordering: DENY=0 < ESCALATE=1 < ALLOW=2
_VERDICT_RANK: dict = {}


class TarlVerdict(str, Enum):
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    ALLOW = "ALLOW"

    def __str__(self) -> str:
        return self.value

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, TarlVerdict):
            return NotImplemented
        return _VERDICT_RANK[self] < _VERDICT_RANK[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, TarlVerdict):
            return NotImplemented
        return _VERDICT_RANK[self] <= _VERDICT_RANK[other]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, TarlVerdict):
            return NotImplemented
        return _VERDICT_RANK[self] > _VERDICT_RANK[other]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, TarlVerdict):
            return NotImplemented
        return _VERDICT_RANK[self] >= _VERDICT_RANK[other]

    @staticmethod
    def meet(a: "TarlVerdict", b: "TarlVerdict") -> "TarlVerdict":
        """Restrictive composition (∧): min in safety ordering."""
        return a if _VERDICT_RANK[a] <= _VERDICT_RANK[b] else b

    @staticmethod
    def join(a: "TarlVerdict", b: "TarlVerdict") -> "TarlVerdict":
        """Permissive composition (∨): max in safety ordering."""
        return a if _VERDICT_RANK[a] >= _VERDICT_RANK[b] else b


# Populate rank table after enum is defined
_VERDICT_RANK.update({
    TarlVerdict.DENY:     0,
    TarlVerdict.ESCALATE: 1,
    TarlVerdict.ALLOW:    2,
})


@dataclass
class TarlRule:
    """A single `when <condition> => VERDICT` rule."""
    condition: str
    verdict: TarlVerdict
    source_line: int = 0

    def __str__(self) -> str:
        return f"when {self.condition} => {self.verdict.value}"


@dataclass
class TarlPolicy:
    """Ordered decision function over a context space: P = [r₁, r₂, ..., rₙ]."""
    rules: List[TarlRule] = field(default_factory=list)
    source: str = ""
    name: str = "unnamed"

    def __str__(self) -> str:
        lines = [f"policy {self.name}:"]
        for r in self.rules:
            lines.append(f"  {r}")
        return "\n".join(lines)


@dataclass
class TarlDecision:
    """Result of evaluating a T.A.R.L. policy against a context."""
    verdict: TarlVerdict
    reason: str = ""
    rule_index: int = -1
    matched_rule: Optional[str] = None

    def __str__(self) -> str:
        return f"[{self.verdict.value}] {self.reason}"


# Ground state. Nothing crosses without an explicit ALLOW.
DEFAULT_DENY = TarlDecision(
    verdict=TarlVerdict.DENY,
    reason="default-deny: no rule matched",
    rule_index=-1,
    matched_rule=None,
)

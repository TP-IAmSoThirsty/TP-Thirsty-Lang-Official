"""
T.A.R.L. Specification Types
TarlVerdict enum, TarlDecision and TarlPolicy dataclasses.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class TarlVerdict(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"

    def __str__(self):
        return self.value


@dataclass
class TarlDecision:
    """Result of evaluating a TARL policy rule."""
    verdict: TarlVerdict
    reason: str = ""
    rule_index: int = -1
    matched_rule: Optional[str] = None

    def __str__(self):
        return f"[{self.verdict.value}] {self.reason}"


@dataclass
class TarlRule:
    """A single TARL policy rule: `when <condition> => VERDICT`"""
    condition: str
    verdict: TarlVerdict
    source_line: int = 0

    def __str__(self):
        return f"when {self.condition} => {self.verdict.value}"


@dataclass
class TarlPolicy:
    """A parsed TARL policy consisting of multiple rules."""
    rules: list = field(default_factory=list)
    source: str = ""
    name: str = "unnamed"

    def __str__(self):
        lines = [f"policy {self.name}:"]
        for r in self.rules:
            lines.append(f"  {r}")
        return "\n".join(lines)


DEFAULT_DENY = TarlDecision(
    verdict=TarlVerdict.DENY,
    reason="Default deny — no matching rule",
    rule_index=-1,
    matched_rule=None
)

"""
Context schema validation for T.A.R.L. evaluation.

Policies decide over a context dict, but an attacker controls that dict's shape
(threat-model A8, context poisoner). Two failure modes matter:

  * **Missing required field (C045)** — a policy that gates on ``amount`` sees no
    ``amount`` at all; a naive ``when amount > 100`` silently fails to match and
    the context slips to a more permissive later rule or to DEFAULT-DENY for the
    wrong reason.
  * **Type confusion (C046)** — ``amount`` arrives as a non-numeric string or a
    dict, so the policy cannot prove the comparison is well-typed.

A :class:`ContextSchema` declares the fields a policy requires and their accepted
types. The runtime validates the context **before** any rule is evaluated; a
violation short-circuits to a fail-closed verdict (DENY by default, or ESCALATE)
with a proof recording exactly which fields were missing or mistyped — never a
silent permissive default.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from utf.tarl.spec import TarlVerdict

# Friendly names for the accepted "kinds" a field may declare.
_KIND_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "int": (int,),
    "float": (float,),
    "number": (int, float),
    "bool": (bool,),
    "list": (list,),
    "dict": (dict,),
}


@dataclass
class FieldSpec:
    """One required/optional context field and its accepted kind(s)."""

    name: str
    kinds: tuple[str, ...] = ("string",)
    required: bool = True

    def accepts(self, value: object) -> bool:
        for kind in self.kinds:
            types = _KIND_TYPES.get(kind, ())
            # bool is a subclass of int; only accept it when explicitly allowed,
            # so a `bool` slipped into an `int`/`number` field is type confusion.
            if isinstance(value, bool):
                if kind == "bool":
                    return True
                continue
            if isinstance(value, types):
                return True
        return False


@dataclass
class ContextSchema:
    """A set of field specs plus the verdict to return on any violation."""

    fields: list[FieldSpec] = field(default_factory=list)
    on_violation: TarlVerdict = TarlVerdict.DENY

    def validate(self, context: dict) -> list[str]:
        """Return a list of human-readable violations ([] when the context is ok)."""
        violations: list[str] = []
        for spec in self.fields:
            if spec.name not in context:
                if spec.required:
                    violations.append(f"missing required field '{spec.name}'")
                continue
            value = context[spec.name]
            if not spec.accepts(value):
                violations.append(
                    f"field '{spec.name}' has type {type(value).__name__}, "
                    f"expected one of {', '.join(spec.kinds)}"
                )
        return violations

    @classmethod
    def from_dict(cls, data: dict) -> ContextSchema:
        """Build a schema from a JSON-friendly dict.

        ``{"on_violation": "DENY", "fields": [
              {"name": "amount", "kinds": ["number"], "required": true}, ...]}``
        """
        on_violation = TarlVerdict(data.get("on_violation", "DENY"))
        fields = [
            FieldSpec(
                name=f["name"],
                kinds=tuple(f.get("kinds", ["string"])),
                required=bool(f.get("required", True)),
            )
            for f in data.get("fields", [])
        ]
        return cls(fields=fields, on_violation=on_violation)


__all__ = ["FieldSpec", "ContextSchema"]

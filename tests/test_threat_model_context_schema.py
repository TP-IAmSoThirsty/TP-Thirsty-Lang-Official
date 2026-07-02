"""Context schema validation tests (THREAT_MODEL C045-C046).

Missing required context fields and type-confused values must fail closed before
any rule runs — never slip through to a permissive later rule or the wrong
DEFAULT-DENY reason.
"""
import pytest

from utf.tarl.core import PolicyParser
from utf.tarl.runtime import TarlRuntime
from utf.tarl.schema import ContextSchema, FieldSpec
from utf.tarl.spec import TarlVerdict
from utf.tarl.verifier import ProofVerifier

# A policy that would ALLOW generously if the context reached the rules.
PERMISSIVE = (
    'policy p\n'
    'when amount > 100 => ALLOW\n'
    'when true => ALLOW\n'
)

SCHEMA = ContextSchema(fields=[
    FieldSpec("amount", kinds=("number",), required=True),
    FieldSpec("action", kinds=("string",), required=True),
])


def _runtime(schema=SCHEMA, policy=PERMISSIVE):
    rt = TarlRuntime(PolicyParser.parse(policy))
    if schema is not None:
        rt.set_context_schema(schema)
    return rt


def test_missing_required_field_fails_closed():
    # No 'amount' — the permissive `when true => ALLOW` must NOT be reached.
    decision = _runtime().evaluate({"action": "charge"})
    assert decision.verdict == TarlVerdict.DENY
    assert "amount" in decision.reason


def test_type_confused_string_for_number_is_rejected():
    decision = _runtime().evaluate({"action": "charge", "amount": "100"})
    assert decision.verdict == TarlVerdict.DENY
    assert "amount" in decision.reason


def test_bool_into_number_field_is_type_confusion():
    decision = _runtime().evaluate({"action": "charge", "amount": True})
    assert decision.verdict == TarlVerdict.DENY


def test_dict_into_number_field_is_rejected():
    decision = _runtime().evaluate({"action": "charge", "amount": {"x": 1}})
    assert decision.verdict == TarlVerdict.DENY


def test_valid_context_passes_through_to_policy():
    decision = _runtime().evaluate({"action": "charge", "amount": 150})
    assert decision.verdict == TarlVerdict.ALLOW


def test_escalate_on_violation_is_configurable():
    schema = ContextSchema(
        fields=[FieldSpec("amount", kinds=("number",))],
        on_violation=TarlVerdict.ESCALATE,
    )
    decision = _runtime(schema=schema).evaluate({"action": "x"})
    assert decision.verdict == TarlVerdict.ESCALATE


def test_schema_violation_proof_is_consistent_and_records_fields():
    decision, proof = _runtime().evaluate_with_proof({"action": "charge"})
    assert decision.verdict == TarlVerdict.DENY
    assert proof.verdict == TarlVerdict.DENY
    assert any("amount" in str(e.get("reason", "")) for e in proof.trace)
    # The proof must still verify (trace internally consistent, rule_index == -1).
    assert ProofVerifier(require_signature=False).verify(proof).checks["trace"] is True


def test_schema_from_dict_round_trips():
    schema = ContextSchema.from_dict({
        "on_violation": "DENY",
        "fields": [
            {"name": "amount", "kinds": ["number"], "required": True},
            {"name": "note", "kinds": ["string"], "required": False},
        ],
    })
    assert schema.validate({"amount": 5}) == []                  # optional 'note' absent
    assert schema.validate({"amount": "5"})                       # type confusion
    assert schema.validate({})                                    # missing required


@pytest.mark.parametrize("value", [5, 5.0, 0, -3])
def test_number_kind_accepts_int_and_float(value):
    assert ContextSchema(fields=[FieldSpec("a", kinds=("number",))]).validate(
        {"a": value}
    ) == []

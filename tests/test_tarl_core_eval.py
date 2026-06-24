"""Exercise the tarl.core condition tokenizer/evaluator across all operators."""
from utf.tarl.core import PolicyParser, evaluate_policy


def verdict(condition, context):
    policy = f"when {condition} => ALLOW\nwhen true => DENY\n"
    return evaluate_policy(context, policy_text=policy).verdict.value


def allows(condition, context):
    return verdict(condition, context) == "ALLOW"


def test_equality():
    assert allows('role == "admin"', {"role": "admin"})
    assert not allows('role == "admin"', {"role": "user"})
    assert allows('role != "guest"', {"role": "admin"})


def test_numeric_comparisons():
    assert allows("count > 100", {"count": 200})
    assert allows("count >= 100", {"count": 100})
    assert allows("count < 5", {"count": 1})
    assert allows("count <= 5", {"count": 5})


def test_arithmetic():
    assert allows("count + 1 > 10", {"count": 10})
    assert allows("count * 2 == 20", {"count": 10})
    assert allows("count / 2 == 5", {"count": 10})
    assert allows("count % 2 == 0", {"count": 4})
    assert allows("count - 1 == 9", {"count": 10})


def test_boolean_logic():
    assert allows('a == 1 and b == 2', {"a": 1, "b": 2})
    assert not allows('a == 1 and b == 2', {"a": 1, "b": 9})
    assert allows('a == 1 or b == 2', {"a": 9, "b": 2})
    assert allows('not (a == 1)', {"a": 2})


def test_membership():
    assert allows('role IN ["admin", "user"]', {"role": "user"})
    assert not allows('role IN ["admin", "user"]', {"role": "ghost"})
    assert allows('role NOT IN ["banned"]', {"role": "ok"})


def test_dotted_access():
    assert allows('user.role == "admin"', {"user": {"role": "admin"}})


def test_parentheses_grouping():
    assert allows('(a == 1 or b == 1) and c == 1',
                  {"a": 0, "b": 1, "c": 1})


def test_true_literal_default():
    assert verdict("count > 999", {"count": 1}) == "DENY"


def test_parse_named_policy():
    p = PolicyParser.parse('policy access\nwhen x == 1 => ALLOW')
    assert p.name == "access"
    assert len(p.rules) == 1

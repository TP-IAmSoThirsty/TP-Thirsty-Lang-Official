"""
Tests for T.A.R.L. (Thirsty's Active Resistance Language)
Tests policy parsing, SafeExpr evaluation, ALLOW/DENY/ESCALATE verdicts, and runtime.
"""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utf.tarl.spec import TarlVerdict, TarlDecision, TarlPolicy, TarlRule, DEFAULT_DENY
from utf.tarl.core import PolicyParser, SafeExpr, evaluate_policy
from utf.tarl.runtime import TarlRuntime


class TestTarlSpec:
    """Test TARL specification types."""

    def test_verdict_enum(self):
        assert TarlVerdict.ALLOW.value == "ALLOW"
        assert TarlVerdict.DENY.value == "DENY"
        assert TarlVerdict.ESCALATE.value == "ESCALATE"
        assert str(TarlVerdict.ALLOW) == "ALLOW"

    def test_decision_dataclass(self):
        d = TarlDecision(verdict=TarlVerdict.ALLOW, reason="test", rule_index=0)
        assert d.verdict == TarlVerdict.ALLOW
        assert d.reason == "test"
        assert d.rule_index == 0
        assert str(d) == "[ALLOW] test"

    def test_default_deny(self):
        assert DEFAULT_DENY.verdict == TarlVerdict.DENY
        assert "deny" in DEFAULT_DENY.reason.lower()


class TestPolicyParser:
    """Test TARL policy rule parsing."""

    def test_parse_single_rule(self):
        parser = PolicyParser()
        text = "when role == \"admin\" => ALLOW"
        policy = parser.parse(text)
        assert len(policy.rules) == 1
        assert policy.rules[0].verdict == TarlVerdict.ALLOW
        assert policy.rules[0].condition == 'role == "admin"'

    def test_parse_multiple_rules(self):
        parser = PolicyParser()
        text = """when role == "admin" => ALLOW
when role == "user" and level >= 3 => ALLOW
when action == "delete" and resource == "critical" => ESCALATE"""
        policy = parser.parse(text)
        assert len(policy.rules) == 3
        assert policy.rules[0].verdict == TarlVerdict.ALLOW
        assert policy.rules[2].verdict == TarlVerdict.ESCALATE

    def test_parse_with_comments(self):
        parser = PolicyParser()
        text = """// This is a comment
when role == "admin" => ALLOW
// Another comment
when count > 100 => ESCALATE"""
        policy = parser.parse(text)
        assert len(policy.rules) == 2

    def test_parse_directive(self):
        # "policy" prefix should be handled by parse()
        policy = PolicyParser.parse("policy mypolicy\nwhen x == 1 => ALLOW")
        assert policy.name == "mypolicy"
        assert len(policy.rules) == 1

        policy = PolicyParser.parse("policy access_control\nwhen x == 1 => ALLOW")
        assert policy.name == "access_control"

    def test_parse_policy_name(self):
        # Policy name is extracted via parse()
        policy = PolicyParser.parse("// comment\npolicy test_policy\nwhen x == 1 => ALLOW")
        assert policy.name == "test_policy"


class TestSafeExpr:
    """Test SafeExpr sandboxed evaluator."""

    def test_compare_eq(self):
        assert SafeExpr.evaluate('x == 5', {'x': 5}) is True
        assert SafeExpr.evaluate('x == 5', {'x': 3}) is False

    def test_compare_ne(self):
        assert SafeExpr.evaluate('x != 5', {'x': 3}) is True
        assert SafeExpr.evaluate('x != 5', {'x': 5}) is False

    def test_compare_gt(self):
        assert SafeExpr.evaluate('count > 5', {'count': 10}) is True
        assert SafeExpr.evaluate('count > 5', {'count': 3}) is False

    def test_compare_lt(self):
        assert SafeExpr.evaluate('count < 5', {'count': 3}) is True
        assert SafeExpr.evaluate('count < 5', {'count': 10}) is False

    def test_compare_ge(self):
        assert SafeExpr.evaluate('level >= 3', {'level': 3}) is True
        assert SafeExpr.evaluate('level >= 3', {'level': 2}) is False

    def test_compare_le(self):
        assert SafeExpr.evaluate('level <= 3', {'level': 3}) is True
        assert SafeExpr.evaluate('level <= 3', {'level': 4}) is False

    def test_and_operator(self):
        assert SafeExpr.evaluate('role == "admin" and level >= 3', {'role': 'admin', 'level': 5}) is True
        assert SafeExpr.evaluate('role == "admin" and level >= 3', {'role': 'user', 'level': 5}) is False
        assert SafeExpr.evaluate('role == "admin" and level >= 3', {'role': 'admin', 'level': 1}) is False

    def test_or_operator(self):
        assert SafeExpr.evaluate('role == "admin" or level >= 3', {'role': 'admin', 'level': 1}) is True
        assert SafeExpr.evaluate('role == "admin" or level >= 3', {'role': 'user', 'level': 5}) is True
        assert SafeExpr.evaluate('role == "admin" or level >= 3', {'role': 'user', 'level': 1}) is False

    def test_not_operator(self):
        result = SafeExpr.evaluate('not (x == 5)', {'x': 3})
        assert result is True

    def test_string_comparison(self):
        assert SafeExpr.evaluate('role == "admin"', {'role': 'admin'}) is True
        assert SafeExpr.evaluate('role == "admin"', {'role': 'user'}) is False

    def test_integer_arithmetic_in_comparison(self):
        """Test that arithmetic within comparisons works."""
        assert SafeExpr.evaluate('count + 1 == 6', {'count': 5}) is True


class TestEvaluatePolicy:
    """Test full policy evaluation."""

    def test_allow_verdict(self):
        policy = """when role == "admin" => ALLOW"""
        result = evaluate_policy({'role': 'admin'}, policy)
        assert result.verdict == TarlVerdict.ALLOW

    def test_deny_verdict(self):
        policy = """when role == "admin" => ALLOW
when role == "user" => DENY"""
        result = evaluate_policy({'role': 'user'}, policy)
        assert result.verdict == TarlVerdict.DENY

    def test_escalate_verdict(self):
        policy = """when role == "admin" => ALLOW
when count > 100 => ESCALATE
when role == "user" => DENY"""
        result = evaluate_policy({'role': 'user', 'count': 150}, policy)
        assert result.verdict == TarlVerdict.ESCALATE

    def test_default_deny(self):
        policy = """when role == "admin" => ALLOW"""
        result = evaluate_policy({'role': 'nonexistent'}, policy)
        assert result.verdict == TarlVerdict.DENY
        assert "deny" in result.reason.lower()

    def test_first_match_wins(self):
        """First matching rule should win."""
        policy = """when x == 1 => ALLOW
when x == 1 => DENY"""
        result = evaluate_policy({'x': 1}, policy)
        assert result.verdict == TarlVerdict.ALLOW

    def test_no_matching_rules(self):
        policy = """when x > 100 => ALLOW
when y < 0 => DENY"""
        result = evaluate_policy({'x': 5, 'y': 10}, policy)
        assert result.verdict == TarlVerdict.DENY

    def test_empty_policy(self):
        result = evaluate_policy({'x': 1}, "")
        assert result.verdict == TarlVerdict.DENY


class TestTarlRuntime:
    """Test the TarlRuntime with LRU cache and parallel evaluation."""

    def test_runtime_basic(self):
        runtime = TarlRuntime()
        policy = """when role == "admin" => ALLOW"""
        
        result = runtime.evaluate({'role': 'admin'}, policy)
        assert result.verdict == TarlVerdict.ALLOW

    def test_runtime_cache(self):
        runtime = TarlRuntime()
        policy = """when role == "admin" => ALLOW"""
        
        # First call
        result1 = runtime.evaluate({'role': 'admin'}, policy)
        assert result1.verdict == TarlVerdict.ALLOW
        
        # Second call with same context and policy should use cache
        result2 = runtime.evaluate({'role': 'admin'}, policy)
        assert result2.verdict == TarlVerdict.ALLOW

    def test_runtime_lru_policy(self):
        runtime = TarlRuntime()
        
        # Evaluate with multiple policies to test adaptive ordering
        policy_a = """when x == 1 => ALLOW"""
        policy_b = """when x == 2 => DENY"""
        policy_c = """when x == 3 => ESCALATE"""
        
        result_a = runtime.evaluate({'x': 1}, policy_a)
        assert result_a.verdict == TarlVerdict.ALLOW
        
        result_b = runtime.evaluate({'x': 2}, policy_b)
        assert result_b.verdict == TarlVerdict.DENY
        
        result_c = runtime.evaluate({'x': 3}, policy_c)
        assert result_c.verdict == TarlVerdict.ESCALATE

    def test_runtime_no_matching(self):
        runtime = TarlRuntime()
        # Empty policy should default to DENY
        result = runtime.evaluate({}, "")
        assert result.verdict == TarlVerdict.DENY


class TestE2E:
    """End-to-end tests for TARL."""

    def test_tarl_file_roundtrip(self):
        """Test that a .tarl policy file is parsed and evaluated correctly."""
        policy_text = """when role == "admin" => ALLOW
when role == "user" and level >= 3 => ALLOW
when action == "delete" and resource == "critical" => ESCALATE
when action == "read" and resource == "public" => ALLOW
when action == "write" and resource == "system" => DENY
when source == "external" and port > 1024 => DENY
when count > 100 => ESCALATE"""
        
        # Test admin
        result = evaluate_policy({'role': 'admin'}, policy_text)
        assert result.verdict == TarlVerdict.ALLOW
        
        # Test user with high level
        result = evaluate_policy({'role': 'user', 'level': 5}, policy_text)
        assert result.verdict == TarlVerdict.ALLOW
        
        # Test user with low level
        result = evaluate_policy({'role': 'user', 'level': 1}, policy_text)
        assert result.verdict == TarlVerdict.DENY
        
        # Test escalate condition
        result = evaluate_policy({'role': 'user', 'action': 'delete', 'resource': 'critical'}, policy_text)
        assert result.verdict == TarlVerdict.ESCALATE
        
        # Test deny condition
        result = evaluate_policy({'role': 'user', 'action': 'write', 'resource': 'system'}, policy_text)
        assert result.verdict == TarlVerdict.DENY
        
        # Test no match - default deny
        result = evaluate_policy({'role': 'guest'}, policy_text)
        assert result.verdict == TarlVerdict.DENY


if __name__ == "__main__":
    for name in dir():
        obj = globals()[name]
        if isinstance(obj, type) and name.startswith("Test"):
            print(f"\n{'='*60}")
            print(f"Running {name}...")
            print('='*60)
            instance = obj()
            for attr in dir(instance):
                if attr.startswith("test_"):
                    try:
                        getattr(instance, attr)()
                        print(f"  ✓ {attr}")
                    except Exception as e:
                        print(f"  ✗ {attr}: {e}")
                        raise
    print("\n✅ All TARL tests passed!")
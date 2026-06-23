"""
T.A.R.L. Phase 2 — Composition Algebra Tests

Covers:
  - CompositionOp / SetOp enums
  - TarlPolicyRef / TarlPolicySet construction
  - TarlPolicy composition fields
  - PolicyParser.parse_all(): multi-policy files, policy_set, EXTENDS,
    STOP, INCLUDE, versioning metadata
  - PolicyComposer: register, register_from_text, load_file
  - EXTENDS: child first, parent fallthrough, STOP, multi-level, cycles
  - RESTRICTS: meet semantics, stricter wins
  - INCLUDES: verdict injection, missing-policy safety, file includes
  - policy_set: UNION, INTERSECT, MAJORITY, multi-group meet
  - TarlRuntime.register_source: static list, callable, error safety
  - Backward compatibility: existing evaluate_policy / TarlRuntime
"""
import os
import sys

import pytest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "src")
)

from utf.tarl.composer import (  # noqa: E402
    CompositionError,
    PolicyComposer,
)
from utf.tarl.core import PolicyParser, evaluate_policy  # noqa: E402
from utf.tarl.runtime import TarlRuntime  # noqa: E402
from utf.tarl.spec import (  # noqa: E402
    DEFAULT_DENY,
    CompositionOp,
    SetOp,
    TarlPolicy,
    TarlPolicyRef,
    TarlPolicySet,
    TarlRule,
    TarlVerdict,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _policy(name, rules):
    """Build a TarlPolicy from a list of (condition, verdict) tuples."""
    text = f"policy {name}:\n" + "\n".join(
        f"  when {c} => {v}" for c, v in rules
    )
    return PolicyParser.parse(text)


def _allow(name="allow_all"):
    return _policy(name, [("1 == 1", "ALLOW")])


def _deny(name="deny_all"):
    return _policy(name, [("1 == 1", "DENY")])


def _escalate(name="escalate_all"):
    return _policy(name, [("1 == 1", "ESCALATE")])


# ── Enum correctness ──────────────────────────────────────────────────────────

class TestEnums:
    def test_composition_op_values(self):
        assert CompositionOp.EXTENDS.value == "EXTENDS"
        assert CompositionOp.RESTRICTS.value == "RESTRICTS"

    def test_set_op_values(self):
        assert SetOp.UNION.value == "UNION"
        assert SetOp.INTERSECT.value == "INTERSECT"
        assert SetOp.MAJORITY.value == "MAJORITY"

    def test_composition_op_str(self):
        assert str(CompositionOp.EXTENDS) == "EXTENDS"

    def test_set_op_str(self):
        assert str(SetOp.UNION) == "UNION"

    def test_set_op_iterable(self):
        ops = {op.value for op in SetOp}
        assert ops == {"UNION", "INTERSECT", "MAJORITY"}


# ── TarlPolicyRef ─────────────────────────────────────────────────────────────

class TestTarlPolicyRef:
    def test_by_name(self):
        ref = TarlPolicyRef(name="base_auth")
        assert ref.name == "base_auth"
        assert ref.alias is None
        assert ref.is_file is False

    def test_by_file(self):
        ref = TarlPolicyRef(
            name="policies/auth.tarl", alias="auth", is_file=True
        )
        assert ref.is_file is True
        assert ref.alias == "auth"

    def test_defaults(self):
        ref = TarlPolicyRef(name="x")
        assert ref.alias is None
        assert ref.is_file is False


# ── TarlPolicySet ─────────────────────────────────────────────────────────────

class TestTarlPolicySet:
    def test_construction(self):
        ps = TarlPolicySet(name="api_gate")
        assert ps.name == "api_gate"
        assert ps.groups == []
        assert ps.default_verdict == TarlVerdict.DENY

    def test_with_groups(self):
        ps = TarlPolicySet(
            name="gate",
            groups=[
                (SetOp.UNION, ["a", "b"]),
                (SetOp.INTERSECT, ["c", "d"]),
            ],
            default_verdict=TarlVerdict.ESCALATE,
        )
        assert len(ps.groups) == 2
        assert ps.default_verdict == TarlVerdict.ESCALATE

    def test_str(self):
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.UNION, ["p1", "p2"])],
        )
        s = str(ps)
        assert "policy_set gate:" in s
        assert "combine UNION [p1, p2]" in s


# ── TarlPolicy composition fields ─────────────────────────────────────────────

class TestTarlPolicyCompositionFields:
    def test_default_no_composition(self):
        p = TarlPolicy(name="foo")
        assert p.parent is None
        assert p.composition is None
        assert p.includes == []
        assert p.has_stop is False
        assert p.version is None

    def test_extends_fields(self):
        p = TarlPolicy(
            name="child",
            parent="parent",
            composition=CompositionOp.EXTENDS,
        )
        assert p.composition == CompositionOp.EXTENDS
        assert p.parent == "parent"

    def test_versioning_stubs(self):
        p = TarlPolicy(
            name="pol",
            version="2",
            supersedes="1",
            valid_from="2026-07-01",
            valid_until="2026-12-31",
            on_expiry=TarlVerdict.ESCALATE,
        )
        assert p.version == "2"
        assert p.supersedes == "1"
        assert p.valid_from == "2026-07-01"
        assert p.on_expiry == TarlVerdict.ESCALATE

    def test_str_includes_composition(self):
        p = TarlPolicy(
            name="child",
            parent="base",
            composition=CompositionOp.EXTENDS,
            version="2",
        )
        assert "policy child EXTENDS base v2:" in str(p)

    def test_str_includes_stop(self):
        p = TarlPolicy(name="x", has_stop=True)
        p.rules.append(TarlRule("1 == 1", TarlVerdict.ALLOW))
        assert "STOP" in str(p)

    def test_str_includes_include(self):
        p = TarlPolicy(name="x")
        p.includes.append(
            TarlPolicyRef(name="base", alias="b", is_file=False)
        )
        assert "INCLUDE base AS b" in str(p)

    def test_str_includes_file_include(self):
        p = TarlPolicy(name="x")
        p.includes.append(
            TarlPolicyRef(
                name="policies/a.tarl", alias="a", is_file=True
            )
        )
        assert 'INCLUDE "policies/a.tarl" AS a' in str(p)


# ── PolicyParser.parse_all() ──────────────────────────────────────────────────

class TestPolicyParserParseAll:
    def test_single_policy(self):
        text = (
            "policy auth:\n"
            '    when role == "admin" => ALLOW\n'
            '    when role == "guest" => DENY\n'
        )
        items = PolicyParser.parse_all(text)
        assert len(items) == 1
        p = items[0]
        assert isinstance(p, TarlPolicy)
        assert p.name == "auth"
        assert len(p.rules) == 2

    def test_multiple_policies(self):
        text = (
            "policy base:\n"
            '    when role == "admin" => ALLOW\n'
            "\n"
            "policy child EXTENDS base:\n"
            '    when role == "superuser" => ALLOW\n'
        )
        items = PolicyParser.parse_all(text)
        assert len(items) == 2
        names = {i.name for i in items if isinstance(i, TarlPolicy)}
        assert names == {"base", "child"}

    def test_extends_parsed(self):
        text = "policy child EXTENDS parent:\n    when x == 1 => ALLOW"
        items = PolicyParser.parse_all(text)
        p = items[0]
        assert p.composition == CompositionOp.EXTENDS
        assert p.parent == "parent"

    def test_restricts_parsed(self):
        text = (
            "policy strict RESTRICTS dev:\n"
            '    when env == "prod" => ALLOW'
        )
        items = PolicyParser.parse_all(text)
        p = items[0]
        assert p.composition == CompositionOp.RESTRICTS
        assert p.parent == "dev"

    def test_version_parsed(self):
        text = "policy auth v2:\n    when x == 1 => ALLOW"
        items = PolicyParser.parse_all(text)
        assert items[0].version == "2"

    def test_stop_parsed(self):
        text = "policy x:\n    when x == 1 => ALLOW\n    STOP"
        items = PolicyParser.parse_all(text)
        assert items[0].has_stop is True

    def test_include_by_name(self):
        text = "policy x:\n    INCLUDE rate_limiter AS rl"
        items = PolicyParser.parse_all(text)
        p = items[0]
        assert len(p.includes) == 1
        ref = p.includes[0]
        assert ref.name == "rate_limiter"
        assert ref.alias == "rl"
        assert ref.is_file is False

    def test_include_by_file(self):
        text = 'policy x:\n    INCLUDE "policies/auth.tarl" AS auth'
        items = PolicyParser.parse_all(text)
        ref = items[0].includes[0]
        assert ref.name == "policies/auth.tarl"
        assert ref.is_file is True

    def test_include_no_alias(self):
        text = "policy x:\n    INCLUDE base_auth"
        items = PolicyParser.parse_all(text)
        ref = items[0].includes[0]
        assert ref.alias is None

    def test_metadata_valid_from(self):
        text = "policy x:\n    valid_from: 2026-07-01"
        items = PolicyParser.parse_all(text)
        assert items[0].valid_from == "2026-07-01"

    def test_metadata_valid_until(self):
        text = "policy x:\n    valid_until: 2026-12-31"
        items = PolicyParser.parse_all(text)
        assert items[0].valid_until == "2026-12-31"

    def test_metadata_supersedes(self):
        text = "policy x v2:\n    supersedes: v1"
        items = PolicyParser.parse_all(text)
        assert items[0].supersedes == "v1"

    def test_metadata_on_expiry_verdict(self):
        text = "policy x:\n    on_expiry: ESCALATE"
        items = PolicyParser.parse_all(text)
        assert items[0].on_expiry == TarlVerdict.ESCALATE

    def test_metadata_on_expiry_unknown_is_none(self):
        text = "policy x:\n    on_expiry: BOGUS"
        items = PolicyParser.parse_all(text)
        assert items[0].on_expiry is None

    def test_policy_set_parsed(self):
        text = (
            "policy_set api_gate:\n"
            "    combine UNION [ip_auth, user_auth]\n"
            "    combine INTERSECT [scope_check, rate_limit]\n"
            "    default: ESCALATE\n"
        )
        items = PolicyParser.parse_all(text)
        assert len(items) == 1
        ps = items[0]
        assert isinstance(ps, TarlPolicySet)
        assert ps.name == "api_gate"
        assert len(ps.groups) == 2
        assert ps.default_verdict == TarlVerdict.ESCALATE
        op0, names0 = ps.groups[0]
        assert op0 == SetOp.UNION
        assert "ip_auth" in names0

    def test_policy_set_default_is_deny(self):
        text = "policy_set x:\n    combine UNION [a, b]"
        items = PolicyParser.parse_all(text)
        assert items[0].default_verdict == TarlVerdict.DENY

    def test_bare_rules_unnamed_policy(self):
        text = 'when role == "admin" => ALLOW'
        items = PolicyParser.parse_all(text)
        assert len(items) == 1
        assert items[0].name == "unnamed"

    def test_comments_skipped(self):
        text = (
            "# comment\n"
            "policy x:\n"
            "    # another comment\n"
            "    when 1 == 1 => ALLOW"
        )
        items = PolicyParser.parse_all(text)
        assert len(items[0].rules) == 1

    def test_mixed_policies_and_sets(self):
        text = (
            "policy base:\n"
            "    when x == 1 => ALLOW\n"
            "\n"
            "policy_set gate:\n"
            "    combine UNION [base]\n"
            "\n"
            "policy child EXTENDS base:\n"
            "    when y == 2 => DENY\n"
        )
        items = PolicyParser.parse_all(text)
        type_names = [type(i).__name__ for i in items]
        assert "TarlPolicy" in type_names
        assert "TarlPolicySet" in type_names


# ── PolicyParser.parse() backward compat ─────────────────────────────────────

class TestPolicyParserParseBackwardCompat:
    def test_returns_first_policy(self):
        text = "policy foo:\n    when 1 == 1 => ALLOW"
        p = PolicyParser.parse(text)
        assert p.name == "foo"

    def test_name_param_applied_to_unnamed(self):
        text = 'when role == "admin" => ALLOW'
        p = PolicyParser.parse(text, name="my_policy")
        assert p.name == "my_policy"

    def test_existing_name_not_overridden(self):
        text = "policy explicit:\n    when 1 == 1 => ALLOW"
        p = PolicyParser.parse(text, name="ignored")
        assert p.name == "explicit"

    def test_empty_text_returns_empty_policy(self):
        p = PolicyParser.parse("", name="empty")
        assert p.name == "empty"
        assert p.rules == []


# ── PolicyComposer registration ───────────────────────────────────────────────

class TestPolicyComposerRegistration:
    def test_register_and_names(self):
        c = PolicyComposer()
        c.register(_allow("a")).register(_deny("b"))
        assert set(c.names()) == {"a", "b"}

    def test_register_set(self):
        c = PolicyComposer()
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.UNION, ["a"])],
        )
        c.register_set(ps)
        assert "gate" in c.set_names()

    def test_register_from_text_single(self):
        c = PolicyComposer()
        c.register_from_text(
            "policy foo:\n    when 1 == 1 => ALLOW"
        )
        assert "foo" in c.names()

    def test_register_from_text_multiple(self):
        text = (
            "policy a:\n    when 1 == 1 => ALLOW\n"
            "policy b:\n    when 1 == 1 => DENY"
        )
        c = PolicyComposer()
        c.register_from_text(text)
        assert {"a", "b"} <= set(c.names())

    def test_register_from_text_with_policy_set(self):
        text = "policy_set gate:\n    combine UNION [a, b]\n"
        c = PolicyComposer()
        c.register_from_text(text)
        assert "gate" in c.set_names()

    def test_unknown_policy_raises(self):
        c = PolicyComposer()
        with pytest.raises(CompositionError, match="Unknown"):
            c.evaluate("missing", {})

    def test_register_overrides(self):
        c = PolicyComposer()
        c.register(_allow("x"))
        assert c.evaluate("x", {}).verdict == TarlVerdict.ALLOW
        c.register(_deny("x"))
        assert c.evaluate("x", {}).verdict == TarlVerdict.DENY


# ── EXTENDS ───────────────────────────────────────────────────────────────────

class TestComposerExtends:
    def test_child_rule_matches(self):
        """Child rule fires before parent is consulted."""
        base = _policy("base", [('role == "user"', "ALLOW")])
        child = PolicyParser.parse(
            "policy child EXTENDS base:\n"
            '    when role == "admin" => ALLOW'
        )
        c = PolicyComposer()
        c.register(base).register(child)
        dec = c.evaluate("child", {"role": "admin"})
        assert dec.verdict == TarlVerdict.ALLOW

    def test_falls_through_to_parent(self):
        """No child rule matches → fall through to parent."""
        base = _policy("base", [('role == "user"', "ALLOW")])
        child = PolicyParser.parse(
            "policy child EXTENDS base:\n"
            '    when role == "admin" => ALLOW'
        )
        c = PolicyComposer()
        c.register(base).register(child)
        dec = c.evaluate("child", {"role": "user"})
        assert dec.verdict == TarlVerdict.ALLOW

    def test_default_deny_when_nothing_matches(self):
        base = _policy("base", [('role == "user"', "ALLOW")])
        child = PolicyParser.parse(
            "policy child EXTENDS base:\n"
            '    when role == "admin" => ALLOW'
        )
        c = PolicyComposer()
        c.register(base).register(child)
        dec = c.evaluate("child", {"role": "ghost"})
        assert dec.verdict == TarlVerdict.DENY

    def test_stop_blocks_parent(self):
        """STOP prevents falling through to parent."""
        base = _policy("base", [("1 == 1", "ALLOW")])
        child = PolicyParser.parse(
            "policy child EXTENDS base:\n"
            '    when role == "admin" => ALLOW\n'
            "    STOP"
        )
        c = PolicyComposer()
        c.register(base).register(child)
        dec = c.evaluate("child", {"role": "user"})
        assert dec.verdict == TarlVerdict.DENY

    def test_stop_child_match_still_returns(self):
        """If child matches before STOP, result is returned normally."""
        base = _policy("base", [("1 == 1", "DENY")])
        child = PolicyParser.parse(
            "policy child EXTENDS base:\n"
            "    when 1 == 1 => ALLOW\n"
            "    STOP"
        )
        c = PolicyComposer()
        c.register(base).register(child)
        assert c.evaluate("child", {}).verdict == TarlVerdict.ALLOW

    def test_multilevel_extends(self):
        """grandchild EXTENDS child EXTENDS base — full chain."""
        base = _policy("base", [("x == 1", "ALLOW")])
        child = PolicyParser.parse(
            "policy child EXTENDS base:\n    when x == 2 => ALLOW"
        )
        grandchild = PolicyParser.parse(
            "policy grandchild EXTENDS child:\n"
            "    when x == 3 => ALLOW"
        )
        c = PolicyComposer()
        c.register(base).register(child).register(grandchild)
        assert c.evaluate("grandchild", {"x": 3}).verdict == (
            TarlVerdict.ALLOW
        )
        assert c.evaluate("grandchild", {"x": 2}).verdict == (
            TarlVerdict.ALLOW
        )
        assert c.evaluate("grandchild", {"x": 1}).verdict == (
            TarlVerdict.ALLOW
        )
        assert c.evaluate("grandchild", {"x": 9}).verdict == (
            TarlVerdict.DENY
        )

    def test_unknown_parent_raises(self):
        # Child rule never matches → evaluation falls to parent lookup
        child = PolicyParser.parse(
            "policy child EXTENDS ghost:\n    when 1 == 2 => ALLOW"
        )
        c = PolicyComposer()
        c.register(child)
        with pytest.raises(CompositionError, match="ghost"):
            c.evaluate("child", {})

    def test_circular_reference_raises(self):
        # Neither child matches → both fall through → cycle
        a = PolicyParser.parse(
            "policy a EXTENDS b:\n    when 1 == 2 => ALLOW"
        )
        b = PolicyParser.parse(
            "policy b EXTENDS a:\n    when 1 == 2 => ALLOW"
        )
        c = PolicyComposer()
        c.register(a).register(b)
        with pytest.raises(CompositionError, match="Circular"):
            c.evaluate("a", {})

    def test_self_reference_raises(self):
        a = PolicyParser.parse(
            "policy a EXTENDS a:\n    when 1 == 2 => ALLOW"
        )
        c = PolicyComposer()
        c.register(a)
        with pytest.raises(CompositionError, match="Circular"):
            c.evaluate("a", {})


# ── RESTRICTS ─────────────────────────────────────────────────────────────────

class TestComposerRestricts:
    def test_both_allow(self):
        parent = _allow("parent")
        child = PolicyParser.parse(
            "policy child RESTRICTS parent:\n    when 1 == 1 => ALLOW"
        )
        c = PolicyComposer()
        c.register(parent).register(child)
        assert c.evaluate("child", {}).verdict == TarlVerdict.ALLOW

    def test_child_deny_overrides_parent_allow(self):
        parent = _allow("parent")
        child = PolicyParser.parse(
            "policy child RESTRICTS parent:\n    when 1 == 1 => DENY"
        )
        c = PolicyComposer()
        c.register(parent).register(child)
        assert c.evaluate("child", {}).verdict == TarlVerdict.DENY

    def test_parent_deny_overrides_child_allow(self):
        parent = _deny("parent")
        child = PolicyParser.parse(
            "policy child RESTRICTS parent:\n    when 1 == 1 => ALLOW"
        )
        c = PolicyComposer()
        c.register(parent).register(child)
        assert c.evaluate("child", {}).verdict == TarlVerdict.DENY

    def test_escalate_beats_allow(self):
        """meet: ESCALATE ∧ ALLOW = ESCALATE."""
        parent = _escalate("parent")
        child = PolicyParser.parse(
            "policy child RESTRICTS parent:\n    when 1 == 1 => ALLOW"
        )
        c = PolicyComposer()
        c.register(parent).register(child)
        assert c.evaluate("child", {}).verdict == TarlVerdict.ESCALATE

    def test_deny_beats_escalate(self):
        """meet: DENY ∧ ESCALATE = DENY."""
        parent = _deny("parent")
        child = PolicyParser.parse(
            "policy child RESTRICTS parent:\n"
            "    when 1 == 1 => ESCALATE"
        )
        c = PolicyComposer()
        c.register(parent).register(child)
        assert c.evaluate("child", {}).verdict == TarlVerdict.DENY

    def test_reason_contains_composition_info(self):
        parent = _allow("parent")
        child = PolicyParser.parse(
            "policy child RESTRICTS parent:\n    when 1 == 1 => ALLOW"
        )
        c = PolicyComposer()
        c.register(parent).register(child)
        dec = c.evaluate("child", {})
        assert "RESTRICTS" in dec.reason

    def test_unknown_parent_raises(self):
        child = PolicyParser.parse(
            "policy child RESTRICTS ghost:\n    when 1 == 1 => ALLOW"
        )
        c = PolicyComposer()
        c.register(child)
        with pytest.raises(CompositionError, match="ghost"):
            c.evaluate("child", {})


# ── INCLUDES ──────────────────────────────────────────────────────────────────

class TestComposerIncludes:
    def test_include_verdict_in_context(self):
        """Included verdict is accessible as alias.verdict in conditions."""
        rate_limiter = _allow("rate_limiter")
        gateway = PolicyParser.parse(
            "policy gateway:\n"
            "    INCLUDE rate_limiter AS rl\n"
            '    when rl.verdict == "ALLOW" => ALLOW'
        )
        c = PolicyComposer()
        c.register(rate_limiter).register(gateway)
        assert c.evaluate("gateway", {}).verdict == TarlVerdict.ALLOW

    def test_include_deny_blocks_gateway(self):
        rate_limiter = _deny("rate_limiter")
        gateway = PolicyParser.parse(
            "policy gateway:\n"
            "    INCLUDE rate_limiter AS rl\n"
            '    when rl.verdict == "ALLOW" => ALLOW'
        )
        c = PolicyComposer()
        c.register(rate_limiter).register(gateway)
        assert c.evaluate("gateway", {}).verdict == TarlVerdict.DENY

    def test_multiple_includes(self):
        ip_auth = _allow("ip_auth")
        user_auth = _allow("user_auth")
        gateway = PolicyParser.parse(
            "policy gateway:\n"
            "    INCLUDE ip_auth AS ip\n"
            "    INCLUDE user_auth AS usr\n"
            '    when ip.verdict == "ALLOW" '
            'and usr.verdict == "ALLOW" => ALLOW'
        )
        c = PolicyComposer()
        c.register(ip_auth).register(user_auth).register(gateway)
        assert c.evaluate("gateway", {}).verdict == TarlVerdict.ALLOW

    def test_include_unknown_policy_defaults_deny(self):
        """Missing include policy safely injects DENY, doesn't crash."""
        gateway = PolicyParser.parse(
            "policy gateway:\n"
            "    INCLUDE nonexistent AS ne\n"
            '    when ne.verdict == "ALLOW" => ALLOW'
        )
        c = PolicyComposer()
        c.register(gateway)
        assert c.evaluate("gateway", {}).verdict == TarlVerdict.DENY

    def test_include_file_not_found_defaults_deny(self):
        gateway = PolicyParser.parse(
            "policy gateway:\n"
            '    INCLUDE "nonexistent_file.tarl" AS ne\n'
            '    when ne.verdict == "ALLOW" => ALLOW'
        )
        c = PolicyComposer()
        c.register(gateway)
        assert c.evaluate("gateway", {}).verdict == TarlVerdict.DENY

    def test_include_from_file(self, tmp_path):
        """Include a policy loaded from a real .tarl file."""
        pol_file = tmp_path / "auth.tarl"
        pol_file.write_text(
            "policy auth:\n    when 1 == 1 => ALLOW\n"
        )
        gateway = PolicyParser.parse(
            "policy gateway:\n"
            '    INCLUDE "auth.tarl" AS auth\n'
            '    when auth.verdict == "ALLOW" => ALLOW'
        )
        c = PolicyComposer(base_path=str(tmp_path))
        c.register(gateway)
        assert c.evaluate("gateway", {}).verdict == TarlVerdict.ALLOW


# ── PolicyComposer.load_file ──────────────────────────────────────────────────

class TestPolicyComposerLoadFile:
    def test_load_single_policy(self, tmp_path):
        f = tmp_path / "auth.tarl"
        f.write_text("policy auth:\n    when 1 == 1 => ALLOW\n")
        c = PolicyComposer(base_path=str(tmp_path))
        c.load_file("auth.tarl")
        assert "auth" in c.names()

    def test_load_multiple_policies(self, tmp_path):
        f = tmp_path / "multi.tarl"
        f.write_text(
            "policy a:\n    when 1 == 1 => ALLOW\n"
            "policy b:\n    when 1 == 1 => DENY\n"
        )
        c = PolicyComposer(base_path=str(tmp_path))
        c.load_file("multi.tarl")
        assert {"a", "b"} <= set(c.names())

    def test_load_absolute_path(self, tmp_path):
        f = tmp_path / "pol.tarl"
        f.write_text("policy pol:\n    when 1 == 1 => ALLOW\n")
        c = PolicyComposer()
        c.load_file(str(f))
        assert "pol" in c.names()

    def test_load_nonexistent_raises(self):
        c = PolicyComposer()
        with pytest.raises(OSError):
            c.load_file("totally_missing_9999.tarl")


# ── UNION ─────────────────────────────────────────────────────────────────────

class TestPolicySetUnion:
    def _c(self, *policies):
        c = PolicyComposer()
        for p in policies:
            c.register(p)
        return c

    def test_any_allow_gives_allow(self):
        c = self._c(_allow("a"), _deny("b"), _deny("c"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.UNION, ["a", "b", "c"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ALLOW

    def test_all_deny_gives_deny(self):
        c = self._c(_deny("a"), _deny("b"))
        ps = TarlPolicySet(
            name="gate", groups=[(SetOp.UNION, ["a", "b"])]
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.DENY

    def test_allow_beats_escalate(self):
        """join: ALLOW ∨ ESCALATE = ALLOW."""
        c = self._c(_allow("a"), _escalate("b"))
        ps = TarlPolicySet(
            name="gate", groups=[(SetOp.UNION, ["a", "b"])]
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ALLOW

    def test_escalate_beats_deny(self):
        """join: ESCALATE ∨ DENY = ESCALATE."""
        c = self._c(_escalate("a"), _deny("b"))
        ps = TarlPolicySet(
            name="gate", groups=[(SetOp.UNION, ["a", "b"])]
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ESCALATE

    def test_unknown_member_treated_as_deny(self):
        c = self._c(_deny("a"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.UNION, ["a", "unknown_policy"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.DENY


# ── INTERSECT ─────────────────────────────────────────────────────────────────

class TestPolicySetIntersect:
    def _c(self, *policies):
        c = PolicyComposer()
        for p in policies:
            c.register(p)
        return c

    def test_all_allow_gives_allow(self):
        c = self._c(_allow("a"), _allow("b"), _allow("c"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.INTERSECT, ["a", "b", "c"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ALLOW

    def test_any_deny_gives_deny(self):
        c = self._c(_allow("a"), _allow("b"), _deny("c"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.INTERSECT, ["a", "b", "c"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.DENY

    def test_escalate_beats_allow(self):
        """meet: ESCALATE ∧ ALLOW = ESCALATE."""
        c = self._c(_allow("a"), _escalate("b"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.INTERSECT, ["a", "b"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ESCALATE


# ── MAJORITY ──────────────────────────────────────────────────────────────────

class TestPolicySetMajority:
    def _c(self, *policies):
        c = PolicyComposer()
        for p in policies:
            c.register(p)
        return c

    def test_majority_allow(self):
        """2 of 3 ALLOW → ALLOW."""
        c = self._c(_allow("a"), _allow("b"), _deny("c"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.MAJORITY, ["a", "b", "c"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ALLOW

    def test_majority_deny(self):
        """1 of 3 ALLOW → DENY."""
        c = self._c(_allow("a"), _deny("b"), _deny("c"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.MAJORITY, ["a", "b", "c"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.DENY

    def test_exactly_half_is_deny(self):
        """Tie (50%) does not reach majority → DENY."""
        c = self._c(_allow("a"), _deny("b"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.MAJORITY, ["a", "b"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.DENY

    def test_unanimous_allow(self):
        c = self._c(_allow("a"), _allow("b"), _allow("c"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.MAJORITY, ["a", "b", "c"])],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ALLOW


# ── Multi-group policy_set ────────────────────────────────────────────────────

class TestPolicySetMultiGroup:
    def test_two_groups_first_passes_second_fails(self):
        """
        Group 1: UNION [allow, deny] → ALLOW
        Group 2: INTERSECT [deny, deny] → DENY
        Final: meet(ALLOW, DENY) = DENY
        """
        c = PolicyComposer()
        c.register(_allow("a"))
        c.register(_deny("b"))
        c.register(_deny("c"))
        ps = TarlPolicySet(
            name="gate",
            groups=[
                (SetOp.UNION, ["a", "b"]),
                (SetOp.INTERSECT, ["b", "c"]),
            ],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.DENY

    def test_two_groups_both_pass(self):
        """
        Group 1: UNION [allow, deny] → ALLOW
        Group 2: INTERSECT [allow, allow] → ALLOW
        Final: meet(ALLOW, ALLOW) = ALLOW
        """
        c = PolicyComposer()
        c.register(_allow("a"))
        c.register(_deny("b"))
        ps = TarlPolicySet(
            name="gate",
            groups=[
                (SetOp.UNION, ["a", "b"]),
                (SetOp.INTERSECT, ["a", "a"]),
            ],
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ALLOW

    def test_no_groups_returns_default(self):
        c = PolicyComposer()
        ps = TarlPolicySet(
            name="gate",
            default_verdict=TarlVerdict.ESCALATE,
        )
        c.register_set(ps)
        assert c.evaluate("gate", {}).verdict == TarlVerdict.ESCALATE

    def test_reason_contains_group_summaries(self):
        c = PolicyComposer()
        c.register(_allow("a"))
        ps = TarlPolicySet(
            name="gate",
            groups=[(SetOp.UNION, ["a"])],
        )
        c.register_set(ps)
        dec = c.evaluate("gate", {})
        assert "UNION" in dec.reason
        assert "gate" in dec.reason


# ── TarlRuntime.register_source ───────────────────────────────────────────────

class TestRuntimeRegisterSource:
    def test_static_list_source(self):
        rt = TarlRuntime()
        rt.register_source("trusted_ips", ["10.0.0.1", "10.0.0.2"])
        policy = PolicyParser.parse(
            "policy test:\n"
            "    when ip IN source:trusted_ips => ALLOW"
        )
        rt.set_policy(policy)
        assert rt.evaluate({"ip": "10.0.0.1"}).verdict == (
            TarlVerdict.ALLOW
        )
        assert rt.evaluate({"ip": "1.2.3.4"}).verdict == (
            TarlVerdict.DENY
        )

    def test_callable_source(self):
        data = ["admin", "operator"]

        rt = TarlRuntime()
        rt.register_source("valid_roles", lambda: data)
        policy = PolicyParser.parse(
            "policy test:\n"
            "    when role IN source:valid_roles => ALLOW"
        )
        rt.set_policy(policy)
        assert rt.evaluate({"role": "admin"}).verdict == (
            TarlVerdict.ALLOW
        )

    def test_callable_source_updated_dynamically(self):
        """Callable is re-invoked per evaluation: updates are reflected."""
        store = {"roles": ["guest"]}

        rt = TarlRuntime()
        rt.register_source("roles", lambda: store["roles"])
        policy = PolicyParser.parse(
            "policy test:\n"
            "    when role IN source:roles => ALLOW"
        )
        rt.set_policy(policy)
        assert rt.evaluate({"role": "admin"}).verdict == (
            TarlVerdict.DENY
        )
        store["roles"].append("admin")
        assert rt.evaluate({"role": "admin"}).verdict == (
            TarlVerdict.ALLOW
        )

    def test_source_absent_without_register(self):
        rt = TarlRuntime()
        policy = PolicyParser.parse(
            "policy test:\n"
            "    when role IN source:unknown_source => ALLOW"
        )
        rt.set_policy(policy)
        assert rt.evaluate({"role": "admin"}).verdict == (
            TarlVerdict.DENY
        )

    def test_failing_callable_defaults_to_empty(self):
        def bad():
            raise RuntimeError("network error")

        rt = TarlRuntime()
        rt.register_source("broken", bad)
        policy = PolicyParser.parse(
            "policy test:\n"
            "    when role IN source:broken => ALLOW"
        )
        rt.set_policy(policy)
        assert rt.evaluate({"role": "admin"}).verdict == (
            TarlVerdict.DENY
        )

    def test_chaining(self):
        rt = TarlRuntime()
        result = (
            rt
            .register_source("a", ["x"])
            .register_source("b", ["y"])
        )
        assert result is rt

    def test_source_does_not_leak_between_contexts(self):
        rt = TarlRuntime()
        rt.register_source("roles", ["admin"])
        policy = PolicyParser.parse(
            "policy test:\n"
            "    when role IN source:roles => ALLOW"
        )
        rt.set_policy(policy)
        assert rt.evaluate({"role": "admin"}).verdict == (
            TarlVerdict.ALLOW
        )
        assert rt.evaluate({"role": "guest"}).verdict == (
            TarlVerdict.DENY
        )


# ── Verdict lattice in composition ────────────────────────────────────────────

class TestVerdictLatticeInComposition:
    def test_meet_deny_deny(self):
        assert TarlVerdict.meet(
            TarlVerdict.DENY, TarlVerdict.DENY
        ) == TarlVerdict.DENY

    def test_meet_allow_allow(self):
        assert TarlVerdict.meet(
            TarlVerdict.ALLOW, TarlVerdict.ALLOW
        ) == TarlVerdict.ALLOW

    def test_meet_allow_deny(self):
        assert TarlVerdict.meet(
            TarlVerdict.ALLOW, TarlVerdict.DENY
        ) == TarlVerdict.DENY

    def test_join_deny_allow(self):
        assert TarlVerdict.join(
            TarlVerdict.DENY, TarlVerdict.ALLOW
        ) == TarlVerdict.ALLOW

    def test_join_escalate_deny(self):
        assert TarlVerdict.join(
            TarlVerdict.ESCALATE, TarlVerdict.DENY
        ) == TarlVerdict.ESCALATE

    def test_ordering_transitivity(self):
        assert TarlVerdict.DENY < TarlVerdict.ESCALATE
        assert TarlVerdict.ESCALATE < TarlVerdict.ALLOW
        assert TarlVerdict.DENY < TarlVerdict.ALLOW


# ── Backward compatibility ────────────────────────────────────────────────────

class TestBackwardCompatibility:
    def test_evaluate_policy_function_unchanged(self):
        result = evaluate_policy(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        assert result.verdict == TarlVerdict.ALLOW

    def test_tarl_runtime_evaluate_unchanged(self):
        rt = TarlRuntime()
        dec = rt.evaluate(
            {"role": "admin"},
            policy_text='when role == "admin" => ALLOW',
        )
        assert dec.verdict == TarlVerdict.ALLOW

    def test_default_deny_singleton_unchanged(self):
        assert DEFAULT_DENY.verdict == TarlVerdict.DENY
        assert "deny" in DEFAULT_DENY.reason.lower()
        assert DEFAULT_DENY.rule_index == -1

    def test_plain_tarlpolicy_still_evaluates(self):
        p = TarlPolicy(rules=[
            TarlRule('role == "admin"', TarlVerdict.ALLOW),
        ], name="simple")
        result = evaluate_policy({"role": "admin"}, policy=p)
        assert result.verdict == TarlVerdict.ALLOW

    def test_composer_evaluates_plain_policy(self):
        """Non-composed policies work through the composer unchanged."""
        p = _allow("x")
        c = PolicyComposer()
        c.register(p)
        assert c.evaluate("x", {}).verdict == TarlVerdict.ALLOW

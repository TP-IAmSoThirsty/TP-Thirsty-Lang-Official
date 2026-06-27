"""Policy-lint (C039) and ESCALATE-quorum (C050) tests."""
from utf.tarl.core import PolicyParser
from utf.tarl.escalation import ApprovalIssuer, QuorumResolver
from utf.tarl.linter import lint_passes, lint_policy
from utf.tarl.runtime import TarlRuntime
from utf.tarl.spec import TarlVerdict

# ── C039: broad-ALLOW policy linting ───────────────────────────────────────────

def test_unconditional_allow_is_flagged_high():
    policy = PolicyParser.parse('policy p\nwhen true => ALLOW\n')
    findings = lint_policy(policy)
    codes = {f.code: f for f in findings}
    assert "TARL-LINT-BROAD-ALLOW" in codes
    assert codes["TARL-LINT-BROAD-ALLOW"].severity == "high"
    assert not lint_passes(policy)


def test_ungated_allow_is_flagged_medium():
    policy = PolicyParser.parse(
        'policy p\nwhen action == "read" => ALLOW\nwhen true => DENY\n'
    )
    codes = {f.code for f in lint_policy(policy)}
    assert "TARL-LINT-UNGATED-ALLOW" in codes


def test_authority_gated_allow_is_clean():
    policy = PolicyParser.parse(
        'policy p\n'
        'when role == "admin" => ALLOW\n'
        'when authority_authenticated == true => ALLOW\n'
        'when true => DENY\n'
    )
    findings = lint_policy(policy)
    assert all(f.code != "TARL-LINT-UNGATED-ALLOW" for f in findings)
    assert all(f.code != "TARL-LINT-BROAD-ALLOW" for f in findings)


def test_missing_default_deny_is_flagged_low():
    policy = PolicyParser.parse('policy p\nwhen role == "admin" => ALLOW\n')
    codes = {f.code for f in lint_policy(policy)}
    assert "TARL-LINT-NO-DEFAULT-DENY" in codes


def test_lint_passes_threshold():
    clean = PolicyParser.parse(
        'policy p\nwhen role == "admin" => ALLOW\nwhen true => DENY\n'
    )
    assert lint_passes(clean)
    assert lint_passes(clean, max_severity="high")


# ── C050: ESCALATE resolves only via signed quorum ─────────────────────────────

ESCALATE_POLICY = (
    'policy p\n'
    'when action == "wire_transfer" => ESCALATE\n'
    'when true => DENY\n'
)


def _escalated():
    rt = TarlRuntime(PolicyParser.parse(ESCALATE_POLICY))
    return rt.evaluate_with_proof({"action": "wire_transfer"})


def _resolver(threshold, issuers):
    r = QuorumResolver(threshold)
    for iss in issuers:
        r.add_approver_key(iss.key_id, iss.public_key_bytes())
    return r


def test_escalate_with_quorum_becomes_allow():
    decision, proof = _escalated()
    assert decision.verdict == TarlVerdict.ESCALATE
    alice = ApprovalIssuer("alice", "ka", bytes(range(32)))
    bob = ApprovalIssuer("bob", "kb", bytes([1] * 32))
    resolver = _resolver(2, [alice, bob])
    result = resolver.resolve(
        decision, proof, [alice.approve(proof), bob.approve(proof)]
    )
    assert result.decision.verdict == TarlVerdict.ALLOW
    assert result.approvals_counted == 2


def test_below_threshold_stays_escalate():
    decision, proof = _escalated()
    alice = ApprovalIssuer("alice", "ka", bytes(range(32)))
    resolver = _resolver(2, [alice])
    result = resolver.resolve(decision, proof, [alice.approve(proof)])
    assert result.decision.verdict == TarlVerdict.ESCALATE
    assert result.approvals_counted == 1


def test_one_approver_cannot_satisfy_quorum_with_duplicates():
    decision, proof = _escalated()
    alice = ApprovalIssuer("alice", "ka", bytes(range(32)))
    resolver = _resolver(2, [alice])
    # Two approvals from the SAME approver count once.
    result = resolver.resolve(
        decision, proof, [alice.approve(proof), alice.approve(proof)]
    )
    assert result.decision.verdict == TarlVerdict.ESCALATE
    assert result.approvals_counted == 1


def test_approval_for_a_different_decision_is_not_counted():
    decision, proof = _escalated()
    other_decision, other_proof = _escalated()  # distinct context? same here
    alice = ApprovalIssuer("alice", "ka", bytes(range(32)))
    bob = ApprovalIssuer("bob", "kb", bytes([1] * 32))
    resolver = _resolver(2, [alice, bob])
    # Bob signs a DIFFERENT context (simulate by tampering the approval).
    bad = bob.approve(other_proof)
    bad.context_hash = "sha256:different"
    result = resolver.resolve(decision, proof, [alice.approve(proof), bad])
    assert result.decision.verdict == TarlVerdict.ESCALATE
    assert result.approvals_counted == 1


def test_unknown_approver_key_is_not_counted():
    decision, proof = _escalated()
    alice = ApprovalIssuer("alice", "ka", bytes(range(32)))
    rogue = ApprovalIssuer("mallory", "km", bytes([9] * 32))
    resolver = _resolver(2, [alice])  # rogue's key not registered
    result = resolver.resolve(
        decision, proof, [alice.approve(proof), rogue.approve(proof)]
    )
    assert result.decision.verdict == TarlVerdict.ESCALATE
    assert result.approvals_counted == 1

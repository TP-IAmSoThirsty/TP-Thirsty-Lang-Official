"""
T.A.R.L. CLI — Evaluate and analyze TARL policy files.
"""
import argparse
import dataclasses
import json
import sys

from utf.tarl.core import PolicyParser, evaluate_policy


def main():
    from utf.console import enable_utf8
    enable_utf8()
    parser = argparse.ArgumentParser(
        description=(
            "T.A.R.L. (Thirsty's Active Resistance Language)"
            " — Policy Evaluator"
        )
    )
    subparsers = parser.add_subparsers(dest='command', help='Sub-commands')

    # eval
    eval_parser = subparsers.add_parser(
        'eval', help='Evaluate a policy file against context'
    )
    eval_parser.add_argument('policy_file', help='Path to .tarl policy file')
    eval_parser.add_argument(
        '--context', '-c', default='{}',
        help='JSON context dict (e.g. \'{"role":"admin"}\')',
    )
    eval_parser.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON'
    )

    # parse
    parse_parser = subparsers.add_parser(
        'parse', help='Parse and display a policy file'
    )
    parse_parser.add_argument('policy_file', help='Path to .tarl policy file')

    # verify
    verify_parser = subparsers.add_parser(
        'verify', help='Verify an evaluation proof certificate'
    )
    verify_parser.add_argument('proof_file', help='Path to proof JSON file')
    verify_parser.add_argument(
        '--policy', '-p', default=None,
        help='Policy file to verify policy_hash against (optional)',
    )
    verify_parser.add_argument(
        '--hmac-key', '-k', default=None, metavar='ID:HEX',
        help='HMAC key as key_id:hex_secret (e.g. key1:deadbeef...)',
    )
    verify_parser.add_argument(
        '--ed25519-key', default=None, metavar='ID:HEX',
        help='Ed25519 public key as key_id:hex_public_key '
             '(deprecated: hex on argv is exposed; prefer --ed25519-key-file)',
    )
    verify_parser.add_argument(
        '--ed25519-key-file', action='append', default=None, metavar='FILE',
        help='Ed25519 public key file from "tarl keygen" (repeatable, so '
             'rotated keys can be verified side by side)',
    )
    verify_parser.add_argument(
        '--require-signature', action='store_true',
        help='Strict: reject unsigned proofs',
    )
    verify_parser.add_argument(
        '--ed25519-only', action='store_true',
        help='Strict: reject any non-Ed25519 (e.g. HMAC) signature',
    )
    verify_parser.add_argument(
        '--max-age', type=float, default=None, metavar='SECONDS',
        help='Strict: reject a proof older than SECONDS (freshness)',
    )
    verify_parser.add_argument(
        '--revoked-policy-hash', action='append', default=None, metavar='HASH',
        help='Reject proofs bound to this policy hash (repeatable)',
    )
    verify_parser.add_argument(
        '--revocation-store', default=None, metavar='DB',
        help='Durable revocation store (SQLite); revoked hashes are loaded and '
             'rejected (combine with --revoked-policy-hash)',
    )
    verify_parser.add_argument(
        '--replay-db', default=None, metavar='DB',
        help='Durable replay store (SQLite); a proof already recorded here is '
             'rejected as a replay across processes',
    )
    verify_parser.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON'
    )

    # lint
    lint_parser = subparsers.add_parser(
        'lint', help='Lint a policy for over-broad/unsafe grants'
    )
    lint_parser.add_argument('policy_file', help='Path to .tarl policy file')
    lint_parser.add_argument(
        '--max-severity', choices=['low', 'medium', 'high'], default='low',
        help='Exit non-zero if any finding meets/exceeds this severity',
    )
    lint_parser.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON'
    )

    # audit
    audit_parser = subparsers.add_parser(
        'audit', help='Query the temporal audit archive'
    )
    audit_sub = audit_parser.add_subparsers(
        dest='audit_command', help='Audit sub-commands'
    )
    audit_chain = audit_sub.add_parser(
        'verify-chain', help='Verify the audit hash chain is intact'
    )
    audit_chain.add_argument(
        '--db', default='tarl_audit.db',
        help='Path to audit database (default: tarl_audit.db)',
    )
    audit_chain.add_argument(
        '--checkpoint', default=None, metavar='FILE',
        help='Trusted external head checkpoint to compare against (detects '
             'suffix rewrite/truncation); see "audit checkpoint"',
    )
    audit_chain.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON'
    )
    audit_checkpoint = audit_sub.add_parser(
        'checkpoint', help='Write the current audit chain head to a file'
    )
    audit_checkpoint.add_argument(
        '--db', default='tarl_audit.db',
        help='Path to audit database (default: tarl_audit.db)',
    )
    audit_checkpoint.add_argument(
        '--out', '-o', default=None, metavar='FILE',
        help='File to write the head hash to (default: stdout)',
    )
    audit_query = audit_sub.add_parser(
        'query', help='Query stored evaluation proofs'
    )
    audit_query.add_argument(
        '--db', default='tarl_audit.db',
        help='Path to audit database (default: tarl_audit.db)',
    )
    audit_query.add_argument(
        '--verdict', '-v', default=None,
        choices=['ALLOW', 'DENY', 'ESCALATE'],
        help='Filter by verdict',
    )
    audit_query.add_argument(
        '--from', dest='from_dt', default=None, metavar='ISO_DATE',
        help='Lower bound on evaluated_at (ISO-8601)',
    )
    audit_query.add_argument(
        '--to', dest='to_dt', default=None, metavar='ISO_DATE',
        help='Upper bound on evaluated_at (ISO-8601)',
    )
    audit_query.add_argument(
        '--limit', '-n', type=int, default=100,
        help='Maximum number of results (default: 100)',
    )
    audit_query.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON array'
    )

    # keygen
    keygen_parser = subparsers.add_parser(
        'keygen', help='Generate an Ed25519 trust-root keypair'
    )
    keygen_parser.add_argument(
        'role',
        choices=['authority-issuer', 'proof-signer', 'time-authority'],
        help='Which trust root the key is for',
    )
    keygen_parser.add_argument(
        '--key-id', required=True, help='Identifier stamped into the key',
    )
    keygen_parser.add_argument(
        '--out', '-o', required=True, metavar='FILE',
        help='Private key file to write (created 0600)',
    )
    keygen_parser.add_argument(
        '--pub', default=None, metavar='FILE',
        help='Public key file to write (default: <out>.pub)',
    )
    keygen_parser.add_argument(
        '--rotate', action='store_true',
        help='Rotation: print guidance to keep prior public keys registered',
    )
    keygen_parser.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON'
    )

    # revoke
    revoke_parser = subparsers.add_parser(
        'revoke', help='Manage the durable policy-revocation store'
    )
    revoke_parser.add_argument(
        'policy_hash', nargs='?', default=None,
        help='Policy hash to revoke (e.g. sha256:...)',
    )
    revoke_parser.add_argument(
        '--store', default='tarl_revocations.db', metavar='DB',
        help='Path to revocation store (default: tarl_revocations.db)',
    )
    revoke_parser.add_argument(
        '--reason', default='', help='Optional reason recorded with the entry',
    )
    revoke_parser.add_argument(
        '--remove', action='store_true', help='Un-revoke the given policy hash',
    )
    revoke_parser.add_argument(
        '--list', action='store_true', help='List all revoked policy hashes',
    )
    revoke_parser.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON'
    )

    # explain
    explain_parser = subparsers.add_parser(
        'explain', help='Explain why a context received a verdict'
    )
    explain_parser.add_argument('policy_file', help='Path to .tarl policy file')
    explain_parser.add_argument(
        '--context', '-c', default='{}',
        help='JSON context dict (e.g. \'{"role":"admin"}\')',
    )
    explain_parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Show skipped rules (those after the first match)',
    )
    explain_parser.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON'
    )

    # test
    test_parser = subparsers.add_parser(
        'test', help='Run .tarl_test test suites'
    )
    test_parser.add_argument(
        'path', nargs='?', default='.',
        help=(
            'Path to a .tarl_test file or directory to scan recursively '
            '(default: current directory)'
        ),
    )
    test_parser.add_argument(
        '--json', '-j', action='store_true', help='Output results as JSON'
    )

    # analyze
    analyze_parser = subparsers.add_parser(
        'analyze', help='Static analysis (requires z3-solver)'
    )
    analyze_parser.add_argument(
        'mode',
        choices=['coverage', 'shadows', 'conflicts', 'equiv', 'refines'],
        help=(
            'coverage: find DEFAULT-DENY gaps; '
            'shadows: find dead rules; '
            'conflicts: find overlapping rules with different verdicts; '
            'equiv: prove two policies are equivalent; '
            'refines: prove strict is a subset of permissive'
        ),
    )
    analyze_parser.add_argument('policy_files', nargs='+',
                                help='Policy file(s)')
    analyze_parser.add_argument(
        '--json', '-j', action='store_true', help='Output as JSON'
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == 'eval':
        _cmd_eval(args)
    elif args.command == 'parse':
        _cmd_parse(args)
    elif args.command == 'verify':
        _cmd_verify(args)
    elif args.command == 'lint':
        _cmd_lint(args)
    elif args.command == 'audit':
        _cmd_audit(args)
    elif args.command == 'keygen':
        _cmd_keygen(args)
    elif args.command == 'revoke':
        _cmd_revoke(args)
    elif args.command == 'explain':
        _cmd_explain(args)
    elif args.command == 'test':
        _cmd_test(args)
    elif args.command == 'analyze':
        _cmd_analyze(args)


# ── eval ──────────────────────────────────────────────────────────────────────

def _cmd_eval(args):
    with open(args.policy_file) as f:
        policy_text = f.read()
    try:
        context = json.loads(args.context)
    except json.JSONDecodeError as e:
        print(f"Error parsing context JSON: {e}", file=sys.stderr)
        sys.exit(1)
    decision = evaluate_policy(context, policy_text=policy_text)
    if args.json:
        print(json.dumps({
            'verdict': decision.verdict.value,
            'reason': decision.reason,
            'rule_index': decision.rule_index,
            'matched_rule': decision.matched_rule,
        }, indent=2))
    else:
        print(f"Verdict: {decision.verdict.value}")
        print(f"Reason:  {decision.reason}")
        if decision.rule_index >= 0:
            print(f"Rule #:  {decision.rule_index}")
        if decision.matched_rule:
            print(f"Rule:    {decision.matched_rule}")


# ── parse ─────────────────────────────────────────────────────────────────────

def _cmd_parse(args):
    with open(args.policy_file) as f:
        policy_text = f.read()
    policy = PolicyParser.parse(policy_text)
    print(f"Policy: {policy.name}")
    print(f"Rules:  {len(policy.rules)}")
    print()
    for i, rule in enumerate(policy.rules):
        print(f"  [{i}] when {rule.condition} => {rule.verdict.value}")


# ── verify ───────────────────────────────────────────────────────────────────

def _cmd_verify(args):
    from utf.tarl.spec import TarlProof
    from utf.tarl.verifier import ProofVerifier

    try:
        with open(args.proof_file) as f:
            proof = TarlProof.from_json(f.read())
    except (OSError, KeyError, ValueError) as e:
        print(f"Error reading proof: {e}", file=sys.stderr)
        sys.exit(1)

    policy_source = None
    if args.policy:
        try:
            with open(args.policy) as f:
                policy_source = f.read()
        except OSError as e:
            print(f"Error reading policy: {e}", file=sys.stderr)
            sys.exit(1)

    revoked = set(getattr(args, "revoked_policy_hash", None) or [])
    if getattr(args, "revocation_store", None):
        from utf.tarl.durable import RevocationStore
        with RevocationStore(args.revocation_store) as store:
            revoked |= store.all()
    replay_guard = None
    if getattr(args, "replay_db", None):
        from utf.tarl.durable import DurableReplayGuard
        replay_guard = DurableReplayGuard(args.replay_db)
    verifier = ProofVerifier(
        require_signature=getattr(args, "require_signature", False),
        allowed_signature_algorithms=(
            {"ed25519"} if getattr(args, "ed25519_only", False) else None
        ),
        max_age_seconds=getattr(args, "max_age", None),
        revoked_policy_hashes=revoked or None,
        replay_guard=replay_guard,
    )
    if args.hmac_key:
        try:
            key_id, _, hex_secret = args.hmac_key.partition(":")
            verifier.add_hmac_key(key_id, bytes.fromhex(hex_secret))
        except ValueError as e:
            print(f"Invalid --hmac-key format: {e}", file=sys.stderr)
            sys.exit(1)
    if args.ed25519_key:
        try:
            key_id, _, hex_public = args.ed25519_key.partition(":")
            verifier.add_ed25519_key(key_id, bytes.fromhex(hex_public))
        except ValueError as e:
            print(f"Invalid --ed25519-key format: {e}", file=sys.stderr)
            sys.exit(1)
    for key_path in (getattr(args, "ed25519_key_file", None) or []):
        from utf.tarl import keystore
        try:
            kf = keystore.load(key_path)
            verifier.add_ed25519_key(kf.key_id, kf.public_bytes())
        except (OSError, ValueError) as e:
            print(f"Invalid --ed25519-key-file {key_path!r}: {e}",
                  file=sys.stderr)
            sys.exit(1)

    result = verifier.verify(proof, policy_source=policy_source)
    if replay_guard is not None:
        replay_guard.close()

    if args.json:
        print(json.dumps({
            "valid": result.valid,
            "message": result.message,
            "checks": dict(result.checks.items()),
        }, indent=2))
    else:
        print(result.summary)

    sys.exit(0 if result.valid else 1)


# ── lint ─────────────────────────────────────────────────────────────────────

def _cmd_lint(args):
    from utf.tarl.linter import lint_passes, lint_policy

    with open(args.policy_file) as f:
        policy = PolicyParser.parse(f.read())
    findings = lint_policy(policy)

    if args.json:
        print(json.dumps([
            {"rule_index": fi.rule_index, "severity": fi.severity,
             "code": fi.code, "message": fi.message}
            for fi in findings
        ], indent=2))
    else:
        if not findings:
            print("No policy-lint findings.")
        for fi in findings:
            print(fi)

    sys.exit(0 if lint_passes(policy, max_severity=args.max_severity) else 1)


# ── audit ────────────────────────────────────────────────────────────────────

def _cmd_audit(args):
    from utf.tarl.archive import TarlAuditArchive

    if args.audit_command == 'verify-chain':
        expected_head = None
        if getattr(args, "checkpoint", None):
            try:
                with open(args.checkpoint) as f:
                    expected_head = f.read().strip()
            except OSError as e:
                print(f"Error reading checkpoint: {e}", file=sys.stderr)
                sys.exit(1)
        try:
            with TarlAuditArchive(args.db) as arc:
                result = arc.verify_chain(expected_head=expected_head)
        except Exception as e:
            print(f"Error reading archive: {e}", file=sys.stderr)
            sys.exit(1)
        if args.json:
            print(json.dumps({
                "valid": result.valid, "length": result.length,
                "broken_at": result.broken_at, "reason": result.reason,
            }, indent=2))
        else:
            print(result)
        sys.exit(0 if result.valid else 1)

    if args.audit_command == 'checkpoint':
        try:
            with TarlAuditArchive(args.db) as arc:
                head = arc.head_hash()
        except Exception as e:
            print(f"Error reading archive: {e}", file=sys.stderr)
            sys.exit(1)
        if getattr(args, "out", None):
            with open(args.out, "w") as f:
                f.write(head + "\n")
            print(f"Wrote checkpoint {head} to {args.out}")
        else:
            print(head)
        sys.exit(0)

    if args.audit_command != 'query':
        print("Usage: tarl audit (query | verify-chain | checkpoint) "
              "[options]", file=sys.stderr)
        sys.exit(1)

    try:
        with TarlAuditArchive(args.db) as arc:
            proofs = arc.query(
                verdict=args.verdict,
                from_dt=args.from_dt,
                to_dt=args.to_dt,
                limit=args.limit,
            )
    except Exception as e:
        print(f"Error reading archive: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps([p.to_dict() for p in proofs], indent=2))
    else:
        if not proofs:
            print("No proofs found.")
        for p in proofs:
            flag = " [SIGNED]" if p.signature else ""
            print(
                f"{p.evaluated_at}  {p.verdict.value:<9} "
                f"rule={p.rule_index:<3}{flag}"
            )
        print(f"\n{len(proofs)} proof(s) returned.")


# ── keygen ───────────────────────────────────────────────────────────────────

def _cmd_keygen(args):
    from utf.tarl import keystore

    key = keystore.generate(args.key_id, args.role)
    pub_path = args.pub or (args.out + ".pub")
    key.write(args.out, include_private=True)
    key.public_only().write(pub_path, include_private=False)

    if args.json:
        print(json.dumps({
            "key_id": key.key_id, "role": key.role,
            "public_key": key.public_key_hex,
            "private_file": args.out, "public_file": pub_path,
        }, indent=2))
    else:
        print(f"Generated {key.role} key {key.key_id!r}")
        print(f"  private: {args.out} (0600)")
        print(f"  public:  {pub_path}")
        print(f"  public_key: {key.public_key_hex}")
        if args.rotate:
            print("\nRotation: keep the PREVIOUS public key(s) registered with "
                  "verifiers until all\nin-flight artifacts signed by the old "
                  "key have expired, then retire them.")
    sys.exit(0)


# ── revoke ───────────────────────────────────────────────────────────────────

def _cmd_revoke(args):
    from utf.tarl.durable import RevocationStore

    with RevocationStore(args.store) as store:
        if args.list:
            entries = store.entries()
            if args.json:
                print(json.dumps([
                    {"policy_hash": h, "revoked_at": t, "reason": r}
                    for h, t, r in entries
                ], indent=2))
            else:
                if not entries:
                    print("No revoked policies.")
                for h, t, r in entries:
                    suffix = f"  ({r})" if r else ""
                    print(f"{t}  {h}{suffix}")
            sys.exit(0)

        if not args.policy_hash:
            print("Usage: tarl revoke <policy_hash> | --list | "
                  "--remove <policy_hash>", file=sys.stderr)
            sys.exit(1)

        if args.remove:
            removed = store.remove(args.policy_hash)
            print(f"{'Removed' if removed else 'Not present'}: "
                  f"{args.policy_hash}")
            sys.exit(0)

        added = store.add(args.policy_hash, reason=args.reason)
        print(f"{'Revoked' if added else 'Already revoked'}: "
              f"{args.policy_hash}")
        sys.exit(0)


# ── explain ──────────────────────────────────────────────────────────────────

def _cmd_explain(args):
    from utf.tarl.explainer import TarlExplainer

    with open(args.policy_file) as f:
        policy_text = f.read()
    try:
        context = json.loads(args.context)
    except json.JSONDecodeError as e:
        print(f"Error parsing context JSON: {e}", file=sys.stderr)
        sys.exit(1)

    exp = TarlExplainer().explain(context, policy_text=policy_text)

    if args.json:
        print(json.dumps(exp.to_dict(), indent=2))
    else:
        print(exp.format(verbose=getattr(args, 'verbose', False)))


# ── test ──────────────────────────────────────────────────────────────────────

def _cmd_test(args):
    from utf.tarl.tester import TarlTestRunner

    runner = TarlTestRunner()
    path = args.path

    import os
    if os.path.isfile(path):
        suite_results = [runner.run_file(path)]
    else:
        suite_results = runner.run_directory(path)

    if not suite_results:
        print("No .tarl_test files found.", file=sys.stderr)
        sys.exit(1)

    total = sum(s.total for s in suite_results)
    passed = sum(s.passed for s in suite_results)
    failed = sum(s.failed for s in suite_results)
    errors = sum(1 for s in suite_results if s.load_error)

    if args.json:
        out = []
        for s in suite_results:
            entry = {
                "file": s.file_path,
                "total": s.total,
                "passed": s.passed,
                "failed": s.failed,
                "load_error": s.load_error,
                "results": [
                    {
                        "name": r.name,
                        "passed": r.passed,
                        "expected": r.expected.value,
                        "actual": r.actual.value,
                        "expected_rule": r.expected_rule,
                        "actual_rule": r.actual_rule,
                        "error": r.error,
                    }
                    for r in s.results
                ],
            }
            out.append(entry)
        print(json.dumps(out, indent=2))
    else:
        for s in suite_results:
            print(s)

        summary = f"\n{passed}/{total} passed"
        if errors:
            summary += f", {errors} file error(s)"
        print(summary)

    sys.exit(0 if failed == 0 and errors == 0 else 1)


# ── analyze ───────────────────────────────────────────────────────────────────

def _cmd_analyze(args):
    from utf.tarl.analyzer import PolicyAnalyzer  # lazy: z3 optional
    from utf.tarl.spec import TarlPolicy

    mode = args.mode
    policies = []
    for path in args.policy_files:
        try:
            with open(path) as f:
                text = f.read()
            items = PolicyParser.parse_all(text)
            for item in items:
                if isinstance(item, TarlPolicy):
                    policies.append(item)
                    break
            else:
                policies.append(PolicyParser.parse(text))
        except OSError as e:
            print(f"Error reading {path}: {e}", file=sys.stderr)
            sys.exit(1)

    if mode in ('equiv', 'refines') and len(policies) < 2:
        print(f"'{mode}' requires two policy files", file=sys.stderr)
        sys.exit(1)

    if mode == 'coverage':
        result = PolicyAnalyzer(policies[0]).check_coverage()
    elif mode == 'shadows':
        result = PolicyAnalyzer(policies[0]).check_shadows()
    elif mode == 'conflicts':
        result = PolicyAnalyzer(policies[0]).check_conflicts()
    elif mode == 'equiv':
        result = PolicyAnalyzer.check_equiv(policies[0], policies[1])
    else:
        result = PolicyAnalyzer.check_refines(policies[0], policies[1])

    if args.json:
        print(json.dumps(_result_to_dict(result), indent=2))
    else:
        print(result.summary)

    sys.exit(0 if result.passed else 1)


def _result_to_dict(result) -> dict:
    d = dataclasses.asdict(result)
    for s in d.get("shadows", []):
        s["verdict"] = str(s["verdict"])
    return d


if __name__ == '__main__':
    main()

"""
T.A.R.L. CLI — Evaluate TARL policy files against context.
"""
import argparse
import sys
import json
from utf.tarl.core import PolicyParser, evaluate_policy
from tarl.spec import TarlDecision, DEFAULT_DENY


def main():
    parser = argparse.ArgumentParser(
        description="T.A.R.L. (Thirsty's Active Resistance Language) — Policy Evaluator"
    )
    subparsers = parser.add_subparsers(dest='command', help='Sub-commands')

    # eval command
    eval_parser = subparsers.add_parser('eval', help='Evaluate a policy file against context')
    eval_parser.add_argument('policy_file', help='Path to .tarl policy file')
    eval_parser.add_argument('--context', '-c', default='{}',
                             help='JSON context dict (e.g. \'{"role":"admin"}\')')
    eval_parser.add_argument('--json', '-j', action='store_true',
                             help='Output as JSON')

    # parse command
    parse_parser = subparsers.add_parser('parse', help='Parse and display a policy file')
    parse_parser.add_argument('policy_file', help='Path to .tarl policy file')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == 'eval':
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

    elif args.command == 'parse':
        with open(args.policy_file) as f:
            policy_text = f.read()

        policy = PolicyParser.parse(policy_text)
        print(f"Policy: {policy.name}")
        print(f"Rules:  {len(policy.rules)}")
        print()
        for i, rule in enumerate(policy.rules):
            print(f"  [{i}] when {rule.condition} => {rule.verdict.value}")


if __name__ == '__main__':
    main()
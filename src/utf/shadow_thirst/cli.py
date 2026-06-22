"""
Shadow Thirst CLI — Check mutations and visualize promotion flow.
"""
import argparse
import sys
import json
from utf.shadow_thirst.core import (
    MutationParser, PromotionEngine, AnalysisLevel
)


def main():
    from utf.console import enable_utf8
    enable_utf8()
    parser = argparse.ArgumentParser(
        description="Shadow Thirst — Mutation Analysis and Promotion Engine"
    )
    subparsers = parser.add_subparsers(dest='command', help='Sub-commands')

    # check command
    check_parser = subparsers.add_parser('check', help='Analyze a mutation file')
    check_parser.add_argument('mutation_file', help='Path to mutation file')
    check_parser.add_argument('--json', '-j', action='store_true',
                              help='Output as JSON')

    # visualize command
    viz_parser = subparsers.add_parser('visualize', help='Generate Mermaid flowchart')
    viz_parser.add_argument('mutation_file', help='Path to mutation file')
    viz_parser.add_argument('--output', '-o', help='Output file (default stdout)')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Read the mutation file
    try:
        with open(args.mutation_file) as f:
            source = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.mutation_file}' not found", file=sys.stderr)
        sys.exit(1)

    # Parse the mutation
    try:
        module = MutationParser.parse(source)
    except ValueError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    engine = PromotionEngine()

    if args.command == 'check':
        verdict, results = engine.evaluate(module)

        if args.json:
            output = {
                'name': module.name,
                'verdict': verdict,
                'replay_hash': module.replay_hash(),
                'results': [
                    {
                        'analyzer': r.analyzer,
                        'passed': r.passed,
                        'level': r.level,
                        'message': r.message
                    }
                    for r in results
                ]
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"Mutation:    {module.name}")
            print(f"Replay Hash: {module.replay_hash()}")
            print(f"{'─' * 60}")
            for r in results:
                status = "✅" if r.passed else "❌"
                level_tag = "[CRITICAL]" if r.level == AnalysisLevel.CRITICAL else "[WARN]"
                print(f"  {status} {level_tag} {r.analyzer}")
                print(f"     {r.message}")
            print(f"{'─' * 60}")
            verdict_icon = "🚀" if verdict == "PROMOTE" else "❌" if verdict == "REJECT" else "⚠️"
            print(f"  {verdict_icon} VERDICT: {verdict}")

    elif args.command == 'visualize':
        verdict, results = engine.evaluate(module)
        mermaid = engine.generate_mermaid(module, verdict, results)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(mermaid)
            print(f"Mermaid flowchart written to {args.output}")
        else:
            print(mermaid)


if __name__ == '__main__':
    main()
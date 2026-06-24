# Operational Continuity Map

Workstream: **Fix operator precedence + governance fail-open** (audit remediation)
Updated: 2026-06-23
Branch: `fix/operator-precedence-governance` (off `master`)
Workspace: `thirsty_lang_exploration_0754`

## Current State

Five audit findings remediated on one branch. Full suite green (652 passed),
ruff clean. Implemented and test-verified locally; **not committed** (awaiting
review) and **black not run** (not installed in this environment).

## Files Inspected

- `src/utf/thirsty_lang/parser.py` — `_parse_expr`, precedence table, unary prefix.
- `src/utf/thirsty_lang/interpreter.py` — `_gate_capability`, `_enforce_governance`.
- `src/utf/tarl/spec.py`, `runtime.py`, `verifier.py`, `archive.py` — proof model.
- `src/utf/thirsty_lang/checker.py`, `diagnostics.py`, `ast.py` — E051/E052.
- `tests/test_verifiers.py` — taint-alias + cascade→spillage (already covered).

## Files Created

- `tests/test_parser_precedence.py` — precedence/associativity + overdraft guard.
- `tests/test_gate_fail_closed.py` — fail-closed gate + proof-carrying contracts.
- `src/utf/examples/governed_agent_runner/policy.tarl` — wired policy so the one
  governed example that does I/O runs under enforced (not implied) governance.
- `docs/operations/CONTINUITY_MAP.md` — this file.

## Files Modified

- `parser.py` — capture operator precedence *before* advancing; left-assoc binary
  recurses at `op_prec`, right-assoc assign at `op_prec - 1`; `UNARY_PRECEDENCE`
  (8) for `-`, `NOT_PRECEDENCE` (4) for `not`.
- `interpreter.py` — `_gate_capability` fail-closed; `_make_decision_proof` +
  `_make_contract_proof`; contract ALLOW/DENY carry proofs.
- `checker.py` / `diagnostics.py` / `ast.py` — remove dead E051/E052.
- `spec.py` / `runtime.py` / `README.md` / `docs/governance_model.md` — proof
  signing docs-truth (unsigned-by-default, symmetric MAC, no Ed25519).
- `CHANGELOG.md` — Unreleased entries; corrected 0.4.0 "signed proof" wording.
- `tests/test_examples.py` — attach sibling `policy.tarl` for governed examples.
- `tests/test_governance_maximal.py` — `test_gate_inactive_without_policy`
  rewritten to `test_gate_fail_closed_without_policy` (asserts DENY).

## Files Deleted

None.

## Commands Run

- `PYTHONPATH=src python -m pytest tests/ -q` → **652 passed, 7 subtests**.
- `PYTHONPATH=src python -m pytest tests/test_parser_precedence.py
  tests/test_gate_fail_closed.py -q` → **28 passed**.
- `PYTHONPATH=src python -m ruff check src/ tests/` → **All checks passed**.
- Interpreter reproductions of the audit's five precedence rows + overdraft
  guard + fail-closed write (see Tests / Verification).

## Tests / Verification

- **Verified by pytest:** 652 passed (was 623 pre-change; +28 new tests, +1 new
  `policy.tarl` parse test, −1 renamed test → net +28).
- **Verified by interpreter:** `2 * 3 + 4` → 10, `10 - 2 - 3` → 5, `20/2/5` → 2,
  `1 + 2 * 3 + 4` → 11, `2 + 3 == 5` → True; `100 - 200 >= 0` → False; overdraft
  `withdraw(100,200)` → DENIED, `withdraw(100,50)` → 50; governed `pour` with no
  policy → DENIED with a DENY proof; core `pour` → runs.
- **Verified by ruff:** clean across `src/` and `tests/`.
- **Not verified:** black formatting (black not installed here); full pre-commit
  hook run.

## Completed Work

All five audit tiers: Critical (precedence), High (fail-closed gate), Medium
(contract proofs + signing docs-truth), Low (dead diagnostics).

## Known Failures

None in the suite.

## Blockers

None.

## Risks

- **Behavioral break (expected):** correct precedence changes the value of any
  program/test that relied on the old parse. The suite surfaced two such cases,
  both reviewed and updated as real semantic changes (the fail-open gate test and
  the governed example), not patched green.
- **black not run** in this environment; pre-commit `black` could still reformat.
  ruff passed and new code matches the surrounding black-formatted style.
- `.pytest_tmp/` is a transient test artifact (untracked); remove before commit.

## Pending Work

- Run `black` / full pre-commit before commit/push.
- Commit + open PR (not yet done — user has not requested commit/push).
- Note (`tp` remote is the push target per project convention, not `origin`).

## Next Recommended Action

Run black/pre-commit; if clean, commit on `fix/operator-precedence-governance`
and open a PR for review. The precedence fix is a breaking semantic correction —
call that out in the PR.

## Safe to Continue

Yes. Working tree changes are scoped, suite is green, no destructive actions
taken, nothing committed or pushed.

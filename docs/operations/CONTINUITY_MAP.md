# Operational Continuity Map

Workstream: **Core-language repair + new control-flow features (0.7.1 → 0.8.0)**
Updated: 2026-06-29
Branch: `master`
Workspace: `thirsty_lang_exploration_0754`

## Current State

Two releases shipped from `master`:

- **0.7.1** — corrected Tier-1 core features that were documented but broken at
  runtime (recursion, `this`/OOP, closures, `|>`, error binding, fountain field
  defaults). Published to PyPI.
- **0.8.0** — added three previously-unimplemented forms: the `times N { … }`
  loop, the C-style `refill(init; cond; step)` loop, and anonymous functions
  (lambdas, `glass(params) { … }`).

The governance layers (T.A.R.L., Shadow Thirst, capability broker, hardened
runtime, threat-model suite) are unchanged and remain the peer-reviewed source
of truth — see `docs/WHITEPAPER.md` and `docs/THREAT_MODEL.md`.

## Files Modified (core language)

- `src/utf/thirsty_lang/lexer.py` — `|>` lexes as a single PIPE token.
- `src/utf/thirsty_lang/parser.py` — `this`, member-assignment targets, lambda
  expressions, `times`, and the desugared C-style `refill`.
- `src/utf/thirsty_lang/checker.py` — recursion hoist (real signatures), `this`,
  error-binding scope, field-default checking, `times`/lambda checks.
- `src/utf/thirsty_lang/interpreter.py` — `this` binding + method dispatch,
  field default initializers, lexical closures (`_make_closure`), `error (name)`
  binding, `_execute_times`, lambda evaluation.
- `src/utf/thirsty_lang/ast.py` — `TimesStmt`, `LambdaExpr`.
- `src/utf/thirsty_lang/formatter.py` — field defaults, `times`, lambdas.

## Tests / Verification

- `tests/test_language_fixes.py` — 0.7.1 correctness regressions.
- `tests/test_new_language_features.py` — 0.8.0 features.
- Gates green: `ruff check src tests`, `mypy -p utf`, and
  `pytest tests/ -q --cov=utf --cov-fail-under=90` (1198 passed, ~91% coverage).

## Known Failures / Blockers / Risks

None. The C-style `refill` is desugared to an init statement plus a while loop,
so it reuses the existing, tested loop machinery.

## Pending / Next Recommended Action

Roadmap surface not yet implemented is tracked in `docs/STATUS.md` (rows marked
**Roadmap**). Releases push to the `tp` remote; tagging `v*` triggers the PyPI
publish workflow.

## Safe to Continue

Yes. Working tree is clean after release; suite is green.

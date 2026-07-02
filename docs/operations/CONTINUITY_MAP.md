# Operational Continuity Map

Workstream: **Proof-Carrying Effects Language + TARL 0.8.2 Peer-Review Corrections**
Updated: 2026-07-01
Branch: `master`
Workspace: `thirsty_lang_exploration_0754`

## Baseline

- Starting branch: `master`.
- Starting git state: clean before this work began.
- Baseline continuity document read before edits.
- Existing governance surfaces inspected: parser/checker/interpreter CLI build,
  T.A.R.L. policy/proof/audit APIs, capability broker, Shadow Thirst, docs, and
  threat-model tests.
- Current problems rule applied: discovered issues are either fixed or listed
  under Open Issues instead of dismissed as pre-existing.
- Dirty state rule applied: current modified/untracked files are from this
  workstream.

## Implemented

- `thirsty prove program.thirsty --policy policy.tarl --emit-manifest` emits a
  machine-readable static proof-obligation report without executing program
  side effects.
- Proof-obligation reports include functions, imports, sensitive stdlib calls,
  governed calls, required TARL actions, required capabilities, context schema,
  authority requirements, contract obligations, proof mode, audit requirement,
  build governance-loss status, Shadow status when statically visible,
  diagnostics, and unresolved proof gaps.
- Required TARL actions include capability actions and governed function-call
  actions.
- TARL policy references can derive simple context schema fields. Explicit JSON
  context schemas remain authoritative. Ambiguous or incomplete derived schemas
  fail closed in `thirsty prove`.
- Explicit JSON context schemas accept both list form and mapping form
  (`{"fields": {"name": "kind"}}`) and reject malformed entries with clear
  validation errors.
- Contract obligations preserve string literals in recorded annotations, so
  `requires path != ""` and `ensures result == "ok"` remain faithful in proof
  reports and manifests.
- `thirsty explain-denial program.thirsty --policy policy.tarl` emits a
  machine-readable explanation of missing policy, context, authority, and proof
  conditions.
- Build manifests now record source hash, optional policy hash, required
  capabilities, context schema, authority mode, proof verification mode, audit
  requirement, Shadow status when available, and governance-loss status.
- Checker-level effect warnings are available in prove/strict-style checking
  paths without changing normal checker behavior.
- TARL ordering comparisons compare numeric-looking strings numerically and
  fail closed on unorderable values instead of falling through.
- TARL policy load validates rule expressions; residual runtime evaluation
  errors produce DENY rather than skipping to a later rule.
- `ProofVerifier` and `tarl verify` reject unsigned proofs by default. Unsigned
  proof inspection must opt in explicitly with `require_signature=False` or
  `--allow-unsigned`.
- `tarl eval` refuses temporal policy windows and `CURRENT_*` builtins unless
  `--now` supplies a trusted evaluation time.
- `thirsty govern --auto-tarl` emits rules keyed on `action`, matching the
  governed runtime context.
- Package metadata is bumped to `0.8.2` for a non-colliding patch release tag.

## Files Modified

- `src/utf/thirsty_lang/proof_obligations.py` — proof-obligation model,
  extraction, derived schema, denial explanation, and effect-warning helpers.
- `src/utf/thirsty_lang/cli.py` — `prove`, `explain-denial`, and
  policy/context-aware manifest output.
- `src/utf/thirsty_lang/checker.py` — optional proof-effect warning diagnostics.
- `src/utf/thirsty_lang/parser.py` — preserves string literals when storing
  contract annotation text.
- `tests/test_proof_obligations.py` — minimum proof tests for extraction,
  schema derivation, fail-closed schema behavior, sensitive stdlib obligations,
  build manifest proof metadata, denial explanation, no-side-effect prove
  behavior, explicit schema mapping shape, contract string-literal preservation,
  and replay/audit/proof regression.
- `README.md` — user-facing CLI additions.
- `docs/STATUS.md` — implemented/tested status rows for proof obligations.
- `docs/THREAT_MODEL.md` — C051/C052 challenge rows and current evidence.
- `docs/governance_model.md` — static proof-obligation model and CLI behavior.
- `docs/operations/CONTINUITY_MAP.md` — this continuity update.
- `src/utf/tarl/core.py` — type-safe comparisons, expression validation,
  trusted-time threading, and fail-closed `evaluate_policy`.
- `src/utf/tarl/runtime.py` — fail-closed runtime rule errors and verdict-aware
  proof traces.
- `src/utf/tarl/verifier.py` — secure-by-default signature requirement and
  trace verdict checks.
- `src/utf/tarl/cli.py` — `tarl eval --now` and `tarl verify --allow-unsigned`.
- `src/utf/tarl/spec.py` — proof documentation aligned with secure verifier
  defaults.
- `tests/test_peer_review_0_8_1_tarl_regressions.py` — adversarial regression
  coverage for the five adversarial TARL review findings.
- `pyproject.toml`, `src/utf/thirsty_lang/__init__.py`, `Dockerfile`,
  `docs/WHITEPAPER.md`, `docs/LANGUAGE_SPEC.md`, and `docs/SIGNING.md` —
  0.8.2 release metadata and stale-doc corrections.

## Tested

- `python -m pytest tests/test_cli_build.py::test_build_emit_manifest -q`
  passed: 1 passed.
- `python -m pytest tests/test_proof_obligations.py -q`
  passed: 10 passed.
- `python -m pytest tests/test_cli_build.py tests/test_threat_model_build_outputs.py -q`
  passed: 23 passed.
- `python -m pytest tests/test_thirsty_lang_governance.py tests/test_tarl_proof.py tests/test_threat_model_context_schema.py -q`
  passed: 110 passed.
- `ruff check src tests` passed.
- `mypy -p utf` passed: no issues in 52 source files.
- `python -m pytest tests/ -q --cov=utf --cov-fail-under=90 --basetemp .tmp_pytest\basetemp`
  passed: 1233 passed, 1 skipped, 7 subtests passed, total coverage 90.77%.
- `python -m build --wheel --no-isolation --verbose` passed and built
  the prior patch wheel before the 0.8.2 correction work.
- `python -m build --sdist --no-isolation --verbose` passed and built
  the prior patch sdist before the 0.8.2 correction work.
- `python -m build --verbose` passed and built
  the prior patch sdist and wheel before the 0.8.2 correction work.
- Fresh venv installed the prior patch wheel and verified
  installed `thirsty` CLI support from a `C:\Temp` venv for `prove`,
  `explain-denial`, and `build --emit-manifest --policy --context-schema`,
  including no side effects during prove, explicit schema mapping, preserved
  contract strings, source and policy hashes, and governance-loss status.
- `python -m pytest tests/test_peer_review_0_8_1_tarl_regressions.py tests/test_cli_tarl.py -q`
  passed: 51 passed.
- `ruff check src tests` passed after the 0.8.2 corrections.
- `mypy -p utf` passed after the 0.8.2 corrections: no issues in 52 source
  files.
- `python -m pytest tests/ -q --cov=utf --cov-fail-under=90 --basetemp .tmp_pytest\basetemp`
  passed after the final CLI correction: 1234 passed, 1 skipped, 7 subtests
  passed, total coverage 90.75%.
- `python -m build --verbose` passed and built
  `thirsty_lang-0.8.2.tar.gz` and
  `thirsty_lang-0.8.2-py3-none-any.whl`.
- `python -m twine check dist\thirsty_lang-0.8.2.tar.gz dist\thirsty_lang-0.8.2-py3-none-any.whl`
  passed for both artifacts.
- Fresh venv installed `dist\thirsty_lang-0.8.2-py3-none-any.whl` from
  `C:\Temp\thirsty-0.8.2-smoke-final` and verified imports/version, all console
  script help commands, numeric-string DENY, malformed-policy clean CLI error,
  temporal `--now`, unsigned-proof default rejection plus explicit unsigned
  mode, and auto-TARL `action` generation.

## Not Yet Verified

- None for this workstream's acceptance gates.

## Behavior Contracts

- `thirsty prove` is a static proof-obligation extractor. It reports obligations
  and unresolved gaps before execution. Runtime TARL verdict enforcement, proof
  verification, broker mediation, and audit append behavior remain runtime
  responsibilities.
- Derived context schema is fail-closed by design. Policy expressions that
  cannot be statically resolved produce an incomplete schema and require an
  explicit schema file before `thirsty prove` can claim schema completeness.
- TARL proof verification is secure by default; unsigned proof verification is
  an explicit compatibility/inspection mode.
- Temporal CLI evaluation requires explicit trusted time when policy windows or
  temporal builtins are present.
- Shadow convergence status is reported when it is present in the statically
  extracted source metadata. `thirsty prove` does not run a separate Shadow
  analysis pass.

## Open Issues

- Git commit, GitHub push, and release tag push remain pending for the 0.8.2
  correction work.

## Resolved Validation Notes

- First `python -m build` attempt timed out after 10 minutes. A later exact
  isolated verbose build passed after build dependencies were cached.
- Installed-wheel smoke initially exposed explicit schema mapping handling and
  contract string-literal preservation bugs. Both were fixed and covered by
  regression tests plus fresh installed-wheel smoke verification.
- A venv launcher under the repo `.tmp` path was blocked by Windows Application
  Control. The same built wheel installed into a fresh `C:\Temp` venv ran the
  generated `thirsty.exe` launcher and passed the full proof/build smoke. This
  is resolved for acceptance by verifying the real console launcher from an
  allowed fresh venv path.

## Future Work

- Extend obligation extraction to richer policy expression inference if the
  TARL grammar grows structured schema declarations.
- Promote selected checker effect warnings from diagnostic-only to strict-mode
  errors if a future release defines that compatibility boundary.
- Add richer Shadow Thirst convergence integration when a stable static
  analysis hook is exposed for ordinary `.thirsty` sources.

## Safe to Continue

Yes. Targeted tests, full coverage gate, lint, type check, wheel build, sdist
build, isolated verbose package build, and fresh installed-wheel CLI smoke are
green.

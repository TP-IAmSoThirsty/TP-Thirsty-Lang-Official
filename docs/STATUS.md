# Feature Status

Every capability below is marked **Real** (implemented and enforced, with a
test that proves it) or **Roadmap** (reserved surface, not yet enforced). The
test reference is the authority — if a row says Real, the cited test fails when
the behaviour regresses. Run the whole matrix with:

```
pytest tests/ -q
```

The optional Z3 layer is exercised only when the `analysis` extra is installed
(`pip install thirsty-lang[analysis]`); its tests `importorskip("z3")` otherwise.

## Language core (Thirsty-Lang)

| Capability | Status | Test reference |
|---|---|---|
| Array / reservoir literals `[1,2,3]` evaluate to a real list | Real | `tests/test_thirsty_lang.py`; `tests/test_examples.py` |
| `flood` / `evaporate` / `new` over reservoirs and fountains | Real | `tests/test_thirsty_lang.py`; `tests/test_examples.py` |
| Variable reassignment (`x = …`) mutates the binding | Real | `tests/test_thirsty_lang.py` |
| OOP: member read/write, method dispatch (`obj.f()`, `obj.x = …`) | Real | `tests/test_thirsty_lang.py`; `tests/test_examples.py` (`gods.thirstofgods`) |
| `cascade` awaits and yields a value (not a Future) | Real | `tests/test_examples.py` |
| `spillage` / `error` / `cleanup` / `finally` control flow | Real | `tests/test_examples.py`; `tests/test_thirst_of_gods.py` |
| `refill (x in xs)` loop accumulation | Real | `tests/test_examples.py` |
| UTF-8-safe CLI output on Windows (cp1252) | Real | `src/utf/console.py` (`enable_utf8`), shared by all CLIs |
| Every shipped example parses, type-checks, and runs clean | Real | `tests/test_examples.py` |
| `let` (immutable binding), `for … in` keyword loop, `:=` (define mutable) | Real | `tests/test_language_features.py` |
| `strict` (requires initialization) / `pure` (no I/O) module modes | Real | `tests/test_language_features.py` |

## Governance (maximal)

| Capability | Status | Test reference |
|---|---|---|
| `requires` precondition on governed functions | Real | `tests/test_governance_maximal.py::TestContracts` |
| `ensures` postcondition (`result` bound after the body) | Real | `tests/test_governance_maximal.py::TestContracts::test_ensures_*` |
| `invariant` checked at entry **and** exit | Real | `tests/test_governance_maximal.py::TestContracts::test_invariant_entry_and_exit` |
| Contracts on methods (design-by-contract, any mode) | Real | `tests/test_governance_maximal.py::TestContracts::test_method_contract_any_mode` |
| Capability gates: imports + I/O routed through TARL, deny-by-default | Real | `tests/test_governance_maximal.py::TestCapabilityGates` |
| Sensitive imported stdlib calls require their own capability verdict after import | Real | `tests/test_gate_fail_closed.py::test_import_allow_does_not_grant_sensitive_stdlib_calls` |
| Denials carry a `TarlProof`; proofs are unsigned unless runtime signing is configured | Real | `tests/test_governance_maximal.py::TestCapabilityGates::test_write_denied_with_proof`; `tests/test_gate_fail_closed.py` |
| Temporal windows govern a call (allow/deny) | Real | `tests/test_governance_maximal.py::TestTemporal` |
| Static E053 for a governed call from `core` mode | Real | `tests/test_governance_maximal.py::TestStatic::test_e053_governed_call_from_core` |
| Forward-reference / mutual-recursion hoisting | Real | `tests/test_governance_maximal.py::TestStatic::test_forward_reference_resolves` |
| Offensive threat model and challenge catalog | Real | `docs/THREAT_MODEL.md` |
| Imported `.thirsty` modules run under the caller's governed gate (not detached core) | Real | `tests/test_threat_model_file_imports.py` |
| Governed module with a parse error fails closed (no statements execute) | Real | `tests/test_threat_model_parser_fail_closed.py` |
| Strict, opt-in proof verification (require signature / Ed25519-only / require policy source) | Real | `tests/test_threat_model_proof_strictness.py` |
| Governed build refuses governance-dropping targets unless explicitly disclosed | Real | `tests/test_threat_model_build_outputs.py` |
| Import-only policy grants no sensitive stdlib side effect | Real | `tests/test_threat_model_capability_broker.py` |

## Semantic verifiers

| Capability | Status | Test reference |
|---|---|---|
| Convergence: structural (alpha-renamed AST) pre-check | Real | `tests/test_verifiers.py::TestConvergence::test_structural_alpha_equivalent_promotes` |
| Convergence: Z3 symbolic proof + counterexample (arith subset) | Real (opt) | `tests/test_verifiers.py::TestConvergenceZ3` |
| Convergence: execute-and-compare over seeded inputs | Real | `tests/test_verifiers.py::TestConvergence::test_execute_and_compare_finds_diverging_input` |
| Convergence abstains on blocks with observable effects | Real | `tests/test_verifiers.py::TestConvergence::test_execute_and_compare_abstains_on_effects` |
| Determinism: taint dataflow follows non-determinism through aliases | Real | `tests/test_verifiers.py::TestEffectPass` |
| Thirst of Gods: each cascade linked to an enclosing spillage handler | Real | `tests/test_verifiers.py::TestCascadeLinking`; `tests/test_thirst_of_gods.py` |
| Shadow Thirst 6-analyzer promote/reject flow (AST-based) | Real | `tests/test_shadow_thirst.py` |

## T.A.R.L. policy engine

| Capability | Status | Test reference |
|---|---|---|
| Policy parsing, first-match-wins evaluation, verdicts | Real | `tests/test_tarl.py` |
| HMAC-signed proof certificates | Real | `tests/test_tarl_proof.py` |
| Ed25519-signed proof certificates | Real | `tests/test_tarl_proof.py` |
| Temporal windows (`valid_from`/`valid_until`, durations) | Real | `tests/test_tarl_temporal.py` |
| Policy composition | Real | `tests/test_tarl_composition.py` |
| Z3 static analysis (coverage / shadows / conflicts / equiv / refines) | Real (opt) | `tests/test_tarl_analyzer.py` |

## Stability

| Capability | Status | Test reference |
|---|---|---|
| Lint gate (ruff) clean under the project config | Real | CI `lint-and-test` job; `ruff check src tests` |
| Full suite on 3.11 + 3.12 with a coverage floor | Real | CI `lint-and-test` job (`--cov-fail-under=55`) |
| Examples executed through their CLIs in CI | Real | CI `lint-and-test` job |
| Package builds and imports cleanly | Real | CI `package-smoke` job |

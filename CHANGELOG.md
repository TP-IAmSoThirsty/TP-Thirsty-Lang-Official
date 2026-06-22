# Changelog

All notable changes to Thirsty-Lang are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [0.3.0] - 2026-06-22

### Added — Real runtime governance enforcement (Thirsty-Lang)

- New `requires` keyword: `glass f(x) requires <expr> { ... }` declares a
  **governed function** with a precondition (parser now emits
  `GovernedFunctionDecl` with the parsed `requires_expr`)
- Interpreter enforces governance on every governed call (`_enforce_governance`),
  layered and deny-by-default: (1) the `requires` precondition is evaluated and
  must be truthy; (2) calling a governed function outside `governed` mode is
  denied (runtime counterpart of `E053`); (3) when a `TarlRuntime` is attached
  via `Interpreter.attach_tarl(...)`, the call is routed through the policy
  engine and a non-`ALLOW` verdict denies, recording a signed `TarlProof`
- New `GovernanceViolation` exception; it is a hard floor — `spillage` handlers
  cannot catch it
- CLI `thirsty run` gains `--policy <file.tarl>` (routes governed calls through a
  policy); `--authority <tag>` now injects the authority tag into the governance
  context. Denials print `governance denied: …` and exit non-zero

### Changed — Shadow Thirst analyzers now reason over the AST

- All six analyzers parse `shadow`/`invariant`/`canonical` blocks with the real
  Thirsty-Lang lexer + parser and walk the resulting AST instead of scanning
  substrings (with a lexical fallback when a block does not parse). Determinism
  matches non-deterministic *calls* (not like-named variables), Plane Isolation
  detects real writes into `canonical_*` bindings (not the word in a comment),
  and Canonical Convergence uses structural AST equivalence (alpha-renamed shape
  and return arity)

### Changed — Thirst of Gods detection is now structural

- `to_gods()` walks the whole AST and decides the deity contract from real
  constructs (`CascadeCall`, `SpillageStmt` with handlers, `CleanupStmt`,
  `ClassDecl` with `init`) found anywhere in the tree, rather than matching
  functions by name

---

## [0.2.0] - 2026-06-20

### Added — Phase 1: Condition Algebra

- Replaced regex tokenizer with a proper state-machine lexer in `core.py`
- Nested attribute access: `user.role.clearance` walks nested context dicts; missing key returns `false` (never errors)
- Full arithmetic operators: `-`, `*`, `/`, `%` alongside existing `+`
- Set membership: `value IN [...]` and `value NOT IN [...]` as first-class operators
- Dynamic source binding: `source:name` references a live data provider registered via `TarlRuntime.register_source(name, callable)`; missing source evaluates to `[]` (never silently ALLOWs)
- Temporal builtins injected at evaluation time: `CURRENT_HOUR`, `CURRENT_DAY`, `CURRENT_WEEKDAY`, `CURRENT_MONTH`, `CURRENT_YEAR`, `CURRENT_TIMESTAMP`
- String predicates: `MATCHES(field, regex)`, `STARTS_WITH`, `ENDS_WITH`, `CONTAINS` — safe, no eval, no import
- Utility functions: `LEN`, `LOWER`, `UPPER`, `ELAPSED_SINCE(iso_timestamp)`
- Universal/existential quantifiers: `ALL(collection, v -> condition)`, `ANY(collection, v -> condition)` over context list values

### Added — Phase 2: Policy Composition

- `EXTENDS` operator: child rules evaluated first; falls through to parent on no match; `STOP` keyword blocks parent fallthrough
- `RESTRICTS` operator: child and parent evaluated independently; final verdict = `meet(child, parent)` — stricter wins
- `INCLUDE "file.tarl" AS alias` and `INCLUDE policy_name AS alias`: pre-evaluate sub-policies, inject verdicts as context variables
- `policy_set` blocks with `combine UNION|INTERSECT|MAJORITY [...]` group operators
- New `composer.py`: `PolicyComposer` registry/evaluator for composed policies; `CompositionError` for unknown parents and circular references
- Cycle detection via `chain: FrozenSet[str]` — catches `A EXTENDS B EXTENDS A` at evaluation time

### Added — Phase 3: Static Analysis Engine

- New `analyzer.py`: `PolicyAnalyzer` backed by Z3 SMT solver (optional dep: `pip install thirsty-lang[analysis]`)
- **Coverage analysis** (`tarl analyze coverage`): finds context regions that fall through to DEFAULT_DENY
- **Dead rule detection** (`tarl analyze shadows`): identifies rules that can never match because an earlier rule always fires first
- **Conflict detection** (`tarl analyze conflicts`): finds pairs of rules with overlapping conditions and different verdicts
- **Policy equivalence** (`tarl analyze equiv policy_a.tarl policy_b.tarl`): proves two policies produce identical verdicts for all contexts
- **Refinement check** (`tarl analyze refines strict.tarl permissive.tarl`): proves every context the strict policy allows is also allowed by the permissive policy
- `tarl analyze` CLI command; graceful degradation when Z3 is absent

### Added — Phase 4: Proof-Carrying Evaluation

- `TarlProof` dataclass: `Π = (H(P), H(c), k, v, T, σ)` — SHA-256 policy hash, SHA-256 context hash, matched rule index, verdict, evaluation trace, HMAC-SHA256 signature
- `TarlRuntime.evaluate_with_proof()`: returns `(TarlDecision, TarlProof)` with full per-rule trace
- HMAC-SHA256 signing via `TarlRuntime.set_signing_key(key_id, secret_bytes)`; unsigned proofs are valid (signature field is empty string, not absent)
- New `verifier.py`: `ProofVerifier` and `VerificationResult` for independent verification without the runtime
- `tarl verify proof.json [--policy policy.tarl] [--hmac-key id:hex]` CLI command; exits 0 on valid, 1 on tampered/invalid
- Proof canonical bytes are deterministic (JSON, sorted keys) — verifiable by any implementation

### Added — Phase 5: Temporal Governance

- Time-bound verdicts: `when condition => ALLOW for: 4h` — `TarlDecision.expires_at` stamped at evaluation time
- `TarlDecision.is_expired()`: caller re-check hook; engine stamps `expires_at` but never auto-re-evaluates
- Policy effective windows: `valid_from`, `valid_until`, `on_expiry` directives on policy blocks
- Policy succession: `if_unresolved_after: 8h => revert_to: baseline_access` — emergency policies with built-in sunset clauses
- Succession cycle detection in `PolicyComposer._evaluate_policy()` — cycles raise `CompositionError`, not `RecursionError`
- `TarlAuditArchive`: append-only SQLite-backed proof store; thread-safe via `threading.Lock`; `check_same_thread=False`
- `TarlAuditArchive.query(verifier=)`: optional `ProofVerifier` filters proofs with cryptographically invalid signatures; unsigned proofs pass through; without a verifier, rows are returned with no tamper check
- `TarlRuntime.set_archive(archive)`: proofs from `evaluate_with_proof()` stored automatically
- Temporal policies bypass the LRU cache so window checks and `expires_at` timestamps are never stale
- `tarl audit query [--db] [--verdict] [--from] [--to] [--limit] [--json]` CLI command
- New `archive.py`

### Added — Phase 6: Governance IDE Surface

- `TarlExplainer`: walks every rule in policy order, records `RuleTrace` (matched / not-matched / skipped-after-first-hit), surfaces temporal exits, stamps `expires_at`; `PolicyExplanation.format(verbose=)` and `.to_dict()`
- `tarl explain <policy.tarl> [--context JSON] [--verbose] [--json]` CLI command
- `TarlTestRunner`: parses and runs `.tarl_test` test suites; `run_file()`, `run_directory()` (recursive), `run_text()`
- `.tarl_test` file format: `policy_file:` or inline `policy:` block, `test "name":` cases with `context:` (JSON), `expect: ALLOW|DENY|ESCALATE`, optional `expect_rule: <int>`; malformed files surface as `load_error`, never crash the run
- `tarl test <path-or-dir> [--json]` CLI command; exits 1 on any failure
- `TarlLanguageServer` (LSP, JSON-RPC over stdio): full text-document sync, syntax diagnostics (synchronous, published immediately), Z3 dead-rule warnings and coverage-gap hints (async daemon thread with version-guard to discard stale results), thread-safe stdout writes via `_write_lock`
- LSP hover: markdown card for rule lines (verdict, condition, time-bound duration) and policy headers (composition, effective window)
- LSP definition: resolves `EXTENDS`/`RESTRICTS` parent to same-document location; resolves `INCLUDE "file.tarl"` to file URI
- `tarl-lsp` console script entry point
- New `explainer.py`, `tester.py`, `lsp.py`

### Added — Runtime Observability

- `TarlRuntime.throw_stats() -> dict`: per-rule exception frequency counter, symmetric to `_hit_counts`
- `_evaluate_rule()` now returns `(matched, decision, threw: bool)`; `_throw_counts` incremented in both `evaluate()` and `evaluate_with_proof()`
- `set_policy()` resets `_throw_counts` alongside `_hit_counts`
- Dead-by-exception predicate: `throw_count > 0 and hit_count == 0`; partial-throw state: both nonzero
- Counter reflects distinct cache-missing contexts that threw, not call frequency; documented in `throw_stats()` docstring

### Fixed

- `TarlRuntime.evaluate()`: result selection now iterates in policy order (`range(len(policy.rules))`) rather than hit-count order, preserving first-match-wins semantics under adaptive ordering — a rule with more historical hits could previously displace an earlier rule that also matched
- `PolicyComposer`: succession cycle detection (`revert_to: A → B → A`) now raises `CompositionError` using the same `chain: FrozenSet[str]` mechanism as `EXTENDS`/`RESTRICTS`; previously would hit Python's recursion limit
- `TarlAuditArchive.query()`: added `verifier=` parameter; without it, rows were returned from SQLite with no tamper check despite the archive being positioned as tamper-evident storage

---

## [0.1.5] - 2026-06-19

### Fixed
- TarlRuntime.evaluate(): preserve first-match-wins semantics by collecting futures in submission order (not completion order)
- utf.tarl public API: export TarlVerdict, TarlDecision, TarlPolicy, TarlRule, DEFAULT_DENY, TarlRuntime from __init__.py
- tests/test_tarl.py: sys.path now points to src/ (not repo root) to avoid ModuleNotFoundError

---

## [0.1.4] - 2025-06-19

### Added
- T.A.R.L. (Thirsty's Active Resistance Language) implementation:
  - Policy parser and sandboxed expression evaluator
  - LRU-cached runtime with parallel rule evaluation
  - Default-deny governance model for security
- CLI support for TARL policy evaluation (tarl eval, tarl parse)
- Lockfile-aware module resolution (--locked flag)
- Reserved Tier 5/6 security keywords documented in GRAMMAR.md
- Smoke test workflow (CI): validates all CLI entry points and imports on Python 3.11, 3.12
- 6 console script entry points: thirsty, thirst-of-gods, tarl, tscg, tscg-b, shadow-thirst
- Optional dev dependencies: pytest, black, ruff, mypy
- Pre-commit hooks: version sync, pyproject validation, entry point checks
- GPG signing guide for wheel releases (docs/SIGNING.md)
- CI enhancement: setuptools version pinning in release workflow
- CI enhancement: wheel contents verification step
- Comprehensive governance model documentation (docs/governance_model.md)

### Changed
- Package structure: added thirsty_lang shim package for import parity
- Enhanced .gitignore with test/coverage/type-checking artifacts

### Fixed
- Govern --auto-tarl TarlRuntime evaluation (indentation + body_len)
- TarlRuntime.body_len now uses BlockStmt.stmts correctly
- Double-print bug in drink/pour operations (now return None)
- LICENSE copyright year: updated to 2025-2026 range
- Console scripts: added tscg, tscg-b, tarl, shadow-thirst to entry points
- CLI: tscg-b now accepts --help/-h flags

---

## [0.1.3] - 2025-06-12

### Added
- README enhancements: install section with pinned/upgrade instructions
- Version reference bumped to 0.1.3 throughout

### Fixed
- Double-print issue resolved (drink/pour functions)

---

## [0.1.2] - 2025-06-10

### Added
- Dynamic __version__ via importlib.metadata
- Fallback version handling for editable installs

### Fixed
- Import path compatibility: from src.utf → from utf for PyPI packages

---

## [0.1.1] - 2025-06-08

### Added
- thirsty_lang shim package for backward compatibility
- __version__ dynamic synchronization

### Fixed
- __version__ sync between utf.thirsty_lang and CLI output

---

## [0.1.0] - 2025-06-01

### Added
- Initial release of Thirsty-Lang
- Tier 1 (Core) language implementation
- 11 CLI subcommands (run, repl, fmt, new, build, govern, add, audit, lock, doctor, lsp, docs)
- Standard library with 14 namespaces
- Type system with generics and type inference
- Module system with import resolution
- Package manager integration
- Security framework (sanitization, armor, security blocks)
- Mutation analysis and shadow execution
- Comprehensive documentation

### Features
- Governance-first design philosophy
- Deny-by-default policy model (T.A.R.L.)
- No runtime dependencies (stdlib only)
- Apache 2.0 license

---

## Future Roadmap

### Planned for 0.1.6+
- Pre-commit hook integration for contributor workflow (expanded)
- GPG-signed wheel releases
- Extended type checking (mypy integration)
- Code coverage tracking
- Automated changelog generation

### Planned for 0.2.0+
- Tier 2 language enhancements (task scheduling, network policies)
- Tier 3-6 language tiers
- External system integration (HTTP, SQL, etc.)
- Advanced governance models
- Performance optimizations
- IDE plugin support (VSCode, JetBrains)

---

## Legend

- **Added** — New features or functionality
- **Changed** — Changes to existing functionality
- **Fixed** — Bug fixes
- **Removed** — Deprecated or removed features
- **Security** — Security-related updates or advisories

---

For upgrade instructions, see [CONTRIBUTING.md](CONTRIBUTING.md).
For installation, see [README.md](README.md).

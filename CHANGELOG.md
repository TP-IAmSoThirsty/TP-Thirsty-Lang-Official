# Changelog

All notable changes to Thirsty-Lang are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Hardened-runtime acceptance bar (C022–C050)

Closes the remaining critical/high threat-model challenges so the governed
runtime meets its own hardened-runtime acceptance bar. All new behavior is
opt-in and backward compatible.

- **Authority provenance (C027–C028)** — `utf.tarl.authority`: Ed25519-signed
  `AuthorityClaim` minted by an `AuthorityIssuer` and checked by an
  `AuthorityVerifier`. `Interpreter.set_hardened()` fails closed unless the
  authority is authenticated *and* the runtime signs proofs with Ed25519. A bare
  `--authority` string grants nothing in hardened mode. New `thirsty run` flags:
  `--hardened`, `--authority-token`, `--authority-key`, `--sign-proofs`.
- **Context schema validation (C045–C046)** — `utf.tarl.schema.ContextSchema`;
  `TarlRuntime.set_context_schema` fails closed on missing/type-confused fields
  before any rule runs.
- **Replay/freshness/revocation (C023–C024)** — `ProofVerifier` gains
  `expected_context`, `max_age_seconds`, `revoked_policy_hashes`, and a
  `ReplayGuard`. `tarl verify` gains `--max-age` and `--revoked-policy-hash`.
- **Tamper-evident audit (C022/C026/C049)** — `TarlAuditArchive` hash-links every
  record; `verify_chain()` detects edits, deletions, and reordering. New
  `tarl audit verify-chain`.
- **Capability broker (C033/C040/C041)** — `utf.tarl.broker.CapabilityBroker`:
  one fail-closed mediation point for FFI/native, subprocess, file, network, and
  MCP/agent tool adapters, with `require_path` confining filesystem targets.
- **Fail-closed under failure (C037–C038)** — evaluator errors surface as
  non-swallowable governance denials; `TarlRuntime.set_require_audit` downgrades
  to DENY when a required proof cannot persist.
- **Path confinement (C042)** — `utf.tarl.pathguard.PathGuard` confines canonical
  (symlink-resolved) paths to allowed roots.
- **Trusted clock (C043)** — `utf.tarl.clock`: `TimeAuthority`/`TrustedClock`;
  `TarlRuntime.set_clock` evaluates temporal windows against verified signed time.
- **Policy lint + quorum (C039/C050)** — `utf.tarl.linter.lint_policy`
  (`tarl lint`) flags broad/ungated ALLOW; `utf.tarl.escalation.QuorumResolver`
  upgrades ESCALATE to ALLOW only on distinct signed approvals.
- CI now runs `mypy -p utf` as a type gate.

### Added — Offensive threat model

- Added `docs/THREAT_MODEL.md`, an offensive adversary model and challenge
  catalog for using Thirsty-Lang as a governance AI substrate. The catalog maps
  current proof/gate behavior to evidence and marks replay, downgrade,
  filesystem, network, subprocess, FFI, agent-tool, archive-tamper, and context
  poisoning defenses as required hardening work where not yet implemented.
- Linked the threat model from `SECURITY.md`.

### Added — Non-repudiable proof signatures

- `TarlRuntime.set_ed25519_signing_key()` now signs `TarlProof` certificates
  with Ed25519, and `ProofVerifier.add_ed25519_key()` verifies them with only
  the public key. Legacy HMAC-SHA256 proof signing remains supported for
  compatibility, but docs now distinguish symmetric MACs from non-repudiable
  signatures.
- `tarl verify` accepts `--ed25519-key ID:HEX_PUBLIC_KEY` for CLI verification
  of Ed25519-signed proof JSON.

### Fixed — Governed stdout bypass

- The callable `print(...)` builtin now routes through the same governed-mode
  `write/stdout` capability gate as the `pour` statement. In governed mode it
  fails closed without policy authority and records a `TarlProof`; with an
  attached policy that ALLOWs `action == "write"`, it executes normally.
- Imported stdlib modules now wrap sensitive callables with capability checks
  after import. Allowing `action == "import"` no longer implicitly grants
  filesystem writes, network calls, process execution, environment mutation,
  logging output, test output, or SQLite operations. The capability/action
  table is centralized in `module_system.SENSITIVE_STDLIB_CAPABILITIES` so every
  sensitive callable carries an explicit `read`/`write`/`network`/`execute`
  action.

### Fixed — Imported `.thirsty` modules ran ungoverned (C035)

- Importing a `.thirsty` source file from a governed module now executes it
  under the **caller's** governed runtime (policy engine + authority), instead
  of a detached core-mode interpreter. An imported module's top-level effects
  are gated during import, and the function closures it exports are gated when
  later called from governed code. A denial during import surfaces as a
  `GovernanceViolation` and is not swallowed into `spillage`.

### Fixed — Governed parse errors no longer smuggle statements (C036)

- A `governed` module with any parse error now fails closed: the parser
  discards all recovered statements and the interpreter refuses to run the
  program, raising a `GovernanceViolation` with a DENY proof. Non-governed
  modules keep error recovery. (Member access after `.` also now accepts
  keyword-like member names such as `log.error`.)

### Added — Strict, opt-in proof verification (C025)

- `ProofVerifier(require_signature=…, allowed_signature_algorithms=…,
  require_policy_source=…)` can reject unsigned proofs, restrict the accepted
  signature family (e.g. Ed25519-only, rejecting HMAC), and require a policy
  source for hash binding. Defaults are unchanged (permissive). `tarl verify`
  gains `--require-signature` and `--ed25519-only`.

### Added — Governed build artifacts must declare governance loss (C034)

- `thirsty build` refuses to emit a governance-dropping target (`js`, `llvm-*`,
  `wasm-pyodide`) for a `governed` module by default. `--allow-governance-loss`
  is required to proceed; it warns on stderr and records
  `build.governance_loss = true` in the emitted manifest.

### Fixed — `->` pipeline operator crashed at runtime

- `Interpreter._evaluate_pipeline` walked a non-existent `.steps` attribute on
  the binary `PipelineExpr` node (which has `left`/`right`), so any `->`
  expression raised `AttributeError`. It now feeds the left value into the right
  operand (same semantics as the `|` pipe). Added a regression test.

### Changed — Type hygiene and PEP 561

- The package now ships a `py.typed` marker and is clean under `mypy`. The
  canonical, flag-free invocation is `mypy -p utf` (configured via `mypy_path`
  + `explicit_package_bases` in `[tool.mypy]`, with a `z3.*` override for the
  optional, stub-less `analysis` extra): **0 errors across 42 modules**.
- Fixes include: removing the `_z3 = None`/`import z3` type-confusion in
  `analyzer.py` and `convergence.py`; replacing `callable` used as a type
  annotation with `Callable[..., Any]`; eliminating implicit-`Optional`
  defaults; giving the parser's expression methods proper AST return types;
  annotating containers (`_VERDICT_RANK`, `TYPE_NAME_MAP`, token lists, scope
  walkers); and coercing `Any`-typed returns (`json.loads`, sqlite rows) at
  trust boundaries. Behavior is unchanged.

### Fixed — Z3 analysis heap corruption under concurrency

- The LSP runs coverage/shadow analysis in a daemon thread while the main
  thread also drives z3, whose Python bindings share a single, non-thread-safe
  global context. Cyclic GC could call `Z3_dec_ref` from a thread other than
  the one using the solver, corrupting the z3 heap (a Windows `0xC0000374` /
  access-violation crash in `Z3_model_dec_ref`). `PolicyAnalyzer` now serializes
  every z3 entry point through a process-wide lock and collects z3 garbage
  inside that lock, so all z3 reference-counting happens on one thread.

---

## [0.5.0] - 2026-06-24

### Added — Build backends, file imports, LSP, and language features

- **Build backends:** `thirsty build --target llvm-ir` emits textual LLVM IR;
  `llvm-asm`/`llvm-obj`/`llvm-exe`/`llvm-jit` drive `llc`/`clang`/`lli` when a
  toolchain is present (clear error otherwise). `--target wasm-pyodide` emits a
  Pyodide (Python-in-WebAssembly) HTML bundle that runs the program in-browser.
- **File imports:** `import "path/to/x.thirsty"` now loads, parses, interprets,
  and exposes a module's top-level functions and values.
- **Language server:** `thirsty lsp --stdio` and `thirsty lsp --port N` run a
  real JSON-RPC language server (syntax diagnostics, hover, go-to-definition).
- **Language features:** `let` (immutable binding), the `for … in` keyword loop,
  `:=` (define-and-assign a new mutable binding), and the `strict` (every
  binding must be initialized) and `pure` (no I/O) module modes.

### Fixed — Cross-platform and correctness bugs

- `thirst::collections.zip` recursed infinitely (shadowed the builtin) — fixed.
- The formatter crashed on `pour` statements (`PourStmt.target`) — fixed.
- Windows `UnicodeEncodeError` (cp1252) writing the shadow-thirst mermaid graph
  and the `thirsty docs` HTML — both now write UTF-8.

### Changed — Quality gate

- Test suite expanded to ~995 tests; coverage raised to **90%+** and the CI
  coverage floor lifted from 55% to **90%**. Removed several unreachable dead
  branches surfaced by the coverage work.

### Fixed — Operator precedence (breaking semantic correction)

- **Critical:** the expression parser's precedence table was dead code.
  `_get_precedence()` was read *after* the operator was consumed, so it saw the
  right operand (precedence 0) and every binary operator collapsed to one
  right-associative level (`2 * 3 + 4` → 14; `10 - 2 - 3` → 11). Predicates in
  `requires`/`ensures`/`invariant` therefore did not mean what was written, so
  deny-by-default guards failed **open** (`balance - amount >= 0` parsed as
  `balance - (amount >= 0)`). The operator's precedence is now captured before
  advancing; arithmetic, comparison, and logic bind correctly and
  left-associatively. Unary `-` binds tighter than `*`; logical `not` binds
  looser than comparison. This changes the value of any program that relied on
  the old (incorrect) parse. Locked in by `tests/test_parser_precedence.py`.

### Changed — Governance fails closed

- **High:** the capability gate no longer fails open. In `governed` mode a gated
  capability (`pour`/`sip`/import) is now **denied with a proof** unless a TARL
  policy engine + authority are wired and return ALLOW. Previously, governed
  mode without a policy ran ungated — governed mode implied authority. Core
  (ungoverned) mode is unaffected. Locked in by `tests/test_gate_fail_closed.py`.
- **Medium:** every governed boundary decision now carries a proof. Contract
  (`requires`/`ensures`/`invariant`) ALLOW and DENY emit a `TarlProof`
  certificate (predicate trace, verdict), not just policy-engine decisions.

### Fixed — Documentation truth

- **Medium:** corrected "signed `TarlProof`" overclaims (README,
  `docs/governance_model.md`, `spec.py`, `runtime.py`). Proofs are **unsigned by
  default**; signing is opt-in HMAC-SHA256 — a *symmetric* MAC, forgeable by any
  key holder, **not** a non-repudiable signature. No Ed25519 path is implemented.
- **Low:** removed dead diagnostics **E051** (never raised) and **E052**
  (unreachable — the parser only builds a `GovernedFunctionDecl` when a contract
  clause exists).

---

## [0.4.0] - 2026-06-22

This release makes the governance stack durable: the language runs its own
surface, governance is maximal, the semantic verifiers reason (and prove)
rather than grep, and CI is the gate.

### Added — Maximal governance

- `ensures` postconditions (`result` bound after the body) and `invariant`
  predicates checked at both call entry and exit, on functions **and** methods
  (design-by-contract, valid in any mode).
- Capability gates: in governed mode, module imports and I/O (`pour`/`sip`) are
  routed through the attached `TarlRuntime` (`evaluate_with_proof`), deny-by-
  default, with a `TarlProof` on denial (unsigned by default; see the
  Unreleased note correcting the earlier "signed" wording). Time-windowed
  policies govern a call through the same path.
- Checker: function/class **hoisting** (forward references and mutual recursion
  now resolve), static **E053** for a governed call from `core` mode.

### Added — Layered semantic verifiers

- **Convergence** (Shadow Thirst) is now three layers: alpha-renamed structural
  AST equality (a sufficient fast proof), **Z3** symbolic equivalence over the
  integer-arithmetic subset (`thirsty-lang[analysis]`; each query in an isolated
  `z3.Context`, hardened to fall back on any native failure), and
  **execute-and-compare** over seeded inputs that reports the diverging input as
  a counterexample. Equal-but-differently-shaped blocks now promote; subtly
  different ones reject with a witness. The sampling layer abstains on blocks
  with observable effects.
- **Determinism** is a taint dataflow (`EffectAnalysis`): non-determinism is
  followed through aliases to a fixpoint, closing the "alias `now` into a
  variable and call it" evasion.
- **Thirst of Gods** links each `cascade` to an enclosing `spillage` handler by
  lexical containment, so "every cascade has an error-aware consumer" is
  literally enforced rather than mere co-presence.

### Added — Correctness floor

- Real array/reservoir literals, working `flood`/`evaporate`/`new`, variable
  reassignment, OOP member access + method dispatch, `cascade` await, and
  `spillage` no longer swallowing `return`. UTF-8-safe CLI output on Windows.
- Every shipped example parses, type-checks, and runs in CI
  (`tests/test_examples.py`).

### Added — Stability

- CI now runs `ruff`, the full suite on 3.11/3.12 with a 55% coverage floor, and
  executes every example through its CLI; a wheel-build/import smoke job remains.
- Cleared the full ruff lint debt (883 → 0) under the project config; replaced
  `import *` with explicit imports across the core language modules.
- New `docs/STATUS.md` feature matrix maps every capability to a test; grammar
  docs reconciled to the implemented surface.

### Fixed

- `_evaluate_new`, `_evaluate_flood`, `_evaporate` read AST fields the nodes did
  not have; reassignment was a silent no-op; member access was unimplemented.

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

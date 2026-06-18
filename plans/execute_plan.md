# Thirsty-Lang Critical Fixes — 3-Pronged Implementation

## Goal
Fix the 3 critical gaps identified — (1) lockfile-aware module resolution to make `add`/`lock`/`audit` real, (2) `thirsty govern --auto-tarl` that actually evaluates policy via TarlRuntime, (3) document/declare the 6 dead security tokens as reserved.

## Research Summary
- `module_system.py` has `resolve_import()` that resolves `thirst::module` imports from built-in registry — never reads `thirsty.lock`
- `package_manager.py` writes lockfiles with SHA-256 integrity hashes, lockfile format: `{"lockfile_version": 1, "dependencies": {"name": {"version": "...", "resolved": "...", "integrity": "sha256-..."}}}`
- `cli.py:cmd_govern()` generates auto-TARL as text file only — never calls `TarlRuntime.evaluate()` or returns a verdict
- `interpreter.py:_enforce_governance()` exists at line 429 but always returns True (no-op)
- `interpreter.py:_evaluate_impl()` already handles `SanitizeExpr` and `ArmorExpr` (pass-through evaluations)
- `token.py` defines SHIELD, SANITIZE, ARMOR, MORPH, DETECT, DEFEND as keyword tokens with full lexer support — but parser has zero grammar rules for them. Interpreter partially handles SanitizeExpr/ArmorExpr
- `tarl/spec.py` missing (spec types live in tarl/core.py or inline)
- `tarl/core.py` has `PolicyParser`, `SafeExpr`, `evaluate_policy()` all working
- `tarl/runtime.py` has `TarlRuntime` with LRU cache + ThreadPoolExecutor

## Approach
Three independent workstreams, executed in order:

1. **Lockfile-aware module resolution** — Wire `resolve_import()` to check `thirsty.lock` in CWD. If lockfile exists, verify the module being loaded has a matching integrity entry. Add `--locked` flag to `thirsty run` that requires lockfile presence and verifies integrity before running. This makes `thirsty add` → `thirsty lock` → `thirsty run --locked` an actual security pipeline.

2. **`thirsty govern --auto-tarl` actually evaluates** — After generating the auto-TARL policy, parse it with `PolicyParser`, feed to `TarlRuntime.evaluate()` with a context built from AST function names/counts, print verdict for each function. Add `--enforce` flag that gates execution.

3. **Dead security tokens → documented reserved** — Add a comment block at the top of the SHIELD/SANITIZE/etc section in `token.py` stating "Tier 5/6 Reserved — not yet active". Update `docs/GRAMMAR.md` with a §Reserved Keywords section. No functional code changes needed — they lex but won't parse.

## Subtasks

1. **Lockfile-aware module resolution** — Modify `src/utf/thirsty_lang/module_system.py`: Add `verify_lockfile(name, version) -> bool` function. Modify `resolve_import()` to accept optional `locked=True` param — when locked, verify integrity hash from `thirsty.lock` before resolving. Keep backward compat (default locked=False).
   - Add `load_lockfile(cwd: str = ".") -> dict` function that reads `thirsty.lock` from CWD and returns parsed JSON
   - Add `check_lock_integrity(dep_name: str, dep_version: str, lock: dict) -> bool` that verifies a dependency against lockfile entries
   - (verify: `python -c "from utf.thirsty_lang.module_system import resolve_import, load_lockfile; print('OK')"`)

2. **Add `--locked` flag to `thirsty run`** — Modify `src/utf/thirsty_lang/cli.py`:
   - Add `--locked` flag to `run_parser` (store_true)
   - In `cmd_run()`, before executing, if `--locked` passed: read `thirsty.lock`, verify the module system will check integrity
   - Wire the locked flag through to interpreter or module_system
   - (verify: `thirsty run --locked src/utf/examples/hello.thirsty` — should either pass or give clear error about missing lockfile)

3. **`thirsty govern --auto-tarl` evaluates via TarlRuntime** — Modify `src/utf/thirsty_lang/cli.py:cmd_govern()`:
   - Import `PolicyParser`, `TarlRuntime`, `evaluate_policy` from `utf.tarl`
   - After generating auto-TARL, parse it with `PolicyParser.parse()`
   - Build a context dict from AST: `{"name": func_name, "params": len(params), "body_len": ...}` for each function
   - Call `TarlRuntime.evaluate(context)` or `evaluate_policy(context, policy_text=...)` for each function
   - Print verdict per function: `greet() => ALLOW (by rule: ...)`
   - Add `--enforce` flag: if any function gets DENY, print blocking message and exit 1
   - (verify: `thirsty govern src/utf/examples/hello.thirsty --auto-tarl` — prints verdicts, not just text file)

4. **Document dead security tokens as reserved** — Add comment header above SHIELD section in `token.py`. Update `docs/GRAMMAR.md` with reserved keywords section.
   - (verify: `grep "Reserved" token.py` — shows comment; tests still pass)

5. **Run full test suite and E2E verification** — `pytest tests/ -q`, `thirsty run --demo`, `thirsty --help`, `thirsty govern src/utf/examples/hello.thirsty --auto-tarl`
   - (verify: all 121 tests pass, CLI commands work, no regressions)

## Deliverables
| File | Change |
|------|--------|
| `src/utf/thirsty_lang/module_system.py` | Add `load_lockfile()`, `check_lock_integrity()`, modify `resolve_import()` with `locked` param |
| `src/utf/thirsty_lang/cli.py` | Add `--locked` to `run_parser`; wire lockfile check in `cmd_run()`; wire TarlRuntime evaluation in `cmd_govern()`; add `--enforce` flag |
| `src/utf/thirsty_lang/token.py` | Add reserved comment above SHIELD section |
| `docs/GRAMMAR.md` | Add §Reserved Keywords section |

## Evaluation Criteria
- ✅ `pytest tests/ -q` — all 121 tests pass with no regressions
- ✅ `thirsty run src/utf/examples/hello.thirsty` — single print, works
- ✅ `thirsty govern src/utf/examples/hello.thirsty --auto-tarl` — prints verdicts using TarlRuntime, not just generates text file
- ✅ `thirsty run --locked src/utf/examples/hello.thirsty` — gives meaningful message about lockfile (or passes if lockfile exists)
- ✅ `thirsty --help` — shows `--locked` flag in run subcommand

## Notes
- The tarl package is imported as `from utf.tarl.core import PolicyParser, evaluate_policy` and `from utf.tarl.runtime import TarlRuntime`
- `tarl/spec.py` doesn't exist — TarlVerdict/TarlDecision classes are in `tarl/core.py` or `tarl/runtime.py`. Need to check actual locations before importing.
- The `tarl/__init__.py` is minimal — just a docstring comment.
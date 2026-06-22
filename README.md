# THIRSTY-LANG

```
„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
 „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
  „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
   „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
    „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
     „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
      „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
       „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
        „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
         „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
          „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
           „„„„„„„„„„„„„„„„„„„„„„„„„„„„
            „„„„„„„„„„„„„„„„„„„„„„„„„„
             „„„„„„„„„„„„„„„„„„„„„„„„
              „„„„„„„„„„„„„„„„„„„„„„
               „„„„„„„„„„„„„„„„„„„„
                „„„„„„„„„„„„„„„„„„
                 „„„„„„„„„„„„„„„„
                  „„„„„„„„„„„„„„
                   „„„„„„„„„„„„
                    „„„„„„„„„„
                     „„„„„„„„
                      „„„„„„
                       „„„„
                        „„
                         „
```

**A 6-tier governance-first programming language family.**  
The water metaphor is not a gimmick. Every keyword maps to a structural security effect. Default-DENY at every gate. 14 built-in module namespaces. A symbolic constraint grammar that compiles to binary frames with CRC32 + SHA-256 integrity. A mutation analyzer that can block your code from promoting if it detects cross-plane data leakage.

This is not a joke. This is **Thirsty-Lang**.

---

## Quick Start — You Have 30 Seconds

```bash
pip install thirsty-lang
```

Write a file called `hello.thirsty`:

```thirsty
module hello: core

glass greet(name) {
    return "hello, " + name + "!"
}

drink main = greet("thirsty world")
pour main
```

Run it:

```bash
thirsty run hello.thirsty
# hello, thirsty world!
```

That's the welcoming committee. Now read the rest. It gets significantly weirder.

---

## The 6-Tier Stack — What the Hell Did You Just Install?

### 🔵 Tier 1: Thirsty-Lang (Core)

A syntax that reads like a hydration app had a baby with a type checker.

```thirsty
module factorial: core

glass fact(n: Int) -> Int {
    thirst (n <= 1) { quench 1 }
    quench n * fact(n - 1)
}
```

**What actually exists (not aspirational, not vapor):**
- **35+ token types** — `DRINK`, `POUR`, `SIP`, `THIRST`, `QUENCH`, `REFILL`, `TIMES`, `GLASS`, `RESERVOIR`, `WELL`, `FLOOD`, `DRIP`, `EVAPORATE`, `CONDENSE`, `FOUNTAIN`, `RETURN`, `PARCHED`, `QUENCHED`, `EMPTY`, `MUT`, `IN`, `CASCADE`, `THIS`, `NEW`, `PUBLIC`, `PRIVATE`, `SPILLAGE`, `CLEANUP`, `ERROR`, `THROW`, `FINALLY`... the lexer tokenizes all of them.
- **Full lexer** — 25 methods, handles strings, numbers, identifiers, operators, multi-character tokens, comments, newlines
- **Full parser** — 59 methods, recursive descent with error recovery and fuzzy match suggestions
- **Full interpreter** — 58 methods, supports functions, variables, if/else guards, while/for loops, pipe operator (`|>`), imports, classes, spillage/cascade, tail call optimization, optimization levels 0-3, debug mode
- **Full type checker** — scope resolution, type inference, builtin registration, edit-distance error suggestions (you type `poour` and it says "did you mean `pour`?")
- **Formatter** — `thirsty fmt` reformats your code with consistent rules
- **JS transpilation** — `thirsty build hello.thirsty --target js` produces valid JavaScript
- **11 CLI subcommands** — run, repl, fmt, new, build, govern, add, audit, lock, doctor, lsp, docs. All of them work.

### 🟣 Tier 2: Thirst of Gods

Object-oriented programming, async (`cascade`/`await`), and structured error handling (`spillage`/`cleanup`/`throw`) — all validated by a **divine contract validator**.

```thirsty
fountain Counter {
    drink count: Int = 0
    glass increment() {
        mut this.count = this.count + 1
    }
}
```

**What exists:** The validator (`to_gods()`) walks the **real AST** and checks your code for:

- A fountain (class) with an `init` method? ✓
- A real `cascade` call (`CascadeCall` node), anywhere in the tree? ✓
- A `spillage` block with at least one handler? ✓
- A real `cleanup` block? ✓

Detection is **structural, not name-based**: a `CascadeCall`/`SpillageStmt`/`CleanupStmt` is found wherever it lives — inside a method body or a nested block — and a function merely *named* something suggestive doesn't satisfy the contract. If your code doesn't satisfy the divine contract, it tells you. This is not decorative.

### 🟢 Tier 3: T.A.R.L. — Thirsty's Active Resistance Language

A policy-as-code engine. Default-DENY. Always.

```tarl
policy access_control:
    when user.role == "admin"    -> ALLOW
    when user.ip in blacklist    -> DENY
    when hour < 6 or hour > 22   -> ESCALATE
    default                       -> DENY
```

**What exists:** `TarlEngine`, `TarlPolicy`, `TarlRule`, `TarlVerdict` (ALLOW/DENY/ESCALATE), `PolicyParser`, `SafeExpr`, LRU-cached evaluation, adaptive policy ordering. Import it from Python and evaluate policies programmatically. First-match-wins semantics. Default-DENY when no rule matches.

**Runtime enforcement in the language:** a governed function declares a precondition with `requires`, and the interpreter enforces it on every call — layered and default-deny:

```thirsty
module bank: governed
glass withdraw(amt) requires amt > 0 {
    return amt * 2
}
```

1. **In-language precondition** — the `requires` expression is evaluated at call time; a falsy result raises `GovernanceViolation`.
2. **Cross-mode guard** — a governed function invoked outside `governed` mode is denied (the runtime counterpart of checker error `E053`).
3. **T.A.R.L. routing** — attach a policy engine (`Interpreter.attach_tarl(...)`, or `thirsty run … --authority <tag> --policy <file.tarl>`); a non-ALLOW verdict denies and a signed `TarlProof` is recorded. Governance denials are a hard floor — `spillage` handlers cannot swallow them.

### 🟡 Tier 4: Shadow Thirst

Mutation analysis and invariant verification. **Code cannot promote unless it passes.**

```shadow
shadow analyze_memory:
    invariant: deterministic
    canonical: converge
promote
```

**What exists: 6 analyzers that run over the real parsed AST** (Thirsty-Lang's own lexer + parser), not over substrings of the source — so a variable merely *named* `nowhere` no longer trips the determinism check, and the word "canonical" in a comment no longer trips plane isolation:

1. **Plane Isolation** — walks the shadow block for writes into `canonical_*` bindings or calls into the canonical plane
2. **Determinism** — flags *calls* to non-deterministic functions (`now()`, `rand()`, `uuid()`, …), distinguishing a call from a like-named variable
3. **Resource Estimation** — estimates CPU/memory from loop, call, and allocation **nodes**
4. **Purity Spring** — checks the invariant block for impure calls / output statements
5. **Memory Evaporation** — counts allocation nodes (`new`, reservoir literals, floods)
6. **Canonical Convergence** — compares shadow and canonical via **structural AST equivalence** (alpha-renamed shape + return arity)

When a block can't be parsed, each analyzer falls back to the original lexical heuristic so partial input still yields a verdict.

**Return codes:** `PromotionEngine` issues a verdict — if critical analyzers fail, promotion is **blocked**. Your code cannot graduate to production.

### 🟠 Tier 5: TSCG — Thirsty Symbolic Constraint Grammar

A symbolic security expression language with 9 core symbols, combined via pipeline, AND, and OR operators, **SHA-256 canonicalized** into a deterministic form.

```tscg
COG -> DNT ^ SHD -> CAP
```

**9 symbols that exist:** COG (Cognition), DNT (Do Not Track), SHD (Shield), INV (Invariant), CAP (Capability), QRM (Quorum), COM (Communication), ANC (Anchor), RFX (Reflexive).

**Operators:** pipeline (`->`), AND-combine (`^`), OR-combine (`||`). Parsed by `TSCGParser`, canonicalized by `canonical_form()` into a SHA-256 digest. `validate_symbols()` checks symbol compatibility.

### 🔴 Tier 6: TSCG-B — Binary Frame Protocol

The same symbolic constraints, now as **binary frames** with integrity guarantees.

```
┌────────┬──────────┬────────────┬──────────┬─────────────┐
│ MAGIC  │ VERSION  │  FLAGS     │  PAYLOAD │   SHA-256   │
│ TSGB   │  0x01    │  0x00      │  ...     │  32 bytes   │
│ 4 bytes│ 1 byte   │  1 byte    │  var     │  32 bytes   │
└────────┴──────────┴────────────┴──────────┴─────────────┘
```

**What exists:** `TSCGBFrame.create()`, `StreamDecoder` (auto-resynchronizing for multi-frame transport), CRC32 integrity checks per frame, SHA-256 payload verification. Encode your TSCG constraints into binary, throw them over a wire, decode on the other side, get back your symbolic expression. Frame fragmentation support with EOF flag.

---

## Stdlib That's Actually Written

The standard library is **14 namespaces, all implemented** (not stubs, not stubs-that-throw-NotImplementedError — actual code):

| Namespace | What it does |
|-----------|-------------|
| `thirst::time` | `now()`, `epoch_ms()`, `sleep(seconds)` |
| `thirst::crypto` | `sha256()`, `sign()`, `hmac()`, `random_bytes()`, `uuid4()` |
| `thirst::reservoir` | `size()`, `push()`, `pop()`, `get()`, `flood()` |
| `thirst::fs` | `read_file()`, `write_file()`, `exists()`, `list_dir()`, `mkdir()`, `remove()` |
| `thirst::path` | `join()`, `dirname()`, `basename()`, `ext()`, `absolute()`, `relative()` |
| `thirst::json` | `parse()`, `dump()` |
| `thirst::dict` | `get()`, `set()` |
| `thirst::http` | `get()`, `post()`, `put()`, `delete()` |
| `thirst::env` | `get()`, `set()`, `all()` |
| `thirst::sys` | `run()`, `exit()`, `args()`, `pid()` |
| `thirst::log` | `info()`, `warn()`, `error()`, `debug()` |
| `thirst::test` | `assert_eq()`, `assert_ne()`, `assert_true()`, `assert_raises()`, `describe()`, `it()` |
| `thirst::collections` | `map()`, `filter()`, `reduce()`, `sort()`, `unique()`, `flatten()`, `zip()` |
| `thirst::net` | `tcp_connect()`, `tcp_listen()`, `udp_send()` |
| `thirst::sqldb` | `connect()`, `query()`, `execute()`, `close()` |

**You can write production Thirsty-Lang programs** that open TCP sockets, compute SHA-256 hashes, query databases, and assert their own correctness. This is not a toy.

---

## CLI That's Actually Shipped

```
thirsty <command> [options]

run      → Execute .thirsty files
repl     → Interactive REPL with .clear / .exit / state persistence
fmt      → Format .thirsty source files
new      → Scaffold a project with directory structure
build    → Build (JS transpilation, etc.)
govern   → Governance operations / divine contract validation
add      → Add a package dependency
audit    → Audit dependency integrity
lock     → Generate lockfile for reproducible builds
doctor   → Health check your project structure
lsp      → Start Language Server Protocol endpoint
docs     → Generate API documentation
```

Installable via PyPI: `pip install thirsty-lang`. Then `thirsty --help` shows you all of them. `thirsty --version` shows you `Thirsty-Lang 0.1.4`.

---

## Formal Grammar

A complete BNF grammar is documented at `docs/GRAMMAR.md`. Formal, recursive-descent parseable, covering all 6 tiers and all 30+ token types. Not aspirational — written, committed, pushed.

---

## The Architecture That Makes This Not Insane

```
┌─────────────────────────────────────────────────────────┐
│                    Tier 6: TSCG-B                       │
│           Binary Frame Protocol (CRC32+SHA256)          │
├─────────────────────────────────────────────────────────┤
│                    Tier 5: TSCG                         │
│      Symbolic Constraint Grammar (9 symbols, SHA-256)   │
├─────────────────────────────────────────────────────────┤
│                    Tier 4: Shadow Thirst                │
│      Mutation Analysis — 6 analyzers, PromotionEngine   │
├─────────────────────────────────────────────────────────┤
│                    Tier 3: T.A.R.L.                     │
│       Policy-as-Code — TarlVerdict (ALLOW/DENY/ESCALATE)│
├─────────────────────────────────────────────────────────┤
│                    Tier 2: Thirst of Gods               │
│    Divine Contract Validation — OOP, Async, Error Hndl. │
├─────────────────────────────────────────────────────────┤
│                    Tier 1: Thirsty-Lang                 │
│  Core Language — Lexer, Parser, Checker, Interpreter,   │
│  Optimizer, Formatter, JS Transpiler, 14 stdlib modules │
└─────────────────────────────────────────────────────────┘
```

Default-DENY at every boundary. Data cannot flow upward without clearing the tier below. That's not a marketing slogan — it's how the architecture is built.

---

## Verification

**121 tests pass.** Every time. Before every commit. No regressions.

```
$ python -m pytest tests/ -q
........................................................................ [ 59%]
.................................................                        [100%]
121 passed in 0.13s
```

The test suite covers: lexer, parser, checker, interpreter, formatter, module system, REPL, JS transpilation, T.A.R.L. policies, Shadow Thirst analyzers, TSCG parsing/canonicalization, TSCG-B frame encoding/decoding, Thirst of Gods divine contract validation, CLI commands, and end-to-end program execution.

---

## Install

Thirsty-Lang is now available on PyPI.

**For pinned installs:**
```bash
pip install thirsty-lang==0.1.4
```

**For upgrade installs:**
```bash
pip install --upgrade thirsty-lang
```

**From source:**
```bash
git clone https://github.com/IAmSoThirsty/Thirstys-Projects-Thirsty-Lang-UTF.git
cd Thirstys-Projects-Thirsty-Lang-UTF
pip install -e .
```

---

## License

Copyright 2026 **Thirsty's Projects LLC** — Apache 2.0

```
„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
 „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
  „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
   „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
    „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
     „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
      „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
       „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
        „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
         „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
          „„„„„„„„„„„„„„„„„„„„„„„„„„„„„„
           „„„„„„„„„„„„„„„„„„„„„„„„„„„„
            „„„„„„„„„„„„„„„„„„„„„„„„„„
             „„„„„„„„„„„„„„„„„„„„„„„„
              „„„„„„„„„„„„„„„„„„„„„„
               „„„„„„„„„„„„„„„„„„„„
                „„„„„„„„„„„„„„„„„„
                 „„„„„„„„„„„„„„„„
                  „„„„„„„„„„„„„„
                   „„„„„„„„„„„„
                    „„„„„„„„„„
                     „„„„„„„„
                      „„„„„„
                       „„„„
                        „„
                         „
```

**Contact:** `FounderOfTP@thirstysprojects.com`
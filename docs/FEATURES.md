# Thirsty-Lang — Feature Reference

> Complete, implementation-accurate inventory of what Thirsty-Lang `0.4.0` can do.
> Every capability here is exercised by the test suite; see
> [STATUS.md](STATUS.md) for the capability → test map.

Thirsty-Lang is a **governance-first language family**. It is not one language
but a layered stack: a small imperative core whose execution is *governed*, a
policy engine that decides what code may do, and a set of semantic verifiers
that *prove* properties of code rather than pattern-matching its text.

---

## 1. Language Core (`thirsty`, `.thirsty`)

A tree-walking interpreter with a recursive-descent + Pratt parser, a static
checker, a type system, and a formatter.

### 1.1 Declarations

| Form | Meaning |
|---|---|
| `drink x = expr` | immutable binding |
| `drink mut x = expr` | mutable binding (reassignable via `x = …`) |
| `drink x: Int = 5` | binding with a type annotation |
| `glass f(a, b) -> Ret { … }` | function (first-class, TCO-eligible) |
| `glass f(x) requires P ensures Q invariant I { … }` | governed function (§2) |
| `fountain C { field: T  glass init(self){…}  glass m(self,…){…} }` | class with fields, constructor, methods |
| `enum`, `struct`, `interface`, `symbol`, `morph`, `defend` | additional type / transform / strategy declarations |

### 1.2 Statements

- **Conditionals:** `thirsty (c) { … } hydrated thirsty (c) { … } hydrated { … }`
  (if / else-if / else).
- **Loops:** `refill (item in iterable) { … }` (for-each),
  `refill (cond) { … }` (while). Loop bodies accumulate into mutable bindings.
- **I/O:** `pour expr` (output), `sip target` (input).
- **Imports:** `import "path" as alias`.
- **Errors:** `spillage { … } error { … }` (try/catch),
  `cleanup { … } finally { … }`, `throw expr`.
- **Async:** `cascade expr` — schedules on a thread pool and **awaits**, yielding
  the value (not a future).
- **Security blocks:** `shield` / `sanitize` / `armor` / `morph` / `detect` /
  `defend`.

### 1.3 Expressions & operators

- Literals: int, float, string, bool, `none`, error, `quenched` (optional),
  and **array/reservoir literals** `[1, 2, 3]` (real Python `list`).
- Arithmetic `+ - * / %`; comparison `== != < > <= >=`; logical `and or not`;
  unary `- !`.
- **OOP:** member read `obj.field`, member write `obj.field = v`, method dispatch
  `obj.method(args)`.
- `new Class(args)`, function calls, pipe `|`, guard `thirst(e) quench(c)`,
  and the TSCG pipeline/combine operators.

### 1.4 Built-in functions

`length`, `size`, `contains`, `get`, `split`, `abs`, `min`, `max`, `push`,
`pop`, `flood`, `condense`, `evaporate`, `strain`, `transmute`, `distill`,
`print`, `pour`.

### 1.5 Modes

A module header declares the enforcement mode:

```
module myapp: core       // ordinary execution
module myapp: governed   // governance enforcement active
```

---

## 2. Governance (the differentiator)

Governance is **runtime-enforced, deny-by-default, and a hard floor**: a
`GovernanceViolation` is *not* catchable by `spillage`. This is what separates
Thirsty-Lang from “contracts as assertions” — a governed program cannot talk its
way out of its own rules.

### 2.1 Design-by-contract

| Clause | When checked |
|---|---|
| `requires P` | at call **entry** |
| `ensures Q` | at call **exit**, with `result` bound to the return value |
| `invariant I` | at **both** entry and exit |

Contracts apply to **free functions and methods** alike.

```
module bank: governed

glass withdraw(balance, amount)
    requires amount > 0
    requires amount <= balance
    ensures result == balance - amount
{
    return balance - amount
}
```

### 2.2 Capability gates

In `governed` mode, sensitive operations — module `import` and I/O (`pour` /
`sip`) — are routed through an attached **T.A.R.L. policy runtime**
(`evaluate_with_proof`). A non-`ALLOW` verdict denies the operation before it
takes effect. With a policy attached, the posture is **deny-by-default**.

### 2.3 Cryptographic proofs

Every gated decision can carry an **HMAC-signed `TarlProof`** certificate. On a
denial it is attached to the `GovernanceViolation`, so callers (and audit logs)
get a verifiable record of *why* an action was refused.

### 2.4 Temporal governance

Because gated calls flow through T.A.R.L., **time-windowed policies**
(`valid_from` / `valid_until`, durations) govern calls automatically — e.g.
“this capability is allowed only until a given date.”

### 2.5 Static parity (checker)

- **E053** — calling a governed function from a `core` module.
- **Hoisting** — top-level function/class names are pre-declared, so forward
  references and mutual recursion resolve.
- Contract predicates are checked for resolvable names.

---

## 3. Semantic Verifiers

### 3.1 Shadow Thirst (`shadow-thirst`) — safe mutation & promotion

Parses a `mutation { validated_canonical { shadow{…} invariant{…} canonical{…} } }`
and runs **six AST-based analyzers** to a **PROMOTE / FLAGGED / REJECT** verdict:

1. **PlaneIsolation** — the shadow plane never writes canonical state.
2. **Determinism** — a taint dataflow (`EffectAnalysis`) that follows
   non-determinism (`now`, `rand`, `uuid`, …) **through aliases to a fixpoint**,
   so aliasing `now` into a variable and calling it is still caught.
3. **ResourceEstimator** — CPU cost estimated from AST structure.
4. **PuritySpring** — the invariant block is side-effect free.
5. **MemoryEvaporation** — peak memory from allocation-producing nodes.
6. **CanonicalConvergence** — three layers (see below).

**Layered convergence** answers “does the shadow compute the same thing as the
validated canonical?”:

| Layer | Mechanism | Guarantee |
|---|---|---|
| Structural | alpha-renamed AST equality | sufficient proof of equivalence |
| Z3 symbolic *(opt)* | translate return values to Z3 over shared inputs | proof for **all** inputs, or a **counterexample** |
| Execute-and-compare | run both over seeded inputs in a sandbox | observed equivalence, or the **diverging input** |

Equal-but-differently-shaped blocks (`x + x` ≡ `x * 2`) now **promote**; subtly
different ones (`x + 1` vs `x + 2`) **reject with a witness**. The sampling layer
abstains on blocks with observable effects (return-value equality is unsound
there). Z3 requires `pip install thirsty-lang[analysis]`.

CLI: `shadow-thirst check <file>`, `shadow-thirst visualize <file>` (Mermaid).

### 3.2 Thirst of Gods (`thirst-of-gods`) — deity contracts

Structural AST validation of four signals, emitting diagnostics `G001–G004`:

- a fountain with an `init` method,
- **every `cascade` lexically inside a `spillage` handler** (a real error
  consumer — not mere co-presence),
- spillage blocks with handlers,
- cleanup blocks.

CLI: `thirst-of-gods run | check | transpile`.

---

## 4. T.A.R.L. — Policy Engine (`tarl`)

A standalone, first-match-wins policy language.

- **Verdicts:** `ALLOW` / `DENY` / `ESCALATE`, default-deny.
- **Conditions:** comparisons, set membership (`in`), arithmetic, attribute
  access, and temporal builtins (`CURRENT_HOUR`, `CURRENT_WEEKDAY`, …).
- **Temporal windows & durations**, with an append-only **audit archive**.
- **HMAC-signed proof certificates** (`verify` re-checks them).
- **Policy composition.**
- **Z3 static analysis** (`analyze`, `[analysis]` extra): coverage gaps,
  shadowed/dead rules, conflicts, and **equivalence / refinement** proofs
  between two policies.

CLI: `tarl eval | parse | verify | audit | explain | test | analyze`, plus a
`tarl-lsp` language server.

---

## 5. TSCG / TSCG-B — symbolic & binary tiers

- **TSCG (`tscg`):** Thirst’s Symbolic Constitutional Grammar — `parse`,
  `canonical` (normalized form), `checksum` (SHA-256), `validate`, `list`.
  Canonicalization + hashing for tamper-evident symbolic expressions.
- **TSCG-B (`tscg-b`):** binary framing — `encode` / `decode` / `stream`, with
  CRC32 + SHA-256 integrity over each frame.

---

## 6. Tooling & Workflow

- **`thirsty` CLI:** `run`, `repl`, `fmt`, `new` (scaffold), `build`, `govern`,
  `add` / `audit` / `lock` (dependency integrity), `doctor`, `lsp`, `docs`.
- **Console scripts:** `thirsty`, `thirst-of-gods`, `tarl`, `tarl-lsp`, `tscg`,
  `tscg-b`, `shadow-thirst`.
- **UTF-8-safe** CLI output on Windows.
- **CI gate:** ruff lint (clean), full suite on Python 3.11/3.12, a coverage
  floor, and every shipped example executed through its CLI; a separate
  wheel-build/import smoke job.

---

## 7. Representative use cases

1. **Governed agent/tool runner** — an agent emits `.thirsty`; in `governed`
   mode with a T.A.R.L. policy it may only import/IO what policy allows, every
   action yields a proof, and contracts bound its behavior.
2. **Provably-safe code migration** — propose a refactor as a Shadow Thirst
   `mutation`; promote only if Z3 proves (or sampling shows) equivalence to the
   validated original, else receive the diverging input.
3. **Time-boxed / conditional permissions** — temporal T.A.R.L. policies enforce
   windowed access, provable via the analyzer and auditable via the archive.
4. **Tamper-evident symbolic artifacts** — TSCG canonical form + checksum;
   TSCG-B integrity-framed binary streams.
5. **Contract-checked libraries** — `requires` / `ensures` / `invariant` on
   methods give runtime design-by-contract that `spillage` cannot bypass.

---

See the [whitepaper](WHITEPAPER.md) for the formal model, architecture, and the
soundness arguments behind the verifier layers.

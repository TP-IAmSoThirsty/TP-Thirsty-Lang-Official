# Thirsty-Lang: A Governance-First Language Family with Provable Capability Control and Layered Semantic Verification

**Version 0.4.0 — Thirsty's Projects LLC**

---

## Abstract

Most programming languages treat *what a program is allowed to do* as someone
else's problem — pushed to the operating system, a container boundary, or a code
reviewer's judgment. As software is increasingly generated and operated by
autonomous agents, that gap is becoming the dominant risk: a program's text no
longer tells you whether it is safe to run, and "trust the author" is no longer
a coherent control when the author is a model.

Thirsty-Lang takes the opposite stance: **governance is a first-class language
construct, enforced by the runtime, proven where possible, and impossible for
the program to escape.** It is a layered family — a small imperative core whose
execution is governed by design-by-contract clauses and capability gates; a
policy engine (T.A.R.L.) that decides what code may do and emits signed proofs
of every decision; and a set of *semantic verifiers* that reason over the real
abstract syntax tree to establish properties — behavioral equivalence,
determinism, structured error handling — rather than grepping source text.

This paper describes the model, the architecture, the formal underpinnings of
each enforcement and verification mechanism, and the engineering that makes the
system stable: a fully linted codebase, continuous integration that runs the
language's own examples, and a capability-to-test matrix in which every claimed
feature is backed by an executable proof obligation.

---

## 1. Introduction

### 1.1 The problem

A conventional language answers "what does this code compute?" It does not answer
"what is this code permitted to compute, on whose authority, within what window,
and can it prove it didn't cheat?" Those questions are answered — if at all — by
machinery *outside* the language: seccomp profiles, IAM policies, container
capabilities, human review. Each lives at a different altitude from the code, so
each is easy to get subtly wrong and impossible to reason about compositionally
with the program itself.

Three trends make this gap urgent:

1. **Code is generated.** When an LLM emits a program, the relevant safety
   question is not "is the author trustworthy" but "can this artifact, as
   written, only do what we sanctioned?"
2. **Code is operated by agents.** Autonomous systems chain tool calls; a single
   ungoverned capability (a file write, an outbound request) is a lateral-movement
   primitive.
3. **Review does not scale.** "Every cascade has an error-aware consumer" or
   "this refactor is behavior-preserving" are claims a reviewer asserts and a
   reader hopes. They should be *checked*.

### 1.2 The thesis

Pull governance *into* the language, at the same altitude as the code it
governs, and make three guarantees:

- **Inescapable.** Governance failures are a hard floor: the program's own error
  handling cannot catch a governance violation.
- **Provable.** Where a property is decidable on a tractable fragment, prove it
  (with an SMT solver); where it is not, fall back to sound sampling and report a
  concrete witness on failure. Never assert a property the system did not
  establish.
- **Auditable.** Every capability decision yields a signed certificate, so the
  record of *why* an action was allowed or denied is verifiable after the fact.

### 1.3 Contributions

- A layered language design in which **design-by-contract** (`requires` /
  `ensures` / `invariant`) and **capability gating** are runtime-enforced and
  non-bypassable (§3).
- **T.A.R.L.**, a first-match-wins policy language with HMAC-signed proofs,
  temporal windows, and **SMT-backed static analysis** (coverage, dead rules,
  conflicts, equivalence, refinement) (§4).
- **Layered semantic verification**: a convergence checker that escalates from
  structural AST equality to SMT equivalence to execute-and-compare with
  counterexamples; a determinism analysis that follows taint through aliases;
  and structural deity-contract linking that ties each async `cascade` to a real
  error consumer (§5).
- An **engineering discipline for stability**: a clean lint gate, a coverage
  floor, examples-in-CI, and a capability→test matrix that turns "done" into an
  enforced invariant rather than a claim (§7).

---

## 2. Design Principles

1. **Reason over the AST, never the text.** A variable merely *named* `nowhere`
   must not trip a non-determinism check; the word `canonical` in a comment must
   not trip plane isolation. Every analyzer walks the parsed tree produced by the
   language's own lexer and parser.
2. **Reuse one mechanism for one job.** Capability gates, temporal enforcement,
   and policy analysis all route through the single T.A.R.L. runtime; SMT work
   reuses one translation strategy. There is no second policy engine and no
   second solver integration.
3. **Soundness over coverage.** A verifier may answer "equivalent," "diverges
   (with witness)," or "I cannot decide." It may never answer "equivalent" when
   it has not established it. Each layer's *positive* answer is a sufficient
   condition; uncertainty escalates to the next layer or abstains.
4. **Make "done" a CI invariant.** A capability is only "real" if a test fails
   when it regresses. The feature matrix ([STATUS.md](STATUS.md)) is the contract
   between the documentation and the code.

---

## 3. The Governance Model

### 3.1 Execution model

Thirsty-Lang is a tree-walking interpreter over a dataclass AST in which every
node carries a source span. A module declares a mode in its header:

```
module m: core        // ordinary execution
module m: governed    // governance enforcement active
```

Governance is layered on the call path. Conceptually, a governed call evaluates:

```
run_governed(decl, args):
    enforce_entry(decl)          # requires + invariant, on entry
    result := eval_body(decl, args)
    bind "result" := result
    enforce_exit(decl)           # ensures + invariant, on exit
    return result
```

### 3.2 Design-by-contract

A governed function may declare three predicate clauses:

| Clause | Obligation | Checkpoint |
|---|---|---|
| `requires P` | precondition | entry |
| `ensures Q` | postcondition (`result` in scope) | exit |
| `invariant I` | stable predicate | entry **and** exit |

A predicate that evaluates falsy raises `GovernanceViolation`. Contracts apply
uniformly to free functions and to methods (dispatched through the same governed
wrapper), so design-by-contract holds across object boundaries.

### 3.3 The hard floor

The defining property: `GovernanceViolation` is **not** an ordinary error.
`spillage`/`error` handlers re-raise it rather than catching it. Formally, for
the language's error-handling construct,

```
eval(spillage B handlers H):
    try eval(B)
    except GovernanceViolation: raise        # uncatchable
    except SpillageException as e: dispatch(e, H)
```

This makes governance a *floor* rather than a *suggestion*: a program cannot use
its own control flow to convert a denied action into a handled one.

### 3.4 Capability gates

In `governed` mode, a bounded, documented set of sensitive operations — module
`import` and I/O (`pour`, `sip`) — are intercepted before they take effect and
submitted to the attached policy runtime as a request
`{action, target, authority}`. The runtime returns a verdict and a proof; a
non-`ALLOW` verdict denies the operation and attaches the proof to the
violation. With a policy attached the posture is **deny-by-default**: an action
with no matching `ALLOW` rule is refused.

The gate fires *before* the effect — a denied `import` never reaches the module
loader — so denial has no side effects to undo.

### 3.5 Temporal governance

Because gated calls flow through T.A.R.L., and T.A.R.L. evaluates temporal
windows as part of every decision (§4.3), **time-windowed policies govern calls
for free**: a capability can be allowed only within `[valid_from, valid_until]`
or for a stated duration, and the same proof certificate records the temporal
basis of the verdict.

### 3.6 Static parity

Runtime enforcement is mirrored by static checks so violations surface before
execution:

- **E053** is emitted when a `core` module calls a governed function.
- **Hoisting** pre-declares top-level function and class names, so forward
  references and mutual recursion type-check.
- `ensures` / `invariant` predicates are checked for resolvable names.

---

## 4. T.A.R.L. — The Policy Engine

T.A.R.L. (Thirsty's Active Resistance Language) is the decision layer beneath
governance, and a usable policy language in its own right.

### 4.1 Semantics

A policy is an ordered list of rules `when <condition> => <verdict>`, evaluated
**first-match-wins** with a **default-deny** fallthrough. Verdicts are `ALLOW`,
`DENY`, `ESCALATE`. Conditions support comparison, set membership (`in`),
arithmetic, attribute access, and temporal builtins (`CURRENT_HOUR`,
`CURRENT_WEEKDAY`, `CURRENT_TIMESTAMP`, …).

Let `φᵢ` be rule *i*'s condition and `vᵢ` its verdict. The decision function is
the first-match chain:

```
V(P, c) = vᵢ   where i = min { i : c ⊨ φᵢ },   DENY if no such i
```

### 4.2 Proof certificates

Each decision can emit a `TarlProof`: an HMAC-signed record of the context, the
matched rule, the verdict, and the temporal basis. `tarl verify` re-checks the
signature and the decision, so an audit can confirm *both* that a decision was
made and that it was the decision the policy prescribes. Proofs are retained in
an append-only temporal **audit archive** queryable via `tarl audit`.

### 4.3 Temporal windows

A policy or rule may carry `valid_from` / `valid_until` bounds and durations.
These are evaluated as part of `evaluate_with_proof`, so temporal admissibility
is not a separate subsystem — it is folded into the same first-match decision and
the same proof.

### 4.4 SMT-backed static analysis

With the `analysis` extra (`z3-solver`), T.A.R.L. answers structural questions
about a policy by translating conditions into Z3 formulas (numeric comparisons →
integers, string equality / set membership → strings, temporal builtins →
bounded integers, everything else → fresh opaque booleans). Encoding verdicts as
an integer `If`-then-`else` chain (`DENY=0, ESCALATE=1, ALLOW=2`) yields:

| Query | Formulation | Meaning |
|---|---|---|
| **coverage** | `SAT(¬φ₁ ∧ … ∧ ¬φₙ)` | a context reaching default-deny exists |
| **shadows** | `UNSAT(¬φ₁ ∧ … ∧ ¬φₖ₋₁ ∧ φₖ)` | rule *k* is dead |
| **conflicts** | `SAT(φᵢ ∧ φⱼ), vᵢ ≠ vⱼ` | two rules overlap with different verdicts |
| **equiv** | `UNSAT(V(P₁,c) ≠ V(P₂,c))` | two policies are equivalent |
| **refines** | `UNSAT(P₁ allows ∧ ¬P₂ allows)` | `P₁ ⊑ P₂` (strict never over-allows) |

Each `SAT` result yields a concrete satisfying context as a counterexample.

---

## 5. Semantic Verifiers

The verifiers establish *properties of code*, layered so that each layer's
positive verdict is sound and uncertainty escalates.

### 5.1 Convergence (Shadow Thirst)

**Problem.** Given a proposed `shadow` implementation and a `validated_canonical`
one, decide whether the shadow computes the same result, and if not, produce a
diverging input.

**Three layers, strongest-cheapest first:**

1. **Structural.** Both blocks are reduced to an alpha-renamed structural
   signature: identifier *names* become positional placeholders while node
   shapes, literal values, and return arity are preserved. Signature equality is
   a **sufficient** condition for equivalence — same shape up to renaming is the
   same computation — so a pass here needs no further work. (It is not
   *necessary*: `x + x` and `x * 2` differ structurally yet are equivalent, which
   is what the next layers are for.)

2. **Z3 symbolic** *(optional)*. For the straight-line integer-arithmetic
   fragment — a sequence of bindings/assignments ending in a `return` over `+`,
   `-`, `*`, `%`, comparisons, and boolean connectives — each block's returned
   value is translated to a Z3 term over a **shared** pool of input symbols. The
   solver is asked whether the two returns can differ:

   ```
   UNSAT(returnₛ ≠ return꜀)  ⇒  equivalent for all inputs   (a proof)
   SAT(…)                    ⇒  diverge; the model is a counterexample input
   ```

   Anything outside the fragment (control flow, division, non-integer types)
   raises "unsupported" and defers to layer 3. Each query runs in an **isolated
   Z3 context** and is wrapped so that *any* solver failure — including a flaky
   native library — degrades to "unsupported" rather than destabilizing the
   verifier. The Z3 layer can only ever *help*; it can never return a wrong
   verdict.

3. **Execute-and-compare.** The two blocks are run in a sandboxed interpreter
   over a deterministic spread of seeded inputs (small, edge, and negative
   values) and their returned values compared. A mismatch is reported with the
   exact input that diverged. This layer is **sound only for effect-free blocks**:
   return-value equality says nothing about whether two blocks *printed*, *read*,
   *imported*, or *threw* differently, so it abstains when either block has an
   observable effect. Equivalence here is *observed*, not proven — a sound
   refutation but a probabilistic confirmation, which is why the structural and
   symbolic layers run first.

The six-analyzer promotion engine (plane isolation, determinism, resource and
memory estimation, invariant purity, convergence) combines these into a
**PROMOTE / FLAGGED / REJECT** verdict.

### 5.2 Determinism as taint dataflow

A callee-name allowlist (`now`, `rand`, `uuid`, …) is trivially evaded by
aliasing: `drink f = now; drink x = f()`. The determinism analyzer instead
computes a **taint set to a fixpoint**: a name bound from anything that
references a non-deterministic source — directly, by aliasing the function, or
transitively — becomes tainted, and a call whose callee is tainted is itself a
finding. Because the fixpoint is order-independent, `g` is tainted by `f` even if
`g`'s binding is read before `f`'s. This closes the indirection class of evasion
that a name list cannot see.

### 5.3 Deity contracts (Thirst of Gods)

The deity tier checks four structural signals over the whole AST — a fountain
with `init`, error-handled `cascade`s, spillage-with-handlers, and cleanup —
*wherever they occur*, never by what a function is named (the magic words are
reserved keywords and cannot be identifiers, which is precisely why a name-based
check could never match a real program).

The strengthened claim is **cascade→spillage linking**: a `cascade` counts as
error-aware only when it is **lexically inside the protected `body` of a
`spillage` block that has handlers** — so an error raised while awaiting it is
actually caught. Co-presence (a spillage elsewhere in the program) does not
count. This makes the contract "every cascade has an error-aware consumer"
literally enforced rather than merely asserted.

---

## 6. Architecture

```
            ┌───────────────────────────────────────────────────────┐
            │                     Thirsty-Lang                       │
            │   lexer → parser → checker → interpreter (governed)    │
            └───────────────┬───────────────────────┬───────────────┘
                            │ capability requests   │ AST
                            ▼                        ▼
        ┌──────────────────────────────┐   ┌────────────────────────────┐
        │           T.A.R.L.           │   │     Semantic Verifiers      │
        │ first-match policy engine    │   │ Shadow Thirst (convergence, │
        │ + signed proofs              │   │   determinism, 6 analyzers) │
        │ + temporal windows + archive │   │ Thirst of Gods (deity)      │
        │ + Z3 static analysis (opt)   │   └────────────────────────────┘
        └──────────────┬───────────────┘                  │
                       │ Z3 translation (shared)           │ Z3 (shared)
                       ▼                                    ▼
                 ┌───────────────────────────────────────────────┐
                 │              z3-solver  [analysis]             │
                 └───────────────────────────────────────────────┘

   Symbolic / binary tiers:  TSCG (canonicalize + checksum) · TSCG-B (framing)
   Tooling: REPL · formatter · LSP · project scaffolding · package integrity
```

Key components:

- **`utf.thirsty_lang`** — `lexer`, `token`, `ast`, `parser`, `checker`,
  `typesys`, `interpreter`, `formatter`, plus the module/package systems and CLI.
- **`utf.tarl`** — `core`/`spec` (parser + verdicts), `runtime`
  (`evaluate_with_proof`, temporal), `analyzer` (Z3), `archive`, `verifier`,
  `composer`, `explainer`, `tester`, `lsp`, CLI.
- **`utf.shadow_thirst`** — six analyzers, the layered `convergence` module, the
  promotion engine, CLI.
- **`utf.thirst_of_gods`** — deity-contract detection and diagnostics, CLI.
- **`utf.tscg` / `utf.tscg_b`** — symbolic grammar and integrity-framed binary.

The unifying engineering choice is reuse: capability gating, temporal
enforcement, and policy analysis are *one* runtime; SMT translation is *one*
strategy shared by policy analysis and convergence; the sandbox that runs
execute-and-compare is the *same* interpreter the language ships.

---

## 7. Stability & Evaluation

The project treats stability as an enforced property, not a milestone.

- **Test suite.** 623 tests pass on Python 3.11 and 3.12, covering the language
  core, governance, the verifier layers (including the Z3 path via
  `importorskip`), T.A.R.L., and the symbolic tiers.
- **Examples-in-CI.** Every shipped example is parsed, type-checked, executed,
  and additionally run through its CLI in CI, so the language cannot drift away
  from its own documented surface.
- **Lint gate.** The codebase is clean under the project's `ruff` configuration
  (the lint debt was reduced from 883 findings to zero, including replacing
  `import *` with explicit imports that unmask genuinely undefined names).
- **Coverage floor.** CI enforces a minimum coverage threshold; a regression
  below it fails the build.
- **Capability → test matrix.** [STATUS.md](STATUS.md) maps every capability to
  the test that proves it. A row marked "Real" is a falsifiable claim.

The continuous-integration pipeline (lint + full suite + coverage + examples,
across two Python versions, plus a wheel-build/import smoke job) is the release
gate: a red pipeline blocks publication.

---

## 8. Use Cases

1. **Governed agent / tool runners.** An autonomous system emits `.thirsty`;
   executed in `governed` mode under a T.A.R.L. policy, it can only import and
   perform I/O that policy sanctions, every action yields a verifiable proof, and
   contracts bound its observable behavior. The governance floor means the
   generated program cannot catch its way out of a denial.
2. **Provably-safe code migration.** A proposed refactor is submitted as a Shadow
   Thirst `mutation` against a validated canonical; it is promoted only if the
   structural, symbolic, or sampling layer establishes equivalence, and rejected
   with a concrete diverging input otherwise.
3. **Time-boxed and conditional authority.** Temporal T.A.R.L. policies express
   "allowed only within this window / for this duration," provable with the
   static analyzer and reconstructable from the audit archive.
4. **Tamper-evident artifacts.** TSCG canonicalization + SHA-256 checksums and
   TSCG-B integrity-framed binary streams give content-addressed, verifiable
   symbolic and binary representations.
5. **Contract-checked components.** `requires` / `ensures` / `invariant` on
   methods give runtime design-by-contract that the component's own error
   handling cannot bypass — useful wherever a library must *guarantee*, not
   merely *document*, its pre- and post-conditions.

---

## 9. Limitations and Roadmap

Stated honestly, because soundness depends on knowing the boundaries:

- **Z3 convergence covers a fragment.** Symbolic equivalence is proven only for
  straight-line integer arithmetic; control flow, division, and non-integer types
  defer to sampling. Sampling *refutes* soundly but *confirms* probabilistically.
- **Effect comparison is conservative.** The execute-and-compare layer abstains
  on any observable effect rather than risk an unsound "equivalent."
- **Single-process runtime.** `cascade` uses a thread pool; the model is
  concurrency-for-await, not a distributed scheduler.
- **Surface still maturing.** Some declared constructs (e.g. richer generics,
  additional security-block semantics) are reserved or partial; the grammar and
  [STATUS.md](STATUS.md) mark what is real versus roadmap.

Planned directions: widen the symbolic fragment (branches, bounded loops);
richer effect typing so more blocks become comparable; distributed cascade
scheduling; and expanded policy composition operators.

---

## 10. Related Work

Thirsty-Lang sits at the intersection of several lines of work and differs from
each in a specific way:

- **Design-by-contract** (Eiffel, JML, Dafny). Thirsty-Lang's `requires` /
  `ensures` / `invariant` are familiar, but contract failure is a *non-bypassable
  governance floor* rather than an assertion the program could disable or catch,
  and contracts are paired with capability gating in the same mode.
- **Capability-secure languages** (E, Pony's object capabilities). Those
  restrict authority through references; Thirsty-Lang externalizes the authority
  decision to a *policy engine with proofs and temporal windows*, so the
  authorization model is inspectable and analyzable apart from the code.
- **Policy languages** (Rego/OPA, Cedar). T.A.R.L. shares first-match evaluation
  and adds HMAC-signed decision proofs, a temporal audit archive, and SMT-backed
  coverage/shadow/conflict/equivalence/refinement analysis — and is wired
  directly into a language's execution rather than sitting beside it.
- **Translation validation / equivalence checking.** Convergence applies the
  classic "prove equivalence, else exhibit a counterexample" discipline at the
  granularity of a language-level mutation, layering a sufficient structural
  check, an SMT proof, and sound sampling.

---

## 11. Conclusion

Thirsty-Lang's wager is that governance belongs *in* the language: enforced by
the runtime, decided by an analyzable policy engine, proven where the fragment is
tractable, and audited by signed certificates — with semantic verifiers that
establish behavioral properties over the real syntax tree instead of guessing
from text. The result is a system where a program's permissions, its
behavioral contracts, and the equivalence of a proposed change are *checked
facts* rather than reviewer hopes. As more code is written and run by agents,
that shift — from "trust the author" to "the artifact carries its own proof" — is
the one that fundamentally changes the game.

---

## Appendix A — Minimal grammar (implemented surface)

```
program        = module_header { import_stmt } { declaration } EOF ;
module_header  = "module" identifier ":" ( "core" | "governed" ) ;
import_stmt    = "import" string [ "as" identifier ] ;
var_decl       = "drink" [ "mut" ] identifier [ ":" type ] "=" expr ;
function       = "glass" identifier "(" params ")" [ "->" type ] contracts block ;
contracts      = { "requires" expr | "ensures" expr | "invariant" expr } ;
class          = "fountain" identifier "{" { field | method } "}" ;
if_stmt        = "thirsty" "(" expr ")" block
                 { "hydrated" "thirsty" "(" expr ")" block } [ "hydrated" block ] ;
refill_stmt    = "refill" "(" identifier "in" expr ")" block      /* for-each */
               | "refill" "(" expr ")" block ;                    /* while    */
spillage_stmt  = "spillage" block { "error" block } ;
cleanup_stmt   = "cleanup" block "finally" block ;
assign_stmt    = expr "=" expr ;
```

(See [GRAMMAR.md](GRAMMAR.md) for the full EBNF and precedence table.)

## Appendix B — Governed function example

```
module bank: governed

glass withdraw(balance, amount)
    requires amount > 0
    requires amount <= balance
    ensures result == balance - amount
    invariant balance >= 0
{
    return balance - amount
}
```

## Appendix C — Policy and proof

```
policy spend:
  valid_until: 2030-12-31
  when action == "write" and authority == "admin" => ALLOW
  when action == "read"                            => ALLOW
```

A denied `pour` under this policy raises an uncatchable `GovernanceViolation`
carrying an HMAC-signed `TarlProof` of the matched rule, verdict, and temporal
basis — replayable with `tarl verify`.

## Appendix D — Convergence verdict ladder

```
structural equal? ── yes ─▶ PROMOTE (proof: same computation up to renaming)
        │ no
        ▼
Z3 available & in fragment? ── UNSAT ─▶ PROMOTE (proof: equal for all inputs)
        │                       SAT  ─▶ REJECT  (counterexample input)
        │ unsupported / unavailable
        ▼
effect-free?  ── run seeds ── all agree ─▶ PROMOTE (observed on N inputs)
        │                     mismatch  ─▶ REJECT  (diverging input)
        │ has effects
        ▼
            fall back to conservative structural verdict
```

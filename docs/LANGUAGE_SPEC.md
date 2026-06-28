# Thirsty-Lang Language Specification

**Version:** 0.1.0
**Copyright:** 2026 Thirsty's Projects LLC (Apache 2.0)

---

## Overview

Thirsty-Lang (Universal Thirsty Family — UTF) is a 6-tier governance-first language stack. Each tier adds progressive capabilities while maintaining default-DENY governance at every gate.

---

## Tier 1 — Thirsty-Lang (Core)

The base language with water-metaphor syntax.

### Keywords

| Keyword | Token | Purpose |
|---------|-------|---------|
| `drink` | DRINK | Variable declaration |
| `mut` | MUT | Mutable modifier |
| `pour` | POUR | Print/emit value |
| `sip` | SIP | Read input |
| `glass` | GLASS | Function declaration |
| `return` | RETURN | Return from function |
| `thirsty` | THIRSTY | If (conditional) |
| `hydrated` | HYDRATED | Else (conditional) |
| `thirst` | THIRST | Guard/when expression |
| `quench` | QUENCH | Default in guard |
| `refill` | REFILL | Loop (while/for) |
| `times` | TIMES | Repeat n times |
| `module` | MODULE | Module declaration |
| `import` | IMPORT | Import module |
| `from` | FROM | From-import |
| `as` | AS | Import alias |
| `and` | AND | Logical AND |
| `or` | OR | Logical OR |
| `not` | NOT | Logical NOT |
| `true` | BOOL_TRUE | Boolean true |
| `false` | BOOL_FALSE | Boolean false |
| `none` | NONE | Null value |

### Operators

| Operator | Token | Purpose |
|----------|-------|---------|
| `+` | PLUS | Addition / string concat |
| `-` | MINUS | Subtraction |
| `*` | STAR | Multiplication |
| `/` | SLASH | Division |
| `%` | PERCENT | Modulo |
| `==` | EQEQ | Equality |
| `!=` | NE | Not equal |
| `<` | LT | Less than |
| `>` | GT | Greater than |
| `<=` | LE | Less or equal |
| `>=` | GE | Greater or equal |
| `=` | ASSIGN | Assignment |
| `\|>` | PIPE | Pipe operator |
| `->` | ARROW | Return type arrow |
| `(` `)` | LPAREN/RPAREN | Grouping / calls |
| `{` `}` | LBRACE/RBRACE | Blocks |
| `[` `]` | LBRACKET/RBRACKET | Indexing (future) |
| `:` | COLON | Type annotation |
| `,` | COMMA | Separator |

### Syntax Examples

```thirsty
module hello: core

glass greet(name: String) -> String {
    return "hello, " + name + "!"
}

drink main = greet("thirsty world")
pour main
```

```thirsty
module loop: core

refill(drink x = 0; x < 10; mut x = x + 1) {
    pour x
}
```

```thirsty
module guards: core

thirst (x > 0) {
    pour "positive"
} hydrated thirst (x < 0) {
    pour "negative"
} hydrated {
    pour "zero"
}
```

### Types

- `Int` — Integer values
- `Float` — Floating-point values
- `String` — String values
- `Bool` — Boolean values
- `NoneType` — Null type

### CLI Commands

| Command | Description |
|---------|-------------|
| `thirsty run <file>` | Execute a .thirsty file |
| `thirsty repl` | Start interactive REPL |
| `thirsty build <file> --target js` | Build to JavaScript |
| `thirsty fmt <files>` | Format .thirsty files |
| `thirsty new <name>` | Scaffold new project |
| `thirsty govern <file>` | Governance operations |
| `thirsty add <package>` | Add dependency |
| `thirsty audit` | Audit dependencies |
| `thirsty lock` | Generate lockfile |
| `thirsty doctor` | Project health check |
| `thirsty lsp` | Start LSP server |
| `thirsty docs` | Generate documentation |

---

## Tier 2 — Thirst of Gods

Adds object-oriented programming, async execution, and structured error handling.

### Keywords

| Keyword | Token | Purpose |
|---------|-------|---------|
| `fountain` | FOUNTAIN | Class declaration |
| `cascade` | CASCADE | Async function |
| `await` | AWAIT | Await async result |
| `spillage` | SPILLAGE | Try block |
| `cleanup` | CLEANUP | Resource cleanup |
| `finally` | FINALLY | Finalizer |
| `error` | ERROR | Error handler |
| `throw` | THROW | Throw error |
| `this` | THIS | Self reference |
| `new` | NEW | Instantiate class |
| `public` | PUBLIC | Public visibility |
| `private` | PRIVATE | Private visibility |

### Syntax Examples

```thirsty
fountain Counter {
    drink count: Int = 0

    glass increment() {
        mut this.count = this.count + 1
    }
}

drink c = new Counter()
c.increment()
```

```thirsty
spillage {
    drink result = risky_operation()
} error (e) {
    pour "Error: " + e
}
```

---

## Tier 3 — T.A.R.L. (Thirsty's Active Resistance Language)

A policy-as-code engine with default-DENY governance.

### Keywords

| Keyword | Token | Purpose |
|---------|-------|---------|
| `policy` | POLICY | Policy declaration |
| `when` | WHEN | Policy condition |
| `ALLOW` | ALLOW | Allow verdict |
| `DENY` | DENY | Deny verdict |
| `ESCALATE` | ESCALATE | Escalate verdict |

### Syntax

```tarl
policy example:
    when user.role == "admin" -> ALLOW
    when user.ip in blacklist -> DENY
    default -> ESCALATE
```

TarlVerdict values: ALLOW, DENY, ESCALATE. Default-DENY applies when no rule matches.

---

## Tier 4 — Shadow Thirst

Mutation analysis and invariant verification.

### Keywords

| Keyword | Token | Purpose |
|---------|-------|---------|
| `shadow` | SHADOW | Shadow block |
| `invariant` | INVARIANT | Invariant declaration |
| `canonical` | CANONICAL | Canonical form |
| `promote` | PROMOTE | Promote block |
| `reject` | REJECT | Reject block |

### Built-in Analyzers

The analyzers parse each `shadow` / `invariant` / `canonical` block with
Thirsty-Lang's own lexer + parser and reason over the resulting **AST** (with a
lexical fallback when a block does not parse):

1. **Plane Isolation** — Walks the shadow block for writes into `canonical_*`
   bindings or calls into the canonical plane
2. **Determinism** — Flags *calls* to non-deterministic functions (`now()`,
   `rand()`, `uuid()`, …), not like-named variables
3. **Resource Estimation** — Estimates CPU/memory from loop, call, and
   allocation nodes
4. **Purity Spring** — Checks the invariant block for impure calls / output
   statements
5. **Memory Evaporation** — Counts allocation nodes (`new`, reservoir literals,
   floods)
6. **Canonical Convergence** — Compares shadow and canonical via structural AST
   equivalence (alpha-renamed shape + return arity)

---

## Tier 5 — TSCG (Thirsty Symbolic Constraint Grammar)

Symbolic security expressions with 9 core symbols.

### Symbols

| Symbol | Name | Purpose |
|--------|------|---------|
| COG | Cognition | Cognitive capability |
| DNT | Do Not Track | Privacy constraint |
| SHD | Shield | Protection boundary |
| INV | Invariant | Invariant condition |
| CAP | Capability | Capability grant |
| QRM | Quorum | Consensus requirement |
| COM | Communication | Communication channel |
| ANC | Anchor | Trust anchor |
| RFX | Reflexive | Self-reference |

### Operators

- Pipeline: `->`
- AND-combine: `^`
- OR-combine: `||`

For boolean operands, `^` evaluates as logical AND and `||` evaluates as
logical OR. For structured operands, `^`/`||` keep their runtime composition
behavior: dictionaries merge and reservoirs concatenate.

All expressions are SHA-256 canonicalized.

---

## Tier 6 — TSCG-B (Thirsty Symbolic Constraint Grammar — Binary)

Binary frame protocol for TSCG expressions.

### Frame Format

- Magic bytes: `TSGB` (4 bytes)
- CRC32 integrity check (4 bytes)
- SHA-256 payload verification (32 bytes)
- Automatic resynchronization for multi-frame transport

---

## License

Copyright 2026 Thirsty's Projects LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Thirsty-Lang Grammar (Tier 1)

## Reserved Keywords (Higher Tiers)

The following keywords are syntactically reserved for Tiers 5/6 (TSCG / TSCG-B)
and produce no runtime effect in Thirsty-Lang core. They exist in the lexer
for upward compatibility only.

```
shield     — identity/access context barrier
sanitize   — data scrubbing annotation
armor      — runtime safety wrap
morph      — type coercion boundary
detect     — anomaly tap point
defend     — invariant enforcement hook
```

See `docs/governance_model.md` for the tier escalation model.

---

An EBNF-style formal grammar for the Thirsty-Lang programming language (core tier).  
This doc covers lexical grammar, program structure, types, expressions, statements, and declarations.

---

## Notation

- `"…"` — literal keyword or symbol
- `'…'` — literal character or token
- `( … )` — grouping
- `[ … ]` — optional
- `{ … }` — zero or more repetitions
- `… | …` — alternation
- `/* … */` — semantic comment

---

## 1. Lexical Grammar

```
letter         = "A".."Z" | "a".."z" ;
digit          = "0".."9" ;
hex_digit      = digit | "a".."f" | "A".."F" ;
ident_char     = letter | digit | "_" | "." ;

identifier     = ( letter | "_" ) { ident_char } ;

integer        = digit { digit }
               | "0x" hex_digit { hex_digit }
               | "0b" ("0" | "1") { ("0" | "1") } ;

float          = digit { digit } "." digit { digit } [ ("e" | "E") ["+" | "-"] digit { digit } ] ;

string         = '"' { char | escape } '"' ;
escape         = "\\" ( "n" | "t" | "r" | "0" | "\\" | '"' | "x" hex_digit hex_digit ) ;

comment        = "//" { char } newline
               | "/*" { char } "*/" ;

newline        = '\n' ;
whitespace     = ' ' | '\t' | '\r' | newline ;
```

---

## 2. Program Structure

```
program        = module_header { import_stmt } { declaration } EOF ;

module_header  = "module" identifier ":" module_mode ;

module_mode    = "core" | "governed" | "strict" | "pure" ;

/* "strict": every `drink`/`let` binding must have an initializer (a bare
   `drink x` is a runtime error). "pure": side-effecting I/O (`pour`/`sip`)
   is rejected at runtime. */

import_stmt    = "import" string [ "as" identifier ] ;
```

---

## 3. Types

```
type           = simple_type | function_type | tuple_type | "any" | "never" ;

simple_type    = "int" | "float" | "str" | "bool" | "void"
               | identifier          /* user-defined types */ ;

function_type  = "(" [type { "," type }] ")" "->" type ;

tuple_type     = "(" type { "," type } ")" ;
```

---

## 4. Expressions

Expressions are listed in order of **increasing precedence** (lowest first).

```
expr           = assignment ;

assignment     = pipeline "=" expr                  /* if LHS is assignable */
               | pipeline ;

pipeline       = pipe { "|" pipe } ;

pipe           = combine { "|>" combine } ;

combine        = logical_or { "||" logical_or } ;

logical_or     = logical_and { "or" logical_and } ;

logical_and    = equality { "and" equality } ;

equality       = comparison { ("==" | "!=") comparison } ;

comparison     = term { ("<" | ">" | "<=" | ">=") term } ;

term           = factor { ("+" | "-") factor } ;

factor         = unary { ("*" | "/" | "%") unary } ;

unary          = ("+" | "-" | "!") unary
               | call ;

call           = primary { "(" [expr { "," expr }] ")"       /* function call */
                         | "." identifier                     /* member access */
                         | "[" expr "]" } ;                   /* subscript */

primary        = literal
               | identifier
               | "(" expr ")"
               | string_expr
               | array_literal
               | struct_literal ;

literal        = integer
               | float
               | "true" | "false"
               | "null"
               | "quenched"
               | "thirsty_error" ;

string_expr    = string { string } ;                /* concatenation */

array_literal  = "[" [expr { "," expr }] "]" ;

struct_literal = identifier "{" [field_init { "," field_init }] "}" ;

field_init     = identifier "=" expr ;
```

---

## 5. Statements

```
stmt           = variable_decl
               | pour_stmt
               | sip_stmt
               | assign_stmt
               | if_stmt
               | refill_stmt
               | return_stmt
               | import_stmt
               | block
               | pipe_block_stmt
               | expr_stmt
               | ";" ;

variable_decl  = "drink" identifier [":" type] [ "=" expr ] ";"
               | "let" identifier [":" type] [ "=" expr ] ";"   /* immutable */
               | identifier ":=" expr ";" ;                      /* define mutable */

for_stmt       = "for" [ "(" ] identifier "in" expr [ ")" ] block ;

pour_stmt      = "pour" expr ";" ;

sip_stmt       = "sip" identifier [ "=" expr ] ";" ;

assign_stmt    = expr "=" expr ";" ;

if_stmt        = "thirsty" "(" expr ")" block
                 { "hydrated" "thirsty" "(" expr ")" block }
                 [ "hydrated" block ] ;

refill_stmt    = "refill" "(" identifier "in" expr ")" block    /* for-loop */
               | "refill" "(" expr ")" block ;                  /* while-loop */

return_stmt    = "return" [expr] ";" ;

block          = "{" { stmt } "}" ;

pipe_block_stmt = "|" [">"] expr ";" ;

expr_stmt      = expr ";" ;
```

---

## 6. Declarations

```
declaration    = function_decl
               | class_decl
               | spillage_decl
               | cleanup_decl
               | enum_decl
               | struct_decl
               | interface_decl
               | morph_def
               | security_block
               | cascade_call
               | mutation
               | symbol ;

function_decl  = "glass" identifier "(" [param { "," param }] ")" [":" type]
                 [ "requires" expr ]                  /* governed precondition */
                 block ;

/* A function with a `requires` clause is a *governed function*: the interpreter
   evaluates the precondition on every call and denies (GovernanceViolation) on a
   falsy result. See docs/governance_model.md § Runtime Enforcement. */

param          = identifier ":" type ;

class_decl     = "fountain" identifier
                 [ ":" type_list ]                    /* mixins / interfaces */
                 "{" { class_member } "}" ;

class_member   = function_decl
               | variable_decl
               | "init" "(" [param { "," param }] ")" block ;

spillage_decl  = "spillage" identifier
                 [ "(" param ")" ]
                 "{" { handler } "}" ;

handler        = "cascade" identifier block
               | "converge" identifier block
               | "deflect" identifier block ;

cleanup_decl   = "cleanup" identifier
                 "(" [param] ")"
                 block
                 [ "->" block ] ;                    /* finalizer */

enum_decl      = "enum" identifier "{" enum_variant { "," enum_variant } "}" ;

enum_variant   = identifier [ "(" type { "," type } ")" ] ;

struct_decl    = "struct" identifier "{" struct_field { "," struct_field } "}" ;

struct_field   = identifier ":" type ;

interface_decl = "interface" identifier "{" interface_sig { ";" interface_sig } "}" ;

interface_sig  = identifier "(" [type { "," type }] ")" [":" type] ;

morph_def      = "morph" identifier "(" identifier ":" type ")" "->" type block ;

security_block = "shield" "(" expr ")" block
               | "detect" "(" expr ")" block ;

defend_strat   = "defend" identifier "(" expr ")" block ;

cascade_call   = "cascade" identifier "(" expr ")" ";" ;

mutation       = "mutation" identifier "(" expr ")" block ;

symbol         = "symbol" identifier "=" expr ";" ;

new_expr       = "new" identifier "(" [expr { "," expr }] ")" ;   /* class instantiation */
```

---

## 7. Patterns

```
pattern        = wildcard_pattern | bind_pattern | literal_pattern | tuple_pattern ;

wildcard_pattern = "_" ;

bind_pattern   = identifier ;

literal_pattern = integer | float | string | "true" | "false" | "null" ;

tuple_pattern  = "(" [pattern { "," pattern }] ")" ;
```

*(Patterns appear in guard/thirsty expressions and cascade handlers.)*

---

## 8. Precedence Table

| Level | Operators | Associativity |
|-------|-----------|---------------|
| 1 (lowest) | `=` | right |
| 2 | `\|\|` | left |
| 3 | `or` | left |
| 4 | `and` | left |
| 5 | `==` `!=` | left |
| 6 | `<` `>` `<=` `>=` | left |
| 7 | `+` `-` | left |
| 8 | `*` `/` `%` | left |
| 9 | unary `+` `-` `!` | right |
| 10 | `(…)` `.` `[…]` | left |
| 11 (highest) | primary | — |

---

## 9. Keywords

```
drink, let, for, strict, pure,
pour, sip, thirsty, hydrated, thirst, quench, refill, times,
glass, reservoir, well, of, flood, drip, evaporate, condense, fountain,
return, parched, quenched, empty, mut, in, import, from, as,
shield, sanitize, armor, morph, detect, defend, cascade, this, new,
public, private, await, spillage, cleanup, finally, error, throw,
policy, when, allow, deny, escalate, mutation, validated_canonical,
invariant, shadow, canonical, promote, reject, governed, requires, ensures,
enum, struct, interface, symbol, module, core, and, or, not,
true, false, none
```

The `requires` keyword introduces a governed-function precondition (see
`function_decl` in § 6). The `governed` keyword is a module mode
(`module <name>: governed`) under which governed functions are enforced and
calls to them from `core` mode are denied.

---

## 10. Comments & Whitespace

- **Comments**: `//` line comments and `/* … */` block comments (can nest).
- **Whitespace**: spaces, tabs, newlines — ignored except as token separators.
- **Semicolons**: required as statement terminators; no automatic semicolon insertion.
# Governance Model

## Overview

Thirsty-Lang implements a **deny-by-default governance model** via T.A.R.L. (Thirsty's Active Resistance Language), ensuring that all potentially sensitive operations must be explicitly authorized before execution.

## Core Principles

1. **Deny by Default**: Without explicit authorization, all operations are denied.
2. **Policy-Driven**: Authorization rules are expressed as declarative policies, not imperative code.
3. **Staged Evaluation**: Policies support three verdicts:
   - **ALLOW** — Operation proceeds
   - **DENY** — Operation is blocked
   - **ESCALATE** — Operation requires manual review or higher-tier approval

4. **Composable Tiers**: Governance tiers stack (Tier 1 through Tier 6), with higher tiers enforcing stricter policies.

## T.A.R.L. Policy Language

### Syntax

```
policy <policy_name>

when <condition> => ALLOW|DENY|ESCALATE
when <condition> => ALLOW|DENY|ESCALATE
...
```

### Example Policy

```
policy resource_access

when role == "admin" => ALLOW
when role == "user" and level >= 3 => ALLOW
when action == "delete" and resource == "critical" => ESCALATE
when action == "read" and resource == "public" => ALLOW
when action == "write" and resource == "system" => DENY
when source == "external" and port > 1024 => DENY
```

### Conditions

Conditions are evaluated as sandboxed expressions supporting:

- **Comparisons**: `==`, `!=`, `<`, `>`, `<=`, `>=`
- **Logical operators**: `and`, `or`, `not`
- **Literals**: strings (`"value"`), integers (`42`), floats (`3.14`), booleans (`true`/`false`)
- **Context variables**: Any key in the evaluation context
- **Arithmetic**: Addition (`+`) within comparisons

### Safe Evaluation

T.A.R.L. expressions are evaluated in a **sandboxed environment**:

- Unknown identifiers resolve to `False` (fail-safe)
- Only literal values and safe operators allowed
- No function calls, imports, or state mutation possible
- Parallel rule evaluation with adaptive ordering (most-matched rules evaluated first)

## Integration with Thirsty-Lang

### Runtime Enforcement (the interpreter, today)

Governance is enforced at runtime for **governed functions** — functions that
declare a precondition with `requires`:

```thirsty
module bank: governed
glass withdraw(amt) requires amt > 0 {
    return amt * 2
}
```

On **every call** to a governed function, the interpreter applies a layered,
default-deny decision (`Interpreter._enforce_governance`):

1. **In-language contract predicates** — `requires`, `ensures`, and `invariant`
   expressions are evaluated in the call scope. A falsy result denies the call
   and raises `GovernanceViolation`.
2. **Cross-mode guard** — a governed function invoked while the program is not
   in `governed` mode is denied (the runtime counterpart of checker error
   `E053`, "cannot call governed function from core mode").
3. **T.A.R.L. routing** — when a `TarlRuntime` is attached
   (`interpreter.attach_tarl(runtime)`) and an authority context is set, the
   call is routed through the policy engine. A non-`ALLOW` verdict denies, and
   a `TarlProof` certificate is recorded on `interpreter._last_proof`.

   The proof binds the policy hash, the canonical context hash, the matched
   rule, the verdict, and the evaluation trace. It is **unsigned by default**.
   Two signing modes exist: legacy **HMAC-SHA256**, a *symmetric* MAC that is
   forgeable by anyone holding the shared key, and **Ed25519**, an asymmetric
   signature whose verifier needs only the public key. Use Ed25519 when a proof
   must attest to the signer rather than merely detect tampering by parties
   without the shared HMAC key. The `thirsty run` path emits unsigned proofs
   unless the embedding runtime configures a signing key.
4. **Default** — in `governed` mode, a governed function with no attached
   policy engine or no authority is **denied** with a proof. A call that no
   layer explicitly allowed is denied (deny-by-default).

A `GovernanceViolation` is a hard floor: `spillage` error handlers do **not**
catch it, so governed denials cannot be swallowed by user error handling. This
includes denials raised while importing a `.thirsty` module: imported modules
run under the **caller's** governed runtime, so their effects are gated rather
than executed in a detached, ungoverned interpreter. A `governed` module that
fails to parse also fails closed — its recovered statements are discarded and
execution is refused.

For verification, `ProofVerifier` rejects unsigned proofs by default. Local
inspection of unsigned proofs must opt in explicitly with
`ProofVerifier(require_signature=False)` or `tarl verify --allow-unsigned`.
Hardened deployments can also restrict signature algorithms (for example,
Ed25519-only) and require policy-source binding. The CLI exposes these as
`tarl verify --ed25519-only --policy <policy.tarl>`.

Building a `governed` module to a target that drops the governed runtime
(`js`, `llvm-*`, `wasm-pyodide`) is refused by default; `thirsty build
--allow-governance-loss` is required to proceed and records the loss in the
emitted manifest. When `--emit-manifest` is used, the manifest records source
hash, optional policy hash, required capabilities, derived or attached context
schema, authority mode, proof verification mode, audit requirement, Shadow
Thirst status when statically visible, and governance-loss status.

### Static proof-obligation reporting

`thirsty prove` is a static, no-side-effect path:

```bash
thirsty prove program.thirsty --policy policy.tarl --emit-manifest
```

It lexes, parses, checks, and walks the AST, then emits a machine-readable JSON
report. It does not instantiate the interpreter and does not execute program
side effects. The report includes functions, imports, sensitive stdlib calls,
governed calls, required TARL actions, required capabilities, context schema,
authority requirements, contract obligations, proof mode, audit requirement,
Shadow Thirst status, governance-loss status, diagnostics, and unresolved proof
gaps. Required TARL actions include capability actions and governed function-call
actions.

Context schema handling is fail-closed. If `--context-schema schema.json` is
provided, that explicit schema is authoritative. Without an explicit schema,
`thirsty prove` derives field names and simple kinds from TARL policy
references where possible. Ambiguous references are reported as
`context_schema.status = incomplete`, and `thirsty prove` exits non-zero instead
of claiming the proof obligation set is complete.
Explicit schema files may use a list of field objects or a compact mapping:

```json
{"fields": {"user.role": "string", "risk": {"kind": "number", "required": false}}}
```

Malformed explicit schema entries fail with validation errors instead of being
treated as proof-ready.

`thirsty explain-denial program.thirsty --policy policy.tarl` emits a
machine-readable explanation of missing policy, context, authority, and proof
conditions for the same static obligation set.

From the CLI:

```bash
thirsty run program.thirsty --thirst-level governed \
    --authority admin --policy access.tarl
```

`--authority` injects the authority tag into the governance context; `--policy`
routes governed calls through the named `.tarl` policy. A denial prints
`governance denied: <fn>: <reason>` (with the proof verdict/hash when policy
routing produced one) and exits non-zero.

### Roadmap (extended governance)

Future tiers aim to extend governance gates to task scheduling, network
operations, filesystem operations, and external interop. These are not yet
enforced by the interpreter.

## Runtime Evaluation

### TarlRuntime

The `TarlRuntime` class provides:

1. **LRU Caching** (128 entries) — Policies are cached by context hash for performance
2. **Parallel Evaluation** — Rules evaluated concurrently via ThreadPoolExecutor
3. **Adaptive Ordering** — Frequently-matched rules are prioritized
4. **Policy Hotswapping** — Policies can be updated at runtime without restart

### CLI Usage

Evaluate a policy against a context:

```bash
tarl eval policy.tarl --context '{"role":"user","level":2}'
```

Temporal policy windows and `CURRENT_*` builtins require a trusted evaluation
time on the CLI:

```bash
tarl eval policy.tarl --context '{"role":"user"}' --now 2026-07-01T12:00:00Z
```

Parse and display a policy:

```bash
tarl parse policy.tarl
```

## Security Considerations

1. **Context Injection** — Contexts are supplied at runtime; validate all sources
2. **Policy Updates** — Policies should be cryptographically signed before deployment
3. **Audit Logging** — All policy decisions (especially ESCALATE) should be logged
4. **Performance** — Cached results may become stale; set appropriate cache TTLs for security-critical paths

## Future Enhancements

- **Cryptographic Policy Signatures** — Sign policies to prevent tampering
- **Temporal Policies** — Time-based authorization (e.g., "allow 9-5 weekdays only")
- **Attribute-Based Access Control (ABAC)** — Richer context and condition evaluation
- **Policy Versioning** — Track policy versions and rollback capability
- **Metrics & Analytics** — Track policy evaluation metrics for optimization

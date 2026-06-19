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

### Tier 1 (Core Language)

Tier 1 requires T.A.R.L. policies for:
- **Module imports** — which modules may be loaded
- **Function definitions** — which functions may be defined at module/global scope
- **Variable access** — which variables may be read/written

### Tier 2+ (Extended Governance)

Higher tiers extend governance to:
- **Task scheduling** — which tasks may execute and with what priority
- **Network operations** — which hosts/ports may be accessed
- **Filesystem operations** — which paths may be read/written
- **Interop with external systems** — which integrations are allowed

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

- **Cryptographic Signatures** — Sign policies to prevent tampering
- **Temporal Policies** — Time-based authorization (e.g., "allow 9-5 weekdays only")
- **Attribute-Based Access Control (ABAC)** — Richer context and condition evaluation
- **Policy Versioning** — Track policy versions and rollback capability
- **Metrics & Analytics** — Track policy evaluation metrics for optimization

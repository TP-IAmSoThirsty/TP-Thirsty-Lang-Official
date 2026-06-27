# Thirsty-Lang Offensive Threat Model

## Purpose

This document defines the adversary model for Thirsty-Lang as a governance AI
substrate: a language/runtime layer that mediates human, AI, script, service,
and tool actions before side effects happen.

The defensive claim is not that Thirsty-Lang is a Python replacement. The claim
is narrower and harder: under hostile conditions, a governed runtime should
make unauthorized capability use structurally difficult, auditable, and
fail-closed.

## Security Objective

Thirsty-Lang succeeds when all sensitive action attempts pass through a single
governed decision path:

1. Build a canonical action context.
2. Evaluate policy and contracts.
3. Produce a proof-bearing ALLOW, DENY, or ESCALATE verdict.
4. Execute only on ALLOW.
5. Refuse by default when authority, policy, context, proof, or runtime state is
   missing, stale, malformed, or compromised.

No claim is earned unless it is backed by code, tests, docs, or explicit
roadmap status.

## Existing Resistance Surface

Thirsty-Lang already has several defensive primitives that directly reduce the
attack surface in this model. These are not complete hardening by themselves,
but they are real substrate features rather than future aspirations.

| Feature | Defensive value | Evidence |
|---|---|---|
| Governed mode | Separates ordinary execution from authority-checked execution | `tests/test_governance_maximal.py`; `tests/test_gate_fail_closed.py` |
| Default-deny capability gates | Blocks governed I/O/import and sensitive imported stdlib calls when policy or authority is missing | `tests/test_gate_fail_closed.py` |
| TARL policy engine | Moves authorization into explicit policy instead of code convention | `tests/test_tarl.py`; `tests/test_tarl_composition.py` |
| `ALLOW` / `DENY` / `ESCALATE` verdicts | Supports refusal and human/escalation workflows instead of binary allow-only logic | `tests/test_tarl.py` |
| `requires` / `ensures` / `invariant` contracts | Makes preconditions, postconditions, and invariants executable runtime checks | `tests/test_governance_maximal.py` |
| `GovernanceViolation` hard floor | Prevents application error handlers from swallowing governance denials | `tests/test_gate_fail_closed.py` |
| Proof-carrying evaluation | Binds decision output to policy hash, context hash, verdict, and trace | `tests/test_tarl_proof.py` |
| Ed25519 proof signatures | Provides asymmetric verification for non-repudiable proof records | `tests/test_tarl_proof.py`; `tests/test_cli_tarl.py` |
| Temporal policy windows | Reduces stale authorization and emergency-policy blast radius | `tests/test_tarl_temporal.py` |
| First-match-wins policy order under adaptive execution | Prevents optimization from changing authorization semantics | `tests/test_tarl.py` |
| Safe expression evaluator | Avoids eval/import/state mutation inside policy conditions | `tests/test_tarl.py` |
| Shadow Thirst analyzers | Detects unsafe mutation promotion, determinism failures, and plane leakage | `tests/test_shadow_thirst.py`; `tests/test_verifiers.py` |
| TSCG/TSCG-B integrity surfaces | Provides symbolic constraints and binary-frame integrity checks | `tests/test_tscg.py`; `tests/test_tscg_b.py` |
| UTF-8-safe CLI output | Keeps denial/proof reporting reliable on Windows terminals | `src/utf/console.py`; CLI tests |

The hardening work is therefore not "invent security from nothing." It is to
connect these primitives into a universal capability broker, extend the gates
to every side-effect adapter, and prove the result with offensive challenge
tests.

## Protected Assets

| Asset | Why it matters | Required protection |
|---|---|---|
| Capability gates | They decide whether side effects happen | No bypass path around the gate |
| TARL policies | They encode authority | Hash-bound, versioned, signed before deployment |
| TarlProof records | They are the audit trail | Ed25519 for non-repudiation, replay resistance, trace integrity |
| Authority context | It identifies who or what is acting | Authenticated source, least privilege, no self-asserted authority |
| Runtime context | It drives policy decisions | Canonicalized, validated, no attacker-controlled silent defaults |
| Tool adapters | They bridge to real effects | Every adapter must request capability before effect |
| Audit archive | It preserves what happened | Append-only, tamper-evident, externally verifiable |
| Human escalation path | It handles ambiguous or high-risk actions | Explicit ESCALATE path, quorum or operator confirmation |

## Trust Boundaries

| Boundary | Trusted by default? | Required rule |
|---|---:|---|
| Thirsty source text | No | Parse, check, and govern before execution |
| TARL policy source | No | Verify hash/signature before use |
| AI-generated code | No | Govern all imports, I/O, tool calls, subprocesses, network, FFI |
| Human operator command | No | Authority must be bound into context by a trusted channel |
| CLI arguments | No | Treat as untrusted input to runtime setup |
| Environment variables | No | Never grant authority from env alone |
| Local filesystem | No | Treat policy/proof/config files as mutable attacker inputs |
| Network services | No | External responses are untrusted context |
| Plugin/MCP/tool adapters | No | Must be capability-brokered |
| Test results | Partially | Useful only when reproducible and mapped to a threat |

## Adversary Classes

| ID | Adversary | Capabilities |
|---|---|---|
| A1 | Prompt-injected AI agent | Can generate tool calls, code, policies, and explanations that look benign |
| A2 | Malicious plugin or tool adapter | Can expose side effects outside the language runtime |
| A3 | Compromised local script | Can call CLI/runtime APIs directly and mutate local files |
| A4 | Insider operator | Has legitimate access but attempts unauthorized actions |
| A5 | Policy downgrader | Can edit, swap, delete, or roll back policy files |
| A6 | Proof forger | Can tamper with or mint audit artifacts |
| A7 | Replay attacker | Can reuse old ALLOW proofs or cached decisions |
| A8 | Context poisoner | Can supply misleading context fields, missing fields, or type-confused values |
| A9 | Parser/semantic attacker | Exploits grammar ambiguity, precedence, parser recovery, or unknown identifiers |
| A10 | Import/FFI attacker | Reaches Python, stdlib, native code, shell, or network outside gates |
| A11 | Archive tamperer | Modifies stored proof history or deletes denials |
| A12 | Availability attacker | Forces fail-open through errors, timeouts, resource pressure, or cache abuse |
| A13 | Build/package attacker | Ships a different package than the audited source |
| A14 | Human-social attacker | Uses urgency, authority language, or false mission framing to trigger unsafe ALLOW |

## Offensive Challenge Catalog

Each challenge is an adversarial success attempt. The expected defensive outcome
is what Thirsty-Lang must do to claim resistance.

| ID | Challenge | Expected defensive outcome | Current status |
|---|---|---|---|
| C001 | Run `pour` in governed mode with no policy | DENY with proof | Covered by `tests/test_gate_fail_closed.py` |
| C002 | Run callable stdout builtin `print(...)` in governed mode with no policy | DENY with proof | Covered by `tests/test_gate_fail_closed.py` |
| C003 | Read stdin with `sip` in governed mode with no policy | DENY with proof | Covered by `tests/test_gate_fail_closed.py` |
| C004 | Import a module in governed mode with no policy | DENY with proof | Covered by `tests/test_gate_fail_closed.py` |
| C005 | Allow write policy, then attempt read/import | DENY non-matching capability | Partially covered by capability tests |
| C006 | Wrap a governed denial in `spillage` | Denial propagates; handler cannot swallow it | Covered by governance behavior |
| C007 | Call governed function from core mode | DENY via cross-mode guard/static E053 | Covered by status matrix tests |
| C008 | Use contract predicate ambiguity to invert policy meaning | Parser precedence must preserve author intent | Covered by precedence tests |
| C009 | Tamper TarlProof verdict after signing | Verification fails | Covered by proof tests |
| C010 | Verify Ed25519 proof with wrong public key | Verification fails | Covered by proof tests |
| C011 | Verify Ed25519 proof with no public key | Verification fails | Covered by proof tests |
| C012 | Verify HMAC proof with wrong shared key | Verification fails | Covered by proof tests |
| C013 | Use HMAC as non-repudiation | Documentation must reject claim | Covered by docs; not a runtime block |
| C014 | Replace policy source after proof generation | Policy hash verification fails | Covered by proof verifier tests |
| C015 | Submit malformed proof JSON | CLI verification exits non-zero | Covered by CLI proof tests |
| C016 | Use expired temporal policy | DENY or configured expiry verdict | Covered by temporal tests |
| C017 | Cache a time-bound ALLOW past expiry | Runtime must not cache temporal decisions | Covered by runtime behavior |
| C018 | Use unknown identifiers to silently allow | Unknown identifiers fail safe | Covered by TARL semantics |
| C019 | Inject malformed context JSON through CLI | CLI exits non-zero | Covered by CLI tests |
| C020 | Mutate policy ordering to exploit adaptive evaluation | First-match-wins must remain policy order | Covered by TARL tests |
| C021 | Trigger evaluator exception inside rule condition | Rule fails safe and throw is observable | Covered by runtime throw stats tests |
| C022 | Store tampered proof in archive and query without verifier | Must be documented as unverified unless verifier supplied | Partially covered; stronger archive tests needed |
| C023 | Replay old ALLOW proof for new context | Must reject by context hash and freshness policy | Roadmap |
| C024 | Replay current ALLOW proof for same context after policy revocation | Must reject by policy version/freshness | Roadmap |
| C025 | Downgrade Ed25519 proof to unsigned proof | Serious deployments must require signed proof | Covered by `tests/test_threat_model_proof_strictness.py` — strict `ProofVerifier(require_signature=…, allowed_signature_algorithms=…)` and `tarl verify --require-signature --ed25519-only` reject unsigned/HMAC/wrong-key/tampered proofs (opt-in; permissive default unchanged) |
| C026 | Delete DENY proof from audit archive | Hash-linked append-only audit must reveal gap | Roadmap |
| C027 | Forge authority by setting CLI `--authority admin` | Authority must come from authenticated identity, not string input alone | Roadmap |
| C028 | Put authority in environment variable | Must not grant authority from env alone | Roadmap |
| C029 | Use stdlib `thirst::fs` to write file without gate | Must route filesystem writes through capability broker | Covered by `tests/test_threat_model_capability_broker.py` and `tests/test_gate_fail_closed.py`; every sensitive callable has an explicit action in `module_system.SENSITIVE_STDLIB_CAPABILITIES`. **Deferred (medium):** path-root/canonicalization policy (see C042) |
| C030 | Use stdlib `thirst::http` or `thirst::net` without gate | Must route network through capability broker | Covered by `tests/test_threat_model_capability_broker.py` and `tests/test_gate_fail_closed.py`. **Deferred (medium):** external adapter / real-egress coverage |
| C031 | Use stdlib `thirst::process.run` without gate | Must route subprocess through capability broker | Covered by `tests/test_threat_model_capability_broker.py` and `tests/test_gate_fail_closed.py`. **Deferred (medium):** CLI build subprocesses (`llc`/`clang`/`lli`) are a separate, non-governed surface |
| C032 | Use `thirst::env.set` to poison later decisions | Must route env mutation through capability broker | Covered by `tests/test_threat_model_capability_broker.py` and `tests/test_gate_fail_closed.py` |
| C033 | Use FFI/native extension to perform side effects | Must deny or broker FFI | **Deferred (high):** no FFI broker yet. Next: deny native/`ctypes` reach in governed mode, then add a brokered FFI capability |
| C034 | Use generated JS build output to skip governed runtime | Build artifacts must preserve or declare governance loss | Covered by `tests/test_threat_model_build_outputs.py` — `thirsty build` refuses governance-dropping targets for governed source by default; `--allow-governance-loss` is required, warns on stderr, and records `build.governance_loss` in the manifest |
| C035 | Use package manager or import path confusion to load malicious module | Imports and dependency integrity must be governed | Covered by `tests/test_threat_model_file_imports.py` — imported `.thirsty` modules execute under the **caller's** governed runtime (policy + authority), so top-level effects and returned closures are gated, not run in a detached core interpreter. **Deferred (medium):** dependency-pin/signature integrity for remote packages |
| C036 | Use parser recovery to smuggle executable statements after an error | Parser errors must fail closed for execution | Covered by `tests/test_threat_model_parser_fail_closed.py` — a governed module with any parse error yields zero statements and the interpreter refuses to run it (DENY proof) |
| C037 | Use resource exhaustion to force fail-open | Runtime errors must DENY, not ALLOW | Roadmap |
| C038 | Use denial-of-service to suppress audit writing | Execution should fail closed when required audit cannot persist | Roadmap |
| C039 | Use AI-generated policy with broad `when true => ALLOW` | Policy analysis must flag broad allow and require review | Roadmap |
| C040 | Use prompt injection to instruct an agent to bypass Thirsty | Agent adapters must enforce broker outside model text | Roadmap |
| C041 | Use MCP/tool call directly from agent runtime | Tool adapter must call broker before tool invocation | Roadmap |
| C042 | Use filesystem symlink/path traversal to escape allowed root | Path canonicalization and root policy required | Roadmap |
| C043 | Use time spoofing to satisfy temporal policy | Trusted clock or signed time source required | Roadmap |
| C044 | Use stale cached decision after context changes | Cache key and invalidation must bind all relevant context | Partially covered |
| C045 | Use partial context omission to get safer defaults wrong | Missing required context must DENY or ESCALATE | Roadmap |
| C046 | Use type confusion in policy context | Context schema validation required | Roadmap |
| C047 | Use policy include/composition cycle | Must raise composition error, not fail open | Covered by composition tests |
| C048 | Use parallel evaluation race to alter first-match semantics | Policy order must win | Covered by TARL tests |
| C049 | Use archive query without signature verification as proof of validity | CLI/docs must distinguish stored from verified | Roadmap |
| C050 | Use social pressure language to force high-risk ALLOW | ESCALATE rules and quorum required | Roadmap |

## Mandatory Invariants

These invariants define the substrate. Violating any of them downgrades
Thirsty-Lang from "active resistance runtime" to "policy library."

1. **No effect before verdict.** A side effect cannot happen before ALLOW.
2. **No policy means DENY.** Missing policy never grants authority.
3. **No authority means DENY.** Missing authority never grants authority.
4. **No proof means no audit claim.** Execution without proof cannot be called
   governed execution.
5. **No unsigned proof in hardened mode.** Hardened deployments require Ed25519.
6. **No stale proof as authority.** Proofs describe decisions; they are not
   reusable permission tokens unless a freshness policy says so.
7. **No adapter side doors.** All tool, file, network, subprocess, import, FFI,
   database, and model-action paths go through the broker.
8. **No catch-and-continue for governance denials.** Application error handling
   must not swallow a denial.
9. **No silent downgrade.** If signing, policy, audit, or identity verification
   is required and unavailable, the runtime fails closed.
10. **No unverifiable readiness claim.** Security claims cite tests or are
    labeled roadmap.

## Offensive Test Suites

Implemented this hardening pass:

| Suite | Purpose |
|---|---|
| `tests/test_threat_model_capability_broker.py` | Asserts an import-only policy grants no fs/http/net/process/env/log/test/sqlite side effect (C029–C032) |
| `tests/test_threat_model_file_imports.py` | Imported `.thirsty` modules run under the caller's governed gate, not a detached core interpreter (C035) |
| `tests/test_threat_model_proof_strictness.py` | Strict verification rejects unsigned/HMAC/wrong-key/tampered proofs and missing policy source (C025) |
| `tests/test_threat_model_build_outputs.py` | Governance-dropping build targets are refused for governed source unless explicitly opted in and disclosed (C034) |
| `tests/test_threat_model_parser_fail_closed.py` | Governed parse errors fail closed: no executable statements survive recovery (C036) |

Still required (deferred):

| Suite | Purpose |
|---|---|
| `tests/test_threat_model_proof_replay.py` | Replays old proofs, changed contexts, revoked policies, and stale windows |
| `tests/test_threat_model_policy_downgrade.py` | Swaps policy files, removes signatures, changes versions |
| `tests/test_threat_model_context_poisoning.py` | Supplies missing, malformed, type-confused, and attacker-controlled context |
| `tests/test_threat_model_archive_tamper.py` | Deletes, reorders, and modifies audit records |
| `tests/test_threat_model_agent_tools.py` | Drives AI/tool adapters through attempted direct invocation |
| `tests/test_threat_model_resource_failure.py` | Forces exceptions, timeouts, audit write failures, and cache pressure |

## Current Defensive Evidence

The following surfaces are implemented and tested today:

- Governed `pour`, `sip`, `import`, callable `print(...)`, and sensitive
  imported stdlib calls fail closed without policy authority.
- Governed denials carry `TarlProof`.
- Contract ALLOW and DENY decisions carry proof records.
- `GovernanceViolation` is not swallowed by `spillage`.
- Ed25519 proof signing and public-key verification are implemented.
- HMAC proof signing remains supported but documented as symmetric and not
  non-repudiable.
- Policy hash, trace consistency, malformed proof, and signature verification
  checks are covered by tests.
- Temporal policy windows and first-match-wins semantics are covered by tests.
- Imported `.thirsty` modules execute under the caller's governed runtime, so
  their top-level effects and returned closures are gated (not run detached).
- Strict, opt-in proof verification can require a signature and restrict the
  signature family to Ed25519 (`ProofVerifier` / `tarl verify --require-signature
  --ed25519-only`); the permissive default is unchanged.
- Governance-dropping build targets are refused for governed source unless
  `--allow-governance-loss` is given, which warns and records the loss in the
  emitted manifest.
- Governed modules that fail to parse fail closed: no recovered statement
  executes, and the interpreter raises a denial.

## Known Gaps

These are critical gaps, not cosmetic work:

1. No universal capability broker covers every filesystem, network, subprocess,
   database, FFI, environment mutation, AI tool call, generated-output, and
   external-adapter path. Imported stdlib calls and imported `.thirsty` modules
   are now brokered; FFI/native, external adapters, and AI/tool calls are not.
2. Hardened mode is not yet a single global switch: strict Ed25519-only proof
   verification is available but opt-in per verifier, not enforced runtime-wide.
3. Authority is still a runtime string in the CLI path; it is not bound to a
   cryptographic identity.
4. Proof freshness, replay rejection, policy revocation, and monotonic sequence
   checks are not yet implemented.
5. Audit archive tamper evidence is not yet strong enough for adversarial
   storage conditions.
6. Context schemas are not yet enforced before policy evaluation.
7. Generated build outputs cannot preserve governance; the build now refuses or
   explicitly discloses governance loss rather than silently dropping it.
8. Agent/MCP/tool integrations are not yet capability-brokered.

## Acceptance Bar For Hardened Runtime

Thirsty-Lang can claim hardened governance-substrate status only when:

1. Every challenge in the catalog is either passing with a test or explicitly
   documented as out of scope.
2. All side-effect adapters are mediated by the same broker.
3. Hardened mode requires Ed25519 proof signatures.
4. Policy and context schemas are verified before evaluation.
5. Audit persistence is hash-linked and tamper-evident.
6. Replay and downgrade attacks are rejected.
7. The full offensive challenge suite passes locally and in CI.

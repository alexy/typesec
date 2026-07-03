# FABLE-REVIEW-1 — Typesec as an interoperable type-level security platform

*Review date: 2026-07-03 · Reviewer: Claude Fable 5 · Scope: all workspace
crates, docs, examples, and the book — focused on what it takes for Typesec to
be the security plane for Pydantic AI, LangChain, OpenAI, and Anthropic
agents.*

This is the third full-repo review (the 2026-06-25 review and its refactor
plan live in `CLAUDE.md`). That round fixed structure, DRY, correctness, and
docs. This round asks a different question: **is Typesec a platform other
agent stacks can actually plug into — and if not, what's missing?** The short
answer was: the *inward* story (Rust types, capabilities, engines) is strong
and clean; the *outward* story stopped at metadata. This review proposes — and
this pass implements — the missing interop plane, then lays out the roadmap
beyond it.

---

## 1. State of the platform (what the last review left us)

The 2026-06-25 refactor did what it promised. Verified in this pass:

- **Structure.** Every `.rs` file is ≤ ~406 lines; tests live in sibling
  files; the nine-crate layering (`core` → engines → `agent`/`integrations` →
  `cli`/`python`/umbrella) is real and enforced by the dependency graph.
- **The invariant holds.** `Capability<P, R>` has no public constructor;
  `mint_capability*` is the only production path; sealed traits +
  `tests/ui/` compile-fail tests guard the boundary. This is the crown jewel
  and nothing in this pass weakens it.
- **One contract, many engines.** `PolicyEngine::check_with_context →
  Allow | Deny | Delegate` is implemented by RBAC, ODRL, graph, JWT-claims,
  WorkOS, and Arcade engines, composable via `FallbackEngine`. This is the
  right chassis for interop: anything that can phrase a question as
  *(subject, action, resource, context)* can ride every engine for free.
- **Docs.** `docs/architecture.md`, the book, and the auth-frameworks
  comparison are honest and current after the Phase E fixes.

## 2. Findings — where the platform stops short of "interoperable"

**F1. The enforcement boundary doesn't reach the wire.** `ProtectedTool`
requires a typed capability — unbeatable, but only for tools *written in
Rust*. Real agents are Pydantic AI / LangChain / OpenAI / Anthropic loops
where the model emits a **tool call as JSON** and the host decides whether to
run it. Nothing in the workspace parsed, checked, or answered those shapes.
The platform guarded the room but not the door the traffic actually uses.

**F2. The Pydantic AI integration is metadata-only.**
`typesec-integrations::pydantic_ai` produces capability *descriptors*
(`id`, `instructions`, tool metadata) and the example enforces the check
by hand inside each tool body. Descriptors don't enforce; a forgotten
`gate.require(...)` line is exactly the "runtime check someone forgot" the
project exists to eliminate.

**F3. No OpenAI or Anthropic story at all.** The two largest agent ecosystems
appeared nowhere in the code, docs, or examples — despite the book positioning
Typesec as agent security infrastructure.

**F4. The Python seam was subject/action/resource only.** `typesec_native`
answered `check(subject, action, resource, purpose)` well, but every framework
adapter had to re-derive the *tool → (action, resource)* mapping itself, in
Python, differently each time. That mapping **is** the security manifest of an
agent deployment; the platform gave it no home. (Ecosystem-level DRY violation
by the repo's own standard.)

**F5. Default-allow by omission was one adapter bug away.** With mapping left
to each adapter, an adapter that "didn't know" a tool would most naturally
skip the check. Deny-by-default for undeclared tools needs to live in the
platform, not in adapter discipline.

**F6. Example enforcement shelled out to `cargo run` per decision.**
`examples/typedid_framework_adapters.py` spawns the CLI for every check —
fine as a sketch, but it models the wrong seam given native bindings exist.
(Left in place; the new demo models the right one.)

**F7. Denials had no return path.** A blocked tool call should flow back to
the model as structured feedback (an error tool-result / retry part) so the
agent can re-plan. Nothing produced those shapes; naive adapters would raise
an exception and kill the run instead.

**F8. `RequestContext.custom` is unreachable from Python.** Only `purpose` is
exposed, so ODRL constraints keyed on custom operands can't be exercised from
agent code. (Not fixed in this pass — see P6.)

**F9. Sibling-checkout coupling bit during this review.** `../grust` carried
mid-flight WIP (a new `grust_core::Value::Graph` variant) that broke
`grust-cypher`, making the *typesec* workspace unbuildable through no fault of
its own. Verification for this pass ran against the published crates.io grust
`0.11.0` by removing the `path` keys from the three grust deps in
`Cargo.toml` (the exact fallback `CLAUDE.md` documents). The original
path-carrying lines are preserved in this doc's margin note¹ and trivially
restorable once the grust WIP lands.

## 3. The proposed architecture — a wire-level interop plane

The design principle: **keep the Rust core framework-neutral; make each
framework a *dialect*, not a dependency.** Frameworks differ only in how tool
calls are spelled in JSON. So:

```text
                       ┌────────────────────────────────────────────┐
 OpenAI  tool_calls ─▶ │ dialect codec: parse → ToolCallRequest      │
 Anthropic tool_use ─▶ │   (openai / anthropic / langchain /         │
 LangChain ToolCall ─▶ │    pydantic-ai)                             │
 PydanticAI part    ─▶ │                                             │
                       └───────────────┬────────────────────────────┘
                                       ▼
                        ToolCallGuard (deny-by-default)
                          bindings: tool → (action, resource[, from arg])
                          engine:  any PolicyEngine (RBAC/ODRL/graph/
                                   WorkOS/Arcade/Fallback composition)
                                       │
                         Allow ──▶ run the tool
                         Deny/Delegate ──▶ dialect codec: denial →
                           framework-shaped error fed back to the model
```

Key decisions, and why:

- **Normalize, don't abstract the frameworks away.** `ToolCallRequest` is
  three fields (`call_id`, `tool_name`, `arguments`). No SDK types cross the
  boundary; each dialect is ~60 lines of serde against publicly documented
  wire shapes, so a new framework (or MCP — see P1) is one small file.
- **Bindings are the deployment's security manifest.** `ToolBinding` states
  what a tool *means* in policy terms. `resource_from_arg` scopes checks to
  the resource each call names (`read_file(path=...)` checks `path`), and
  **fails closed** when the argument is missing.
- **Deny-by-default is structural.** An unbound tool never reaches an engine;
  it is refused with a reason. Delegation is not permission.
- **Denials speak the framework's language.** Each codec renders a refusal
  the way that framework feeds errors back to the model (OpenAI `role:"tool"`
  message, Anthropic `tool_result` + `is_error`, LangChain error
  `ToolMessage`, Pydantic AI `retry-prompt` part) — so policy enforcement
  becomes agent *feedback*, and the loop keeps running.
- **The typed and wire layers share one declaration.**
  `ToolCallGuard::bind_registry(&ToolRegistry)` seeds wire bindings from
  typed `ProtectedTool` specs; `pydantic_ai::binding_from_metadata` reads the
  same `typesec_*` metadata keys the integrations crate already emits. One
  tool, one declaration, two enforcement layers.
- **Python gets the guard whole, not pieces.** `typesec_native.ToolGate`
  compiles the policy once and answers whole model turns
  (`guard_json(subject, payload, dialect)`), returning per-call verdicts plus
  ready-to-send denial payloads. Python adapters shrink to ~5 lines and can't
  get the mapping wrong because they no longer own it.

## 4. Implemented in this pass

All landed, tested, and demoed. `cargo test` green (against crates.io grust —
see F9); the four-dialect demo runs end-to-end.

### 4.1 `typesec-agent::interop` (new module, 8 files, all ≤ ~210 lines)

| File | Contents |
| --- | --- |
| `interop.rs` | module docs + re-exports |
| `interop/call.rs` | `ToolCallRequest`, `ToolBinding` (incl. `from_spec`, fail-closed `resolve_resource`), `ToolCallVerdict`, `GuardedToolCall`, `InteropError` |
| `interop/guard.rs` | `ToolCallGuard`: `bind`, `bind_registry`, `check`, `check_async`, `check_all`; structured `tracing` event per decision |
| `interop/wire.rs` | shared JSON helpers (one home for array/argument/string parsing) |
| `interop/{openai,anthropic,langchain,pydantic_ai}.rs` | dialect codecs: `parse_tool_calls` + `denial` (+ `binding_from_metadata` for Pydantic AI) |
| `interop/tests.rs` | 14 tests: deny-by-default, per-policy allow/deny, resource-arg scoping + fail-closed, async parity, registry seeding, all four codecs round-trip, malformed-payload rejection, delegation-is-not-permission (ODRL) |

Re-exported from `typesec_agent` and the `typesec` umbrella (feature
`agent`).

### 4.2 `typesec-python`: `ToolGate`

- `CompiledPolicyEngine` now implements `PolicyEngine` itself, so the same
  compiled RBAC/ODRL/graph engine backs the guard with zero glue (string
  entry point renamed to `decide` for clarity).
- New `ToolGate` pyclass: constructor takes the policy + a list of binding
  dicts (`tool`, `action`, `resource`, optional `resource_arg`);
  `from_file(...)`; `check_tool(subject, tool_name, arguments_json, purpose)`
  → `Decision`; `guard_json(subject, payload_json, dialect, purpose)` → JSON
  report (`tool_name`, `call_id`, `action`, `resource`, `allowed`, `reason`,
  `denial`). 3 new inline tests (cdylib crate, per the documented exception).

### 4.3 Example + docs

- `examples/agent_interop_demo.py` — one `ToolGate` guarding realistic
  OpenAI / Anthropic / LangChain / Pydantic AI payloads with no SDKs or
  credentials; demonstrates deny-by-default (an `exfiltrate_data` call is
  refused before any engine runs), resource-arg scoping (same tool allowed
  for `reports/annual`, denied for `code/secrets`), and framework-shaped
  denial feedback. Verified run output is in the session log.
- `docs/agent-interop.md` — the integration guide: model, Rust and Python
  quickstarts, per-framework hook points, security posture.
- `CHANGELOG.md` entry; `CLAUDE.md` architecture map updated.

## 5. Proposed work (next, in priority order)

**P1. MCP dialect + gateway.** Model Context Protocol is becoming the common
tool bus (Claude Code, IDEs, OpenAI adopting it). Add an `interop::mcp`
dialect (`tools/call` params → `ToolCallRequest`; denial → JSON-RPC error /
`isError` result), then a small stdio/HTTP proxy binary (`typesec-mcp-gate`)
that fronts any MCP server and enforces a `ToolGate` policy on every
`tools/call` — Typesec as a drop-in guard for tools you don't control. This
is the highest-leverage single item on the list.

**P2. Ship the Python surface as a real package.** Publish `typesec` to PyPI
(maturin wheel for `typesec_native` + a thin pure-Python layer): typed
dataclasses over the `guard_json` report, and first-class adapters —
`typesec.langchain.guarded_tool_node(...)`, `typesec.openai.guard(client)`,
`typesec.anthropic.guard(client)`, `typesec.pydantic_ai.prepare_tools(gate)`
(Pydantic AI's `prepare_tools` hook can *hide* unauthorized tools from the
model up front, which beats post-hoc denial). The wire shapes are already
handled in Rust; the adapters are thin and testable against recorded
payloads.

**P3. Tool-argument schemas as policy.** Bindings currently map name →
(action, resource). Add optional per-tool JSON-Schema validation (garde is
already in-tree) so malformed or out-of-range arguments are denied *before*
policy evaluation, and multiple `resource_arg`s / templated resources
(`"repo/{org}/{name}"`) are expressible. This turns the binding list into a
complete, auditable tool manifest.

**P4. Signed decision receipts (portable capabilities).** A `GuardedToolCall`
verdict is honored only in-process. Mint an optional short-lived signed
receipt (ed25519 is already in-tree via the DID stack) binding
`(subject, action, resource, call_id, exp)` — a Biscuit-style attenuable
proof a downstream service can verify offline. This extends the "unforgeable
capability" invariant across process boundaries and closes the loop with
TypeDID messaging (receipt travels in the envelope).

**P5. Taint the tool *results*, not just the calls.** Tool output re-enters
the prompt — that's the prompt-injection channel. Wrap guarded tool results
as `SecureValue<L, T>` with a label derived from the resource's privacy
level, and require declassification authority before a result may flow into
a context that leaves the trust boundary (another tool call, the final
answer). The lattice and `SecureValue` machinery already exist in core; this
is composition, not new theory.

**P6. Full `RequestContext` from Python + per-call context.** Expose
`custom: dict[str, str]` on `check_tool`/`guard_json` (F8), and let bindings
lift chosen tool arguments into ODRL constraint operands — then
purpose/count/time constraints apply per tool call with no Python glue.

**P7. Decision observability.** An audit sink that emits OpenTelemetry spans
per decision (subject, tool, action, resource, verdict, engine), plus a
`typesec replay` CLI subcommand that re-evaluates a recorded decision log
against a proposed policy change — policy diffs become testable before
rollout.

**P8. Fuzz the codecs.** The dialect parsers are the new untrusted-input
surface. Add `fuzz_targets/interop_dialects.rs` feeding arbitrary JSON
through all four `parse_tool_calls` (they must error or parse, never panic)
alongside the existing `rbac_yaml` target.

## 6. More ideas (further out, roughly ordered by ambition)

- **Policy-aware tool *listing*.** Beyond guarding calls, filter the tool
  list each framework sends the model (`tools=[...]`) through the same
  bindings — what the model can't see, it won't call; denial becomes the
  backstop instead of the primary control.
- **A `#[typesec::tool]` proc-macro** that generates the `ProtectedTool`,
  its `ToolBinding`, its JSON schema, *and* per-framework export metadata
  from one function definition — one declaration, every layer.
- **TypeScript/WASM bindings.** `typesec-core` + engines compile to WASM
  (crypto crates permitting); a `@typesec/guard` npm package would cover the
  Vercel AI SDK / LangChain.js half of the ecosystem with the same Rust
  decision core — same policy file, four languages.
- **OpenAI-compatible enforcement proxy.** A `typesec-proxy` that speaks
  `/v1/chat/completions` and `/v1/messages`, forwards to any upstream, and
  strips/denies tool calls in the response stream per policy — zero-code
  adoption for any stack that can change a base URL.
- **Typestate for conversations.** The `SecureAgent<S>` idea extended to
  multi-turn protocols: a conversation whose type records which consents/
  scopes have been established, so "ask before acting" is a compile-time
  obligation (pairs with the TypeDID `mode`/`profile` negotiation).
- **Capability attenuation API.** `cap.attenuate::<CanRead>()` (down the
  lattice only) so a planner agent can hand a sub-agent a strictly weaker
  capability — delegation with proof, matching how multi-agent trees
  actually work.
- **Graph-policy for agent org charts.** The grust-backed engine already
  models reporting lines; extend it to *agent* hierarchies (planner →
  worker), so blast radius of a compromised sub-agent is a queryable graph
  property.
- **Conformance suite as a product.** Publish the dialect test corpus
  (payload → expected verdicts) as versioned JSON fixtures other
  implementations can run against — "Typesec-compatible" becomes checkable.

## 7. Verification record (this pass)

- `cargo test -p typesec-agent`: all green, including 14 new interop tests.
- `cargo test -p typesec-python`: 9/9 green (6 existing + 3 new `ToolGate`).
- `cargo test --workspace` + clippy + fmt: green — run against crates.io
  grust `0.11.0`¹ (see F9).
- `uv run maturin develop` + `uv run python examples/agent_interop_demo.py`:
  end-to-end demo verified (allow, policy-deny, deny-by-default, fail-closed
  resource scoping, denial payloads in all four dialects).

---

## 8. Roadmap progress (updated 2026-07-03, second pass)

The §5 roadmap was executed the same day, each item its own green commit:

| Item | Status | Where |
| --- | --- | --- |
| P1 MCP dialect + gateway | **Done** | `interop::mcp` codec; `typesec mcp-gate` stdio proxy (denies never reach the server, `--filter-list` hides unbound tools); verified against a scripted MCP server |
| P2 Python package | **Partial** | native adapters + `examples/pydantic_ai_toolgate.py` (live Pydantic AI agent over `TestModel` guarded by `ToolGate`, verified). PyPI packaging + per-SDK helper modules remain open |
| P3 Argument schemas | **Done** (glob subset) | `ToolBinding::require_args` / `arg_glob` — fail-closed presence + compiled glob constraints; full JSON-Schema validation remains open |
| P4 Signed receipts | **Done** | `typesec_integrations::receipt` — ed25519 `ReceiptIssuer`/`ReceiptVerifier`, expiry + tamper tests |
| P5 Tainted tool results | **Done** | `GuardedToolCall::protect_output::<L, T>()` → `SecureValue` tied to the resolved resource id; reveal requires a matching minted capability (tested end to end) |
| P6 Full context from Python | **Done** | `context={...}` on every check surface; ODRL custom-operand test |
| P7 Decision observability | **Done** (replay half) | `typesec check --audit-log` JSONL + `typesec replay` verdict-drift detection (exit 1 on drift); OTel spans remain open |
| P8 Fuzz the codecs | **Written, build-blocked** | `fuzz_targets/interop_dialects.rs` covers all five parsers; `libfuzzer-sys` won't compile on this machine (C++ stdlib headers missing — pre-existing, hits `rbac_yaml` too). Run `cargo fuzz build` on a machine with a working C++ toolchain |

Still open from §5/§6, in suggested order: PyPI packaging (P2 rest),
JSON-Schema argument validation (P3 rest), OTel audit spans (P7 rest),
policy-aware tool listing beyond MCP, the `#[typesec::tool]` macro, WASM/TS
bindings, the OpenAI-compatible proxy, capability attenuation, conversation
typestate.

---

¹ **grust path-dep note (F9).** `Cargo.toml` lines 70–72 temporarily read
`grust-graph = { version = "0.11.0", features = ["typed-zod-rs"] }`,
`grust-cypher = { version = "0.11.0" }`, `grust-sail = { version = "0.11.0" }`.
To restore the sibling-checkout workflow once the grust `Value::Graph` WIP
compiles again, re-add `path = "../grust/crates/{grust,grust-cypher,grust-sail}"`
to the respective entries (original lines preserved in git history at
`4fbdb2b`).

# TypeSec 0.12 "Torcello": typed authority for agent tools

*July 2026 — TypeSec 0.12.0 "Torcello"*

Most agent stacks treat tool security as an agreement between documentation, prompts, and callback code. The model asks to call a tool. The framework passes along JSON. Somewhere nearby, hopefully, an application checks whether that call is allowed.

TypeSec was built to close that gap. Its first job is still the same: turn authority into a value the compiler and runtime can see. A privileged Rust function can require a `Capability<P, R>` argument; that value has no public constructor; the only production path to one is a policy decision. Forgetting the check becomes a type error, not a best-practices document.

Torcello is the release where that idea grows from an in-process Rust pattern into a wire-level guard for the agent ecosystem.

## The load-bearing idea

A `Capability<P, R>` is unforgeable proof that permission `P` was granted over resource `R`. It is minted only by the policy boundary, and that boundary emits audit evidence. `Permission`, `AgentState`, and privacy labels are sealed, so application code cannot smuggle in its own authority type.

![The capability-minting flow: a request runs the policy engine; only an Allow mints an unforgeable capability, and every decision emits an audit event.](diagrams/capability-flow.png)

That is the local invariant. Torcello carries it across the wire: OpenAI tool calls, Anthropic tool-use blocks, LangChain tool calls, Pydantic AI tool parts, and MCP `tools/call` requests all pass through the same deny-by-default `ToolCallGuard`.

## What landed in Torcello

- **One interop plane.** `typesec_agent::interop` parses tool-call shapes for OpenAI, Anthropic, LangChain, Pydantic AI, and MCP, then returns structured allow/deny reports using one binding model.
- **Deny by default.** A tool without a TypeSec binding is not an accident waiting for a prompt injection; it is denied.
- **Policy-aware tool listing.** Tools that a subject cannot use can be hidden before the model sees them, while per-argument resources still get checked at call time.
- **Argument schemas.** A binding can carry a JSON Schema, so malformed arguments are denied before policy evaluation.
- **MCP gateway.** `typesec mcp-gate` is a stdio proxy that sits between an MCP client and server, enforcing policy and bindings without changing the server.
- **OpenAI/Anthropic proxy.** `typesec proxy` guards OpenAI-compatible chat completions and Anthropic messages, including streaming-aware enforcement for tool-call portions.
- **Signed decision receipts.** Allowed decisions can be carried as short-lived, offline-verifiable receipts rather than trusted process memory.
- **Decision logs and replay.** `typesec check --audit-log` records decisions, and `typesec replay` evaluates the same log against a changed policy.
- **OpenTelemetry audit sink.** Mint decisions can become `typesec.decision` spans with subject, action, resource, verdict, and reason.
- **`#[typesec_tool]`.** A Rust tool function and its security binding can now live in one declaration.
- **Python and WASM/JS.** The Python package exposes `typesec.guard(...)`, `ToolGate`, and dependency-free SDK adapters; `typesec-wasm` brings the same guard to JavaScript and TypeScript runtimes.

The workspace is now ten crates, still layered on `typesec-core`, with the umbrella `typesec` facade re-exporting the pieces behind feature flags:

![The TypeSec workspace: crates layered on typesec-core, re-exported by the umbrella typesec facade.](diagrams/layering.png)

## Why this matters for agents

Agents do not only need fewer hallucinations. They need smaller, typed blast radii.

When a model sees a tool, TypeSec can first ask whether the subject should see that tool at all. When the model tries to call it, TypeSec checks the declared action and resource. When arguments arrive, TypeSec validates their schema before policy logic runs. When the call is allowed, TypeSec can issue a receipt. When it is denied, the framework receives a dialect-native denial: an OpenAI tool message, an Anthropic tool result, a LangChain error tool message, a Pydantic AI retry prompt, or an MCP JSON-RPC error.

That means the security boundary is not hidden in a framework-specific adapter. The adapter is just transport. The authority model is the same.

## TypeSec in QueryGraph

TypeSec tracks **Grust 0.12.0 "Lobster"**, the QueryGraph graph substrate. Graph policies lower into typed Grust graphs; roles, resources, and relationships become graph-shaped authorization data; `grust-cypher` can query and mutate the graph through the same store boundary.

In **LakeCat 0.3.0 "Ocelot"**, TypeSec protects catalog actions: governed scans, credential vending, policy updates, and evidence emission. LakeCat's release-candidate proof now runs with Grust 0.12 and TypeSec 0.12, and its QGLake handoff verifies OpenLineage drain artifacts, QueryGraph import plans, and graph projection evidence from a clean tree.

In **QueryGraph 0.4 "Sentinel"**, TypeSec is the governance fabric under the navigator: typed decisions, TypeDID envelopes, receipts, and replayable evidence around agent work rather than an unbounded prompt over a warehouse.

## Try it

TypeSec 0.12.0 is published on crates.io:

```toml
[dependencies]
typesec = { version = "0.12.0", features = ["integrations"] }
```

Python:

```python
from typesec import ToolGate, guard
```

MCP:

```sh
typesec mcp-gate --policy policy.yaml --subject agent:analyst --bindings tools.yaml -- server-command
```

Read next:

- `RELEASES.md` for the Torcello release line.
- `CHANGELOG.md` for the detailed interop surface.
- `crates/typesec-python/README.md` for Python package usage.
- `crates/typesec-wasm/README.md` for JS/TS bindings.
- `docs/company-graph-grust-sail.md` for graph policy over Grust.

The check is the easy part. Torcello makes sure the tool call after the check cannot pretend the check never happened.

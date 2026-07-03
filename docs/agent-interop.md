# Agent framework interop: guarding tool calls

Every agent framework converges on the same last mile: the model emits a
**tool call** — a tool name plus JSON arguments — and the host decides whether
to run it. None of the frameworks authorize that decision for you. Typesec
does, at two layers:

1. **Typed (Rust, strongest):** `ProtectedTool` — the tool cannot be *called*
   without a `Capability<P, R>`, which only `mint_capability` can produce.
2. **Wire (any framework, any language):** `typesec_agent::interop` — a
   deny-by-default guard over the JSON tool-call shapes of OpenAI, Anthropic,
   LangChain, and Pydantic AI, exposed to Python as `typesec_native.ToolGate`.

```text
model output ─▶ dialect::parse_tool_calls ─▶ ToolCallGuard::check_all
                                                  │ Allow ─▶ run the tool
                                                  └ Deny  ─▶ dialect::denial ─▶ model
```

## The model

- **`ToolCallRequest`** — normalized call: `call_id`, `tool_name`, JSON
  `arguments`.
- **`ToolBinding`** — declares what a tool *means* in policy terms: the
  Typesec `action` (permission name) and `resource`. With
  `resource_from_arg("path")`, the resource is taken from the named string
  argument of each call — and the call is **denied** if that argument is
  missing (fail closed, never widen).
- **`ToolCallGuard`** — holds any `PolicyEngine` (RBAC, ODRL, graph, WorkOS,
  Arcade, or a `FallbackEngine` composition) plus the bindings. Unbound tools
  are denied by default. `Delegate` is *not* permission: an undecided call is
  refused.
- **Dialect codecs** (`interop::{openai, anthropic, langchain, pydantic_ai}`)
  parse each framework's wire shape and render denials back in the shape the
  framework expects, so a blocked call becomes model feedback, not a crash:

  | Dialect | Parses | Denial rendered as |
  | --- | --- | --- |
  | `openai` | `choices[*].message.tool_calls`, an assistant message, or a bare array | `{"role": "tool", ...}` message |
  | `anthropic` | `content` blocks with `type: "tool_use"` | `tool_result` block, `is_error: true` |
  | `langchain` | `AIMessage.tool_calls` / bare `ToolCall` dicts | `ToolMessage` dict, `status: "error"` |
  | `pydantic-ai` | response `parts` with `part_kind: "tool-call"` | `retry-prompt` part |
  | `mcp` | JSON-RPC `tools/call` requests | JSON-RPC response with `isError: true` tool result |

## Rust

```rust
use std::sync::Arc;
use typesec_agent::interop::{openai, ToolBinding, ToolCallGuard};
use typesec_core::policy::{RequestContext, SubjectId};

let engine = Arc::new(typesec_rbac::RbacEngine::from_yaml(policy_yaml)?);
let guard = ToolCallGuard::new(engine)
    .bind(ToolBinding::new("read_report", "read", "reports/q1"))
    .bind(ToolBinding::new("read_file", "read", "code/").resource_from_arg("path"));

let calls = openai::parse_tool_calls(&completion_json)?;
for call in guard.check_all(&SubjectId::from("agent:analyst"), calls, &RequestContext::default()) {
    if call.verdict.is_allowed() {
        // dispatch the tool
    } else if let Some(denial) = openai::denial(&call) {
        // append `denial` to the chat history and continue the loop
    }
}
```

A typed `ToolRegistry` can seed the bindings (`guard.bind_registry(&registry)`),
so the wire guard and the capability-typed tools share one declaration.
`check_async` serves IO-bound engines (WorkOS / Arcade).

## Python

```python
from typesec_native import ToolGate

gate = ToolGate.from_file("policies/rbac-example.yaml", [
    {"tool": "read_report", "action": "read", "resource": "reports/unspecified",
     "resource_arg": "report"},
    {"tool": "deploy_service", "action": "execute", "resource": "infra/prod"},
])

# One call for a whole model turn, in the framework's own shape:
report = json.loads(gate.guard_json(subject, json.dumps(payload), dialect))
# entry: {tool_name, call_id, action, resource, allowed, reason, denial}

# Or one tool at a time:
decision = gate.check_tool("agent:deploy-bot", "deploy_service",
                           arguments_json='{"env": "prod"}', purpose="release")
```

`purpose` flows into the ODRL `RequestContext`, so purpose-constrained
permissions work per call.

### Where to hook each framework

- **OpenAI SDK / any OpenAI-compatible server:** between receiving the
  completion and executing `tool_calls`; append the `denial` entries as
  `role: "tool"` messages for blocked calls.
- **Anthropic SDK:** on `stop_reason == "tool_use"`, guard the `content`
  blocks; send `denial` entries back as `tool_result` blocks in the next user
  message.
- **LangChain / LangGraph:** wrap the tool-execution node (or `ToolNode`):
  guard `message.tool_calls`, execute the allowed ones, return the denial
  `ToolMessage`s for the rest.
- **Pydantic AI:** declare bindings as tool `metadata`
  (`typesec_required_permission` / `typesec_resource_id`, see
  `examples/pydantic_ai_capabilities.py`); enforce either inside the tool via
  `gate`/`deps`, or centrally by guarding the model response parts with
  `dialect="pydantic-ai"`.

Runnable end-to-end demo (all four dialects, no SDKs or credentials needed):

```bash
uv run maturin develop -m crates/typesec-python/Cargo.toml
uv run python examples/agent_interop_demo.py
```

## Security posture

- **Deny by default.** No binding → refused, even for an admin subject. The
  bindings are the deployment's tool manifest; the model cannot reach an
  action nobody declared.
- **Fail closed.** A binding that promises a per-argument resource denies
  calls that omit the argument rather than falling back to a broader default.
- **Delegation is not permission.** `PolicyResult::Delegate` refuses unless a
  fallback engine resolves it to `Allow`.
- **Audited.** Decisions go through the engines' existing audit path, and the
  guard logs one structured `tracing` event per call
  (`subject`, `tool`, `action`, `resource`, `allowed`).

# typesec (Python)

Type-level security for AI agents: a Rust policy core (RBAC / ODRL / graph)
behind a deny-by-default tool-call guard that speaks the wire shapes of
OpenAI, Anthropic, LangChain, Pydantic AI, and MCP.

```python
from typesec import ToolGate, guard

gate = ToolGate.from_file("policy.yaml", [
    {"tool": "read_report", "action": "read", "resource": "reports/unspecified",
     "resource_arg": "report"},
])

result = guard(gate, "agent:analyst", completion.model_dump(), "openai")
for call in result.allowed:
    ...  # run the tool
messages.extend(result.denials)  # framework-shaped refusals for blocked calls
```

Per-SDK helpers live in `typesec.adapters.{openai,anthropic,langchain,
pydantic_ai,mcp}`. Tools without a declared binding are **denied by default**;
bindings can scope the resource per call (`resource_arg`), require arguments,
and constrain argument values with globs.

Build from source: `maturin develop` in `crates/typesec-python` of the
[typesec repository](https://github.com/alexy/typesec); the full guide is
`docs/agent-interop.md` there.

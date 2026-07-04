# typesec-wasm

Type-level security for AI agents, for JavaScript/TypeScript: the same Rust
policy core (RBAC / ODRL) and deny-by-default tool-call guard that back the
[typesec](https://github.com/alexy/typesec) Rust and Python surfaces, compiled
to WebAssembly. One policy file, the same verdicts, across four languages.

Guards the JSON tool-call shapes of **OpenAI**, **Anthropic**, **LangChain**,
**Pydantic AI**, and **MCP** — ideal for the Vercel AI SDK, LangChain.js, and
edge/serverless agent runtimes.

## Build

No prebuilt binary is checked in; build it from the workspace:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version <the wasm-bindgen version in Cargo.lock>
./build-npm.sh nodejs      # or: web | bundler
# → crates/typesec-wasm/pkg/  (import-ready; publish with `npm publish` from there)
```

`wasm-pack build --target nodejs crates/typesec-wasm` works too.

## Use

```js
import { WasmToolGate } from "typesec-wasm";

const gate = new WasmToolGate(policyYaml, "rbac", JSON.stringify([
  { tool: "read_report", action: "read", resource: "reports/unspecified",
    resource_arg: "report" },
  { tool: "deploy",      action: "execute", resource: "infra/prod",
    required_args: ["version"], arg_globs: { env: "infra/*" } },
]));

// Guard a whole model turn in the framework's own shape:
const report = JSON.parse(
  gate.guard_json("agent:analyst", JSON.stringify(completion), "openai"),
);
for (const call of report) {
  if (!call.allowed) messages.push(call.denial); // framework-shaped refusal
}

// Hide tools the subject may not call before the model sees them:
const tools = JSON.parse(
  gate.filter_tools("agent:analyst", JSON.stringify(requestTools), "openai"),
);
```

Binding fields: `tool`, `action`, `resource` (required); optional
`resource_arg` (take the resource from a call argument, fail-closed),
`required_args`, `arg_globs`, and `args_schema` (a full JSON Schema object).

`WasmGate` exposes plain subject/action/resource decisions
(`new WasmGate(policyYaml, "rbac").check(subject, action, resource)`).

Dialects for `guard_json` / `filter_tools`: `openai`, `anthropic`,
`langchain`, `pydantic-ai`, `mcp`. The graph policy engine is not available in
the wasm build (RBAC and ODRL are).

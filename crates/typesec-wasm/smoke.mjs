// Node smoke test for the built typesec-wasm package.
// Run via `./build-npm.sh nodejs` (which builds ./pkg then invokes this),
// or directly with `node smoke.mjs` after a nodejs-target build.
import { WasmGate, WasmToolGate } from "./pkg/typesec_wasm.js";

const policy = `
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
`;

const gate = new WasmToolGate(
  policy,
  "rbac",
  JSON.stringify([
    { tool: "read_report", action: "read", resource: "reports/unspecified", resource_arg: "report" },
    { tool: "wipe_disk", action: "execute", resource: "infra/disk" },
  ]),
);

const completion = {
  tool_calls: [
    { id: "c1", function: { name: "read_report", arguments: '{"report":"reports/q1"}' } },
    { id: "c2", function: { name: "wipe_disk", arguments: "{}" } },
  ],
};

const report = JSON.parse(gate.guard_json("agent:analyst", JSON.stringify(completion), "openai"));
const allowed = report.filter((r) => r.allowed).map((r) => r.tool_name);
const blocked = report.filter((r) => !r.allowed).map((r) => r.tool_name);
console.log("allowed:", allowed, "blocked:", blocked);

const filtered = JSON.parse(
  gate.filter_tools(
    "agent:analyst",
    JSON.stringify([{ name: "read_report" }, { name: "wipe_disk" }, { name: "ghost" }]),
    "anthropic",
  ),
);
console.log("listed tools:", filtered.map((t) => t.name));

const decision = JSON.parse(new WasmGate(policy, "rbac").check("agent:analyst", "read", "reports/q1"));
console.log("decision allowed:", decision.allowed);

const ok =
  allowed.length === 1 &&
  allowed[0] === "read_report" &&
  blocked.length === 1 &&
  blocked[0] === "wipe_disk" &&
  filtered.length === 1 &&
  filtered[0].name === "read_report" &&
  decision.allowed === true;

if (!ok) {
  console.error("SMOKE FAILED");
  process.exit(1);
}
console.log("SMOKE OK");

// Memory vault: remember → recall (ceiling redaction) → forget.
const { WasmMemoryVault } = await import("./pkg/typesec_wasm.js");
const memPolicy = `
roles:
  - name: keeper
    permissions: [read, write, delete]
    resources: ["memory/**"]
assignments:
  - subject: "agent:js"
    roles: [keeper]
`;
const vault = new WasmMemoryVault(memPolicy, "rbac");
const { id } = JSON.parse(vault.remember("agent:js", "memory/user:alice/profile", "likes wasm"));
const mem = JSON.parse(vault.recall("agent:js", "memory/user:alice/profile"));
const memPublic = JSON.parse(vault.recall("agent:js", "memory/user:alice/profile", null, "public"));
const gone = JSON.parse(vault.forget("agent:js", "memory/user:alice/profile", [id]));
console.log("memory:", mem.hits.length, "hit;", memPublic.redacted.length, "redacted at public;",
            gone.forgotten.length, "forgotten");
const memOk = mem.hits.length === 1 && memPublic.hits.length === 0 &&
              memPublic.redacted.length === 1 && gone.forgotten.length === 1;
if (!memOk) { console.error("MEMORY SMOKE FAILED"); process.exit(1); }
console.log("MEMORY SMOKE OK");

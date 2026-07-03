// These run on the host (`cargo test -p typesec-wasm`) — the API is plain
// Rust under the wasm-bindgen attributes. Cross-compilation to
// wasm32-unknown-unknown is verified separately in CI/dev via
// `cargo build -p typesec-wasm --target wasm32-unknown-unknown`.
use super::*;

const POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
"#;

const BINDINGS: &str = r#"[
  {"tool": "read_report", "action": "read", "resource": "reports/unspecified",
   "resource_arg": "report"},
  {"tool": "wipe_disk", "action": "execute", "resource": "infra/disk"}
]"#;

fn tool_gate() -> WasmToolGate {
    WasmToolGate::new_impl(POLICY, "rbac", BINDINGS).expect("gate builds")
}

#[test]
fn wasm_gate_checks_decisions() {
    let gate = WasmGate::new_impl(POLICY, "rbac").expect("gate builds");
    let allowed: Value =
        serde_json::from_str(&gate.check("agent:analyst", "read", "reports/q1", None)).unwrap();
    assert_eq!(allowed["allowed"], true);
    let denied: Value =
        serde_json::from_str(&gate.check("agent:analyst", "write", "reports/q1", None)).unwrap();
    assert_eq!(denied["allowed"], false);
    assert!(
        WasmGate::new_impl(POLICY, "graph").is_err(),
        "graph unsupported on wasm"
    );
}

#[test]
fn wasm_tool_gate_guards_openai_turns() {
    let payload = r#"{"tool_calls": [
        {"id": "c1", "function": {"name": "read_report",
                                  "arguments": "{\"report\": \"reports/q1\"}"}},
        {"id": "c2", "function": {"name": "wipe_disk", "arguments": "{}"}}
    ]}"#;
    let report: Value = serde_json::from_str(
        &tool_gate()
            .guard_json_impl("agent:analyst", payload, "openai", None)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report[0]["allowed"], true);
    assert_eq!(report[1]["allowed"], false);
    assert_eq!(report[1]["denial"]["role"], "tool");
}

#[test]
fn wasm_tool_gate_filters_listings() {
    let tools = r#"[{"name": "read_report"}, {"name": "wipe_disk"}, {"name": "ghost"}]"#;
    let filtered: Value = serde_json::from_str(
        &tool_gate()
            .filter_tools_impl("agent:analyst", tools, "anthropic", None)
            .unwrap(),
    )
    .unwrap();
    let names: Vec<&str> = filtered
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["read_report"]);
}

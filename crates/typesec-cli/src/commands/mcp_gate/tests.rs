use super::*;

const POLICY: &str = r#"
roles:
  - name: files
    permissions: [read]
    resources: ["docs/**"]
assignments:
  - subject: "agent:mcp"
    roles: [files]
"#;

const BINDINGS: &str = r#"
tools:
  - tool: read_file
    action: read
    resource: docs/unspecified
    resource_arg: path
  - tool: search
    action: read
    resource: docs/index
    arg_globs:
      query: "*"
"#;

fn gate(filter_list: bool) -> Gate {
    let engine: std::sync::Arc<dyn typesec_core::policy::PolicyEngine> =
        std::sync::Arc::new(typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses"));
    let file: BindingsFile = serde_yaml::from_str(BINDINGS).expect("bindings parse");
    let (guard, bound_tools) = build_guard(engine, file).expect("guard builds");
    Gate {
        guard,
        subject: SubjectId::from("agent:mcp"),
        ctx: RequestContext::default(),
        bound_tools,
        filter_list,
        pending_list_ids: Mutex::new(HashSet::new()),
    }
}

fn tools_call(id: u64, name: &str, arguments: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    .to_string()
}

#[test]
fn allowed_call_is_forwarded() {
    let action = gate(false).on_client_line(&tools_call(
        1,
        "read_file",
        serde_json::json!({"path": "docs/guide.md"}),
    ));
    assert!(matches!(action, ClientAction::Forward));
}

#[test]
fn denied_call_is_answered_by_the_gate_not_forwarded() {
    let action = gate(false).on_client_line(&tools_call(
        2,
        "read_file",
        serde_json::json!({"path": "secrets/key.pem"}),
    ));
    let ClientAction::Respond(response) = action else {
        panic!("denied call must not be forwarded");
    };
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["id"], 2);
    assert_eq!(response["result"]["isError"], true);
}

#[test]
fn unbound_tool_and_malformed_call_fail_closed() {
    let unbound =
        gate(false).on_client_line(&tools_call(3, "delete_everything", serde_json::json!({})));
    assert!(matches!(unbound, ClientAction::Respond(_)));

    let malformed = gate(false).on_client_line(
        &serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {}})
            .to_string(),
    );
    let ClientAction::Respond(response) = malformed else {
        panic!("malformed tools/call must not be forwarded");
    };
    assert!(response.contains("rejected the call"));
}

#[test]
fn non_tool_messages_pass_through() {
    let gate = gate(false);
    let init = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).to_string();
    assert!(matches!(gate.on_client_line(&init), ClientAction::Forward));
    assert!(matches!(
        gate.on_client_line("not json at all"),
        ClientAction::Forward
    ));
    // Server lines are untouched without --filter-list.
    let line = r#"{"jsonrpc":"2.0","id":9,"result":{"tools":[{"name":"rm_rf"}]}}"#;
    assert_eq!(gate.on_server_line(line), line);
}

#[test]
fn tools_list_responses_are_filtered_to_bound_tools() {
    let gate = gate(true);
    let request = serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"});
    assert!(matches!(
        gate.on_client_line(&request.to_string()),
        ClientAction::Forward
    ));

    let response = serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": [
        {"name": "read_file"}, {"name": "rm_rf"}, {"name": "search"}
    ]}});
    let filtered: serde_json::Value =
        serde_json::from_str(&gate.on_server_line(&response.to_string())).unwrap();
    let names: Vec<&str> = filtered["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["read_file", "search"]);

    // A second response with the same id is no longer treated as tools/list.
    let replay = gate.on_server_line(&response.to_string());
    assert!(replay.contains("rm_rf"));

    // Unrelated responses pass through even with filtering on.
    let other = r#"{"jsonrpc":"2.0","id":8,"result":{"tools":[{"name":"rm_rf"}]}}"#;
    assert_eq!(gate.on_server_line(other), other);
}

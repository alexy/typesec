use super::*;

const POLICY: &str = r#"
roles:
  - name: keeper
    permissions: [read, write, delete]
    resources: ["memory/**"]
  - name: reader
    permissions: [read]
    resources: ["memory/user:alice/**"]
assignments:
  - subject: "agent:keeper"
    roles: [keeper]
  - subject: "agent:reader"
    roles: [reader]
"#;

fn server(subject: &str) -> Server {
    let engine: Arc<dyn typesec_core::policy::PolicyEngine> =
        Arc::new(typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses"));
    Server::new(engine, subject, RequestContext::default())
}

fn respond(server: &Server, request: Value) -> Value {
    let response = server
        .handle(&request.to_string())
        .expect("request with id gets a response");
    serde_json::from_str(&response).unwrap()
}

fn tools_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
}

#[test]
fn initialize_and_tools_list_speak_mcp() {
    let server = server("agent:keeper");
    let init = respond(
        &server,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "typesec-memory-serve");

    let list = respond(
        &server,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, [TOOL_RECALL, TOOL_REMEMBER, TOOL_FORGET]);

    // Notifications get no response.
    assert!(
        server
            .handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string())
            .is_none()
    );
}

#[test]
fn remember_then_recall_roundtrips_through_mcp() {
    let server = server("agent:keeper");
    let stored = respond(
        &server,
        tools_call(
            3,
            TOOL_REMEMBER,
            json!({"space": "memory/user:alice/profile", "text": "prefers dark mode"}),
        ),
    );
    assert!(stored["result"].get("isError").is_none());
    let body: Value =
        serde_json::from_str(stored["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(body["id"].as_str().unwrap().starts_with("mem-"));

    let recalled = respond(
        &server,
        tools_call(
            4,
            TOOL_RECALL,
            json!({"space": "memory/user:alice/profile"}),
        ),
    );
    let body: Value =
        serde_json::from_str(recalled["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["hits"][0]["text"], "prefers dark mode");
}

#[test]
fn denied_calls_return_is_error_results() {
    // The reader may read alice's spaces but not write them, and not touch bob's.
    let server = server("agent:reader");

    let write = respond(
        &server,
        tools_call(
            5,
            TOOL_REMEMBER,
            json!({"space": "memory/user:alice/profile", "text": "x"}),
        ),
    );
    assert_eq!(write["result"]["isError"], true, "guard denies the write");
    assert_eq!(write["id"], 5, "JSON-RPC id echoed");

    let other = respond(
        &server,
        tools_call(6, TOOL_RECALL, json!({"space": "memory/user:bob/profile"})),
    );
    assert_eq!(
        other["result"]["isError"], true,
        "out-of-scope space denied"
    );

    let malformed = respond(
        &server,
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {}}),
    );
    assert_eq!(
        malformed["result"]["isError"], true,
        "malformed call fails closed"
    );
}

#[test]
fn unknown_methods_are_jsonrpc_errors() {
    let server = server("agent:keeper");
    let response = respond(
        &server,
        json!({"jsonrpc": "2.0", "id": 8, "method": "resources/list"}),
    );
    assert_eq!(response["error"]["code"], -32601);
}

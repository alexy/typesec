use std::sync::Arc;

use serde_json::json;
use typesec_core::policy::{RequestContext, SubjectId};

use super::*;
use crate::tool::{ProtectedTool, ToolFuture, ToolRegistry};
use typesec_core::{CanExecute, resource::GenericResource};

const POLICY: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["reports/*"]
  - name: engineer
    permissions: [read, write, execute]
    resources: ["code/*", "infra/*"]
assignments:
  - subject: "agent:analyst"
    roles: [analyst]
  - subject: "agent:engineer"
    roles: [engineer]
"#;

fn guard() -> ToolCallGuard {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses");
    ToolCallGuard::new(Arc::new(engine))
        .bind(ToolBinding::new("read_report", "read", "reports/q1"))
        .bind(ToolBinding::new("read_file", "read", "code/").resource_from_arg("path"))
}

fn ctx() -> RequestContext {
    RequestContext::default()
}

#[test]
fn unbound_tool_is_denied_by_default() {
    let call = guard().check(
        &SubjectId::from("agent:analyst"),
        ToolCallRequest::new("delete_everything", json!({})),
        &ctx(),
    );
    assert!(!call.verdict.is_allowed());
    assert!(
        call.verdict
            .reason()
            .unwrap()
            .contains("no typesec binding")
    );
    assert_eq!(call.action, None);
}

#[test]
fn bound_tool_allows_and_denies_per_policy() {
    let guard = guard();
    let allowed = guard.check(
        &SubjectId::from("agent:analyst"),
        ToolCallRequest::new("read_report", json!({})),
        &ctx(),
    );
    assert!(allowed.verdict.is_allowed());
    assert!(allowed.denial_message().is_none());

    let denied = guard.check(
        &SubjectId::from("agent:engineer"),
        ToolCallRequest::new("read_report", json!({})),
        &ctx(),
    );
    assert!(!denied.verdict.is_allowed());
    assert_eq!(denied.action.as_deref(), Some("read"));
    assert_eq!(denied.resource.as_deref(), Some("reports/q1"));
}

#[test]
fn resource_argument_scopes_the_check_per_call() {
    let guard = guard();
    let subject = SubjectId::from("agent:engineer");
    let inside = guard.check(
        &subject,
        ToolCallRequest::new("read_file", json!({"path": "code/main.rs"})),
        &ctx(),
    );
    assert!(inside.verdict.is_allowed());
    assert_eq!(inside.resource.as_deref(), Some("code/main.rs"));

    let outside = guard.check(
        &subject,
        ToolCallRequest::new("read_file", json!({"path": "reports/q1"})),
        &ctx(),
    );
    assert!(!outside.verdict.is_allowed());
}

#[test]
fn missing_resource_argument_fails_closed() {
    let call = guard().check(
        &SubjectId::from("agent:engineer"),
        ToolCallRequest::new("read_file", json!({})),
        &ctx(),
    );
    assert!(!call.verdict.is_allowed());
    assert!(
        call.verdict
            .reason()
            .unwrap()
            .contains("requires string argument 'path'")
    );
    assert_eq!(call.resource, None);
}

#[test]
fn required_arguments_and_arg_globs_fail_closed() {
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses");
    let guard = ToolCallGuard::new(Arc::new(engine)).bind(
        ToolBinding::new("deploy", "execute", "infra/prod")
            .require_args(["version"])
            .arg_glob("env", "infra/*")
            .expect("valid glob"),
    );
    let subject = SubjectId::from("agent:engineer");

    let ok = guard.check(
        &subject,
        ToolCallRequest::new("deploy", json!({"version": "1.2.3", "env": "infra/prod"})),
        &ctx(),
    );
    assert!(ok.verdict.is_allowed());

    let missing_required = guard.check(
        &subject,
        ToolCallRequest::new("deploy", json!({"env": "infra/prod"})),
        &ctx(),
    );
    assert!(
        missing_required
            .verdict
            .reason()
            .unwrap()
            .contains("requires argument 'version'")
    );

    let missing_constrained = guard.check(
        &subject,
        ToolCallRequest::new("deploy", json!({"version": "1.2.3"})),
        &ctx(),
    );
    assert!(
        !missing_constrained.verdict.is_allowed(),
        "constrained arg is required"
    );

    let out_of_pattern = guard.check(
        &subject,
        ToolCallRequest::new("deploy", json!({"version": "1.2.3", "env": "prod-db"})),
        &ctx(),
    );
    assert!(
        out_of_pattern
            .verdict
            .reason()
            .unwrap()
            .contains("does not match the allowed pattern")
    );

    let non_string = guard.check(
        &subject,
        ToolCallRequest::new("deploy", json!({"version": "1.2.3", "env": 5})),
        &ctx(),
    );
    assert!(
        !non_string.verdict.is_allowed(),
        "non-string constrained arg is denied"
    );

    assert!(
        ToolBinding::new("t", "read", "r")
            .arg_glob("a", "[bad")
            .is_err(),
        "invalid glob is rejected at declaration time"
    );
}

#[tokio::test]
async fn async_check_matches_sync() {
    let guard = guard();
    let call = guard
        .check_async(
            &SubjectId::from("agent:analyst"),
            ToolCallRequest::new("read_report", json!({})),
            &ctx(),
        )
        .await;
    assert!(call.verdict.is_allowed());
}

fn no_op_tool(_resource: &GenericResource) -> ToolFuture<'_> {
    Box::pin(async { Ok(()) })
}

#[test]
fn bind_registry_reuses_typed_tool_specs() {
    let mut registry = ToolRegistry::new();
    registry.register(ProtectedTool::<CanExecute, _, _>::new(
        "deploy",
        "Deploy a build",
        GenericResource::new("infra/deploy", "tool"),
        no_op_tool,
    ));
    let engine = typesec_rbac::RbacEngine::from_yaml(POLICY).expect("policy parses");
    let guard = ToolCallGuard::new(Arc::new(engine)).bind_registry(&registry);

    let binding = guard.binding("deploy").expect("registered tool is bound");
    assert_eq!(binding.action, "execute");
    assert_eq!(binding.resource, "infra/deploy");

    let call = guard.check(
        &SubjectId::from("agent:engineer"),
        ToolCallRequest::new("deploy", json!({})),
        &ctx(),
    );
    assert!(call.verdict.is_allowed());
}

#[test]
fn openai_parses_completion_message_and_bare_array() {
    let completion = json!({
        "choices": [{"message": {"tool_calls": [
            {"id": "call_1", "type": "function",
             "function": {"name": "read_report", "arguments": "{\"quarter\": \"q1\"}"}}
        ]}}]
    });
    let calls = openai::parse_tool_calls(&completion).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool_name, "read_report");
    assert_eq!(calls[0].call_id.as_deref(), Some("call_1"));
    assert_eq!(calls[0].arguments["quarter"], "q1");

    let message = json!({"tool_calls": [
        {"id": "call_2", "function": {"name": "read_file", "arguments": {"path": "code/x"}}}
    ]});
    assert_eq!(openai::parse_tool_calls(&message).unwrap().len(), 1);

    let bare = json!([{"function": {"name": "read_report"}}]);
    let calls = openai::parse_tool_calls(&bare).unwrap();
    assert_eq!(calls[0].arguments, json!({}));
}

#[test]
fn openai_denial_is_a_tool_role_message() {
    let call = guard().check(
        &SubjectId::from("agent:engineer"),
        ToolCallRequest::new("read_report", json!({})).with_call_id("call_9"),
        &ctx(),
    );
    let denial = openai::denial(&call).expect("denied call renders a denial");
    assert_eq!(denial["role"], "tool");
    assert_eq!(denial["tool_call_id"], "call_9");
    assert!(denial["content"].as_str().unwrap().contains("denied"));
}

#[test]
fn anthropic_parses_tool_use_blocks_and_renders_error_result() {
    let message = json!({"content": [
        {"type": "text", "text": "let me check"},
        {"type": "tool_use", "id": "toolu_1", "name": "read_report", "input": {"q": 1}}
    ]});
    let calls = anthropic::parse_tool_calls(&message).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].call_id.as_deref(), Some("toolu_1"));

    let call = guard().check(&SubjectId::from("agent:engineer"), calls[0].clone(), &ctx());
    let denial = anthropic::denial(&call).expect("denied");
    assert_eq!(denial["type"], "tool_result");
    assert_eq!(denial["tool_use_id"], "toolu_1");
    assert_eq!(denial["is_error"], true);
}

#[test]
fn langchain_parses_tool_calls_and_renders_error_tool_message() {
    let calls = langchain::parse_tool_calls(&json!([
        {"name": "read_file", "args": {"path": "code/a.rs"}, "id": "lc_1", "type": "tool_call"}
    ]))
    .unwrap();
    assert_eq!(calls[0].tool_name, "read_file");

    let call = guard().check(&SubjectId::from("agent:analyst"), calls[0].clone(), &ctx());
    let denial = langchain::denial(&call).expect("analyst cannot read code");
    assert_eq!(denial["type"], "tool");
    assert_eq!(denial["status"], "error");
    assert_eq!(denial["tool_call_id"], "lc_1");
}

#[test]
fn pydantic_ai_parses_parts_and_renders_retry_prompt() {
    let response = json!({"parts": [
        {"part_kind": "text", "content": "checking"},
        {"part_kind": "tool-call", "tool_name": "read_report",
         "args": "{\"quarter\": \"q1\"}", "tool_call_id": "pyd_1"}
    ]});
    let calls = pydantic_ai::parse_tool_calls(&response).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].arguments["quarter"], "q1");

    let call = guard().check(&SubjectId::from("agent:engineer"), calls[0].clone(), &ctx());
    let denial = pydantic_ai::denial(&call).expect("denied");
    assert_eq!(denial["part_kind"], "retry-prompt");
    assert_eq!(denial["tool_name"], "read_report");
    assert_eq!(denial["tool_call_id"], "pyd_1");
}

#[test]
fn pydantic_ai_binding_from_capability_metadata() {
    let metadata = json!({
        "typesec_required_permission": "read",
        "typesec_resource_id": "reports/q1",
    });
    let binding = pydantic_ai::binding_from_metadata("summarize_report", &metadata)
        .expect("both keys present");
    assert_eq!(binding.action, "read");
    assert_eq!(binding.resource, "reports/q1");
    assert!(pydantic_ai::binding_from_metadata("t", &json!({})).is_none());
}

#[test]
fn mcp_parses_tools_call_requests_and_skips_other_methods() {
    let batch = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "read_report", "arguments": {"report": "reports/q1"}}},
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
    ]);
    let calls = mcp::parse_tool_calls(&batch).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool_name, "read_report");
    assert_eq!(calls[0].call_id.as_deref(), Some("2"));

    let single = json!({"jsonrpc": "2.0", "id": "abc", "method": "tools/call",
                        "params": {"name": "read_report"}});
    let calls = mcp::parse_tool_calls(&single).unwrap();
    assert_eq!(calls[0].call_id.as_deref(), Some("abc"));
    assert_eq!(calls[0].arguments, json!({}));

    let other = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"});
    assert!(mcp::parse_tool_calls(&other).unwrap().is_empty());
    assert!(!mcp::is_tools_call(&other));
}

#[test]
fn mcp_denial_is_a_jsonrpc_error_result() {
    let request = json!({"jsonrpc": "2.0", "id": 42, "method": "tools/call",
                         "params": {"name": "drop_tables", "arguments": {}}});
    let calls = mcp::parse_tool_calls(&request).unwrap();
    let call = guard().check(&SubjectId::from("agent:analyst"), calls[0].clone(), &ctx());

    let denial = mcp::denial(&call).expect("unbound tool is denied");
    assert_eq!(denial["jsonrpc"], "2.0");
    assert_eq!(
        denial["id"], 42,
        "numeric JSON-RPC id survives the round trip"
    );
    assert_eq!(denial["result"]["isError"], true);
    assert!(
        denial["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("deny by default")
    );

    let echoed = mcp::denial_with_id(&call, json!("weird-id")).unwrap();
    assert_eq!(echoed["id"], "weird-id");
}

#[test]
fn malformed_payloads_error_instead_of_passing_silently() {
    assert!(openai::parse_tool_calls(&json!({"nope": 1})).is_err());
    assert!(
        openai::parse_tool_calls(&json!([{"function": {"name": "x", "arguments": "{bad"}}]))
            .is_err()
    );
    assert!(langchain::parse_tool_calls(&json!([{"args": {}}])).is_err());
    assert!(anthropic::parse_tool_calls(&json!(42)).is_err());
}

#[test]
fn delegation_is_not_permission() {
    let engine = typesec_odrl::OdrlEngine::from_yaml(
        r#"
policies:
  - uid: "policy:1"
    type: Set
    rules:
      - type: permission
        assignee: "agent:analyst"
        action: read
        target: "customer-data"
"#,
    )
    .expect("odrl parses");
    let guard = ToolCallGuard::new(Arc::new(engine)).bind(ToolBinding::new(
        "unrelated",
        "write",
        "somewhere-else",
    ));
    let call = guard.check(
        &SubjectId::from("agent:analyst"),
        ToolCallRequest::new("unrelated", json!({})),
        &ctx(),
    );
    assert!(matches!(call.verdict, ToolCallVerdict::Delegate { .. }));
    assert!(!call.verdict.is_allowed());
    assert!(call.denial_message().unwrap().contains("not authorized"));
}
